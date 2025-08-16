from __future__ import annotations
import json, subprocess, urllib.parse
from pathlib import Path
from typing import Optional

import typer, yaml
from pydantic import IPvAnyAddress

from .models import Config, State, GroupState, PortIPv6
from .nft import (
    detect_default_iface,
    purge_table,
    ensure_table_chain,
    replace_v6_set_elems,
    ensure_queue_rule,
    generate_ipv6_hosts,
)
from .ipam import reconcile_ipv6_addresses
from .proxy_config import render_3proxy_cfg
from .state_io import write_state_locked

PROXY_CFG_HEADER = (
    "log /dev/stdout\n"
    "rotate 0\n"
)

DEFAULT_CONFIG = Path("/app/config/config.yaml")
app = typer.Typer(add_completion=False, no_args_is_help=False)

def load_config(path: Path):
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict) or not data:
        raise typer.BadParameter(f"Config file {path} is empty or invalid YAML")
    return Config.model_validate(data) if hasattr(Config, "model_validate") else Config.parse_obj(data)


@app.callback(invoke_without_command=True)
def _entry(ctx: typer.Context,
           config: Path = typer.Option(DEFAULT_CONFIG, "--config","-c"),
           iface: str = typer.Option("auto", "--iface")):
    if ctx.invoked_subcommand is None:
        apply(config=config, iface=iface)

@app.command()
def apply(config: Path = typer.Option(DEFAULT_CONFIG, "--config","-c"),
          iface: str = typer.Option("auto", "--iface")) -> None:
    _apply_impl(config, iface)

def _apply_impl(config_path: Path, iface: Optional[str]) -> None:
    cfg = load_config(config_path)

    # 0) iface
    interface = iface or getattr(cfg.global_, "ipv6_interface", "auto")
    if interface == "auto":
        interface = detect_default_iface()
        print(f"[manager] autodetected interface: {interface}")

    # 1) желаемое состояние
    groups: dict[str, GroupState] = {}
    for g in cfg.proxy_groups:
        hosts = generate_ipv6_hosts(g.ipv6_subnet, g.count)
        desired_ports = list(range(g.port_range.start, g.port_range.start + g.count))
        mappings = [PortIPv6(port=p, ipv6=hosts[i]) for i, p in enumerate(desired_ports)]
        groups[g.name] = GroupState(name=g.name, persona=g.persona, nfqueue_num=g.nfqueue_num, mappings=mappings)
    new_state = State(groups=groups)

    # 2) IPv6: добавить недостающие (и pinned), удаление лишних — по флагу
    all_ipv6 = [m.ipv6 for gs in new_state.groups.values() for m in gs.mappings]
    managed_subnets = list({pg.ipv6_subnet for pg in cfg.proxy_groups})
    pinned = set(cfg.global_.pinned_ipv6)
    reconcile_ipv6_addresses(
        interface, all_ipv6, managed_subnets,
        remove_extras=cfg.global_.reconcile_remove_extras, pinned=pinned
    )

    # 3) nft: полная чистка и пересоздание
    purge_table(cfg.global_.nf_table)
    ensure_table_chain(cfg.global_.nf_table, cfg.global_.nf_chain_out, cfg.global_.nf_policy_accept)
    for gs in new_state.groups.values():
        set_name = f"{gs.name}_src"
        saddr_list = [str(m.ipv6) for m in gs.mappings]
        replace_v6_set_elems(cfg.global_.nf_table, set_name, saddr_list)
        ensure_queue_rule(cfg.global_.nf_table, cfg.global_.nf_chain_out, set_name, gs.nfqueue_num)

    # 4) 3proxy.cfg
    entries: list[tuple[int, str, str]] = []
    for group_cfg in cfg.proxy_groups:
        gs = new_state.groups[group_cfg.name]
        for m in gs.mappings:
            entries.append((m.port, str(m.ipv6), group_cfg.proxy_type))

    proxy_cfg_text = PROXY_CFG_HEADER + render_3proxy_cfg(entries, cfg.global_.inbound_ipv4_address)
    Path(cfg.global_.proxy_config_path).write_text(proxy_cfg_text, encoding="utf-8")
    write_state_locked(str(Path(cfg.global_.state_file_path)), new_state.dict())
    _restart_proxy_via_docker_api()
    print("Manager apply: done")

def _restart_proxy_via_docker_api() -> None:
    try:
        filters = json.dumps({
            "label": [
                "com.docker.compose.project=weaver",
                "com.docker.compose.service=proxy"
            ]
        })
        url = f"http://localhost/v1.45/containers/json?filters={urllib.parse.quote(filters)}"
        out = subprocess.run(
            ["curl", "--fail", "--silent", "--unix-socket", "/var/run/docker.sock", "--globoff", url],
            check=True, capture_output=True, text=True
        ).stdout
        arr = json.loads(out)
        if not arr:
            print("[manager] proxy restart via Docker API: container not found")
            return
        cid = arr[0]["Id"]
        subprocess.run(
            ["curl", "-X", "POST", "--fail", "--silent", "--unix-socket", "/var/run/docker.sock",
             f"http://localhost/v1.45/containers/{cid}/restart"],
            check=True
        )
        print("[manager] proxy restart via Docker API: restarted 1 container(s)")
    except Exception as e:
        print(f"[manager] proxy restart via Docker API failed: {e}")

def _restart_proxy_via_docker_api() -> None:
    sock = "/var/run/docker.sock"
    base = "http://localhost/v1.45"

    def _curl(args, **kw):
        return subprocess.run(args, check=False, capture_output=True, text=True, **kw)

    ping = _curl(["curl","--silent","--unix-socket",sock,f"{base}/_ping"])
    if ping.returncode != 0:
        print(f"[manager] Docker API not reachable on {sock}: {ping.stderr or ping.stdout}".strip())
        return

    # 1) пробуем рестарт по "стабильному" имени compose-контейнера без фильтров
    for name in ("weaver-proxy-1", "proxy-1", "proxy"):
        r = _curl(["curl","--fail","--silent","--unix-socket",sock,"-X","POST",f"{base}/containers/{name}/restart"])
        if r.returncode == 0:
            print(f"[manager] proxy restart via Docker API: restarted container '{name}'")
            return

    # 2) если имя не сработало — ищем по label фильтрам через --get/--data-urlencode
    filters = json.dumps({
        "label": [
            "com.docker.compose.project=weaver",
            "com.docker.compose.service=proxy",
        ]
    })

    rlist = _curl([
        "curl","--fail","--silent","--unix-socket",sock,"--get", f"{base}/containers/json",
        "--data-urlencode", f"filters={filters}"
    ])
    if rlist.returncode != 0:
        print(f"[manager] proxy list via Docker API failed: {rlist.stderr or rlist.stdout}".strip())
        return

    try:
        arr = json.loads(rlist.stdout)
    except Exception as e:
        print(f"[manager] proxy list parse failed: {e}")
        return

    if not arr:
        print("[manager] proxy restart via Docker API: container not found")
        return

    cid = arr[0].get("Id")
    if not cid:
        print("[manager] proxy restart via Docker API: bad response (no Id)")
        return

    rrest = _curl(["curl","--fail","--silent","--unix-socket",sock,"-X","POST",f"{base}/containers/{cid}/restart"])
    if rrest.returncode == 0:
        print("[manager] proxy restart via Docker API: restarted 1 container(s)")
    else:
        print(f"[manager] proxy restart via Docker API failed: {rrest.stderr or rrest.stdout}".strip())


def _restart_proxy_via_cli_fallback() -> None:
    import shutil, subprocess
    if shutil.which("docker"):
        subprocess.run(["docker","compose","restart","proxy"], check=False)
        print("[manager] proxy restart via CLI fallback done")
    else:
        print("[manager] proxy restart fallback skipped: docker not found")


if __name__ == "__main__":
    app()
