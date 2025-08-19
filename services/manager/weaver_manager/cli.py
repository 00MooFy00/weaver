from __future__ import annotations
import json, subprocess, urllib.parse, shlex
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
    replace_v6_set_from_subnets
)
from .ipam import reconcile_ipv6_addresses
from .proxy_config import render_3proxy_cfg
from .state_io import write_state_locked

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
    # Быстрый доступ к исходным группам из конфигурации (там есть ipv6_subnet)
    pg_by_name = {pg.name: pg for pg in cfg.proxy_groups}

    use_subnet_set = os.environ.get("WEAVER_USE_SUBNET_SET", "0").lower() in ("1", "true", "yes")

    for gs in new_state.groups.values():
        set_name = f"{gs.name}_src"

        if use_subnet_set:
            subnet = str(pg_by_name[gs.name].ipv6_subnet)  # например, "2a01:4f8:c0c:1234::/64"
            replace_v6_set_from_subnets(
                cfg.global_.nf_table,
                set_name,
                [subnet],
                cfg.global_.nf_chain_out,
                gs.nfqueue_num
            )
        else:
            # Старый режим: все хост‑адреса (с твоей уже исправленной чанк‑загрузкой)
            saddr_list = [str(m.ipv6) for m in gs.mappings]
            replace_v6_set_elems(cfg.global_.nf_table, set_name, saddr_list)

        # На всякий — гарантируем правило (в режиме префикса оно уже ставится, но вызов идемпотентный)
        ensure_queue_rule(cfg.global_.nf_table, cfg.global_.nf_chain_out, set_name, gs.nfqueue_num)

    # 4) 3proxy.cfg
    entries: list[tuple[int, str, str]] = []
    for group_cfg in cfg.proxy_groups:
        gs = new_state.groups[group_cfg.name]
        for m in gs.mappings:
            entries.append((m.port, str(m.ipv6), group_cfg.proxy_type))

    eb = str(getattr(cfg.global_, "egress_bind", "bind")).lower()
    bind_egress = eb in ("bind", "auto")
    proxy_cfg_text = render_3proxy_cfg(entries, cfg.global_.inbound_ipv4_address, bind_egress)
    Path(cfg.global_.proxy_config_path).write_text(proxy_cfg_text, encoding="utf-8")
    write_state_locked(str(Path(cfg.global_.state_file_path)), new_state.dict())
    _restart_proxy_via_docker_api()
    print("Manager apply: done")


def _docker_api(path: str, params: dict | None = None, method: str = "GET") -> str:
    sock = "/var/run/docker.sock"
    base = "http://localhost"
    cmd = ["curl", "--fail", "--silent", "--unix-socket", sock]
    if method != "GET":
        cmd += ["-X", method]
    url = f"{base}{path}"
    if params:
        cmd += ["--get"]
        for k, v in params.items():
            cmd += ["--data-urlencode", f"{k}={v}"]
    cmd += [url]
    return subprocess.check_output(cmd, text=True)

def _restart_proxy_via_docker_api():
    try:
        ver = json.loads(_docker_api("/version")).get("ApiVersion", "v1.41")
        if not ver.startswith("v"):
            ver = "v" + ver
    except Exception:
        ver = "v1.41"

    filters = json.dumps({
        "label": [
            "com.docker.compose.project=weaver",
            "com.docker.compose.service=proxy",
        ]
    })

    try:
        data = _docker_api(f"/{ver}/containers/json", {"filters": filters})
        arr = json.loads(data)
    except Exception as e:
        print("[manager] proxy list via Docker API failed:", e)
        return

    if not arr:
        print("[manager] proxy list via Docker API: no containers found")
        return

    for c in arr:
        cid = c.get("Id")
        if not cid:
            continue
        try:
            _docker_api(f"/{ver}/containers/{cid}/restart", method="POST")
            print(f"[manager] proxy restart via Docker API: restarted container '{cid[:12]}'")
        except Exception as e:
            print(f"[manager] proxy restart via Docker API: failed for {cid[:12]}:", e)

def _restart_proxy_via_cli_fallback() -> None:
    import shutil, subprocess
    if shutil.which("docker"):
        subprocess.run(["docker","compose","restart","proxy"], check=False)
        print("[manager] proxy restart via CLI fallback done")
    else:
        print("[manager] proxy restart fallback skipped: docker not found")


if __name__ == "__main__":
    app()
