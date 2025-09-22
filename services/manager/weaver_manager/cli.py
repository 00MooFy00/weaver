from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import typer
import yaml

from weaver_manager.ipam import generate_ipv6_hosts, reconcile_ipv6_addresses
from weaver_manager.models import Config
from weaver_manager.nft import apply_nfqueue_rules
# ВНИМАНИЕ: если у тебя файл называется proxy_conf.py — оставь как ниже.
# Если ты использовал proxy_config.py — поменяй импорт на proxy_config.
from weaver_manager.proxy_conf import render_3proxy_cfg, write_config
from weaver_manager.state_io import write_state_atomic


app = typer.Typer(add_completion=False)


@dataclass(frozen=True)
class Binding:
    port: int
    ipv6: str
    group: str
    type: str


def _calc_bindings(cfg: Config) -> List[Binding]:
    out: List[Binding] = []
    for g in cfg.proxy_groups:
        ports = list(range(g.port_range.start, g.port_range.end + 1))
        ips = generate_ipv6_hosts(g.ipv6_subnet, g.count)
        for i in range(g.count):
            out.append(Binding(port=ports[i], ipv6=ips[i], group=g.name, type=g.proxy_type))
    return out


def do_apply(config_path: str) -> None:
    cfg_raw = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    cfg = Config.model_validate(cfg_raw)

    # 1) рассчитать целевые биндинги
    bindings = _calc_bindings(cfg)

    # 2) IPv6 адреса на интерфейсе хоста
    desired_ips = [b.ipv6 for b in bindings]
    pinned = list(cfg.global_.pinned_ipv6)
    added, removed = reconcile_ipv6_addresses(
        cfg.global_.ipv6_interface, desired_ips, pinned=pinned, remove_extras=True
    )
    print(f"[manager] ipv6 +{len(added)} / -{len(removed)} on {cfg.global_.ipv6_interface}")

    # 3) nft правила NFQUEUE (если задано)
    queues = [g.nfqueue_num for g in cfg.proxy_groups if g.nfqueue_num is not None]
    if queues:
        apply_nfqueue_rules(queues)
        print(f"[manager] nft NFQUEUE rules applied: {sorted(set(int(q) for q in queues))}")

    # 4) 3proxy.cfg + reload via monitor
    btuples: List[Tuple[int, str, str]] = [(b.port, b.ipv6, b.type) for b in bindings]
    bind_egress = cfg.global_.egress_bind != "off"
    content = render_3proxy_cfg(cfg.global_.inbound_ipv4_address, btuples, bind_egress=bind_egress)
    write_config(cfg.global_.proxy_config_path, "/run/3proxy/3proxy.ver", content)
    print(f"[manager] 3proxy.cfg written and reload signalled")

    # 5) state.json для контроля
    state: Dict[str, object] = {
        "version": 2,
        "groups": {
            g.name: {
                "subnet": g.ipv6_subnet,
                "type": g.proxy_type,
                "ports": [b.port for b in bindings if b.group == g.name],
                "ipv6": [b.ipv6 for b in bindings if b.group == g.name],
            }
            for g in cfg.proxy_groups
        },
    }
    write_state_atomic(cfg.global_.state_file_path, state)
    print(f"[manager] state saved to {cfg.global_.state_file_path}")


# === Fallback: если ты вызовешь БЕЗ подкоманды, просто с --config, мы всё равно применим ===
@app.callback(invoke_without_command=True)
def _default(ctx: typer.Context, config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml")) -> None:
    if ctx.invoked_subcommand is None:
        if not config:
            raise typer.BadParameter("Use --config to point to config.yaml or call 'apply --config ...'")
        do_apply(config)


# === Нормальная подкоманда ===
@app.command()
def apply(config: str = typer.Option(..., "--config", "-c", help="Path to config.yaml")) -> None:
    do_apply(config)


if __name__ == "__main__":
    app()
