from __future__ import annotations

import json
import ipaddress as ipa
import subprocess as sp
from pathlib import Path
from typing import Iterable, List, Optional, Set, Dict

import typer
import yaml
from pydantic import BaseModel, Field, conint, field_validator

app = typer.Typer(no_args_is_help=True)


# =========================
#        MODELS
# =========================

class PortRange(BaseModel):
    start: conint(ge=1, le=65535)
    end: conint(ge=1, le=65535)

    @field_validator("end")
    @classmethod
    def _check_range(cls, v, info):
        start = info.data.get("start", 0)
        if v < start:
            raise ValueError("port_range.end must be >= port_range.start")
        return v


class ProxyGroup(BaseModel):
    name: str
    ipv6_subnet: str                     # e.g. "2a01:4f8:c0c:1234::/64"
    count: conint(ge=1)
    proxy_type: str                      # "http" or "socks5"
    port_range: PortRange
    listen_stack: str = "ipv6"           # "ipv6" | "ipv4"
    nfqueue_num: Optional[int] = None
    persona: Optional[str] = None


class GlobalConfig(BaseModel):
    state_file_path: str
    proxy_config_path: str
    ipv6_interface: str
    inbound_ipv4_address: str = "0.0.0.0"
    egress_bind: str                     # "auto" | "off"
    pinned_ipv6: List[str] = []
    observe_enabled: bool = False

    @field_validator("egress_bind")
    @classmethod
    def _check_egress_bind(cls, v: str):
        v = str(v).lower()
        if v not in ("auto", "off"):
            raise ValueError("egress_bind must be 'auto' or 'off'")
        return v


class Config(BaseModel):
    global_: GlobalConfig = Field(alias="global")
    proxy_groups: List[ProxyGroup]


class Assignment(BaseModel):
    group: str
    port: int
    ipv6: str
    proxy_type: str
    listen_stack: str
    nfqueue_num: Optional[int] = None


class State(BaseModel):
    assignments: List[Assignment] = []


# =========================
#       IO HELPERS
# =========================

def _load_config(path: Path) -> Config:
    with path.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    if not doc:
        raise typer.BadParameter("empty config")
    try:
        return Config.model_validate(doc)
    except Exception as e:
        raise typer.BadParameter(f"invalid config: {e}") from e


def read_state(path: Path) -> State:
    if not path.exists():
        return State(assignments=[])
    try:
        return State.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception:
        # если state повреждён — начинаем с пустого
        return State(assignments=[])


def write_state(path: Path, st: State) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(st.model_dump(), indent=2, ensure_ascii=False)
    path.write_text(text, encoding="utf-8")

# =========================
#   ADDR / NFT UTILS
# =========================

def _iface_ipv6_addrs(iface: str) -> List[Dict]:
    """
    Возвращает addr_info по интерфейсу в JSON (iproute2 -j).
    """
    out = sp.check_output(["ip", "-j", "-6", "addr", "show", "dev", iface], text=True)
    data = json.loads(out)
    if not data:
        return []
    return data[0].get("addr_info", [])


def _weaver_subnets(cfg: Config) -> List[ipa.IPv6Network]:
    nets: List[ipa.IPv6Network] = []
    for g in cfg.proxy_groups:
        nets.append(ipa.IPv6Network(g.ipv6_subnet, strict=False))
    return nets


def _eligible_iface_managed_addrs(iface: str, nets: List[ipa.IPv6Network]) -> Set[str]:
    """
    Берём ТОЛЬКО глобальные /128 адреса на интерфейсе, попадающие в наши подсети.
    SLAAC/DHCPv6 (/64), link-local (fe80::/10) отбрасываем.
    """
    out: Set[str] = set()
    for ai in _iface_ipv6_addrs(iface):
        if ai.get("family") != "inet6":
            continue
        scope = ai.get("scope")
        if scope != "global":
            continue
        pfx = ai.get("prefixlen")
        if pfx != 128:
            continue
        addr = ai.get("local")
        if not addr:
            continue
        a = ipa.IPv6Address(addr)
        if any(a in n for n in nets):
            out.add(str(a))
    return out


def _reconcile_iface_ipv6(
    iface: str,
    want: Iterable[str],
    pinned: Iterable[str],
    nets: List[ipa.IPv6Network],
) -> None:
    want_set: Set[str] = set(want)
    pin: Set[str] = set(pinned)

    have: Set[str] = _eligible_iface_managed_addrs(iface, nets)

    to_add = sorted(want_set - have)
    to_del = sorted(have - want_set - pin)

    for a in to_add:
        sp.run(["ip", "-6", "addr", "replace", f"{a}/128", "dev", iface], check=True)
    for a in to_del:
        sp.run(["ip", "-6", "addr", "del", f"{a}/128", "dev", iface], check=True)


def _build_assignments(cfg: Config, prev: State) -> List[Assignment]:
    assigns: List[Assignment] = []
    for g in cfg.proxy_groups:
        net = ipa.IPv6Network(g.ipv6_subnet, strict=False)
        needed = g.count
        capacity = g.port_range.end - g.port_range.start + 1
        if capacity < needed:
            raise typer.BadParameter(
                f"group '{g.name}': port_range capacity {capacity} < count {needed}"
            )

        for i in range(needed):
            # начинаем с ::1, ::2, ...
            host = int(net.network_address) + (i + 2)
            ipv6 = str(ipa.IPv6Address(host))
            port = g.port_range.start + i
            assigns.append(
                Assignment(
                    group=g.name,
                    port=port,
                    ipv6=ipv6,
                    proxy_type=g.proxy_type,
                    listen_stack=g.listen_stack,
                    nfqueue_num=g.nfqueue_num,
                )
            )
    return assigns


def _render_3proxy_cfg(cfg: Config, assigns: List[Assignment]) -> str:
    lines: List[str] = [
        "# auto-generated by weaver_manager",
        "pidfile /run/3proxy/3proxy.pid",
        "nserver 1.1.1.1",
        "nserver 2606:4700:4700::1111",
        "nscache 65536",
        "",
        "setgid 1337",
        "setuid 1337",
        'monitor "/run/3proxy/3proxy.ver"',
        "log /run/3proxy/3proxy.log D",
        "rotate 10",
        "flush",
        "",
        "auth none",
        "allow *",
        "",
    ]

    for a in assigns:
        family_flag = "-6" if a.listen_stack == "ipv6" else ""
        listen_ip = "::" if a.listen_stack == "ipv6" else cfg.global_.inbound_ipv4_address
        # ВАЖНО: без пробела и без скобок
        egress = f"-e{a.ipv6}" if cfg.global_.egress_bind == "auto" else ""
        cmd = "proxy" if a.proxy_type.lower() == "http" else "socks"
        parts = [cmd, family_flag, f"-p{a.port}", f"-i{listen_ip}", "-n", "-a"]
        if egress:
            parts.append(egress)
        line = " ".join(p for p in parts if p)
        lines.append(line)

    return "\n".join(lines) + "\n"


def _write_proxy_cfg(cfg_path: Path, content: str) -> None:
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(content, encoding="utf-8")
    # пнуть 3proxy через 'monitor'
    Path("/run/3proxy/3proxy.ver").write_text("reload\n", encoding="utf-8")


def _apply_nft(cfg: Config, assigns: List[Assignment]) -> None:
    """
    Простейшие observe-правила: одна таблица, сеты портов по номерам NFQUEUE.
    Без заморочек с флагами TCP, чтобы не ловить "No symbol type information".
    """
    if not cfg.global_.observe_enabled:
        print("[manager] nft rules skipped (observe disabled).")
        return

    # собираем порты по номеру очереди
    by_q: Dict[int, Set[int]] = {}
    for a in assigns:
        if a.nfqueue_num is None:
            continue
        by_q.setdefault(a.nfqueue_num, set()).add(a.port)

    # сначала снесём нашу таблицу (если была)
    sp.run(["nft", "delete", "table", "inet", "weaver"], check=False)

    if not by_q:
        print("[manager] nft rules: no queues/ports to install.")
        return

    lines: List[str] = ["table inet weaver {"]

    # сеты портов
    for q, ports in sorted(by_q.items()):
        set_name = f"weaver_ports_{q}"
        elems = ", ".join(str(p) for p in sorted(ports))
        lines.append(f"  set {set_name} {{ type inet_service; elements = {{ {elems} }} }}")

    # цепочка
    lines.append("  chain input { type filter hook input priority 0;")
    for q, _ in sorted(by_q.items()):
        set_name = f"weaver_ports_{q}"
        lines.append(f"    tcp dport @{set_name} queue num {q} bypass")
    lines.append("  }")
    lines.append("}")

    script = "\n".join(lines) + "\n"
    sp.run(["nft", "-f", "-"], input=script, text=True, check=True)
    print("[manager] nft rules applied.")


# =========================
#         CLI
# =========================

@app.command("apply")
def apply_cmd(
    config: str = typer.Option(
        "/app/config/config.yaml",
        "--config",
        "-c",
        help="Путь к YAML конфигурации",
    ),
    nft_mode: str = typer.Option(
        "auto",
        "--nft-mode",
        help="auto|none: где применять nft (auto=менеджер применяет; none=не трогаем)",
    ),
    addr_mode: str = typer.Option(
        "manage",
        "--addr-mode",
        help="manage|skip: управлять адресами /128 на интерфейсе или пропустить (Dev)",
    ),
) -> None:
    cfg_path = Path(config)
    cfg = _load_config(cfg_path)
    state_path = Path(cfg.global_.state_file_path)
    prev = read_state(state_path)

    assigns = _build_assignments(cfg, prev)
    nets = _weaver_subnets(cfg)

    # 1) IPv6 адреса на интерфейсе (безопасное reconcile)
    if addr_mode == "manage":
        _reconcile_iface_ipv6(cfg.global_.ipv6_interface, (a.ipv6 for a in assigns), cfg.global_.pinned_ipv6, nets)
    else:
        print("[manager] iface IPv6 reconciliation skipped (--addr-mode=skip)")

    # 2) 3proxy.cfg
    _write_proxy_cfg(Path(cfg.global_.proxy_config_path), _render_3proxy_cfg(cfg, assigns))

    # 3) nft (observe)
    if nft_mode == "auto" and cfg.global_.observe_enabled:
        _apply_nft(cfg, assigns)
    else:
        print("[manager] nft rules skipped (observe disabled or nft_mode=none).")

    # 4) сохранить состояние
    write_state(state_path, State(assignments=assigns))
    print("[manager] state.json updated.")


if __name__ == "__main__":
    app()

