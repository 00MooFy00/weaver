from __future__ import annotations

from pathlib import Path
from typing import Iterable, Literal, Tuple


def render_3proxy_cfg(
    inbound_ipv4: str,
    bindings: Iterable[Tuple[int, str, Literal["http", "socks5"]]],
    bind_egress: bool,
) -> str:
    """
    bindings: (port, ipv6, type)
    """
    lines = [
        "setgid 1337",
        "setuid 1337",
        'monitor "/run/3proxy/3proxy.ver"',
        "log /run/3proxy/3proxy.log",
        "rotate 0",
        "nscache 65536",
        "timeouts 1 5 30 60 180 1800 15 60",
        "flush",
    ]

    for port, ipv6, ptype in bindings:
        common = f"-p{port} -i{inbound_ipv4} -a"
        if ptype == "http":
            lines.append(f"proxy {common} -e{ipv6}" if bind_egress else f"proxy {common}")
        else:
            lines.append(f"socks {common} -e{ipv6}" if bind_egress else f"socks {common}")
    return "\n".join(lines) + "\n"


def write_config(cfg_path: str, ver_path: str, content: str) -> None:
    p = Path(cfg_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(p)

    v = Path(ver_path)
    v.parent.mkdir(parents=True, exist_ok=True)
    v.touch()
