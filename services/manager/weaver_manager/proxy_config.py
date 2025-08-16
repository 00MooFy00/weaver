from __future__ import annotations
from typing import Iterable, Tuple

def render_3proxy_cfg(entries: Iterable[Tuple[int, str, str]], inbound_ipv4: str) -> str:
    lines = [
        "nscache 65536",
        "timeouts 1 5 30 60 180 1800 15 60",
        "flush",
        "auth none",
    ]
    for port, ipv6, ptype in entries:
        if ptype.lower() == "http":
            # -6: IPv6, -n: не резолвим имена, -i: bind inbound IPv4, -p: порт,
            # -e: исходящий IPv6, -l: лог в stdout
            lines.append(f"proxy -6 -n -i{inbound_ipv4} -p{port} -a -e{ipv6} -l")
        elif ptype.lower() == "socks5":
            lines.append(f"socks -6 -i{inbound_ipv4} -p{port} -e{ipv6} -l")
        else:
            raise ValueError(f"Unknown proxy_type: {ptype}")
    return "\n".join(lines) + "\n"
