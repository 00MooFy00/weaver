from __future__ import annotations
from typing import Iterable, Tuple

def render_3proxy_cfg(entries, inbound_ipv4, bind_egress: bool) -> str:
    header = (
        "log /dev/stdout\n"
        "rotate 0\n"
        "nscache 65536\n"
        "timeouts 1 5 30 60 180 1800 15 60\n"
        "flush\n"
        "auth none\n"
    )
    lines = [header]
    for port, ipv6, ptype in entries:
        eflag = (f" -e{ipv6}") if bind_egress else ""
        if ptype == "http":
            lines.append(f"proxy -6 -i{inbound_ipv4} -p{port} -a{eflag} -l")
        elif ptype == "socks5":
            lines.append(f"socks -6 -i{inbound_ipv4} -p{port}{eflag} -l")
    return "\n".join(lines) + "\n"
