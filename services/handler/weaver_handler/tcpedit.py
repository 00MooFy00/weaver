from __future__ import annotations
import os
from typing import List, Tuple, Optional
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import TCP


def _calc_mss(ip: IPv6) -> int:
    # Можно переопределить через env (например 1440 для IPv6 MTU=1500).
    env = os.environ.get("WEAVER_HANDLER_IPV6_MSS")
    try:
        return int(env) if env else 1460
    except Exception:
        return 1460

def _build_tcp_options(layout: List[dict], ip: IPv6) -> List[Tuple]:
    opts: List[Tuple] = []
    for item in layout:
        name = item.get("name")
        val = item.get("value", None)
        if not name:
            continue
        n = name.lower()
        if n == "mss":
            mss = _calc_mss(ip) if (val is None or str(val).lower() == "calc") else int(val)
            opts.append(("MSS", mss))
        elif n == "sack":
            opts.append(("SAckOK", b""))
        elif n in ("timestamps", "ts", "timestamp"):
            # TSval/TSecr — нули достаточно (ядро поправит, а p0f/сниффер увидит поле)
            opts.append(("Timestamp", (0, 0)))
        elif n == "nop":
            opts.append(("NOP", None))
        elif n in ("wscale", "window_scale", "ws"):
            ws = int(val) if val is not None else 7
            opts.append(("WScale", ws))
        else:
            # неизвестное скипаем
            pass
    return opts

def apply_persona_to_syn(ip: IPv6, tcp: TCP, persona: dict, force: bool = True) -> None:
    # Применяем только к syn
    if not tcp.flags & 0x02 or tcp.flags & 0x10:
        return

    if force:
        ip.hlim = int(persona.get("ttl", ip.hlim))
        tcp.window = int(persona.get("window_size", tcp.window))

    layout = persona.get("tcp_options_layout") or []
    new_opts = _build_tcp_options(layout, ip)
    if new_opts:
        tcp.options = new_opts

    if hasattr(tcp, "chksum"):
        del tcp.chksum
    if hasattr(ip, "plen"):
        del ip.plen
