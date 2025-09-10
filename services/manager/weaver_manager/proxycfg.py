from typing import Iterable, Dict, Any, List
from pathlib import Path

HEADER_TMPL = """\
daemon
pidfile /run/3proxy.pid
# DNS
{dns_lines}
# Логи в stdout, ротация каждые {rotate} минут
log /dev/stdout D
rotate {rotate}
nscache 65536
# Разрешаем всем (auth none); обязательно прикрывайте вход фаерволом
auth none
flush
"""

def _dns_lines(dns: List[str]) -> str:
    return "\n".join(f"nserver {d}" for d in dns)

def generate(cfg_path: str, inbound_host: str, rotate_minutes: int, dns: List[str],
             services: Iterable[Dict[str, Any]]) -> None:
    """
    services: [{type: "http"|"socks5", port: int, external6: "IPv6"}]
    """
    p = Path(cfg_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [HEADER_TMPL.format(dns_lines=_dns_lines(dns), rotate=rotate_minutes)]

    for s in services:
        t = s["type"]
        port = s["port"]
        ext6 = s["external6"]
        if t == "http":
            # proxy -p<port> -e<external-ipv4/6>
            lines.append(f"proxy -p{port} -e{ext6}")
        elif t == "socks5":
            lines.append(f"socks -p{port} -e{ext6}")
        else:
            raise ValueError(f"unknown service type: {t}")

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
