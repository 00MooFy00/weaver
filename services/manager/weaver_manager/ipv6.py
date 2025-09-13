from __future__ import annotations
import subprocess
from ipaddress import IPv6Network
from typing import List


def generate_ipv6_addrs(subnet: str, count: int) -> List[str]:
    net = IPv6Network(subnet, strict=False)
    base = int(net.network_address)
    addrs = []
    # пропускаем network ::, начинаем с +1
    for i in range(1, count + 1):
        addr_int = base + i
        addrs.append(str(IPv6Network((addr_int, 128)).network_address))
    return addrs


def current_ipv6_addrs(iface: str) -> List[str]:
    out = subprocess.run(
        ["ip", "-6", "-o", "addr", "show", "dev", iface],
        check=False,
        capture_output=True,
        text=True,
    ).stdout
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        for p in parts:
            if "/" in p and ":" in p:
                ip, plen = p.split("/", 1)
                if plen == "128":
                    addrs.append(ip)
    return addrs


def ensure_ipv6_addrs(iface: str, desired: List[str]) -> None:
    have = set(current_ipv6_addrs(iface))
    want = set(desired)
    to_add = sorted(want - have)
    to_del = sorted(have - want)
    for ip in to_del:
        subprocess.run(["ip", "-6", "addr", "del", f"{ip}/128", "dev", iface], check=False)
    for ip in to_add:
        subprocess.run(["ip", "-6", "addr", "add", f"{ip}/128", "dev", iface], check=True)
