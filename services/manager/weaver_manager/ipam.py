from __future__ import annotations

import subprocess
from ipaddress import IPv6Network
from typing import Iterable, List, Set, Tuple


def generate_ipv6_hosts(subnet: str, count: int) -> List[str]:
    """
    Детерминированно выдаёт первые `count` адресов /128 в подсети (пропуская ::).
    """
    net = IPv6Network(subnet, strict=False)
    base = int(net.network_address)
    out: List[str] = []
    for i in range(1, count + 1):
        addr_int = base + i
        out.append(str(IPv6Network((addr_int, 128)).network_address))
    return out


def _run(args: List[str], check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, capture_output=True, text=True, input=input_text)


def list_iface_ipv6(iface: str) -> Set[str]:
    """
    Возвращает множество IPv6 /128, назначенных на iface.
    """
    out = _run(["ip", "-6", "-o", "addr", "show", "dev", iface], check=False).stdout
    have: Set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        for p in parts:
            if ":" in p and "/" in p:
                ip, plen = p.split("/", 1)
                if plen == "128":
                    have.add(ip)
    return have


def reconcile_ipv6_addresses(
    iface: str,
    desired: Iterable[str],
    pinned: Iterable[str] = (),
    remove_extras: bool = True,
) -> Tuple[Set[str], Set[str]]:
    """
    Приводит список /128 на интерфейсе к desired.
    pinned — адреса, которые нельзя удалять.
    Возвращает (added, removed).
    """
    want = set(desired)
    have = list_iface_ipv6(iface)
    pin = set(pinned)

    to_add = sorted(want - have)
    to_del = sorted((have - want) - pin) if remove_extras else []

    for ip in to_del:
        _run(["ip", "-6", "addr", "del", f"{ip}/128", "dev", iface], check=False)

    for ip in to_add:
        # nodad = быстрее, без Duplicate Address Detection
        _run(["ip", "-6", "addr", "add", f"{ip}/128", "dev", iface, "nodad"], check=True)

    return set(to_add), set(to_del)
