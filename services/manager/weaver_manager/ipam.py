from __future__ import annotations

from ipaddress import IPv6Address, IPv6Network
from typing import Iterable, List, Set


def generate_ipv6_hosts(subnet: str, count: int, exclude: Iterable[str] = ()) -> List[str]:
    """
    Детерминированная генерация первых N уникальных /128 из заданного /64.
    exclude: адреса, которые надо пропустить (например, pinned).
    """
    net = IPv6Network(subnet, strict=False)
    if net.prefixlen > 64:
        # Разрешаем и другие размеры, но просто идём по available hosts
        pass
    ex: Set[IPv6Address] = {IPv6Address(x) for x in exclude}
    res: List[str] = []
    # Начинаем с первого адреса в подсети + 1 (пропустим network-address)
    start = int(net.network_address)
    # По /64 свободные 64 бита, но мы не мудрим: идём последовательно
    i = 1
    while len(res) < count:
        addr = IPv6Address(start + i)
        i += 1
        if addr in ex:
            continue
        if addr not in net:
            break
        res.append(str(addr))
    if len(res) < count:
        raise ValueError(f"not enough addresses in {subnet} to allocate {count}")
    return res

