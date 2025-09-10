import ipaddress
import os
import random
from typing import Dict, List, Set, Tuple
from pyroute2 import IPRoute

def _rand_host_in_subnet(subnet: ipaddress.IPv6Network) -> ipaddress.IPv6Address:
    # исключаем сетевой адрес, генерируем нижние 64 бита (для /64)
    host_bits = subnet.max_prefixlen - subnet.prefixlen
    rnd = random.getrandbits(host_bits)
    return ipaddress.IPv6Address(int(subnet.network_address) + rnd)

def allocate_random_ipv6(subnet_str: str, want: int, reserved: Set[str]) -> List[str]:
    subnet = ipaddress.IPv6Network(subnet_str, strict=False)
    out: Set[str] = set()
    attempts = 0
    while len(out) < want:
        attempts += 1
        if attempts > want * 100:
            raise RuntimeError("cannot allocate enough unique IPv6 addresses")
        cand = str(_rand_host_in_subnet(subnet))
        if cand in reserved or cand in out:
            continue
        out.add(cand)
    return list(out)

def ensure_addrs_on_iface(ifname: str, desired: Set[str]) -> Tuple[Set[str], Set[str]]:
    """
    Приводит список /128 на интерфейсе к desired. Возвращает (added, removed).
    """
    ipr = IPRoute()
    idx_list = ipr.link_lookup(ifname=ifname)
    if not idx_list:
        raise RuntimeError(f"interface {ifname} not found")
    idx = idx_list[0]
    present: Set[str] = set()
    for addr in ipr.get_addr(index=idx, family=10):  # AF_INET6
        attrs = dict(addr.get('attrs', []))
        ip = attrs.get('IFA_ADDRESS')
        plen = addr.get('prefixlen')
        if ip and plen == 128:
            present.add(ip)
    to_add = desired - present
    to_del = present - desired
    for ip in sorted(to_add):
        ipr.addr('add', index=idx, address=ip, prefixlen=128)
    for ip in sorted(to_del):
        ipr.addr('del', index=idx, address=ip, prefixlen=128)
    return to_add, to_del
