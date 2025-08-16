from __future__ import annotations
import subprocess
from typing import Sequence, List, Set
from ipaddress import IPv6Address, IPv6Network

def _run(args: Sequence[str]) -> None:
    subprocess.run(list(args), check=True)

def _cap(args: Sequence[str]) -> str:
    p = subprocess.run(list(args), check=False, capture_output=True, text=True)
    return p.stdout or ""

def list_iface_ipv6(interface: str) -> Set[IPv6Address]:
    out=_cap(["ip","-6","addr","show","dev",interface]); res=set()
    for ln in out.splitlines():
        ln=ln.strip()
        if ln.startswith("inet6 "):
            try: res.add(IPv6Address(ln.split()[1].split("/")[0]))
            except Exception: pass
    return res

def reconcile_ipv6_addresses(interface: str, desired: List[IPv6Address],
                             managed_subnets: List[IPv6Network],
                             remove_extras: bool=False,
                             pinned: Set[IPv6Address] | None = None)->None:
    pinned = pinned or set()
    desired_set = set(desired)|set(pinned)
    have = list_iface_ipv6(interface)
    for ip6 in desired_set - have:
        _run(["ip","-6","addr","add", f"{str(ip6)}/128","dev",interface,"nodad"])
    if remove_extras:
        for ip6 in have - desired_set:
            if ip6 in pinned: continue
            if any(ip6 in sn for sn in managed_subnets):
                subprocess.run(["ip","-6","addr","del", f"{str(ip6)}/128","dev",interface], check=False)
