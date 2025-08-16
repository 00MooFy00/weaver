from __future__ import annotations
import subprocess
from typing import Sequence, List
from ipaddress import IPv6Address, IPv6Network

MIN_IID_DEFAULT = 0x100

def _run(args: Sequence[str]) -> None:
    subprocess.run(list(args), check=True)

def _run_ok(args: Sequence[str]) -> bool:
    return subprocess.run(list(args),
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0

def _cap(args: Sequence[str]) -> str:
    p = subprocess.run(list(args), check=False, capture_output=True, text=True)
    return (p.stdout or "") + (p.stderr or "")


# -------- iface detect --------

def detect_default_iface() -> str:
    for cmd in (
        ["ip", "-6", "route", "show", "default"],
        ["ip", "route", "show", "default"],
    ):
        text = _cap(cmd).strip()
        for line in text.splitlines():
            parts = line.split()
            if "dev" in parts:
                try:
                    idx = parts.index("dev")
                    return parts[idx + 1]
                except Exception:
                    continue
    raise RuntimeError("No default route iface detected")


# -------- IPv6 helpers --------

def ensure_ipv6_addresses(interface: str, addrs: List[IPv6Address]) -> None:
    have_text = _cap(["ip", "-6", "addr", "show", "dev", interface])
    have = set()
    for line in have_text.splitlines():
        line = line.strip()
        if line.startswith("inet6 "):
            try:
                addr = line.split()[1].split("/")[0]
                have.add(addr.lower())
            except Exception:
                pass
    for ip6 in addrs:
        s = str(ip6).lower()
        if s not in have:
            _run(["ip", "-6", "addr", "add", f"{s}/128", "dev", interface, "nodad"])


def generate_ipv6_hosts(subnet: IPv6Network, count: int, min_iid: int = MIN_IID_DEFAULT) -> List[IPv6Address]:
    hosts: List[IPv6Address] = []
    base = int(subnet.network_address)
    max_iid = (1 << (128 - subnet.prefixlen)) - 1
    start = min_iid if min_iid <= max_iid else 1
    for ofs in range(start, start + count):
        ip_int = base + ofs
        ip = IPv6Address(ip_int)
        if ip not in subnet:
            break
        hosts.append(ip)
    if len(hosts) < count:
        raise RuntimeError(
            f"generate_ipv6_hosts: only {len(hosts)} addresses available in {subnet} from IID 0x{start:x}"
        )
    return hosts


# -------- nftables --------

def purge_table(table: str) -> None:
    # тихо: нет - так нет
    if _run_ok(["nft", "list", "table", "inet", table]):
        subprocess.run(["nft", "flush", "table", "inet", table],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["nft", "delete", "table", "inet", table],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ensure_table_chain(table: str, chain_out: str, policy_accept: bool) -> None:
    if not _run_ok(["nft", "list", "table", "inet", table]):
        _run(["nft", "add", "table", "inet", table])

    have_chain = _run_ok(["nft", "list", "chain", "inet", table, chain_out])
    if not have_chain:
        pol = "accept" if policy_accept else "drop"
        _run([
            "nft","add","chain","inet",table,chain_out,
            "{","type","filter","hook","output","priority","filter",";","policy",pol,";","}"
        ])
    else:
        # при необходимости можно поправить policy
        text = subprocess.run(["nft","list","chain","inet",table,chain_out],
                              check=False, capture_output=True, text=True).stdout or ""
        need = "policy accept" if policy_accept else "policy drop"
        if need not in text:
            pol = "accept" if policy_accept else "drop"
            _run(["nft","flush","chain","inet",table,chain_out])
            _run([
                "nft","add","chain","inet",table,chain_out,
                "{","type","filter","hook","output","priority","filter",";","policy",pol,";","}"
            ])

def ensure_v6_set(table: str, set_name: str) -> None:
    if not _run_ok(["nft","list","set","inet",table,set_name]):
        _run(["nft","add","set","inet",table,set_name,"{","type","ipv6_addr",";","}"])

def replace_v6_set_elems(table: str, set_name: str, elems: List[str]) -> None:
    ensure_v6_set(table, set_name)
    _run(["nft","flush","set","inet",table,set_name])
    if not elems:
        return
    CHUNK = 512
    for i in range(0, len(elems), CHUNK):
        chunk = elems[i:i+CHUNK]
        _run(["nft","add","element","inet",table,set_name,"{",",".join(chunk),"}"])


def ensure_queue_rule(table: str, chain_out: str, set_name: str, nfqueue_num: int) -> None:
    text = _cap(["nft", "list", "chain", "inet", table, chain_out])
    signature = f"ip6 saddr @{set_name} tcp flags syn queue flags bypass to {nfqueue_num}"
    if signature in text:
        return
    _run([
        "nft","add","rule","inet",table,chain_out,
        "ip6","saddr",f"@{set_name}",
        "tcp","flags","syn",
        "queue","flags","bypass","to",str(nfqueue_num)
    ])

# back-compat wrapper если где-то ждут одним вызовом
def ensure_nfqueue_rule_set(
    table: str,
    chain_out: str,
    set_name: str,
    elems: List[str],
    nfqueue_num: int,
    policy_accept: bool = True,
) -> None:
    ensure_table_chain(table, chain_out, policy_accept=policy_accept)
    replace_v6_set_elems(table, set_name, elems)
    ensure_queue_rule(table, chain_out, set_name, nfqueue_num)
