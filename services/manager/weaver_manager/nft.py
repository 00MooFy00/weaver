from __future__ import annotations

import subprocess as sp
from collections import defaultdict
from typing import Dict, Iterable, List, Set, Tuple

from weaver_manager.state_io import Assignment


def run(cmd: List[str], check: bool = True) -> None:
    sp.run(cmd, check=check)


def ensure_table_chains() -> None:
    # inet weaver: chains in/out, policy accept
    run(["nft", "add", "table", "inet", "weaver"], check=False)
    run(
        [
            "nft",
            "add",
            "chain",
            "inet",
            "weaver",
            "in",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "0",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ]
    , check=False)
    run(
        [
            "nft",
            "add",
            "chain",
            "inet",
            "weaver",
            "out",
            "{",
            "type",
            "filter",
            "hook",
            "output",
            "priority",
            "0",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ]
    , check=False)
    # flush both
    run(["nft", "flush", "chain", "inet", "weaver", "in"], check=True)
    run(["nft", "flush", "chain", "inet", "weaver", "out"], check=True)


def apply_nfqueue_rules(assignments: Iterable[Assignment]) -> None:
    """
    Inbound: по портам групп -> очередь.
    Outbound: по ip6 saddr (назначенным /128) -> очередь.
    """
    ensure_table_chains()

    # inbound: queue per nfqueue_num -> set of ports
    ports_by_q: Dict[int, Set[int]] = defaultdict(set)
    # outbound: queue -> set of ipv6 saddr
    saddrs_by_q: Dict[int, Set[str]] = defaultdict(set)

    for a in assignments:
        if a.nfqueue_num is None:
            continue
        q = int(a.nfqueue_num)
        ports_by_q[q].add(a.port)
        # только IPv6 исходники (egress bind) — используем для out
        saddrs_by_q[q].add(a.ipv6)

    # создать наборы портов и правил inbound
    for q, ports in ports_by_q.items():
        set_name = f"weaver_in_ports_{q}"
        # удалим, если был (чтобы тип/содержимое не конфликтовало)
        run(["nft", "delete", "set", "inet", "weaver", set_name], check=False)
        run(["nft", "add", "set", "inet", "weaver", set_name, "{", "type", "inet_service", ";", "}"])
        # добавляем порты батчем
        elems = ",".join(str(p) for p in sorted(ports))
        if elems:
            run(["nft", "add", "element", "inet", "weaver", set_name, "{", elems, "}"])
        # правило на SYN без ACK в очередь q
        run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "weaver",
                "in",
                "tcp",
                "flags",
                "&",
                "syn",
                "==",
                "syn",
                "and",
                "tcp",
                "flags",
                "&",
                "ack",
                "==",
                "0",
                "and",
                "tcp",
                "dport",
                "@"+set_name,
                "queue",
                "num",
                str(q),
                "bypass",
            ]
        )

    # outbound: наборы ip6 saddr по очередям
    for q, saddrs in saddrs_by_q.items():
        set_name = f"weaver_out_s6_{q}"
        run(["nft", "delete", "set", "inet", "weaver", set_name], check=False)
        run(["nft", "add", "set", "inet", "weaver", set_name, "{", "type", "ipv6_addr", ";", "}"])
        elems = ",".join(saddrs)
        if elems:
            run(["nft", "add", "element", "inet", "weaver", set_name, "{", elems, "}"])
        run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "weaver",
                "out",
                "ip6",
                "saddr",
                "@"+set_name,
                "and",
                "tcp",
                "flags",
                "&",
                "syn",
                "==",
                "syn",
                "and",
                "tcp",
                "flags",
                "&",
                "ack",
                "==",
                "0",
                "queue",
                "num",
                str(q),
                "bypass",
            ]
        )

