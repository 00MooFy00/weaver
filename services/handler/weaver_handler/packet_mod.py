from __future__ import annotations

import struct
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scapy.all import IP, IPv6, TCP, raw  # type: ignore[import-not-found]


def _is_syn_only(tcp: TCP) -> bool:
    return int(tcp.flags) & 0x02 and not (int(tcp.flags) & 0x10)


def _dst_ip(pkt: Any) -> str:
    if isinstance(pkt, IP):
        return str(pkt.dst)
    if isinstance(pkt, IPv6):
        return str(pkt.dst)
    raise ValueError("unsupported packet type")


def _canon_name(name: str) -> str:
    n = name.strip().lower()
    mapping = {
        "mss": "mss",
        "sack": "sackok",
        "sackok": "sackok",
        "sack_ok": "sackok",
        "ws": "wscale",
        "wscale": "wscale",
        "ts": "timestamp",
        "timestamp": "timestamp",
        "nop": "nop",
        "eol": "eol",
    }
    return mapping.get(n, n)


def _reorder_options_preserving_values(opts: List[Tuple[str, Any]], layout: List[str]) -> List[Tuple[str, Any]]:
    if not opts or not layout:
        return opts
    # нормализуем имена
    layout_norm = [_canon_name(x) for x in layout]
    used = set()
    bucket: Dict[str, List[Tuple[str, Any]]] = {}
    for name, val in opts:
        c = _canon_name(name)
        bucket.setdefault(c, []).append((name, val))
    res: List[Tuple[str, Any]] = []
    # сначала — в порядке layout
    for want in layout_norm:
        items = bucket.get(want, [])
        if not items:
            continue
        res.extend(items)
        used.add(want)
    # остальные — как были
    for name, val in opts:
        c = _canon_name(name)
        if c in used:
            continue
        res.append((name, val))
    return res


def mutate_syn_payload(payload: bytes, cfg: Dict[str, Any], persona: Optional[Dict[str, Any]]) -> Tuple[bytes, Dict[str, Any]]:
    lab = (cfg.get("handler") or {}).get("lab_mutation") or {}
    if not lab or not lab.get("enable", False):
        return payload, {"mutated": False, "reason": "lab_mutation_disabled"}

    # фокусируемся на SYN без ACK
    try:
        ver = payload[0] >> 4
    except Exception:
        return payload, {"mutated": False, "reason": "empty_or_invalid"}

    changes: Dict[str, Any] = {"mutated": False}

    def in_targets(dst: str) -> bool:
        tgts: Iterable[str] = lab.get("targets") or []
        if not tgts:
            return True
        for t in tgts:
            try:
                if ":" in t:
                    if ip_address(dst) in IPv6Network(t, strict=False):
                        return True
                else:
                    if ip_address(dst) in IPv4Network(t, strict=False):
                        return True
            except Exception:
                continue
        return False

    try:
        if ver == 4:
            pkt = IP(payload)  # type: ignore
            if not pkt.haslayer(TCP):
                return payload, {"mutated": False, "reason": "no_tcp"}
            tcp: TCP = pkt[TCP]  # type: ignore
            if not _is_syn_only(tcp):
                return payload, {"mutated": False, "reason": "not_syn"}
            dst = _dst_ip(pkt)
            if not in_targets(dst):
                return payload, {"mutated": False, "reason": "dst_not_in_targets"}

            ip_tos = lab.get("ip_tos")
            if ip_tos is not None:
                old = pkt.tos
                pkt.tos = int(ip_tos)
                changes["ip_tos"] = {"old": old, "new": pkt.tos}
                changes["mutated"] = True

            ttl = (persona or {}).get("ttl") or lab.get("ttl_override")
            if ttl is not None:
                old = pkt.ttl
                pkt.ttl = int(ttl)
                changes["ttl"] = {"old": old, "new": pkt.ttl}
                changes["mutated"] = True

            win = (persona or {}).get("window_size")
            if win is not None:
                old = tcp.window
                pkt[TCP].window = min(int(win), int(old))
                changes["win"] = {"old": int(old), "new": int(pkt[TCP].window)}
                changes["mutated"] = True

            # перестановка TCP-опций
            layout = (persona or {}).get("tcp_options_layout") or []
            if layout and tcp.options:
                pkt[TCP].options = _reorder_options_preserving_values(list(tcp.options), layout)
                changes["tcp_options"] = "reordered"
                changes["mutated"] = True

            # сбросить поля для пересчёта
            if changes["mutated"]:
                if hasattr(pkt, "len"):
                    del pkt.len
                if hasattr(pkt[TCP], "dataofs"):
                    del pkt[TCP].dataofs
                if hasattr(pkt[TCP], "chksum"):
                    del pkt[TCP].chksum
                return raw(pkt), changes
            return payload, changes

        elif ver == 6:
            pkt6 = IPv6(payload)  # type: ignore
            if not pkt6.haslayer(TCP):
                return payload, {"mutated": False, "reason": "no_tcp"}
            tcp: TCP = pkt6[TCP]  # type: ignore
            if not _is_syn_only(tcp):
                return payload, {"mutated": False, "reason": "not_syn"}
            dst = _dst_ip(pkt6)
            if not in_targets(dst):
                return payload, {"mutated": False, "reason": "dst_not_in_targets"}

            tc = lab.get("ip6_tc")
            if tc is not None:
                old = pkt6.tc
                pkt6.tc = int(tc)
                changes["ip6_tc"] = {"old": old, "new": pkt6.tc}
                changes["mutated"] = True

            hlim = (persona or {}).get("ttl") or lab.get("ttl_override")
            if hlim is not None:
                old = pkt6.hlim
                pkt6.hlim = int(hlim)
                changes["hlim"] = {"old": old, "new": pkt6.hlim}
                changes["mutated"] = True

            win = (persona or {}).get("window_size")
            if win is not None:
                old = tcp.window
                pkt6[TCP].window = min(int(win), int(old))
                changes["win"] = {"old": int(old), "new": int(pkt6[TCP].window)}
                changes["mutated"] = True

            layout = (persona or {}).get("tcp_options_layout") or []
            if layout and tcp.options:
                pkt6[TCP].options = _reorder_options_preserving_values(list(tcp.options), layout)
                changes["tcp_options"] = "reordered"
                changes["mutated"] = True

            if changes["mutated"]:
                if hasattr(pkt6[TCP], "dataofs"):
                    del pkt6[TCP].dataofs
                if hasattr(pkt6[TCP], "chksum"):
                    del pkt6[TCP].chksum
                return raw(pkt6), changes
            return payload, changes

        else:
            return payload, {"mutated": False, "reason": "unknown_version"}
    except Exception as e:
        return payload, {"mutated": False, "error": str(e)}

