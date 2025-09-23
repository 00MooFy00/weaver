from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scapy.all import IP, IPv6, TCP  # type: ignore


def _parse_targets(targets: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for t in targets:
        try:
            nets.append(ipaddress.ip_network(t, strict=False))
        except Exception:
            continue
    return nets


def _is_syn_only(tcp: TCP) -> bool:
    # SYN без ACK
    return bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10)


def _dst_ip(pkt) -> Optional[str]:
    if IP in pkt:
        return pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].dst
    return None


def _canon_name(n: str) -> str:
    n = n.strip().lower()
    if n in ("sack", "sackok", "sack_ok", "sack-permitted"):
        return "sack"
    if n in ("timestamps", "timestamp", "ts"):
        return "ts"
    if n in ("wscale", "window_scale", "wsc"):
        return "wscale"
    if n in ("mss",):
        return "mss"
    if n in ("nop", "pad"):
        return "nop"
    if n in ("eol", "end"):
        return "eol"
    return n


def _fmt_opts(opts: Any) -> Any:
    out = []
    if not isinstance(opts, list):
        return str(opts)
    for it in opts:
        if not isinstance(it, tuple) or not it:
            out.append(str(it))
            continue
        nm = str(it[0])
        val = it[1] if len(it) > 1 else None
        if isinstance(val, (bytes, bytearray)):
            val = val.hex()
        elif isinstance(val, tuple):
            val = list(val)
        out.append([nm, val])
    return out


def _reorder_options_preserving_values(
    orig: List[tuple],
    persona_layout: List[Dict[str, Any]],
) -> List[tuple]:
    """
    Безопасный режим: НЕ добавляем и НЕ удаляем опции, только переупорядочиваем
    существующие согласно persona_layout. Значения (MSS/WScale/TS/SACK/NOP/EOL) не меняем.
    """
    if not orig:
        return orig

    # Списки вида [("MSS",1460), ("SAckOK",b""), ("Timestamp",(ts,0)), ("NOP",None), ("WScale",7)]
    # Сформируем "желаемый" порядок по именам из персоны.
    desired = [_canon_name(str(i.get("name", ""))) for i in persona_layout if i.get("name")]

    # Превратим orig в список (name_canon, index)
    cn_pairs: List[Tuple[str, int]] = []
    for idx, item in enumerate(orig):
        nm = _canon_name(str(item[0]))
        cn_pairs.append((nm, idx))

    used = set()
    out: List[tuple] = []

    # 1) Положим те, чьи имена встречаются в desired (в порядке desired, по одному вхождению)
    for want in desired:
        for nm, idx in cn_pairs:
            if idx in used:
                continue
            if nm == want:
                out.append(orig[idx])
                used.add(idx)
                break

    # 2) Добавим остальные в их исходном порядке
    for idx, item in enumerate(orig):
        if idx not in used:
            out.append(item)

    return out


def mutate_syn_payload(payload: bytes, cfg: Dict[str, Any], persona: Optional[Dict[str, Any]]) -> Tuple[bytes, Dict[str, Any]]:
    """
    IPv4/IPv6 SYN (без ACK), цели — handler.lab_mutation.targets.
    Безопасно меняем TTL/TOS/TC и ре‑упорядочиваем TCP options без смены значений.
    Окно уменьшаем до min(old, persona.window_size) если задано.
    """
    changes: Dict[str, Any] = {"mutated": False}
    lab = cfg.get("handler", {}).get("lab_mutation", {}) or {}
    if not lab.get("enable"):
        return payload, changes

    targets = _parse_targets(lab.get("targets", []))
    ip_tos = lab.get("ip_tos")
    ipv6_tc = lab.get("ipv6_tc")
    ttl_override = lab.get("ttl_override")
    tcp_opts_enabled = bool(lab.get("tcp_options", True))  # по умолчанию включено
    tcp_opts_mode = str(lab.get("tcp_options_mode", "reorder_only")).strip().lower()

    persona_ttl = None
    persona_win = None
    persona_layout: List[Dict[str, Any]] = []
    if persona:
        persona_ttl = persona.get("ttl")
        persona_win = persona.get("window_size")
        layout = persona.get("tcp_options_layout")
        if isinstance(layout, list):
            persona_layout = layout

    ttl_final = persona_ttl if persona_ttl is not None else ttl_override

    try:
        if not payload:
            return payload, changes

        ver = payload[0] >> 4

        if ver == 4:
            pkt = IP(payload)
            if TCP not in pkt:
                return payload, changes
            tcp: TCP = pkt[TCP]
            if not _is_syn_only(tcp):
                return payload, changes

            dst = _dst_ip(pkt)
            if not dst:
                return payload, changes
            ip_dst = ipaddress.ip_address(dst)
            if not any(ip_dst in net for net in targets):
                return payload, changes

            changes["dst"] = dst
            changes["sport"] = int(tcp.sport)
            changes["dport"] = int(tcp.dport)
            changes["family"] = "IPv4"

            mutated = False

            # IPv4 TOS (DSCP) / TTL
            if ip_tos is not None:
                old = pkt[IP].tos
                newv = int(ip_tos) & 0xFF
                if newv != old:
                    pkt[IP].tos = newv
                    changes["ipv4_tos"] = {"old": old, "new": newv}
                    mutated = True
            if ttl_final is not None:
                old = pkt[IP].ttl
                newv = int(ttl_final) & 0xFF
                if newv != old:
                    pkt[IP].ttl = newv
                    changes["ipv4_ttl"] = {"old": old, "new": newv}
                    mutated = True

            # Окно: только уменьшаем (безопасно)
            if persona_win is not None:
                oldw = int(tcp.window)
                neww = min(oldw, int(persona_win) & 0xFFFF)
                if neww != oldw:
                    tcp.window = neww
                    changes["tcp_window"] = {"old": oldw, "new": neww}
                    mutated = True

            # TCP options: только reorder (safe)
            if tcp_opts_enabled and persona_layout and tcp.options:
                old_opts = tcp.options
                if tcp_opts_mode == "reorder_only":
                    new_opts = _reorder_options_preserving_values(old_opts, persona_layout)
                else:
                    # на всякий случай fallback: не делаем ничего опасного
                    new_opts = old_opts

                if new_opts != old_opts:
                    tcp.options = new_opts
                    changes["tcp_options"] = {
                        "old": _fmt_opts(old_opts),
                        "new": _fmt_opts(new_opts),
                    }
                    mutated = True

            # Форс‑пересчёты (иначе словишь таймаут)
            for fld in ("len", "chksum"):
                if hasattr(pkt[IP], fld):
                    try:
                        delattr(pkt[IP], fld)
                    except Exception:
                        pass
            for fld in ("dataofs", "chksum"):
                if hasattr(tcp, fld):
                    try:
                        delattr(tcp, fld)
                    except Exception:
                        pass

            if mutated:
                out = bytes(pkt)
                changes["mutated"] = True
                return out, changes
            return payload, changes

        elif ver == 6:
            pkt = IPv6(payload)
            if TCP not in pkt:
                return payload, changes
            tcp: TCP = pkt[TCP]
            if not _is_syn_only(tcp):
                return payload, changes

            dst = _dst_ip(pkt)
            if not dst:
                return payload, changes
            ip_dst = ipaddress.ip_address(dst)
            if not any(ip_dst in net for net in targets):
                return payload, changes

            changes["dst"] = dst
            changes["sport"] = int(tcp.sport)
            changes["dport"] = int(tcp.dport)
            changes["family"] = "IPv6"

            mutated = False

            # IPv6 Traffic Class / hop-limit
            if ipv6_tc is not None:
                old = pkt[IPv6].tc
                newv = int(ipv6_tc) & 0xFF
                if newv != old:
                    pkt[IPv6].tc = newv
                    changes["ipv6_tc"] = {"old": old, "new": newv}
                    mutated = True
            if ttl_final is not None:
                old = pkt[IPv6].hlim
                newv = int(ttl_final) & 0xFF
                if newv != old:
                    pkt[IPv6].hlim = newv
                    changes["ipv6_hlim"] = {"old": old, "new": newv}
                    mutated = True

            # Окно: только уменьшаем
            if persona_win is not None:
                oldw = int(tcp.window)
                neww = min(oldw, int(persona_win) & 0xFFFF)
                if neww != oldw:
                    tcp.window = neww
                    changes["tcp_window"] = {"old": oldw, "new": neww}
                    mutated = True

            # TCP options reorder (если есть, у IPv6 это те же TCP опции)
            if tcp_opts_enabled and persona_layout and tcp.options:
                old_opts = tcp.options
                new_opts = _reorder_options_preserving_values(old_opts, persona_layout)
                if new_opts != old_opts:
                    tcp.options = new_opts
                    changes["tcp_options"] = {
                        "old": _fmt_opts(old_opts),
                        "new": _fmt_opts(new_opts),
                    }
                    mutated = True

            # Пересчёты
            if hasattr(pkt[IPv6], "plen"):
                try:
                    del pkt[IPv6].plen
                except Exception:
                    pass
            for fld in ("dataofs", "chksum"):
                if hasattr(tcp, fld):
                    try:
                        delattr(tcp, fld)
                    except Exception:
                        pass

            if mutated:
                out = bytes(pkt)
                changes["mutated"] = True
                return out, changes
            return payload, changes

        else:
            return payload, changes

    except Exception as e:
        changes["error"] = str(e)
        return payload, changes

