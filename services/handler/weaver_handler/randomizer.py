from __future__ import annotations
from types import SimpleNamespace
from typing import Callable, List, Optional

from netfilterqueue import NetfilterQueue
from scapy.all import conf, IP, IPv6, TCP

# длины TCP‑опций
_OPT_LEN = {
    "MSS": 4,
    "SAckOK": 2,
    "NOP": 1,
    "Timestamp": 10,
    "WScale": 3,
}


def _opts_len(opts: List[tuple]) -> int:
    return sum(_OPT_LEN.get(k, 0) for k, _ in (opts or []))


def _extract_original_mss(tcp: TCP) -> Optional[int]:
    if not tcp.options:
        return None
    for k, v in tcp.options:
        if k == "MSS":
            try:
                return int(v)
            except Exception:
                return None
    return None


def _safe_calc_mss(ip_pkt, orig_mss: Optional[int]) -> int:
    if orig_mss and orig_mss > 0:
        return orig_mss
    if IPv6 in ip_pkt:
        return 1440
    return 1460


def _build_options_for_persona(ip_pkt, tcp: TCP, persona: SimpleNamespace) -> List[tuple]:
    """
    persona.tcp_options_layout — список SimpleNamespace(name: str, value: Optional[str]).
    value может быть 'calc' для MSS.
    """
    orig_mss = _extract_original_mss(tcp)
    opts: List[tuple] = []

    for o in getattr(persona, "tcp_options_layout", []) or []:
        name = o.name
        val  = getattr(o, "value", None)

        if name == "MSS":
            mss = _safe_calc_mss(ip_pkt, orig_mss) if (val is None or str(val).lower() == "calc") else int(val)
            opts.append(("MSS", int(mss)))

        elif name == "SACK":
            opts.append(("SAckOK", b""))

        elif name == "Timestamps":
            # ядро при реальном коннекте может вписать свои ts; для «паттерна» достаточно (0,0)
            opts.append(("Timestamp", (0, 0)))

        elif name == "NOP":
            opts.append(("NOP", None))

        elif name == "WScale":
            ws = int(val) if val is not None else 7
            opts.append(("WScale", ws))

        # прочее игнорируем

    pad = (4 - (_opts_len(opts) % 4)) % 4
    for _ in range(pad):
        opts.append(("NOP", None))

    return opts


def apply_persona_to_syn(ip_pkt, persona: SimpleNamespace, logger=None):
    """
    Меняет TTL/HLIM, окно и TCP‑опции в SYN без ACK.
    Возвращает изменённый пакет (scapy Packet).
    """
    tcp = ip_pkt[TCP]

    ttl = int(getattr(persona, "ttl", 64))
    if IPv6 in ip_pkt:
        ip_pkt[IPv6].hlim = ttl
    else:
        ip_pkt[IP].ttl = ttl

    tcp.window = int(getattr(persona, "window_size", 65535))

    new_opts = _build_options_for_persona(ip_pkt, tcp, persona)
    tcp.options = new_opts

    hdr_len = 20 + _opts_len(new_opts)
    if hdr_len % 4 != 0:
        hdr_len += (4 - (hdr_len % 4))
        for _ in range((hdr_len - (20 + _opts_len(new_opts)))):
            tcp.options.append(("NOP", None))
    tcp.dataofs = hdr_len // 4

    # Сброс длин/чексумм для пересчёта
    if IPv6 in ip_pkt:
        if hasattr(ip_pkt[IPv6], "plen"):
            del ip_pkt[IPv6].plen
    else:
        if hasattr(ip_pkt[IP], "len"):
            del ip_pkt[IP].len
    if hasattr(tcp, "chksum"):
        del tcp.chksum

    if logger:
        try:
            logger.info(
                "persona=%s src=%s sport=%s dst=%s dport=%s ttl=%s win=%s opts=%s",
                getattr(persona, "name", "unknown"),
                ip_pkt[IPv6].src if IPv6 in ip_pkt else ip_pkt[IP].src,
                tcp.sport,
                ip_pkt[IPv6].dst if IPv6 in ip_pkt else ip_pkt[IP].dst,
                tcp.dport,
                ttl,
                tcp.window,
                new_opts,
            )
        except Exception:
            pass

    return ip_pkt


def run_nfqueue_randomizer(queues: List[int],
                           choose_persona: Callable[[], Optional[SimpleNamespace]],
                           on_activity: Optional[Callable[[int, Optional[str]], None]] = None,
                           logger=None) -> None:
    """
    Вешается на NFQUEUE. Для каждого syn ack выбирает персону (через choose_persona()),
    применяет её к пакету и отправляет дальше. Все пакеты всегда accept().
    """
    conf.ipv6_enabled = True

    def _mk_handler(qn: int):
        def _handler(pkt):
            try:
                raw = pkt.get_payload()
                is_v6 = bool(raw) and ((raw[0] >> 4) == 6)
                sp = IPv6(raw) if is_v6 else IP(raw)

                if TCP in sp:
                    t = sp[TCP]
                    syn = bool(t.flags & 0x02)
                    ack = bool(t.flags & 0x10)
                    if syn and not ack:
                        persona = choose_persona()
                        if persona is not None:
                            sp = apply_persona_to_syn(sp, persona, logger=logger)
                            pkt.set_payload(bytes(sp))
                        if on_activity:
                            on_activity(qn, getattr(persona, "name", None))
            except Exception as e:
                if logger:
                    try:
                        logger.warning("nfqueue error: %s", e)
                    except Exception:
                        pass
            finally:
                try:
                    pkt.accept()
                except Exception:
                    pass
        return _handler

    nfqs: List[NetfilterQueue] = []
    try:
        for q in queues:
            nfq = NetfilterQueue()
            nfq.bind(q, _mk_handler(q))
            nfqs.append(nfq)
        # блокирующий run() — запускаем все очереди последовательно в отдельных потоках снаружи
        for nfq in nfqs:
            nfq.run()
    finally:
        for nfq in nfqs:
            try: nfq.unbind()
            except Exception: pass
