from __future__ import annotations

import argparse
import threading
from pathlib import Path
from typing import Dict, List, Optional

import yaml

try:
    from netfilterqueue import NetfilterQueue  # preferred
except Exception:  # pragma: no cover
    from NetfilterQueue import NetfilterQueue  # type: ignore

from weaver_handler.health import HealthRegistry, serve
from weaver_handler.util import json_log
from weaver_handler.packet_mod import mutate_syn_payload

PersonaConfig = Dict[str, int]


def _tcp_flags_str(payload: bytes) -> str:
    if not payload:
        return "?"
    ver = payload[0] >> 4
    if ver == 4:
        if len(payload) < 20:
            return "IPv4:short"
        ihl = (payload[0] & 0x0F) * 4
        if len(payload) < ihl + 14:
            return "IPv4:short"
        flags = payload[ihl + 13]
        return f"IPv4:{flags:08b}"
    if ver == 6:
        if len(payload) < 54:
            return "IPv6:short"
        nxt = payload[6]
        if nxt != 6:
            return f"IPv6:nxt={nxt}"
        flags = payload[40 + 13]
        return f"IPv6:{flags:08b}"
    return "?"


def _load_cfg(path: str) -> dict:
    raw = Path(path).read_text(encoding="utf-8")
    return yaml.safe_load(raw) or {}


def _worker(
    queue_num: int,
    persona: Optional[PersonaConfig],
    reg: HealthRegistry,
    modify_packets: bool,
    full_cfg: dict,
) -> None:
    def cb(pkt) -> None:
        try:
            reg.mark(queue_num)
            payload: bytes = pkt.get_payload()
            flags = _tcp_flags_str(payload)

            mutated = False
            changes: Dict[str, object] = {}
            if modify_packets:
                new_payload, info = mutate_syn_payload(payload, full_cfg, persona)
                mutated = bool(info.get("mutated"))
                changes = info
                if mutated and new_payload != payload:
                    pkt.set_payload(new_payload)

            json_log(
                "info",
                "packet_observed",
                queue=queue_num,
                flags=flags,
                persona_applied=bool(persona),
                modify_packets=modify_packets,
                mutated=mutated,
                changes=changes if mutated else None,
            )
            pkt.accept()
        except Exception as e:
            json_log("error", "handler_exception", queue=queue_num, error=str(e))
            pkt.accept()

    q = NetfilterQueue()
    try:
        q.bind(queue_num, cb, max_len=1024, range=128)
    except TypeError:
        q.bind(queue_num, cb)
    try:
        q.run()
    finally:
        q.unbind()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to config.yaml")
    args = ap.parse_args()

    cfg = _load_cfg(args.config)
    proxy_groups = cfg.get("proxy_groups", [])
    personas_cfg: Dict[str, PersonaConfig] = cfg.get("personas", {})

    handler_cfg = cfg.get("handler", {})
    modify_packets: bool = bool(handler_cfg.get("modify_packets", False))
    obs_cfg = cfg.get("observability", {})
    bind_addr = obs_cfg.get("health_bind", "127.0.0.1:9090")
    interval_sec = int(obs_cfg.get("health_interval_sec", 60))

    queue_persona_map: Dict[int, Optional[PersonaConfig]] = {}
    for group in proxy_groups:
        qn = group.get("nfqueue_num")
        if qn is None:
            continue
        persona_name = group.get("persona")
        persona_conf = None
        if persona_name:
            persona_conf = personas_cfg.get(str(persona_name)) or personas_cfg.get(persona_name)
            if persona_conf is None:
                json_log("error", "unknown_persona", queue=int(qn), persona=str(persona_name))
        queue_persona_map[int(qn)] = persona_conf

    expected_queues = sorted(queue_persona_map.keys())

    reg = HealthRegistry()
    threading.Thread(
        target=serve,
        args=(bind_addr, reg, interval_sec, expected_queues),
        daemon=True,
        name="health",
    ).start()

    threads: List[threading.Thread] = []
    for qn, persona_conf in queue_persona_map.items():
        t = threading.Thread(
            target=_worker,
            args=(qn, persona_conf, reg, modify_packets, cfg),
            name=f"nfqueue-{qn}",
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()

