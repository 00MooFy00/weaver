from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path
from typing import List

import yaml
from NetfilterQueue import NetfilterQueue  # type: ignore

from weaver_handler.health import HealthRegistry, serve


def _parse_tcp_flags(payload: bytes) -> str:
    if len(payload) < 1:
        return "?"
    v = payload[0] >> 4
    if v == 4:
        if len(payload) < 20:
            return "?"
        ihl = (payload[0] & 0x0F) * 4
        if len(payload) < ihl + 14:
            return "?"
        flags = payload[ihl + 13]
        return f"IPv4:{flags:08b}"
    if v == 6:
        if len(payload) < 40 + 14:
            return "?"
        nxt = payload[6]
        if nxt != 6:
            return "IPv6:nonTCP"
        flags = payload[40 + 13]
        return f"IPv6:{flags:08b}"
    return "?"


def _worker(queue_num: int, reg: HealthRegistry) -> None:
    def cb(pkt):
        reg.mark(queue_num)
        payload = pkt.get_payload()
        flags = _parse_tcp_flags(payload)
        print(json.dumps({"ts": time.time(), "queue": queue_num, "flags": flags, "verdict": "accept"}))
        pkt.accept()

    q = NetfilterQueue()
    q.bind(queue_num, cb)
    try:
        q.run()
    finally:
        q.unbind()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    groups = cfg.get("proxy_groups", [])
    queues: List[int] = []
    for g in groups:
        if g.get("nfqueue_num") is not None:
            queues.append(int(g["nfqueue_num"]))

    reg = HealthRegistry()
    obs = cfg.get("observability", {})
    bind = obs.get("health_bind", "127.0.0.1:9090")
    interval = int(obs.get("health_interval_sec", 60))
    threading.Thread(target=serve, args=(bind, reg, interval), daemon=True).start()

    threads = []
    for q in sorted(set(queues)):
        t = threading.Thread(target=_worker, args=(q, reg), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
