from __future__ import annotations

import json
import socket
import threading
import time
from typing import Dict, Iterable, List, Tuple


class HealthRegistry:
    def __init__(self, expected_queues: Iterable[int]) -> None:
        self._last: Dict[int, float] = {q: 0.0 for q in expected_queues}
        self._lock = threading.RLock()

    def mark(self, q: int) -> None:
        with self._lock:
            self._last[q] = time.time()

    def snapshot(self) -> Dict[int, float]:
        with self._lock:
            return dict(self._last)


def serve(bind: str, registry: HealthRegistry, interval: float = 1.0) -> None:
    host, port = bind.split(":")
    addr = (host, int(port))
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET

    with socket.socket(fam, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(addr)
        s.listen(5)
        while True:
            conn, _ = s.accept()
            with conn:
                last = registry.snapshot()
                now = time.time()
                stale: List[int] = [q for q, ts in last.items() if now - ts > 60.0]
                status = 200 if not stale else 503
                body = {
                    "status": "ok" if status == 200 else "stale",
                    "stale_queues": stale,
                    "last_seen": last,
                }
                payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
                headers = [
                    f"HTTP/1.1 {status} {'OK' if status==200 else 'Service Unavailable'}",
                    "Content-Type: application/json; charset=utf-8",
                    f"Content-Length: {len(payload)}",
                    "Connection: close",
                    "",
                    "",
                ]
                conn.sendall("\r\n".join(headers).encode("utf-8") + payload)
