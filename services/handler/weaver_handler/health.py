from __future__ import annotations

import json
import socket
import threading
import time
from typing import Dict


class HealthRegistry:
    """
    Tracks last-seen timestamps per NFQUEUE number.
    """

    def __init__(self) -> None:
        self._last_seen: Dict[int, float] = {}
        self._lock = threading.Lock()

    def mark(self, queue_num: int) -> None:
        with self._lock:
            self._last_seen[queue_num] = time.time()

    def snapshot(self) -> Dict[int, float]:
        with self._lock:
            return dict(self._last_seen)


def _parse_bind(bind_addr: str) -> tuple[str, int]:
    """
    Accept "127.0.0.1:9090" or "[::1]:9090".
    """
    if bind_addr.startswith("["):
        host, port = bind_addr[1:].split("]:", 1)
    else:
        host, port = bind_addr.split(":", 1)
    return host, int(port)


def serve(bind_addr: str, reg: HealthRegistry, interval_sec: int) -> None:
    """
    Very small HTTP server exposing /health.
    Returns 200 if every known queue was seen within interval_sec.
    Body: JSON with per-queue timestamps and global status.
    """
    host, port = _parse_bind(bind_addr)
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(32)

    while True:
        conn, _addr = s.accept()
        try:
            req = conn.recv(2048)
            if b"GET /health" not in req:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                continue

            now = time.time()
            snaps = reg.snapshot()
            ok = True
            stale: Dict[int, float] = {}
            for qn, ts in snaps.items():
                if now - ts > interval_sec:
                    ok = False
                    stale[qn] = now - ts

            body = json.dumps(
                {
                    "status": "ok" if ok else "stale",
                    "interval_sec": interval_sec,
                    "queues_seen": snaps,
                    "stale_queues": stale,
                    "ts": round(now, 3),
                }
            ).encode("utf-8")
            status_line = b"HTTP/1.1 200 OK" if ok else b"HTTP/1.1 503 Service Unavailable"
            headers = b"\r\n".join(
                [
                    status_line,
                    b"Content-Type: application/json; charset=utf-8",
                    f"Content-Length: {len(body)}".encode(),
                    b"Connection: close",
                    b"",
                    b"",
                ]
            )
            conn.sendall(headers + body)
        finally:
            conn.close()
