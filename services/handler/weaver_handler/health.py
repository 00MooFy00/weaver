from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict


class HealthRegistry:
    def __init__(self) -> None:
        self._last_seen: Dict[int, float] = {}
        self._lock = threading.Lock()

    def mark(self, queue_num: int) -> None:
        with self._lock:
            self._last_seen[queue_num] = time.time()

    def snapshot(self) -> Dict[int, float]:
        with self._lock:
            return dict(self._last_seen)


class HealthHandler(BaseHTTPRequestHandler):
    registry: HealthRegistry = HealthRegistry()
    interval_sec: int = 60

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler)
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return
        now = time.time()
        snap = self.registry.snapshot()
        ok = len(snap) > 0 and all((now - ts) <= self.interval_sec for ts in snap.values())
        body = json.dumps(
            {"ok": ok, "queues": {str(k): now - v for k, v in snap.items()}}, ensure_ascii=False
        ).encode()
        self.send_response(200 if ok else 503)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(bind: str, registry: HealthRegistry, interval_sec: int) -> None:
    host, port_s = bind.rsplit(":", 1)
    srv = HTTPServer((host, int(port_s)), HealthHandler)
    HealthHandler.registry = registry
    HealthHandler.interval_sec = interval_sec
    srv.serve_forever()
