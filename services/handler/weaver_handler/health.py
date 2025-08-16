from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, Any


def start_health_server(get_state: Callable[[], Dict[str, Any]],
                        host: str = "0.0.0.0",
                        port: int = 8081) -> None:
    """
    Поднимает простой HTTP сервер. На GET /health отдаёт JSON, который возвращает get_state().
    Сервер запускается в текущем потоке (блокирующий).
    """

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # без стандартного access‑лога
            pass

        def do_GET(self):
            if self.path != "/health":
                self.send_response(404); self.end_headers(); return
            try:
                payload = json.dumps(get_state(), ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as e:
                body = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

    srv = HTTPServer((host, port), Handler)
    srv.serve_forever()
