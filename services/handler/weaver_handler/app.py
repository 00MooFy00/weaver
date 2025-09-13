import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List

import yaml
from netfilterqueue import NetfilterQueue  # PyPI NetfilterQueue
from .util import json_log

class HealthHandler(BaseHTTPRequestHandler):
    state = None  # будет присвоено в run()

    def do_GET(self):
        if self.path != "/health":
            self.send_response(404); self.end_headers(); return
        cfg = self.state["cfg"]
        last_seen = self.state["last_seen"]
        window = cfg["global"]["health"]["window_seconds"]
        now = time.time()
        healthy = True
        per_queue = {}
        for q in cfg["global"]["nfqueue"]["numbers"]:
            t = last_seen.get(q, 0.0)
            ok = (now - t) <= window
            healthy = healthy and ok
            per_queue[str(q)] = {"last_ts": t, "ok": ok}

        body = {
            "ok": healthy,
            "now": now,
            "window_seconds": window,
            "queues": per_queue
        }
        self.send_response(200 if healthy else 503)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write((json.dumps(body) + "\n").encode("utf-8"))

def _load_config() -> dict:
    path = os.environ.get("CONFIG_PATH", "/app/config/config.yaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def run():
    cfg = _load_config()
    queues: List[int] = cfg["global"]["nfqueue"]["numbers"]
    on_error = cfg["global"]["nfqueue"].get("on_error", "accept")
    copy_range = int(cfg["global"]["nfqueue"].get("copy_range", 128))
    max_len = int(cfg["global"]["nfqueue"].get("max_len", 1024))
    last_seen: Dict[int, float] = {}

    verdict_on_error = "accept" if on_error == "accept" else "drop"

    def make_cb(qn: int):
        def cb(pkt):
            try:
                last_seen[qn] = time.time()
                # безопасный путь — не меняем пакет, только считаем/наблюдаем
                pkt.set_mark(pkt.get_mark())  # no-op, просто демонстрация API
                pkt.accept()
            except Exception as e:
                json_log("error", "handler_exception", queue=qn, error=str(e))
                getattr(pkt, verdict_on_error)()
        return cb

    # Готовим health сервер
    hs = HealthHandler
    hs.state = {"cfg": cfg, "last_seen": last_seen}
    host, port = cfg["global"]["health"]["listen"].split(":")
    httpd = ThreadingHTTPServer((host, int(port)), hs)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    json_log("info", "health_started", listen=cfg["global"]["health"]["listen"])

    # Привязка к нескольким очередям
    nfs: List[NetfilterQueue] = []
    socks: List[socket.socket] = []
    for qn in queues:
        nf = NetfilterQueue()
        nf.bind(qn, make_cb(qn), max_len=max_len, range=copy_range)
        s = socket.fromfd(nf.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        nfs.append(nf); socks.append(s)
        json_log("info", "queue_bound", queue=qn, copy_range=copy_range, max_len=max_len)

    try:
        # блокирующий цикл для каждой очереди в отдельном треде
        threads = []
        for nf, qn in zip(nfs, queues):
            t = threading.Thread(target=nf.run, kwargs={"block": True}, daemon=True, name=f"nfq-{qn}")
            t.start(); threads.append(t)
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass
    finally:
        for s in socks:
            try: s.close()
            except: pass
        for nf in nfs:
            try: nf.unbind()
            except: pass

if __name__ == "__main__":
    run()
