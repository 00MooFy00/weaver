from __future__ import annotations
import os, time, json, random, hashlib, threading
import yaml
from http.server import BaseHTTPRequestHandler, HTTPServer

from netfilterqueue import NetfilterQueue
from scapy.all import IPv6, TCP

CFG_PATH = os.environ.get("WEAVER_CONFIG", "/app/config/config.yaml")
NFQ_NUM = int(os.environ.get("NFQUEUE_NUM", "0"))

# ---- health ----
_last_seen = 0.0
_health_lock = threading.Lock()

def _health_ok(within=60.0):
    with _health_lock:
        return (time.time() - _last_seen) <= within

def _mark_seen():
    global _last_seen
    with _health_lock:
        _last_seen = time.time()

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ok = _health_ok()
        body = json.dumps({"ok": ok, "last_seen": _last_seen}).encode()
        self.send_response(200 if ok else 500)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):  # quiet
        pass

def start_health_server(port=9090):
    t = threading.Thread(target=lambda: HTTPServer(('127.0.0.1', port), HealthHandler).serve_forever(), daemon=True)
    t.start()

# ---- personas ----
class Persona:
    def __init__(self, name, hlim, window, layout):
        self.name=name; self.hlim=hlim; self.window=window; self.layout=layout

def load_config(path):
    with open(path, 'r') as f:
        cfg = yaml.safe_load(f)
    personas={}
    for name, p in cfg.get('personas', {}).items():
        personas[name]=Persona(
            name=name,
            hlim=int(p.get('hlim', 64)),
            window=int(p.get('window', 65535)),
            layout=p.get('tcp_options_layout', [])
        )
    sel = cfg.get('selection', {"mode":"weighted","weighted":[{"persona":list(personas)[0],"weight":1}]})
    nfq = cfg.get('nfqueue', {"number": NFQ_NUM, "drop_on_error": False, "health_port": 9090})
    return personas, sel, nfq

def stable_choice_weighted(personas, sel, key_bytes: bytes):
    # deterministic pick by hashing key -> [0,1)
    h = hashlib.blake2b(key_bytes, digest_size=8).digest()
    val = int.from_bytes(h, 'big') / float(2**64)
    total = sum(float(w["weight"]) for w in sel["weighted"])
    acc=0.0
    for w in sel["weighted"]:
        acc += float(w["weight"]) / total
        if val <= acc:
            return personas[w["persona"]]
    return personas[sel["weighted"][-1]["persona"]]

def build_tcp_options(layout):
    opts=[]
    ts_now = int(time.time()) & 0xffffffff
    for item in layout:
        name=item.get("name","")
        if name == "MSS":
            val=int(item.get("value",1460)); opts.append(('MSS', val))
        elif name == "SACK":
            opts.append(('SAckOK',''))
        elif name == "Timestamps":
            opts.append(('Timestamp', (ts_now, 0)))
        elif name == "WScale":
            val=int(item.get("value",7)); opts.append(('WScale', val))
        elif name == "NOP":
            opts.append(('NOP', None))
        else:
            # ignore/unknown
            pass
    return opts

def apply_persona(pkt: IPv6, persona: Persona):
    # IPv6 hop limit
    pkt.hlim = persona.hlim
    # TCP window/options
    tcp = pkt.getlayer(TCP)
    tcp.window = persona.window
    tcp.options = build_tcp_options(persona.layout)
    # recalc lengths/checksums
    if hasattr(pkt, 'plen'): del pkt.plen
    if hasattr(tcp, 'chksum'): del tcp.chksum
    return pkt

def callback(packet):
    try:
        payload = packet.get_payload()
        pkt = IPv6(payload)
        if not pkt.haslayer(TCP):
            packet.accept(); return
        tcp = pkt.getlayer(TCP)
        # только первичный SYN (без ACK)
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            packet.accept(); return

        key = f"{pkt.src}|{pkt.dst}|{tcp.sport}|{tcp.dport}|6".encode()
        persona = stable_choice_weighted(PERSONAS, SELECTION, key)
        new_pkt = apply_persona(pkt, persona)

        packet.set_payload(bytes(new_pkt))
        packet.accept()
        _mark_seen()
        print(json.dumps({
            "ts": time.time(),
            "event": "syn_modified",
            "persona": persona.name,
            "dst": pkt.dst,
            "dport": tcp.dport
        }), flush=True)
    except Exception as e:
        print(json.dumps({"ts": time.time(), "event": "error", "err": str(e)}), flush=True)
        if NFQ_DROP_ON_ERR:
            packet.drop()
        else:
            packet.accept()

if __name__ == "__main__":
    PERSONAS, SELECTION, nfq = load_config(CFG_PATH)
    NFQ_NUM = int(nfq.get("number", NFQ_NUM))
    NFQ_DROP_ON_ERR = bool(nfq.get("drop_on_error", False))
    start_health_server(int(nfq.get("health_port", 9090)))

    print(json.dumps({
        "ts": time.time(),
        "event": "handler_start",
        "nfqueue": NFQ_NUM,
        "personas": list(PERSONAS.keys()),
        "selection": SELECTION
    }), flush=True)

    q = NetfilterQueue()
    q.bind(NFQ_NUM, callback, 0xffff)
    try:
        q.run()
    except KeyboardInterrupt:
        pass
    finally:
        q.unbind()
