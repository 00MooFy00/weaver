import json, sys, time
from pythonjsonlogger import jsonlogger

def json_log(level: str, msg: str, **kwargs):
    rec = {"level": level, "msg": msg, "ts": time.time()}
    rec.update(kwargs)
    sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
    sys.stdout.flush()
