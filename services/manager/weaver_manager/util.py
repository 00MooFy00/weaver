import json
import sys
import time
from pythonjsonlogger import jsonlogger

def json_log(level: str, msg: str, **kwargs):
    record = {"level": level, "msg": msg, "ts": time.time()}
    record.update(kwargs)
    sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
    sys.stdout.flush()
