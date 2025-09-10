import fcntl
import json
import os
import tempfile
from typing import Any, Dict

def read_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"version": 1, "mappings": []}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_state_locked(path: str, obj: Dict[str, Any]) -> None:
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(lock_path, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path))
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as tf:
                json.dump(obj, tf, ensure_ascii=False, indent=2)
                tf.flush()
                os.fsync(tf.fileno())
            os.replace(tmp_path, path)
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            fcntl.flock(lf, fcntl.LOCK_UN)
