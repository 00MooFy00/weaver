from __future__ import annotations

import json
import sys
import time
from typing import Any


def _json_safe(x: Any) -> Any:
    if isinstance(x, (bytes, bytearray)):
        return x.hex()
    if isinstance(x, set):
        return list(x)
    if isinstance(x, tuple):
        return list(x)
    try:
        json.dumps(x)
        return x
    except Exception:
        try:
            return str(x)
        except Exception:
            return "<unrepr>"


def json_log(level: str, msg: str, **kwargs: Any) -> None:
    rec = {"ts": time.time(), "level": level, "msg": msg}
    rec.update(kwargs)
    try:
        sys.stdout.write(json.dumps(rec, ensure_ascii=False, default=_json_safe) + "\n")
    except Exception:
        rec["__fallback__"] = {k: _json_safe(v) for k, v in kwargs.items()}
        sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
    sys.stdout.flush()

