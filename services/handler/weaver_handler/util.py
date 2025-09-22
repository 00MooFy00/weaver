from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict


def json_log(level: str, msg: str, **fields: Any) -> None:
    """
    Minimal JSON logger to stdout. Use levels: debug/info/warn/error.
    """
    rec: Dict[str, Any] = {"ts": round(time.time(), 3), "level": level, "msg": msg}
    if fields:
        rec.update(fields)
    sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
    sys.stdout.flush()
