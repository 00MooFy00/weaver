from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict


def write_state_atomic(path: str, obj: Dict[str, Any]) -> None:
    """
    Атомарная запись JSON с временным файлом и заменой.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".state.", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o644)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
