from __future__ import annotations
import os, json, fcntl, tempfile


def write_state_locked(path: str, obj: dict) -> None:
    dir_ = os.path.dirname(path)
    os.makedirs(dir_, exist_ok=True)
    lock_path = os.path.join(dir_, "state.lock")
    with open(lock_path, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=dir_, prefix=".state.tmp.", text=True)
        try:
            with os.fdopen(tmp_fd, "w") as tf:
                json.dump(obj, tf, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
                tf.flush()
                os.fsync(tf.fileno())
            os.replace(tmp_path, path)
            os.chmod(path, 0o644)
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
        fcntl.flock(lf, fcntl.LOCK_UN)