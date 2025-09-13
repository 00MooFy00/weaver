from __future__ import annotations
import json, os, time
from dataclasses import dataclass, asdict
from fcntl import LOCK_EX, LOCK_NB, LOCK_UN, flock
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class Binding:
    port: int
    ipv6: str
    group: str


@dataclass
class State:
    version: int
    bindings: List[Binding]
    updated_at: float

    def to_json(self) -> str:
        payload = {
            "version": self.version,
            "bindings": [asdict(b) for b in self.bindings],
            "updated_at": self.updated_at,
        }
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class StateStore:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> State:
        if not self._path.exists():
            return State(version=1, bindings=[], updated_at=time.time())
        data = json.loads(self._path.read_text(encoding="utf-8"))
        bindings = [Binding(**b) for b in data.get("bindings", [])]
        return State(
            version=int(data.get("version", 1)),
            bindings=bindings,
            updated_at=float(data.get("updated_at", 0)),
        )

    def save(self, state: State) -> None:
        with self._path.open("a+", encoding="utf-8") as f:
            try:
                flock(f.fileno(), LOCK_EX | LOCK_NB)
            except OSError as e:
                raise RuntimeError(f"state file lock failed: {e}") from e
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(state.to_json(), encoding="utf-8")
            os.replace(tmp, self._path)
            flock(f.fileno(), LOCK_UN)
