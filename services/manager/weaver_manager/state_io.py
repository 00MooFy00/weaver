from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class Assignment:
    group: str
    port: int
    ipv6: str
    proxy_type: str
    listen_stack: str
    nfqueue_num: Optional[int]


@dataclass
class State:
    assignments: List[Assignment]


def read_state(path: Path) -> State:
    if not path.exists():
        return State(assignments=[])
    data = json.loads(path.read_text(encoding="utf-8"))
    assigns = [
        Assignment(
            group=a["group"],
            port=int(a["port"]),
            ipv6=a["ipv6"],
            proxy_type=a["proxy_type"],
            listen_stack=a.get("listen_stack", "ipv4"),
            nfqueue_num=a.get("nfqueue_num"),
        )
        for a in data.get("assignments", [])
    ]
    return State(assignments=assigns)


def write_state_atomic(path: Path, state: State) -> None:
    tmp_dir = path.parent
    os.makedirs(tmp_dir, exist_ok=True)
    payload = {
        "assignments": [asdict(a) for a in state.assignments],
    }
    with tempfile.NamedTemporaryFile("w", delete=False, dir=tmp_dir, encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        tmp_name = f.name
    os.replace(tmp_name, path)

