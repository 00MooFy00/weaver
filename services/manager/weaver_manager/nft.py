from __future__ import annotations

import subprocess
from typing import Iterable, List


def _run(args: List[str], check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, capture_output=True, text=True, input=input_text)


def ensure_table_chain() -> None:
    """
    Создаёт таблицу inet weaver и цепочку out (output hook), очищает цепочку.
    Политика accept, ничего не ломаем.
    """
    _run(["nft", "add", "table", "inet", "weaver"], check=False)
    # создаём chain, если нет
    _run(["nft", "add", "chain", "inet", "weaver", "out",
          "{", "type", "filter", "hook", "output", "priority", "filter", ";", "policy", "accept", ";", "}"],
         check=False)
    # flush chain
    _run(["nft", "flush", "chain", "inet", "weaver", "out"], check=False)


def apply_nfqueue_rules(queue_nums: Iterable[int]) -> None:
    """
    Ставит правила queue ... bypass на SYN исходящих от 3proxy (uid 1337).
    """
    qs = sorted({int(q) for q in queue_nums})
    if not qs:
        return
    ensure_table_chain()
    for q in qs:
        # meta skuid 1337 tcp flags syn queue num <q> bypass
        _run([
            "nft", "add", "rule", "inet", "weaver", "out",
            "meta", "skuid", "1337", "tcp", "flags", "syn",
            "queue", "num", str(q), "bypass"
        ])
