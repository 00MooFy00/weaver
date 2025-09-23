from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple

import yaml


def load_groups(path: str) -> List[Tuple[int, int, int | None]]:
    p = Path(path)
    if p.is_dir():
        p = p / "config.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    groups: List[Tuple[int, int, int | None]] = []
    for g in cfg.get("proxy_groups", []) or []:
        pr = g.get("port_range") or {}
        s = int(pr.get("start", 0))
        e = int(pr.get("end", -1))
        qn = g.get("nfqueue_num")
        if s and e >= s:
            groups.append((s, e, int(qn) if qn is not None else None))
    return groups


def run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check)


def nft_open(groups: List[Tuple[int, int, int | None]]) -> None:
    # Чистим прошлое
    run(["nft", "delete", "table", "inet", "weaver_proxy"], check=False)

    run(["nft", "add", "table", "inet", "weaver_proxy"])
    run(["nft", "add", "set", "inet", "weaver_proxy", "weaver_ports", "{", "type", "inet_service", ";", "flags", "interval", ";", "}"])

    if groups:
        elements = [f"{s}-{e}" for (s, e, _qn) in groups]
        run(["nft", "add", "element", "inet", "weaver_proxy", "weaver_ports", "{", ", ".join(elements), "}"])

    # INPUT: только SYN‑only на наши порты -> NFQUEUE
    run(["nft", "add", "chain", "inet", "weaver_proxy", "weaver_input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"])
    for s, e, qn in groups:
        if qn is None:
            continue
        run([
            "nft", "add", "rule", "inet", "weaver_proxy", "weaver_input",
            "tcp", "dport", f"{s}-{e}",
            "tcp", "flags", "&", "syn", "==", "syn",
            "tcp", "flags", "&", "ack", "==", "0",
            "queue", "num", str(qn), "bypass"
        ])
    run(["nft", "add", "rule", "inet", "weaver_proxy", "weaver_input", "tcp", "dport", "@weaver_ports", "accept"])

    # OUTPUT: только SYN‑only от uid=1337 (3proxy) -> NFQUEUE
    run(["nft", "add", "chain", "inet", "weaver_proxy", "weaver_output", "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"])
    for _s, _e, qn in groups:
        if qn is None:
            continue
        run([
            "nft", "add", "rule", "inet", "weaver_proxy", "weaver_output",
            "meta", "skuid", "1337",
            "tcp", "flags", "&", "syn", "==", "syn",
            "tcp", "flags", "&", "ack", "==", "0",
            "queue", "num", str(qn), "bypass"
        ])


def nft_close() -> None:
    run(["nft", "delete", "table", "inet", "weaver_proxy"], check=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["open", "close"])
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    if args.action == "open":
        groups = load_groups(args.config)
        nft_open(groups)
    else:
        nft_close()


if __name__ == "__main__":
    main()

