#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess as sp
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import yaml


def run(cmd: List[str], check: bool = True) -> None:
    sp.run(cmd, check=check)


def run_quiet(cmd: List[str]) -> None:
    sp.run(cmd, check=False, stdout=sp.DEVNULL, stderr=sp.DEVNULL)


def load_groups(cfg_path: Path) -> List[Tuple[int, int, Optional[int]]]:
    with cfg_path.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    res: List[Tuple[int, int, Optional[int]]] = []
    for g in (doc.get("proxy_groups") or []):
        pr = g.get("port_range") or {}
        s = int(pr.get("start", 0))
        e = int(pr.get("end", -1))
        qn = g.get("nfqueue_num")
        if s <= e:
            res.append((s, e, qn))
    return res


def open_rules(cfg_path: Path) -> None:
    groups = load_groups(cfg_path)

    # Снесли старую таблицу тихо (без мусора в логах)
    run_quiet(["nft", "delete", "table", "inet", "weaver_proxy"])

    # Создали новую
    run(["nft", "add", "table", "inet", "weaver_proxy"])
    # flags interval — иначе диапазоны портов не принимаются
    run([
        "nft", "add", "set", "inet", "weaver_proxy", "weaver_ports",
        "{", "type", "inet_service", ";", "flags", "interval", ";", "}"
    ])
    run([
        "nft","add","chain","inet","weaver_proxy","in",
        "{","type","filter","hook","input","priority","0",";","policy","accept",";","}",
    ])
    run([
        "nft","add","chain","inet","weaver_proxy","out",
        "{","type","filter","hook","output","priority","0",";","policy","accept",";","}",
    ])

    # Заполняем сет диапазонами
    any_q = None
    for s, e, qn in groups:
        run(["nft","add","element","inet","weaver_proxy","weaver_ports","{",f"{s}-{e}","}"])
        if qn is not None:
            any_q = qn

    # Входящий первый SYN на наши порты -> в очередь
    # IPv4
    if any_q is not None:
        run([
            "nft","add","rule","inet","weaver_proxy","in",
            "ip","protocol","tcp",
            "tcp","flags","&","(","syn","|","ack",")","==","syn",
            "and","tcp","dport","@weaver_ports",
            "queue","num",str(any_q),"bypass",
        ])
        # IPv6
        run([
            "nft","add","rule","inet","weaver_proxy","in",
            "ip6","nexthdr","tcp",
            "tcp","flags","&","(","syn","|","ack",")","==","syn",
            "and","tcp","dport","@weaver_ports",
            "queue","num",str(any_q),"bypass",
        ])

    # Пропускаем остальной трафик на эти порты
    run(["nft","add","rule","inet","weaver_proxy","in","tcp","dport","@weaver_ports","accept"])

    # Исходящий первый SYN от uid 1337 -> в очередь (обе семьи)
    if any_q is not None:
        run([
            "nft","add","rule","inet","weaver_proxy","out",
            "ip","protocol","tcp",
            "meta","skuid","1337","and",
            "tcp","flags","&","(","syn","|","ack",")","==","syn",
            "queue","num",str(any_q),"bypass",
        ])
        run([
            "nft","add","rule","inet","weaver_proxy","out",
            "ip6","nexthdr","tcp",
            "meta","skuid","1337","and",
            "tcp","flags","&","(","syn","|","ack",")","==","syn",
            "queue","num",str(any_q),"bypass",
        ])


def close_rules() -> None:
    run_quiet(["nft", "delete", "table", "inet", "weaver_proxy"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["open", "close"])
    ap.add_argument("--config", default="/app/config/config.yaml")
    args = ap.parse_args()

    cfg = Path(args.config)
    if args.action == "open":
        open_rules(cfg)
    else:
        close_rules()
    return 0


if __name__ == "__main__":
    sys.exit(main())

