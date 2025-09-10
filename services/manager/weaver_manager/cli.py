import os
import sys
import time
import json
from typing import Dict, List, Set, Any, Tuple
from .config_io import load_config
from .state_io import read_state, write_state_locked
from .ipam import allocate_random_ipv6, ensure_addrs_on_iface
from .proxycfg import generate as gen_proxycfg
from . import nft as nftmod
from .util import json_log

PROXY_UID = 1337  # должен совпадать с UID пользователя в образе proxy

def _validate_ports(groups) -> None:
    for g in groups:
        total = g.count
        slots = g.port_range.end - g.port_range.start + 1
        if total > slots:
            raise ValueError(f"group {g.name}: count={total} > port slots={slots}")

def _build_state(config) -> Dict[str, Any]:
    """
    Строит и возвращает новый объект состояния, сохраняя стабильные привязки.
    state: {"version":1,"mappings":[{"group":"...","port":30000,"ipv6":"..."}]}
    """
    state_path = config.global_.state_file_path
    state = read_state(state_path)
    old_map = state.get("mappings", [])
    # индексы
    by_group_port: Dict[Tuple[str, int], Dict[str, Any]] = {
        (m["group"], int(m["port"])): m for m in old_map
    }

    new_mappings: List[Dict[str, Any]] = []
    for g in config.proxy_groups:
        _validate_ports([g])
        # какие порты нам нужны
        needed_ports = [g.port_range.start + i for i in range(g.count)]
        # какие IPv6 уже закреплены за этими портами
        have_ipv6 = {m["ipv6"] for k, m in by_group_port.items() if k[0] == g.name}
        reserved = set(have_ipv6)
        # добираем недостающие адреса
        need = g.count - sum(1 for p in needed_ports if (g.name, p) in by_group_port)
        addrs = allocate_random_ipv6(g.ipv6_subnet, need, reserved)
        add_iter = iter(addrs)
        for p in needed_ports:
            key = (g.name, p)
            if key in by_group_port:
                ipv6 = by_group_port[key]["ipv6"]
            else:
                ipv6 = next(add_iter)
            new_mappings.append({
                "group": g.name,
                "port": p,
                "ipv6": ipv6,
                "type": g.proxy_type,
                "nfqueue_num": g.nfqueue_num
            })
    return {"version": 1, "mappings": new_mappings}

def _services_from_state(state) -> List[Dict[str, Any]]:
    out = []
    for m in state["mappings"]:
        out.append({"type": "http" if m["type"] == "http" else "socks5",
                    "port": int(m["port"]),
                    "external6": m["ipv6"]})
    return out

def apply():
    cfg_path = os.environ.get("CONFIG_PATH", "/app/config/config.yaml")
    cfg = load_config(cfg_path)
    json_log("info", "config_loaded", path=cfg_path)

    # 1) рассчитать новое состояние (с учётом старого)
    new_state = _build_state(cfg)
    # 2) привести IPv6 адреса на интерфейсе
    desired_ipv6: Set[str] = {m["ipv6"] for m in new_state["mappings"]}
    added, removed = ensure_addrs_on_iface(cfg.global_.ipv6_interface, desired_ipv6)
    json_log("info", "ipam_reconciled", added=list(added), removed=list(removed))

    # 3) сгенерировать 3proxy.cfg
    services = _services_from_state(new_state)
    gen_proxycfg(cfg.global_.proxy_config_path, cfg.global_.inbound_ipv4_address,
                 cfg.global_.log_rotate_minutes, cfg.global_.proxy_dns, services)
    json_log("info", "proxy_cfg_generated", path=cfg.global_.proxy_config_path, services=len(services))

    # 4) применить nftables правила:
    #    - матч по skuid 1337 (процесс 3proxy в контейнере proxy)
    #    - queue fanout по диапазону очередей из config.global.nfqueue.numbers
    nftmod.apply_rules(PROXY_UID, cfg.global_.nfqueue.numbers)
    json_log("info", "nft_applied", uid=PROXY_UID, queues=cfg.global_.nfqueue.numbers)

    # 5) записать state атомарно
    write_state_locked(cfg.global_.state_file_path, new_state)
    json_log("info", "state_written", path=cfg.global_.state_file_path)

    # 6) послать 3proxy сигнал USR1 для перечтения конфига
    #    выполняется в host netns, виден PID 3proxy (как процесс на хосте).
    try:
        os.system("pkill -USR1 -f '/usr/local/3proxy/bin/3proxy'")
        json_log("info", "proxy_reloaded", method="SIGUSR1")
    except Exception as e:
        json_log("error", "proxy_reload_failed", error=str(e))

def main():
    if len(sys.argv) < 2:
        print("usage: manager apply|reload|flush", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd in ("apply", "reload"):
        apply()
    elif cmd == "flush":
        # Опционально: очистка таблицы nft
        import nftables
        n = nftables.Nftables(); n.set_json_output(True)
        n.json_cmd({"nftables": [{"delete": {"table": {"family": "inet", "name": "pw"}}}]})
        print("flushed nft table inet pw")
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
