from __future__ import annotations

import fcntl
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import structlog
import yaml


log = structlog.get_logger()


@dataclass
class ProxyGroup:
    name: str
    ipv6_subnet: str
    count: int
    proxy_type: str
    port_start: int
    port_end: int
    persona: str
    nfqueue_num: int


@dataclass
class GlobalCfg:
    state_file_path: str
    proxy_config_path: str
    ipv6_interface: str
    inbound_ipv4_address: str
    enable_outbound_e: bool = False  # включить -e<ipv6> на proxy-линиях (только когда будет routed /64)


def _run_quiet(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def sh(*args: str) -> None:
    # Использовать только там, где действительно нужно check=True и видимый вывод
    subprocess.run(list(args), check=True)


def _load_cfg(path: Path) -> Tuple[GlobalCfg, List[ProxyGroup]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    g = raw.get("global", {}) or {}
    global_cfg = GlobalCfg(
        state_file_path=g.get("state_file_path", "/app/state/state.json"),
        proxy_config_path=g.get("proxy_config_path", "/app/config/3proxy.cfg"),
        ipv6_interface=g.get("ipv6_interface", "eth0"),
        inbound_ipv4_address=g.get("inbound_ipv4_address", "0.0.0.0"),
        enable_outbound_e=bool(g.get("enable_outbound_e", False)),
    )
    groups: List[ProxyGroup] = []
    for it in raw.get("proxy_groups", []) or []:
        pr = it.get("port_range", {}) or {}
        groups.append(
            ProxyGroup(
                name=str(it["name"]),
                ipv6_subnet=str(it["ipv6_subnet"]),
                count=int(it.get("count", 0)),
                proxy_type=str(it.get("proxy_type", "http")),
                port_start=int(pr.get("start")),
                port_end=int(pr.get("end")),
                persona=str(it.get("persona", "")),
                nfqueue_num=int(it.get("nfqueue_num", 0)),
            )
        )
    return global_cfg, groups


def _alloc_ipv6(subnet: str, n: int) -> List[str]:
    import ipaddress

    net = ipaddress.ip_network(subnet, strict=False)
    if net.version != 6:
        raise ValueError("ipv6_subnet must be IPv6")
    base = int(net.network_address)
    out: List[str] = []
    # Начинаем с +1, чтобы не брать сам адрес сети
    for i in range(1, n + 1):
        out.append(str(ipaddress.IPv6Address(base + i)))
    return out


def _state_lock(path: Path):
    f = path.open("a+")
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    return f


def _read_state(path: Path) -> Dict:
    if not path.exists():
        return {"version": 1, "groups": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "groups": {}}


def _write_state(path: Path, data: Dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _iface_has_addr(iface: str, addr: str) -> bool:
    cp = subprocess.run(
        ["ip", "-6", "addr", "show", "dev", iface],
        check=False,
        capture_output=True,
        text=True,
    )
    return (cp.returncode == 0) and (addr.lower() in (cp.stdout or "").lower())


def _ensure_addr_on_iface(iface: str, addr: str) -> None:
    """
    Идемпотентно вешаем хостовой IPv6 на интерфейс как /128.
    Полностью тихо: без вывода в stdout/stderr.
    """
    if _iface_has_addr(iface, addr):
        return
    _run_quiet(["ip", "-6", "addr", "add", f"{addr}/128", "dev", iface])


def _generate_3proxy_cfg(gcfg: GlobalCfg, bindings: List[Tuple[int, str]]) -> str:
    """
    Генерация 3proxy.cfg:
      - без 'daemon'
      - без '-6'
      - '-i <inbound_ipv4_address>' если задан
      - без '-e' по умолчанию (включается флагом enable_outbound_e = true, когда будет routed /64)
    """
    lines = [
        "nscache 65536",
        "timeouts 1 5 30 60 180 1800 15 60",
        "flush",
        "allow *",
    ]
    use_i = (gcfg.inbound_ipv4_address or "").strip()
    for port, ip6 in bindings:
        line = f"proxy -n -p{port}"
        if use_i:
            line += f" -i {use_i}"
        if gcfg.enable_outbound_e and ip6:
            # 3proxy ожидает -e<addr> без пробела (как у тебя было раньше)
            line += f" -e{ip6}"
        lines.append(line)
    return "\n".join(lines) + "\n"


# Алиас на случай старого вызова
def generate_3proxy_cfg(bindings: List[Tuple[int, str]]) -> str:
    # Если вдруг кто-то вызовет старую сигнатуру — вернём универсальный конфиг без -i/-e.
    lines = [
        "nscache 65536",
        "timeouts 1 5 30 60 180 1800 15 60",
        "flush",
        "allow *",
    ]
    for port, _ipv6 in bindings:
        lines.append(f"proxy -n -p{port}")
    return "\n".join(lines) + "\n"


def apply(config_path: Path) -> None:
    gcfg, groups = _load_cfg(config_path)
    state_path = Path(gcfg.state_file_path)
    cfg_out = Path(gcfg.proxy_config_path)
    cfg_out.parent.mkdir(parents=True, exist_ok=True)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    with _state_lock(state_path) as _f:
        state = _read_state(state_path)

        all_mappings: List[Tuple[int, str]] = []

        for grp in groups:
            ports = list(range(grp.port_start, grp.port_end + 1))
            if grp.count > len(ports):
                raise ValueError(f"{grp.name}: count {grp.count} > available ports {len(ports)}")
            ports = ports[: grp.count]

            grp_state = state["groups"].get(grp.name) or {}
            port_to_ip: Dict[str, str] = grp_state.get("port_to_ipv6") or {}

            # Если состояние пустое или размер не совпал — сгенерировать заново
            if len(port_to_ip) != len(ports):
                addrs = _alloc_ipv6(grp.ipv6_subnet, len(ports))
                port_to_ip = {str(p): a for p, a in zip(ports, addrs)}
                state["groups"][grp.name] = {
                    "ipv6_subnet": grp.ipv6_subnet,
                    "port_to_ipv6": port_to_ip,
                    "persona": grp.persona,
                }

            # Навесить адреса на интерфейс (тихо, /128, идемпотентно)
            for ip6 in port_to_ip.values():
                _ensure_addr_on_iface(gcfg.ipv6_interface, ip6)

            # Собрать маппинг для конфига
            mapping = [(int(p), ip6) for p, ip6 in sorted(port_to_ip.items(), key=lambda x: int(x[0]))]
            all_mappings.extend(mapping)

        # Сохранить state
        _write_state(state_path, state)

    # Сгенерить 3proxy.cfg (современный генератор с -i/-e по флагу)
    text = _generate_3proxy_cfg(gcfg, all_mappings)
    cfg_out.write_text(text, encoding="utf-8")
    log.info("manager_apply_done", cfg=str(cfg_out), state=str(state_path), total_bind=len(all_mappings))
    print(text)  # на всякий случай для диагностики


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/app/config/config.yaml")
    parser.add_argument("cmd", nargs="?", default="apply")
    args = parser.parse_args()

    structlog.configure(processors=[structlog.processors.TimeStamper(), structlog.processors.JSONRenderer()])
    if args.cmd != "apply":
        raise SystemExit("supported: apply")

    apply(Path(args.config))


if __name__ == "__main__":
    main()

