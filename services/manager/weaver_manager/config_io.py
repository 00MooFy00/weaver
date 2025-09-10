import os
import yaml
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class PortRange:
    start: int
    end: int

@dataclass
class ProxyGroup:
    name: str
    ipv6_subnet: str
    count: int
    proxy_type: str
    port_range: PortRange
    persona: str
    nfqueue_num: int

@dataclass
class HealthCfg:
    listen: str
    window_seconds: int

@dataclass
class NFQueueCfg:
    numbers: List[int]
    on_error: str
    copy_range: int
    max_len: int

@dataclass
class GlobalCfg:
    state_file_path: str
    proxy_config_path: str
    ipv6_interface: str
    inbound_ipv4_address: str
    health: HealthCfg
    nfqueue: NFQueueCfg
    proxy_dns: List[str]
    log_rotate_minutes: int

@dataclass
class Config:
    global_: GlobalCfg
    personas: Dict[str, Any]
    proxy_groups: List[ProxyGroup]

def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    g = raw["global"]
    prx_dns = g.get("proxy_dns") or []
    health = HealthCfg(**g["health"])
    nfq = NFQueueCfg(**g["nfqueue"])

    global_cfg = GlobalCfg(
        state_file_path=g["state_file_path"],
        proxy_config_path=g["proxy_config_path"],
        ipv6_interface=g["ipv6_interface"],
        inbound_ipv4_address=g["inbound_ipv4_address"],
        health=health,
        nfqueue=nfq,
        proxy_dns=prx_dns,
        log_rotate_minutes=g.get("log_rotate_minutes", 60),
    )

    groups = []
    for it in raw["proxy_groups"]:
        pr = it["port_range"]
        groups.append(
            ProxyGroup(
                name=it["name"],
                ipv6_subnet=it["ipv6_subnet"],
                count=int(it["count"]),
                proxy_type=it["proxy_type"],
                port_range=PortRange(int(pr["start"]), int(pr["end"])),
                persona=it["persona"],
                nfqueue_num=int(it["nfqueue_num"]),
            )
        )

    return Config(
        global_=global_cfg,
        personas=raw.get("personas", {}),
        proxy_groups=groups
    )
