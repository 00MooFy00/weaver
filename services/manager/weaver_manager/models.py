from __future__ import annotations
from typing import Dict, List, Optional, Union
from ipaddress import IPv6Network
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class PersonaOption(BaseModel):
    name: str
    value: Optional[Union[str, int]] = None

    @field_validator("value", mode="before")
    @classmethod
    def _coerce_value(cls, v):
        if v is None:
            return v
        if isinstance(v, int):
            return str(v)
        return v


class Persona(BaseModel):
    ttl: int
    window_size: int
    tcp_options_layout: List[PersonaOption]


class PortRange(BaseModel):
    start: int
    end: int


class GlobalHandler(BaseModel):
    on_error: str = "accept"            # accept|drop
    health_window_sec: int = 60


class GlobalConfig(BaseModel):
    state_file_path: str = "/app/state/state.json"
    proxy_config_path: str = "/app/config/3proxy.cfg"
    ipv6_interface: str = "auto"
    inbound_ipv4_address: str = "127.0.0.1"

    nf_table: str = "weaver"
    nf_chain_out: str = "out"
    nf_policy_accept: bool = True

    reconcile_remove_extras: bool = False
    pinned_ipv6: List[IPvAnyAddress] = Field(default_factory=list)

    handler: GlobalHandler = Field(default_factory=GlobalHandler)


class ProxyGroup(BaseModel):
    name: str
    ipv6_subnet: IPv6Network
    count: int
    proxy_type: str                 # http|socks5
    port_range: PortRange
    persona: str
    nfqueue_num: int


class Config(BaseModel):
    global_: GlobalConfig = Field(alias="global")
    personas: Dict[str, Persona]
    proxy_groups: List[ProxyGroup]


class PortIPv6(BaseModel):
    port: int
    ipv6: IPvAnyAddress


class GroupState(BaseModel):
    name: str
    persona: str
    nfqueue_num: int
    mappings: List[PortIPv6]


class State(BaseModel):
    groups: Dict[str, GroupState]
