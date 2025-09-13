from __future__ import annotations

from ipaddress import IPv6Network
from typing import Literal, Optional, Sequence

from pydantic import BaseModel, Field, ValidationError, field_validator


class GlobalConfig(BaseModel):
    state_file_path: str
    proxy_config_path: str
    ipv6_interface: str
    inbound_ipv4_address: str = "0.0.0.0"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    egress_bind: Literal["auto", "off"] = "auto"
    pinned_ipv6: Sequence[str] = ()


class PortRange(BaseModel):
    start: int
    end: int

    @field_validator("start", "end")
    @classmethod
    def _port_ok(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port must be 1..65535")
        return v

    @field_validator("end")
    @classmethod
    def _end_ge_start(cls, v: int, info) -> int:
        start = info.data.get("start")
        if start is not None and v < start:
            raise ValueError("end must be >= start")
        return v


class ProxyGroup(BaseModel):
    name: str
    ipv6_subnet: str
    count: int = Field(ge=1)
    proxy_type: Literal["http", "socks5"] = "http"
    port_range: PortRange
    nfqueue_num: Optional[int] = None
    persona: Optional[str] = None

    @field_validator("ipv6_subnet")
    @classmethod
    def _subnet_ok(cls, v: str) -> str:
        IPv6Network(v, strict=False)  # валидация
        return v

    @field_validator("count")
    @classmethod
    def _count_vs_ports(cls, v: int, info) -> int:
        pr: PortRange = info.data.get("port_range")  # type: ignore[assignment]
        if pr and v > (pr.end - pr.start + 1):
            raise ValueError("count exceeds available ports in port_range")
        return v


class Observability(BaseModel):
    health_bind: str = "127.0.0.1:9090"
    health_interval_sec: int = Field(60, ge=5)


class Config(BaseModel):
    global_: GlobalConfig = Field(alias="global")
    proxy_groups: Sequence[ProxyGroup]
    observability: Observability = Observability()

    model_config = {"populate_by_name": True}
