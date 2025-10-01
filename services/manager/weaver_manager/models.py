from __future__ import annotations

from ipaddress import IPv6Network
from typing import Literal, Optional

from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator


class PortRange(BaseModel):
    start: int
    end: int

    @field_validator("start", "end")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("port must be >= 0")
        if v > 65535:
            raise ValueError("port must be <= 65535")
        return v

    @model_validator(mode="after")
    def _check_range(self) -> "PortRange":
        if self.start > self.end:
            raise ValueError("port_range.start must be <= end")
        return self


class GlobalConfig(BaseModel):
    state_file_path: str
    proxy_config_path: str
    ipv6_interface: str
    inbound_ipv4_address: str = "0.0.0.0"
    egress_bind: Literal["auto", "off"] = "auto"
    pinned_ipv6: list[str] = Field(default_factory=list)
    observe_enabled: bool = True


class ProxyGroup(BaseModel):
    name: str
    ipv6_subnet: str
    count: int
    proxy_type: Literal["http", "socks5"]
    port_range: PortRange
    listen_stack: Literal["ipv4", "ipv6"] = "ipv4"
    nfqueue_num: Optional[int] = None
    persona: Optional[str] = None  # зарезервировано на будущее

    @field_validator("count")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("count must be > 0")
        return v

    @model_validator(mode="after")
    def _validate_ports_capacity(self) -> "ProxyGroup":
        capacity = self.port_range.end - self.port_range.start + 1
        if self.count > capacity:
            raise ValueError(f"{self.name}: count {self.count} exceeds port capacity {capacity}")
        return self

    @field_validator("ipv6_subnet")
    @classmethod
    def _validate_subnet(cls, v: str, info: ValidationInfo) -> str:
        try:
            IPv6Network(v, strict=False)
        except Exception as e:
            raise ValueError(f"invalid ipv6_subnet {v}: {e}") from e
        return v


class Config(BaseModel):
    global_: GlobalConfig = Field(alias="global")
    proxy_groups: list[ProxyGroup]

    model_config = dict(populate_by_name=True)

