"""Data structures describing the difference between two scan runs."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class PortChange:
    address: str
    port: str  # e.g. "tcp/445"


@dataclass
class ServiceChange:
    address: str
    port: str
    before: str
    after: str


@dataclass
class HostnameChange:
    address: str
    before: str
    after: str


@dataclass
class OSChange:
    address: str
    before: str
    after: str


@dataclass
class RouteChange:
    hop: str
    note: str = ""


@dataclass
class ScanDiff:
    hosts_added: list[str] = field(default_factory=list)
    hosts_removed: list[str] = field(default_factory=list)
    ports_opened: list[PortChange] = field(default_factory=list)
    ports_closed: list[PortChange] = field(default_factory=list)
    services_changed: list[ServiceChange] = field(default_factory=list)
    hostnames_changed: list[HostnameChange] = field(default_factory=list)
    os_changed: list[OSChange] = field(default_factory=list)
    routes_added: list[RouteChange] = field(default_factory=list)
    routes_removed: list[RouteChange] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            [
                self.hosts_added,
                self.hosts_removed,
                self.ports_opened,
                self.ports_closed,
                self.services_changed,
                self.hostnames_changed,
                self.os_changed,
                self.routes_added,
                self.routes_removed,
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
