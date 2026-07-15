"""Internal data model for NetMapper.

Nmap XML (not ``.nmap`` text) is the source of truth. The parser normalises
raw XML into these dataclasses, and every downstream consumer (CSV/JSON export,
Graphviz map, HTML report, diff engine) works against this model. That keeps
report generation independent from Nmap's raw output formatting.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class OperationState(str, Enum):
    """Lifecycle states for an operation, persisted so scans can resume."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"
    STALE = "stale"


@dataclass
class PortRecord:
    protocol: str  # tcp / udp
    portid: int
    state: str  # open / closed / filtered ...
    reason: Optional[str] = None
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.portid}"

    def service_string(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        if parts:
            return " ".join(parts)
        return self.service_name or ""


@dataclass
class OSMatch:
    name: str
    accuracy: int = 0
    os_family: Optional[str] = None
    os_gen: Optional[str] = None
    vendor: Optional[str] = None


@dataclass
class TraceHop:
    ttl: int
    ipaddr: Optional[str] = None
    rtt: Optional[str] = None
    host: Optional[str] = None


@dataclass
class HostRecord:
    address: str
    status: str
    hostnames: list[str] = field(default_factory=list)
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    os_matches: list[OSMatch] = field(default_factory=list)
    ports: list[PortRecord] = field(default_factory=list)
    trace: list[TraceHop] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def open_ports(self) -> list[PortRecord]:
        return [p for p in self.ports if p.state == "open"]

    def best_os(self) -> Optional[OSMatch]:
        if not self.os_matches:
            return None
        return max(self.os_matches, key=lambda m: m.accuracy)

    def primary_hostname(self) -> Optional[str]:
        return self.hostnames[0] if self.hostnames else None


@dataclass
class Inventory:
    """A normalised, merged view of all hosts across the scan's XML outputs."""

    hosts: dict[str, HostRecord] = field(default_factory=dict)
    generated_at: Optional[datetime] = None

    def upsert(self, host: HostRecord) -> None:
        existing = self.hosts.get(host.address)
        if existing is None:
            self.hosts[host.address] = host
            return
        _merge_host(existing, host)

    def sorted_hosts(self) -> list[HostRecord]:
        return sorted(self.hosts.values(), key=_address_sort_key)

    def live_hosts(self) -> list[HostRecord]:
        return [h for h in self.sorted_hosts() if h.status == "up"]


def _merge_host(existing: HostRecord, incoming: HostRecord) -> None:
    """Merge data from a later scan into an existing host record."""
    if incoming.status == "up":
        existing.status = "up"
    for name in incoming.hostnames:
        if name not in existing.hostnames:
            existing.hostnames.append(name)
    if incoming.mac_address:
        existing.mac_address = incoming.mac_address
    if incoming.mac_vendor:
        existing.mac_vendor = incoming.mac_vendor
    if incoming.os_matches:
        existing.os_matches = incoming.os_matches
    if incoming.trace:
        existing.trace = incoming.trace

    ports_by_key = {p.key: p for p in existing.ports}
    for port in incoming.ports:
        ports_by_key[port.key] = port
    existing.ports = sorted(
        ports_by_key.values(), key=lambda p: (p.protocol, p.portid)
    )

    if incoming.last_seen:
        existing.last_seen = incoming.last_seen
    if incoming.first_seen and (
        existing.first_seen is None or incoming.first_seen < existing.first_seen
    ):
        existing.first_seen = incoming.first_seen


def _address_sort_key(host: HostRecord) -> tuple:
    return _ip_sort_key(host.address)


def _ip_sort_key(address: str) -> tuple:
    """Sort IPv4 numerically, everything else lexically but after IPv4."""
    parts = address.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts))
    return (1, address)


def host_to_dict(host: HostRecord) -> dict[str, Any]:
    data = asdict(host)
    data["first_seen"] = host.first_seen.isoformat() if host.first_seen else None
    data["last_seen"] = host.last_seen.isoformat() if host.last_seen else None
    return data
