"""Parse and normalise Nmap target specifications.

Supported entry forms (one per line, ``#`` comments and blank lines ignored):

* Single IPv4/IPv6 address        ``10.0.0.1``
* CIDR network                    ``10.0.0.0/24``
* Nmap-style octet range          ``10.0.0-3.1-254``
* Hyphenated IPv4 range           ``10.0.0.1-10.0.0.50``
* Hostname                        ``scanme.nmap.org``

Normalisation deduplicates entries and produces a canonical, sorted list so
that the SHA-256 target hash is stable regardless of input ordering or
formatting. The scope counter estimates the number of IPv4 addresses covered so
the review screen can warn about accidentally huge ranges.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


_OCTET_RANGE_RE = re.compile(r"^\d{1,3}(-\d{1,3})?$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


@dataclass
class TargetEntry:
    raw: str
    kind: str  # ip / cidr / range / octet-range / hostname / invalid
    normalized: str
    address_count: int  # estimated IPv4 addresses (0 for hostnames)
    error: str | None = None


@dataclass
class TargetSet:
    entries: list[TargetEntry] = field(default_factory=list)

    @property
    def valid_entries(self) -> list[TargetEntry]:
        return [e for e in self.entries if e.kind != "invalid"]

    @property
    def invalid_entries(self) -> list[TargetEntry]:
        return [e for e in self.entries if e.kind == "invalid"]

    def normalized_lines(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for entry in self.valid_entries:
            if entry.normalized not in seen:
                seen.add(entry.normalized)
                result.append(entry.normalized)
        result.sort(key=_normalized_sort_key)
        return result

    def network_count(self) -> int:
        return sum(1 for e in self.valid_entries if e.kind in ("cidr", "range", "octet-range"))

    def address_count(self) -> int:
        return sum(e.address_count for e in self.valid_entries)


def _normalized_sort_key(value: str) -> tuple:
    head = value.split("/")[0].split("-")[0]
    try:
        return (0, int(ipaddress.ip_address(head)))
    except ValueError:
        return (1, value)


def classify_target(raw: str) -> TargetEntry:
    token = raw.strip()
    if not token or token.startswith("#"):
        return TargetEntry(raw=raw, kind="invalid", normalized="", address_count=0,
                           error="blank or comment")

    # CIDR network
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            count = net.num_addresses if net.version == 4 else 0
            return TargetEntry(raw=token, kind="cidr", normalized=str(net),
                               address_count=count)
        except ValueError as exc:
            return TargetEntry(raw=token, kind="invalid", normalized="",
                               address_count=0, error=str(exc))

    # Single address
    try:
        addr = ipaddress.ip_address(token)
        return TargetEntry(raw=token, kind="ip", normalized=str(addr),
                           address_count=1 if addr.version == 4 else 0)
    except ValueError:
        pass

    # Hyphenated full-address range: a.b.c.d-w.x.y.z or a.b.c.d-N
    if "-" in token and token.count(".") >= 3:
        entry = _parse_hyphen_range(token)
        if entry is not None:
            return entry

    # Nmap octet-range form: 10.0.0-3.1-254
    if "." in token:
        parts = token.split(".")
        if len(parts) == 4 and all(_OCTET_RANGE_RE.match(p) for p in parts):
            count = 1
            for part in parts:
                if "-" in part:
                    lo, hi = (int(x) for x in part.split("-"))
                    if hi < lo or lo > 255 or hi > 255:
                        return TargetEntry(raw=token, kind="invalid", normalized="",
                                           address_count=0, error="octet out of range")
                    count *= (hi - lo + 1)
                else:
                    if int(part) > 255:
                        return TargetEntry(raw=token, kind="invalid", normalized="",
                                           address_count=0, error="octet out of range")
            return TargetEntry(raw=token, kind="octet-range", normalized=token,
                               address_count=count)

    # Hostname
    if _HOSTNAME_RE.match(token):
        return TargetEntry(raw=token, kind="hostname", normalized=token.lower(),
                           address_count=0)

    return TargetEntry(raw=token, kind="invalid", normalized="", address_count=0,
                       error="unrecognised target format")


def _parse_hyphen_range(token: str) -> TargetEntry | None:
    left, _, right = token.partition("-")
    try:
        start = ipaddress.ip_address(left)
    except ValueError:
        return None
    if start.version != 4:
        return None
    if right.isdigit():
        prefix = ".".join(left.split(".")[:3])
        try:
            end = ipaddress.ip_address(f"{prefix}.{right}")
        except ValueError:
            return TargetEntry(raw=token, kind="invalid", normalized="",
                               address_count=0, error="invalid range end")
    else:
        try:
            end = ipaddress.ip_address(right)
        except ValueError:
            return TargetEntry(raw=token, kind="invalid", normalized="",
                               address_count=0, error="invalid range end")
    if int(end) < int(start):
        return TargetEntry(raw=token, kind="invalid", normalized="",
                           address_count=0, error="range end before start")
    count = int(end) - int(start) + 1
    normalized = f"{start}-{str(end).split('.')[-1]}" if right.isdigit() else f"{start}-{end}"
    return TargetEntry(raw=token, kind="range", normalized=normalized,
                       address_count=count)


def parse_targets_text(text: str) -> TargetSet:
    entries: list[TargetEntry] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # a single line may contain multiple whitespace-separated targets
        for token in stripped.split():
            entries.append(classify_target(token))
    return TargetSet(entries=entries)


def parse_targets_file(path) -> TargetSet:
    from pathlib import Path

    text = Path(path).read_text(encoding="utf-8")
    return parse_targets_text(text)
