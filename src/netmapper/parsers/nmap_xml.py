"""Parse Nmap XML output into the internal :mod:`netmapper.models` structures.

Uses ``lxml`` when available for speed, falling back to the standard library
``xml.etree.ElementTree``. The parser never trusts filenames: it verifies that
the XML root element is ``<nmaprun>`` before accepting a file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

try:  # pragma: no cover - optional dependency
    from lxml import etree as _ET  # type: ignore
    _USING_LXML = True
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as _ET  # type: ignore
    _USING_LXML = False

from ..models import HostRecord, Inventory, OSMatch, PortRecord, TraceHop


class NotNmapXMLError(Exception):
    """Raised when a file is not valid Nmap XML."""


def _parse_root(source):
    if _USING_LXML:
        parser = _ET.XMLParser(resolve_entities=False, no_network=True)
        tree = _ET.parse(str(source), parser)
        return tree.getroot()
    tree = _ET.parse(str(source))
    return tree.getroot()


def _parse_root_from_string(text: str):
    if _USING_LXML:
        parser = _ET.XMLParser(resolve_entities=False, no_network=True)
        return _ET.fromstring(text.encode("utf-8"), parser)
    return _ET.fromstring(text)


def is_nmap_xml(path: Path | str) -> bool:
    """Return True only when the file exists and its root is ``<nmaprun>``."""
    try:
        root = _parse_root(path)
    except (OSError, _ET.ParseError, ValueError):
        return False
    except Exception:  # lxml raises XMLSyntaxError (subclass) but be safe
        return False
    return _localname(root.tag) == "nmaprun"


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _epoch_to_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).astimezone()
    except (ValueError, OSError):
        return None


def parse_file(path: Path | str) -> list[HostRecord]:
    """Parse one Nmap XML file into a list of host records."""
    root = _parse_root(path)
    if _localname(root.tag) != "nmaprun":
        raise NotNmapXMLError(f"{path} is not Nmap XML (root={_localname(root.tag)})")
    scan_end = _epoch_to_dt(root.get("start"))
    runstats = root.find("runstats/finished")
    if runstats is not None:
        scan_end = _epoch_to_dt(runstats.get("time")) or scan_end
    return [_parse_host(h, scan_end) for h in root.findall("host")]


def parse_string(text: str) -> list[HostRecord]:
    root = _parse_root_from_string(text)
    if _localname(root.tag) != "nmaprun":
        raise NotNmapXMLError("input is not Nmap XML")
    scan_end = _epoch_to_dt(root.get("start"))
    return [_parse_host(h, scan_end) for h in root.findall("host")]


def _parse_host(host_el, seen_at: Optional[datetime]) -> HostRecord:
    address = ""
    mac_address = None
    mac_vendor = None
    for addr in host_el.findall("address"):
        addrtype = addr.get("addrtype")
        if addrtype in ("ipv4", "ipv6"):
            address = addr.get("addr", address)
        elif addrtype == "mac":
            mac_address = addr.get("addr")
            mac_vendor = addr.get("vendor")

    status_el = host_el.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"

    hostnames = []
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        for hn in hostnames_el.findall("hostname"):
            name = hn.get("name")
            if name:
                hostnames.append(name)

    ports = _parse_ports(host_el)
    os_matches = _parse_os(host_el)
    trace = _parse_trace(host_el)

    return HostRecord(
        address=address or "unknown",
        status=status,
        hostnames=hostnames,
        mac_address=mac_address,
        mac_vendor=mac_vendor,
        os_matches=os_matches,
        ports=ports,
        trace=trace,
        first_seen=seen_at,
        last_seen=seen_at,
    )


def _parse_ports(host_el) -> list[PortRecord]:
    ports: list[PortRecord] = []
    ports_el = host_el.find("ports")
    if ports_el is None:
        return ports
    for port_el in ports_el.findall("port"):
        state_el = port_el.find("state")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"
        reason = state_el.get("reason") if state_el is not None else None
        service_el = port_el.find("service")
        cpes = []
        service_name = product = version = extrainfo = None
        if service_el is not None:
            service_name = service_el.get("name")
            product = service_el.get("product")
            version = service_el.get("version")
            extrainfo = service_el.get("extrainfo")
            for cpe in service_el.findall("cpe"):
                if cpe.text:
                    cpes.append(cpe.text)
        scripts = {}
        for script in port_el.findall("script"):
            sid = script.get("id")
            if sid:
                scripts[sid] = script.get("output", "")
        try:
            portid = int(port_el.get("portid", "0"))
        except ValueError:
            portid = 0
        ports.append(
            PortRecord(
                protocol=port_el.get("protocol", "tcp"),
                portid=portid,
                state=state,
                reason=reason,
                service_name=service_name,
                product=product,
                version=version,
                extrainfo=extrainfo,
                cpe=cpes,
                scripts=scripts,
            )
        )
    return ports


def _parse_os(host_el) -> list[OSMatch]:
    matches: list[OSMatch] = []
    os_el = host_el.find("os")
    if os_el is None:
        return matches
    for match in os_el.findall("osmatch"):
        try:
            accuracy = int(match.get("accuracy", "0"))
        except ValueError:
            accuracy = 0
        vendor = os_family = os_gen = None
        osclass = match.find("osclass")
        if osclass is not None:
            vendor = osclass.get("vendor")
            os_family = osclass.get("osfamily")
            os_gen = osclass.get("osgen")
        matches.append(
            OSMatch(
                name=match.get("name", "unknown"),
                accuracy=accuracy,
                os_family=os_family,
                os_gen=os_gen,
                vendor=vendor,
            )
        )
    return matches


def _parse_trace(host_el) -> list[TraceHop]:
    hops: list[TraceHop] = []
    trace_el = host_el.find("trace")
    if trace_el is None:
        return hops
    for hop in trace_el.findall("hop"):
        try:
            ttl = int(hop.get("ttl", "0"))
        except ValueError:
            ttl = 0
        hops.append(
            TraceHop(
                ttl=ttl,
                ipaddr=hop.get("ipaddr"),
                rtt=hop.get("rtt"),
                host=hop.get("host"),
            )
        )
    return hops


def build_inventory(xml_files: Iterable[Path | str]) -> Inventory:
    """Merge multiple Nmap XML files into a single normalised inventory."""
    inventory = Inventory(generated_at=datetime.now(timezone.utc).astimezone())
    for xml_file in xml_files:
        path = Path(xml_file)
        if not path.exists() or not is_nmap_xml(path):
            continue
        for host in parse_file(path):
            if host.address == "unknown" and not host.ports:
                continue
            inventory.upsert(host)
    return inventory
