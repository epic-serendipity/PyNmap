"""Compute the difference between two inventories and render change reports."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Inventory, HostRecord, PortRecord
from .models import (
    HostnameChange,
    OSChange,
    PortChange,
    RouteChange,
    ScanDiff,
    ServiceChange,
)


def _open_ports_map(host: HostRecord) -> dict[str, PortRecord]:
    return {p.key: p for p in host.open_ports()}


def _os_string(host: HostRecord) -> str:
    best = host.best_os()
    return best.name if best else ""


def _route_hops(host: HostRecord) -> set[str]:
    return {hop.ipaddr for hop in host.trace if hop.ipaddr}


def diff_inventories(previous: Inventory, current: Inventory) -> ScanDiff:
    """Compare a previous inventory against the current one."""
    diff = ScanDiff()

    prev_hosts = {a: h for a, h in previous.hosts.items() if h.status == "up"}
    curr_hosts = {a: h for a, h in current.hosts.items() if h.status == "up"}

    prev_addrs = set(prev_hosts)
    curr_addrs = set(curr_hosts)

    diff.hosts_added = sorted(curr_addrs - prev_addrs, key=_ip_key)
    diff.hosts_removed = sorted(prev_addrs - curr_addrs, key=_ip_key)

    prev_hops: set[str] = set()
    curr_hops: set[str] = set()

    for addr in sorted(prev_addrs & curr_addrs, key=_ip_key):
        prev_host = prev_hosts[addr]
        curr_host = curr_hosts[addr]

        prev_ports = _open_ports_map(prev_host)
        curr_ports = _open_ports_map(curr_host)

        for key in sorted(set(curr_ports) - set(prev_ports)):
            diff.ports_opened.append(PortChange(address=addr, port=key))
        for key in sorted(set(prev_ports) - set(curr_ports)):
            diff.ports_closed.append(PortChange(address=addr, port=key))

        for key in sorted(set(prev_ports) & set(curr_ports)):
            before = prev_ports[key].service_string()
            after = curr_ports[key].service_string()
            if before != after and (before or after):
                diff.services_changed.append(
                    ServiceChange(address=addr, port=key, before=before, after=after)
                )

        prev_name = prev_host.primary_hostname() or ""
        curr_name = curr_host.primary_hostname() or ""
        if prev_name != curr_name and (prev_name or curr_name):
            diff.hostnames_changed.append(
                HostnameChange(address=addr, before=prev_name, after=curr_name)
            )

        prev_os = _os_string(prev_host)
        curr_os = _os_string(curr_host)
        if prev_os != curr_os and (prev_os or curr_os):
            diff.os_changed.append(
                OSChange(address=addr, before=prev_os, after=curr_os)
            )

    for host in prev_hosts.values():
        prev_hops |= _route_hops(host)
    for host in curr_hosts.values():
        curr_hops |= _route_hops(host)

    diff.routes_added = [RouteChange(hop=h) for h in sorted(curr_hops - prev_hops, key=_ip_key)]
    diff.routes_removed = [RouteChange(hop=h) for h in sorted(prev_hops - curr_hops, key=_ip_key)]

    return diff


def _ip_key(value: str) -> tuple:
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts))
    return (1, value)


def render_text(diff: ScanDiff) -> str:
    """Render the change report as human-readable text."""
    lines: list[str] = []

    def section(title: str, rows: list[str]) -> None:
        if not rows:
            return
        lines.append(f"{title}:")
        lines.extend(f"  {row}" for row in rows)
        lines.append("")

    host_rows = [f"+ {a} appeared" for a in diff.hosts_added]
    host_rows += [f"- {a} no longer responds" for a in diff.hosts_removed]
    section("Hosts", host_rows)

    port_rows = [f"+ {c.address} {c.port} opened" for c in diff.ports_opened]
    port_rows += [f"- {c.address} {c.port} closed" for c in diff.ports_closed]
    section("Ports", port_rows)

    svc_rows = []
    for c in diff.services_changed:
        svc_rows.append(f"~ {c.address} {c.port} changed:")
        svc_rows.append(f"    {c.before or '(none)'} -> {c.after or '(none)'}")
    section("Services", svc_rows)

    name_rows = []
    for c in diff.hostnames_changed:
        name_rows.append(f"~ {c.address} changed:")
        name_rows.append(f"    {c.before or '(none)'} -> {c.after or '(none)'}")
    section("Hostnames", name_rows)

    os_rows = []
    for c in diff.os_changed:
        os_rows.append(f"~ {c.address}:")
        os_rows.append(f"    {c.before or '(none)'} -> {c.after or '(none)'}")
    section("Operating system", os_rows)

    route_rows = [f"+ New traceroute hop {c.hop}" for c in diff.routes_added]
    route_rows += [f"- Traceroute hop gone {c.hop}" for c in diff.routes_removed]
    section("Routes", route_rows)

    if not lines:
        return "No changes detected.\n"
    return "\n".join(lines).rstrip() + "\n"


def render_html(diff: ScanDiff, name: str = "") -> str:
    import html as _html

    esc = _html.escape
    parts = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
             f"<title>NetMapper changes: {esc(name)}</title>",
             "<style>body{font-family:Helvetica,Arial,sans-serif;margin:2rem;}"
             "h2{border-bottom:1px solid #ccd;}"
             ".add{color:#186a3b;}.rem{color:#922;}.chg{color:#8a6d00;}"
             "li{margin:2px 0;}</style></head><body>"]
    parts.append(f"<h1>Change report{': ' + esc(name) if name else ''}</h1>")
    if diff.is_empty():
        parts.append("<p>No changes detected.</p>")
    else:
        _html_section(parts, "Hosts",
                      [(f"{a} appeared", "add") for a in diff.hosts_added] +
                      [(f"{a} no longer responds", "rem") for a in diff.hosts_removed])
        _html_section(parts, "Ports",
                      [(f"{c.address} {c.port} opened", "add") for c in diff.ports_opened] +
                      [(f"{c.address} {c.port} closed", "rem") for c in diff.ports_closed])
        _html_section(parts, "Services",
                      [(f"{c.address} {c.port}: {c.before or '(none)'} &rarr; {c.after or '(none)'}", "chg")
                       for c in diff.services_changed])
        _html_section(parts, "Hostnames",
                      [(f"{c.address}: {c.before or '(none)'} &rarr; {c.after or '(none)'}", "chg")
                       for c in diff.hostnames_changed])
        _html_section(parts, "Operating system",
                      [(f"{c.address}: {c.before or '(none)'} &rarr; {c.after or '(none)'}", "chg")
                       for c in diff.os_changed])
        _html_section(parts, "Routes",
                      [(f"New hop {c.hop}", "add") for c in diff.routes_added] +
                      [(f"Hop gone {c.hop}", "rem") for c in diff.routes_removed])
    parts.append("</body></html>")
    return "\n".join(parts)


def _html_section(parts: list[str], title: str, rows: list[tuple[str, str]]) -> None:
    import html as _html

    if not rows:
        return
    parts.append(f"<h2>{_html.escape(title)}</h2><ul>")
    for text, cls in rows:
        parts.append(f"<li class='{cls}'>{text}</li>")
    parts.append("</ul>")


def write_diff(diff: ScanDiff, json_path: Path, text_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(diff.to_dict(), indent=2) + "\n", encoding="utf-8")
    text_path.write_text(render_text(diff), encoding="utf-8")
