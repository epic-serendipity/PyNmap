"""Export the internal inventory model to JSON, CSV, and text summaries."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ..models import Inventory, HostRecord, host_to_dict


def write_hosts_json(inventory: Inventory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {
        "generated_at": inventory.generated_at.isoformat()
        if inventory.generated_at
        else None,
        "host_count": len(inventory.hosts),
        "live_host_count": len(inventory.live_hosts()),
        "hosts": [host_to_dict(h) for h in inventory.sorted_hosts()],
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def write_hosts_csv(inventory: Inventory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["address", "status", "hostnames", "mac_address", "mac_vendor",
             "os", "open_ports"]
        )
        for host in inventory.sorted_hosts():
            best_os = host.best_os()
            writer.writerow([
                host.address,
                host.status,
                ";".join(host.hostnames),
                host.mac_address or "",
                host.mac_vendor or "",
                best_os.name if best_os else "",
                ";".join(p.key for p in host.open_ports()),
            ])


def write_services_csv(inventory: Inventory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["address", "hostname", "protocol", "port", "state",
             "service", "product", "version", "extrainfo"]
        )
        for host in inventory.sorted_hosts():
            hostname = host.primary_hostname() or ""
            for port in host.ports:
                writer.writerow([
                    host.address,
                    hostname,
                    port.protocol,
                    port.portid,
                    port.state,
                    port.service_name or "",
                    port.product or "",
                    port.version or "",
                    port.extrainfo or "",
                ])


def write_routes_json(inventory: Inventory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    routes = []
    for host in inventory.sorted_hosts():
        if not host.trace:
            continue
        routes.append({
            "destination": host.address,
            "hops": [
                {"ttl": hop.ttl, "ipaddr": hop.ipaddr, "rtt": hop.rtt, "host": hop.host}
                for hop in host.trace
            ],
        })
    path.write_text(json.dumps({"routes": routes}, indent=2) + "\n", encoding="utf-8")


def write_summary_txt(inventory: Inventory, path: Path, name: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if name:
        lines.append(f"PyNmap scan summary: {name}")
    else:
        lines.append("PyNmap scan summary")
    if inventory.generated_at:
        lines.append(f"Generated: {inventory.generated_at.isoformat()}")
    live = inventory.live_hosts()
    total_open = sum(len(h.open_ports()) for h in live)
    lines.append(f"Live hosts: {len(live)}")
    lines.append(f"Open ports (total): {total_open}")
    lines.append("")
    for host in live:
        header = host.address
        if host.hostnames:
            header += f" ({', '.join(host.hostnames)})"
        best_os = host.best_os()
        if best_os:
            header += f" [{best_os.name} ~{best_os.accuracy}%]"
        lines.append(header)
        for port in host.open_ports():
            svc = port.service_string()
            svc_str = f"  {svc}" if svc else ""
            lines.append(f"    {port.key:<12} {port.state}{svc_str}")
        if not host.open_ports():
            lines.append("    (no open ports found)")
        lines.append("")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def export_all(inventory: Inventory, inventory_dir: Path, name: str = "") -> list[Path]:
    """Write hosts.json, hosts.csv, services.csv, routes.json and return paths."""
    inventory_dir.mkdir(parents=True, exist_ok=True)
    hosts_json = inventory_dir / "hosts.json"
    hosts_csv = inventory_dir / "hosts.csv"
    services_csv = inventory_dir / "services.csv"
    routes_json = inventory_dir / "routes.json"
    write_hosts_json(inventory, hosts_json)
    write_hosts_csv(inventory, hosts_csv)
    write_services_csv(inventory, services_csv)
    write_routes_json(inventory, routes_json)
    return [hosts_json, hosts_csv, services_csv, routes_json]
