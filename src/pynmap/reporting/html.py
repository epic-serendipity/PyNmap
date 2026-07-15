"""HTML report generation.

Two strategies are supported:

* The standard Nmap HTML report rendered with ``xsltproc`` and Nmap's bundled
  ``nmap.xsl`` stylesheet (when both are available).
* A self-contained fallback report generated directly from the internal
  inventory model, so a report is always produced even without xsltproc.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..models import Inventory
from ..runner import has_command, run_command


_NMAP_XSL_CANDIDATES = [
    "/usr/share/nmap/nmap.xsl",
    "/usr/local/share/nmap/nmap.xsl",
    "/opt/homebrew/share/nmap/nmap.xsl",
]


def find_nmap_xsl() -> Optional[Path]:
    for candidate in _NMAP_XSL_CANDIDATES:
        path = Path(candidate)
        if path.exists():
            return path
    return None


def render_standard_report(xml_path: Path, output_path: Path) -> bool:
    """Render an Nmap XML file to HTML using xsltproc + nmap.xsl."""
    if not has_command("xsltproc"):
        return False
    xsl = find_nmap_xsl()
    if xsl is None:
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = run_command(
        ["xsltproc", "-o", str(output_path), str(xsl), str(xml_path)],
        capture=True,
    )
    return result.ok and output_path.exists()


def render_fallback_report(
    inventory: Inventory, output_path: Path, name: str = ""
) -> None:
    """Generate a self-contained HTML report from the inventory model."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    esc = html.escape
    live = inventory.live_hosts()
    generated = (
        inventory.generated_at.isoformat()
        if inventory.generated_at
        else datetime.now().isoformat()
    )
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>PyNmap report: {esc(name)}</title>")
    parts.append(
        "<style>"
        "body{font-family:Helvetica,Arial,sans-serif;margin:2rem;color:#1c2b3a;}"
        "h1{color:#12385c;}h2{margin-top:2rem;border-bottom:1px solid #ccd;}"
        "table{border-collapse:collapse;width:100%;margin:0.5rem 0;}"
        "th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left;font-size:0.9rem;}"
        "th{background:#eef4fb;}"
        ".up{color:#186a3b;font-weight:bold;}.down{color:#922;}"
        ".summary{background:#f6f8fa;padding:1rem;border-radius:6px;}"
        "</style></head><body>"
    )
    parts.append(f"<h1>PyNmap scan report{': ' + esc(name) if name else ''}</h1>")
    total_open = sum(len(h.open_ports()) for h in live)
    parts.append('<div class="summary">')
    parts.append(f"<p>Generated: {esc(generated)}</p>")
    parts.append(f"<p>Live hosts: <strong>{len(live)}</strong></p>")
    parts.append(f"<p>Total open ports: <strong>{total_open}</strong></p>")
    parts.append("</div>")

    for host in live:
        title = esc(host.address)
        if host.hostnames:
            title += f" ({esc(', '.join(host.hostnames))})"
        parts.append(f"<h2>{title}</h2>")
        best_os = host.best_os()
        if best_os:
            parts.append(
                f"<p>OS guess: {esc(best_os.name)} "
                f"(~{best_os.accuracy}% accuracy)</p>"
            )
        if host.mac_address:
            vendor = f" ({esc(host.mac_vendor)})" if host.mac_vendor else ""
            parts.append(f"<p>MAC: {esc(host.mac_address)}{vendor}</p>")
        ports = host.ports
        if ports:
            parts.append(
                "<table><tr><th>Port</th><th>State</th><th>Service</th>"
                "<th>Product</th><th>Version</th></tr>"
            )
            for port in ports:
                parts.append(
                    "<tr>"
                    f"<td>{esc(port.key)}</td>"
                    f"<td>{esc(port.state)}</td>"
                    f"<td>{esc(port.service_name or '')}</td>"
                    f"<td>{esc(port.product or '')}</td>"
                    f"<td>{esc(port.version or '')}</td>"
                    "</tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p>No port information.</p>")

    parts.append("</body></html>")
    output_path.write_text("\n".join(parts), encoding="utf-8")


def generate_report(
    inventory: Inventory,
    output_path: Path,
    xml_path: Optional[Path] = None,
    name: str = "",
) -> Path:
    """Generate the scan report, preferring the standard Nmap stylesheet."""
    if xml_path is not None and xml_path.exists():
        if render_standard_report(xml_path, output_path):
            return output_path
    render_fallback_report(inventory, output_path, name)
    return output_path
