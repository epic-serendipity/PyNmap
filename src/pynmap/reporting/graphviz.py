"""Generate a Graphviz network map (DOT) and render SVG/PNG via ``dot``.

Two builders are provided so the map always reflects *every* piece of data a
scan happened to collect, no matter which operations ran:

* :func:`build_dot` -- the ``standard`` map: compact one-node-per-host boxes
  with newline-separated text labels.
* :func:`build_enhanced_dot` -- the ``enhanced`` map: richer HTML-table nodes
  with a colour-coded port table, OS/MAC/NSE details, a per-subnet grouping,
  and a legend plus a scan-coverage summary node.

Both builders draw from the same normalised :class:`~pynmap.models.Inventory`,
so hostnames, MAC address/vendor, OS guesses, open TCP *and* UDP ports with
service product/version/extrainfo, NSE script output, and traceroute paths
(with per-hop RTT) are surfaced whenever they are present, and simply omitted
when a given scan did not gather them.
"""

from __future__ import annotations

import html as _html
from collections import Counter
from pathlib import Path
from typing import Optional

from ..models import Inventory, HostRecord
from ..runner import has_command, run_command

# Shared palette (kept in sync with the HTML report styling).
_COLOR_SCANNER = "#d5f5d5"
_COLOR_HOST = "#eef4fb"
_COLOR_HOP = "#fdf1c7"
_COLOR_TCP = "#d6f5d6"
_COLOR_UDP = "#dbe9fb"
_COLOR_HEADER = "#12385c"


def _escape(label: str) -> str:
    """Escape a value for a quoted (non-HTML) DOT string."""
    return label.replace("\\", "\\\\").replace('"', '\\"')


def _html_escape(text: str) -> str:
    """Escape a value for a Graphviz HTML-like label."""
    return _html.escape(text, quote=True)


# --- data coverage ---------------------------------------------------------

def _coverage(inventory: Inventory) -> tuple[list[HostRecord], int, dict[str, bool]]:
    """Return (live hosts, total open ports, {data-type: present?}).

    The presence map lets the map advertise exactly what the run collected,
    which varies per scan (e.g. OS detection or UDP may be absent).
    """
    live = inventory.live_hosts()
    open_ports = sum(len(h.open_ports()) for h in live)
    present = {
        "OS detection": any(h.os_matches for h in live),
        "Service versions": any(
            (p.product or p.version) for h in live for p in h.ports
        ),
        "UDP ports": any(p.protocol == "udp" for h in live for p in h.ports),
        "Traceroute": any(h.trace for h in live),
        "MAC vendor": any(h.mac_address for h in live),
        "NSE scripts": any(p.scripts for h in live for p in h.ports),
    }
    return live, open_ports, present


def _summary_lines(inventory: Inventory) -> list[str]:
    live, open_ports, present = _coverage(inventory)
    lines = [f"{len(live)} live host(s), {open_ports} open port(s)"]
    collected = [name for name, ok in present.items() if ok]
    if collected:
        lines.append("Data: " + ", ".join(collected))
    return lines


# --- traceroute topology (shared by both builders) -------------------------

def _topology_lines(live: list[HostRecord]) -> list[str]:
    """Emit hop nodes and edges (scanner -> hops -> host) with RTT labels."""
    lines: list[str] = []
    hop_nodes: set[str] = set()
    for host in live:
        node_id = _escape(host.address)
        if not host.trace:
            lines.append(f'  "scanner" -> "{node_id}" [style=dashed];')
            continue
        prev = "scanner"
        for hop in host.trace:
            hop_addr = hop.ipaddr or f"ttl{hop.ttl}"
            rtt = f' [label="{_escape(hop.rtt)} ms"]' if hop.rtt else ""
            if hop_addr == host.address:
                lines.append(f'  "{prev}" -> "{node_id}"{rtt};')
                prev = node_id
                continue
            hop_id = _escape(hop_addr)
            if hop_id not in hop_nodes:
                hop_nodes.add(hop_id)
                hlabel = hop_id
                if hop.host:
                    hlabel += "\\n" + _escape(hop.host)
                lines.append(
                    f'  "{hop_id}" [label="{hlabel}", shape=diamond, '
                    f'fillcolor="{_COLOR_HOP}"];'
                )
            lines.append(f'  "{prev}" -> "{hop_id}"{rtt};')
            prev = hop_id
        if prev != node_id:
            lines.append(f'  "{prev}" -> "{node_id}";')
    return lines


def _subnet_key(address: str) -> str:
    parts = address.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "other"


# --- standard (text-label) map ---------------------------------------------

def _host_label(host: HostRecord) -> str:
    lines = [host.address]
    if host.hostnames:
        lines.append(", ".join(host.hostnames))
    best_os = host.best_os()
    if best_os:
        os_line = best_os.name
        if best_os.accuracy:
            os_line += f" (~{best_os.accuracy}%)"
        lines.append(os_line)
    if host.mac_address:
        mac = host.mac_address
        if host.mac_vendor:
            mac += f" [{host.mac_vendor}]"
        lines.append("MAC " + mac)
    open_ports = host.open_ports()
    for proto in ("tcp", "udp"):
        proto_ports = [p for p in open_ports if p.protocol == proto]
        if not proto_ports:
            continue
        shown = []
        for port in proto_ports[:6]:
            svc = port.service_string()
            shown.append(f"{port.portid}/{svc}" if svc else str(port.portid))
        if len(proto_ports) > 6:
            shown.append(f"+{len(proto_ports) - 6}")
        lines.append(f"{proto.upper()}: " + ", ".join(shown))
    filtered = [p for p in host.ports if p.state not in ("open", "closed")]
    if filtered:
        lines.append(f"{len(filtered)} filtered")
    if len(lines) == 1:
        lines.append("(no open ports found)")
    return "\\n".join(_escape(line) for line in lines)


def build_dot(inventory: Inventory, title: str = "PyNmap") -> str:
    """Build the standard Graphviz DOT document from the inventory."""
    live = inventory.live_hosts()
    label = "\\n".join(_escape(t) for t in [title, *_summary_lines(inventory)])

    out: list[str] = []
    out.append("digraph pynmap {")
    out.append('  labelloc="t";')
    out.append(f'  label="{label}";')
    out.append("  rankdir=LR;")
    out.append('  node [shape=box, style="rounded,filled", '
               f'fillcolor="{_COLOR_HOST}", fontname="Helvetica"];')
    out.append('  edge [fontname="Helvetica", fontsize=9];')
    out.append(f'  "scanner" [label="Scanner", shape=oval, '
               f'fillcolor="{_COLOR_SCANNER}"];')

    for host in live:
        node_id = _escape(host.address)
        out.append(f'  "{node_id}" [label="{_host_label(host)}"];')

    out.extend(_topology_lines(live))
    out.append("}")
    return "\n".join(out) + "\n"


# --- enhanced (HTML-table) map ---------------------------------------------

def _cell(text: str, size: int = 9, extra: str = "") -> str:
    return f'<TD{extra}><FONT POINT-SIZE="{size}">{text or " "}</FONT></TD>'


def _row(text: str, *, size: int = 9, colspan: int = 3,
         bgcolor: str = "", bold: bool = False, color: str = "") -> str:
    attrs = f' COLSPAN="{colspan}"'
    if bgcolor:
        attrs += f' BGCOLOR="{bgcolor}"'
    inner = _html_escape(text)
    if bold:
        inner = f"<B>{inner}</B>"
    font = f'<FONT POINT-SIZE="{size}"'
    if color:
        font += f' COLOR="{color}"'
    font += f">{inner}</FONT>"
    return f"<TR><TD{attrs}>{font}</TD></TR>"


def _html_host_label(host: HostRecord) -> str:
    rows: list[str] = []
    rows.append(_row(host.address, size=11, bold=True,
                     bgcolor=_COLOR_HEADER, color="white"))
    if host.hostnames:
        rows.append(_row(", ".join(host.hostnames)))
    best_os = host.best_os()
    if best_os:
        detail = []
        if best_os.accuracy:
            detail.append(f"~{best_os.accuracy}%")
        if best_os.vendor:
            detail.append(best_os.vendor)
        os_txt = best_os.name + (f" ({', '.join(detail)})" if detail else "")
        rows.append(_row(f"OS: {os_txt}"))
    if host.mac_address:
        mac = host.mac_address + (f" {host.mac_vendor}" if host.mac_vendor else "")
        rows.append(_row(f"MAC: {mac}"))

    open_ports = host.open_ports()
    if open_ports:
        rows.append(_row("Open ports", bold=True, bgcolor=_COLOR_HOST))
        for port in open_ports:
            color = _COLOR_UDP if port.protocol == "udp" else _COLOR_TCP
            detail_parts = [x for x in (port.product, port.version,
                                        port.extrainfo) if x]
            detail = " ".join(detail_parts)
            if port.scripts:
                detail += (" " if detail else "") + "NSE:" + ",".join(
                    sorted(port.scripts)
                )
            rows.append(
                "<TR>"
                + _cell(_html_escape(f"{port.protocol}/{port.portid}"),
                        extra=f' BGCOLOR="{color}"')
                + _cell(_html_escape(port.service_name or ""))
                + _cell(_html_escape(detail))
                + "</TR>"
            )
    others = [p for p in host.ports if p.state != "open"]
    if others:
        counts = Counter(p.state for p in others)
        summary = ", ".join(f"{n} {state}" for state, n in sorted(counts.items()))
        rows.append(_row(summary, size=8, color="#666666"))
    elif not open_ports:
        rows.append(_row("no ports scanned", size=8, color="#666666"))

    table = (
        '<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="3">'
        + "".join(rows)
        + "</TABLE>"
    )
    return f"<{table}>"


def _legend_node() -> str:
    rows = [
        _row("Legend", bold=True, bgcolor=_COLOR_HEADER, color="white", colspan=1),
        f'<TR><TD BGCOLOR="{_COLOR_SCANNER}"><FONT POINT-SIZE="9">Scanner</FONT></TD></TR>',
        f'<TR><TD BGCOLOR="{_COLOR_TCP}"><FONT POINT-SIZE="9">Open TCP port</FONT></TD></TR>',
        f'<TR><TD BGCOLOR="{_COLOR_UDP}"><FONT POINT-SIZE="9">Open UDP port</FONT></TD></TR>',
        f'<TR><TD BGCOLOR="{_COLOR_HOP}"><FONT POINT-SIZE="9">Traceroute hop</FONT></TD></TR>',
    ]
    table = (
        '<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="3">'
        + "".join(rows)
        + "</TABLE>"
    )
    return f'  "legend" [shape=plain, label=<{table}>];'


def _summary_node(inventory: Inventory) -> str:
    live, open_ports, present = _coverage(inventory)
    rows = [_row("Scan coverage", bold=True, bgcolor=_COLOR_HEADER,
                 color="white", colspan=1)]
    rows.append(
        f'<TR><TD><FONT POINT-SIZE="9">{len(live)} live host(s)</FONT></TD></TR>'
    )
    rows.append(
        f'<TR><TD><FONT POINT-SIZE="9">{open_ports} open port(s)</FONT></TD></TR>'
    )
    for name, ok in present.items():
        mark = "yes" if ok else "no"
        color = "#186a3b" if ok else "#999999"
        rows.append(
            f'<TR><TD><FONT POINT-SIZE="9" COLOR="{color}">'
            f"{_html_escape(name)}: {mark}</FONT></TD></TR>"
        )
    table = (
        '<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="3">'
        + "".join(rows)
        + "</TABLE>"
    )
    return f'  "coverage" [shape=plain, label=<{table}>];'


def build_enhanced_dot(inventory: Inventory, title: str = "PyNmap") -> str:
    """Build the enhanced (HTML-table) Graphviz DOT document."""
    live = inventory.live_hosts()

    out: list[str] = []
    out.append("digraph pynmap {")
    out.append('  labelloc="t";')
    out.append(f'  label="{_escape(title)}";')
    out.append('  fontname="Helvetica"; fontsize=14;')
    out.append("  rankdir=LR;")
    out.append("  compound=true;")
    out.append('  node [shape=box, style="rounded,filled", '
               f'fillcolor="{_COLOR_HOST}", fontname="Helvetica"];')
    out.append('  edge [fontname="Helvetica", fontsize=9];')
    out.append(f'  "scanner" [label="Scanner", shape=oval, '
               f'fillcolor="{_COLOR_SCANNER}"];')

    # Group hosts into per-/24 subnet clusters for readability.
    subnets: dict[str, list[HostRecord]] = {}
    for host in live:
        subnets.setdefault(_subnet_key(host.address), []).append(host)

    for index, (subnet, hosts) in enumerate(sorted(subnets.items())):
        out.append(f'  subgraph "cluster_{index}" {{')
        out.append(f'    label="{_escape(subnet)}";')
        out.append('    style="rounded,dashed"; color="#9db3c8"; fontsize=10;')
        for host in hosts:
            node_id = _escape(host.address)
            out.append(f'    "{node_id}" [shape=plain, '
                       f"label={_html_host_label(host)}];")
        out.append("  }")

    out.extend(_topology_lines(live))
    out.append(_summary_node(inventory))
    out.append(_legend_node())
    out.append("}")
    return "\n".join(out) + "\n"


# --- rendering -------------------------------------------------------------

def render(dot_path: Path, output_path: Path, fmt: str) -> bool:
    """Render ``dot_path`` to ``output_path`` in ``fmt`` (svg/png) using dot."""
    if not has_command("dot"):
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = run_command(
        ["dot", f"-T{fmt}", str(dot_path), "-o", str(output_path)],
        capture=True,
    )
    return result.ok and output_path.exists()


def generate_map(
    inventory: Inventory,
    maps_dir: Path,
    title: str = "PyNmap",
    style: str = "enhanced",
) -> dict[str, Optional[Path]]:
    """Write network-map.dot and render SVG/PNG when Graphviz is available.

    ``style`` selects the builder: ``"enhanced"`` (default) for the rich
    HTML-table map, or ``"standard"`` for the compact text-label map. Any other
    value falls back to the standard builder.
    """
    maps_dir.mkdir(parents=True, exist_ok=True)
    dot_path = maps_dir / "network-map.dot"
    svg_path = maps_dir / "network-map.svg"
    png_path = maps_dir / "network-map.png"
    if style == "enhanced":
        dot_text = build_enhanced_dot(inventory, title)
    else:
        dot_text = build_dot(inventory, title)
    dot_path.write_text(dot_text, encoding="utf-8")
    results: dict[str, Optional[Path]] = {"dot": dot_path, "svg": None, "png": None}
    if render(dot_path, svg_path, "svg"):
        results["svg"] = svg_path
    if render(dot_path, png_path, "png"):
        results["png"] = png_path
    return results
