"""Generate a Graphviz network map (DOT) and render SVG/PNG via ``dot``."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..models import Inventory, HostRecord
from ..runner import has_command, run_command


def _escape(label: str) -> str:
    return label.replace("\\", "\\\\").replace('"', '\\"')


def _host_label(host: HostRecord) -> str:
    lines = [host.address]
    if host.hostnames:
        lines.append(host.hostnames[0])
    best_os = host.best_os()
    if best_os:
        lines.append(best_os.name)
    open_ports = host.open_ports()
    if open_ports:
        shown = ", ".join(p.key for p in open_ports[:6])
        if len(open_ports) > 6:
            shown += f", +{len(open_ports) - 6}"
        lines.append(shown)
    return "\\n".join(_escape(line) for line in lines)


def build_dot(inventory: Inventory, title: str = "NetMapper") -> str:
    """Build a Graphviz DOT document from hosts and traceroute data."""
    out: list[str] = []
    out.append(f'digraph netmapper {{')
    out.append(f'  labelloc="t";')
    out.append(f'  label="{_escape(title)}";')
    out.append('  rankdir=LR;')
    out.append('  node [shape=box, style="rounded,filled", fillcolor="#eef4fb", '
               'fontname="Helvetica"];')
    out.append('  edge [fontname="Helvetica", fontsize=9];')
    out.append('  "scanner" [label="Scanner", shape=oval, fillcolor="#d5f5d5"];')

    hop_nodes: set[str] = set()
    live = inventory.live_hosts()

    for host in live:
        node_id = _escape(host.address)
        out.append(f'  "{node_id}" [label="{_host_label(host)}"];')

    for host in live:
        node_id = _escape(host.address)
        if host.trace:
            prev = "scanner"
            for hop in host.trace:
                hop_addr = hop.ipaddr or f"ttl{hop.ttl}"
                if hop_addr == host.address:
                    out.append(f'  "{prev}" -> "{node_id}";')
                    prev = node_id
                    continue
                hop_id = _escape(hop_addr)
                if hop_id not in hop_nodes and hop_addr != host.address:
                    hop_nodes.add(hop_id)
                    out.append(f'  "{hop_id}" [label="{hop_id}", shape=diamond, '
                               f'fillcolor="#fdf1c7"];')
                out.append(f'  "{prev}" -> "{hop_id}";')
                prev = hop_id
            if prev != node_id:
                out.append(f'  "{prev}" -> "{node_id}";')
        else:
            out.append(f'  "scanner" -> "{node_id}" [style=dashed];')

    out.append('}')
    return "\n".join(out) + "\n"


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
    inventory: Inventory, maps_dir: Path, title: str = "NetMapper"
) -> dict[str, Optional[Path]]:
    """Write network-map.dot and render SVG/PNG when Graphviz is available."""
    maps_dir.mkdir(parents=True, exist_ok=True)
    dot_path = maps_dir / "network-map.dot"
    svg_path = maps_dir / "network-map.svg"
    png_path = maps_dir / "network-map.png"
    dot_path.write_text(build_dot(inventory, title), encoding="utf-8")
    results: dict[str, Optional[Path]] = {"dot": dot_path, "svg": None, "png": None}
    if render(dot_path, svg_path, "svg"):
        results["svg"] = svg_path
    if render(dot_path, png_path, "png"):
        results["png"] = png_path
    return results
