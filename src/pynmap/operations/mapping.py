"""Derived operation: Graphviz network map generation."""

from __future__ import annotations

from .base import Operation, OperationRunResult, ScanContext
from .reports import build_project_inventory
from ..reporting import graphviz as gv


class NetworkMapOperation(Operation):
    id = "network_map"
    display_name = "Generate network map"
    description = "Render a Graphviz map of hosts and traceroute paths."
    dependencies = ("discovery", "inventory", "traceroute")
    outputs = ("maps/network-map.dot",)
    # Highest order: generating the graphic is the last thing PyNmap does, so
    # the map reflects every piece of data collected during the run.
    order = 100
    becomes_stale = True
    rerun_on_update = True
    requires_root = False
    is_derived = True

    def run(self, ctx: ScanContext) -> OperationRunResult:
        inventory = build_project_inventory(ctx)
        title = ctx.manifest.name or "PyNmap"
        style = getattr(ctx.config, "map_style", "enhanced")
        results = gv.generate_map(inventory, ctx.project.maps_dir, title, style=style)
        rendered = [fmt for fmt, path in results.items() if path is not None]
        message = f"{style} map rendered: " + ", ".join(rendered)
        return OperationRunResult(op_id=self.id, status="complete", message=message)
