"""Traceroute operation."""

from __future__ import annotations

from typing import Optional

from .base import Operation, ScanContext


class TracerouteOperation(Operation):
    id = "traceroute"
    display_name = "Traceroute"
    description = "Record network paths (hops) to each live host."
    dependencies = ("discovery",)
    outputs = ("traceroute/traceroute.xml",)
    order = 60
    becomes_stale = True
    rerun_on_update = True
    requires_root = True  # --traceroute uses raw packets
    uses_live_hosts = True

    def build_command(self, ctx: ScanContext) -> Optional[list[str]]:
        live_hosts = ctx.project.live_hosts
        output_stem = ctx.project.root / "traceroute" / "traceroute"
        output_stem.parent.mkdir(parents=True, exist_ok=True)
        return [
            "nmap",
            "-sn",
            "--traceroute",
            "--reason",
            ctx.timing_flag(),
            "-iL",
            str(live_hosts),
            "-oA",
            str(output_stem),
        ]
