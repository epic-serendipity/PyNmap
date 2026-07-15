"""UDP scanning operation."""

from __future__ import annotations

from typing import Optional

from .base import Operation, ScanContext


class UdpTop50Operation(Operation):
    id = "udp_top_50"
    display_name = "Common UDP ports"
    description = "UDP scan of the top 50 UDP ports on live hosts."
    dependencies = ("discovery",)
    outputs = ("udp/top-50/udp-top-50.xml",)
    order = 40
    becomes_stale = True
    rerun_on_update = True
    requires_root = True  # UDP scan needs raw sockets
    uses_live_hosts = True

    def build_command(self, ctx: ScanContext) -> Optional[list[str]]:
        live_hosts = ctx.project.live_hosts
        output_stem = ctx.project.udp_dir / "top-50" / "udp-top-50"
        output_stem.parent.mkdir(parents=True, exist_ok=True)
        return [
            "nmap",
            "-sU",
            "--top-ports",
            "50",
            "--reason",
            ctx.timing_flag(),
            "-iL",
            str(live_hosts),
            "-oA",
            str(output_stem),
        ]
