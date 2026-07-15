"""OS detection operation."""

from __future__ import annotations

from typing import Optional

from .base import Operation, ScanContext


class OsDetectionOperation(Operation):
    id = "os_detection"
    display_name = "OS detection"
    description = "TCP/IP stack fingerprinting to guess operating systems."
    dependencies = ("discovery",)
    outputs = ("os/os-detection.xml",)
    becomes_stale = True
    rerun_on_update = True
    requires_root = True  # -O needs raw sockets
    uses_live_hosts = True

    def build_command(self, ctx: ScanContext) -> Optional[list[str]]:
        live_hosts = ctx.project.live_hosts
        output_stem = ctx.project.root / "os" / "os-detection"
        output_stem.parent.mkdir(parents=True, exist_ok=True)
        return [
            "nmap",
            "-O",
            "--osscan-guess",
            "--reason",
            ctx.timing_flag(),
            "-iL",
            str(live_hosts),
            "-oA",
            str(output_stem),
        ]
