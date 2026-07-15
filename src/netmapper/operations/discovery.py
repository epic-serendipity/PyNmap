"""Host discovery operation."""

from __future__ import annotations

from typing import Optional

from .base import Operation, ScanContext


class DiscoveryOperation(Operation):
    id = "discovery"
    display_name = "Host discovery"
    description = "Ping/ARP sweep to find live hosts before port scanning."
    dependencies = ()
    outputs = ("discovery/discovery.xml",)
    becomes_stale = True
    rerun_on_update = True
    requires_root = False

    def build_command(self, ctx: ScanContext) -> Optional[list[str]]:
        targets_file = ctx.project.targets_normalized
        output_stem = ctx.project.discovery_dir / "discovery"
        return [
            "nmap",
            "-sn",
            "-PE",
            "-PP",
            "-PS22,80,135,139,443,445,3389,5985,8080,8443",
            "-PA80,443,445,3389",
            "-PU53,161",
            "--reason",
            ctx.timing_flag(),
            "-iL",
            str(targets_file),
            "-oA",
            str(output_stem),
        ]
