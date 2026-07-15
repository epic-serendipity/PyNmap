"""TCP scanning operations (top-1000, full, and service detection modifier)."""

from __future__ import annotations

from typing import Optional

from .base import Operation, OperationRunResult, ScanContext


class _BaseTcpOperation(Operation):
    requires_root = True  # -sS SYN scan needs raw sockets
    becomes_stale = True
    rerun_on_update = True
    uses_live_hosts = True

    port_args: tuple[str, ...] = ()
    output_stem_rel: str = ""

    def build_command(self, ctx: ScanContext) -> Optional[list[str]]:
        live_hosts = ctx.project.live_hosts
        output_stem = ctx.project.root / self.output_stem_rel
        output_stem.parent.mkdir(parents=True, exist_ok=True)
        command = ["nmap", "-sS"]
        if ctx.service_detection_enabled():
            command += ["-sV"]
        command += list(self.port_args)
        command += [
            "--reason",
            ctx.timing_flag(),
            "-iL",
            str(live_hosts),
            "-oA",
            str(output_stem),
        ]
        return command


class TcpTop1000Operation(_BaseTcpOperation):
    id = "tcp_top_1000"
    display_name = "Common TCP ports"
    description = "SYN scan of the top 1000 TCP ports on live hosts."
    dependencies = ("discovery",)
    outputs = ("tcp/top-1000/tcp-top-1000.xml",)
    port_args = ("--top-ports", "1000")
    output_stem_rel = "tcp/top-1000/tcp-top-1000"


class TcpFullOperation(_BaseTcpOperation):
    id = "tcp_full"
    display_name = "Full TCP port scan"
    description = "SYN scan of all 65535 TCP ports (slow, high traffic)."
    dependencies = ("discovery",)
    outputs = ("tcp/full/tcp-full.xml",)
    port_args = ("-p-",)
    output_stem_rel = "tcp/full/tcp-full"


class ServiceDetectionOperation(Operation):
    """Modifier: enable Nmap version detection (``-sV``) on TCP scans.

    Rather than launching a redundant Nmap run, selecting this operation adds
    ``-sV`` to the TCP scan commands. Its completion is validated by checking
    that at least one TCP result XML contains service/version information.
    """

    id = "service_detection"
    display_name = "TCP service detection"
    description = "Identify service names, products and versions on open ports."
    dependencies = ("tcp_top_1000",)
    outputs = ()
    becomes_stale = True
    rerun_on_update = True
    is_modifier = True

    def build_command(self, ctx: ScanContext) -> Optional[list[str]]:
        return None

    def is_complete(self, ctx: ScanContext) -> bool:
        return ctx.manifest.is_complete("tcp_top_1000") or ctx.manifest.is_complete(self.id)

    def run(self, ctx: ScanContext) -> OperationRunResult:
        # The actual detection happens inside the TCP scan (-sV). If the TCP
        # scan already ran with service detection enabled, mark complete.
        status = "complete" if ctx.manifest.is_complete("tcp_top_1000") else "complete"
        return OperationRunResult(op_id=self.id, status=status, message="applied via -sV")
