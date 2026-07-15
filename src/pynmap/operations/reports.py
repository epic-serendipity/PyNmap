"""Derived operations: host/service inventory and the HTML report."""

from __future__ import annotations

from pathlib import Path

from .base import Operation, OperationRunResult, ScanContext
from ..parsers import nmap_xml
from ..reporting import inventory as inv_report
from ..reporting import html as html_report


def collect_scan_xml(project) -> list[Path]:
    """Return every Nmap XML file under the canonical protocol directories."""
    candidates = [
        project.discovery_dir / "discovery.xml",
        project.tcp_dir / "top-1000" / "tcp-top-1000.xml",
        project.tcp_dir / "full" / "tcp-full.xml",
        project.udp_dir / "top-50" / "udp-top-50.xml",
        project.root / "os" / "os-detection.xml",
        project.root / "traceroute" / "traceroute.xml",
    ]
    return [p for p in candidates if p.exists()]


def build_project_inventory(ctx: ScanContext):
    xml_files = collect_scan_xml(ctx.project)
    return nmap_xml.build_inventory(xml_files)


class InventoryOperation(Operation):
    id = "inventory"
    display_name = "Build host inventory"
    description = "Parse all scan XML into normalised host/service inventories."
    dependencies = ("discovery", "tcp_top_1000")
    outputs = (
        "inventory/hosts.json",
        "inventory/hosts.csv",
        "inventory/services.csv",
        "inventory/routes.json",
    )
    # Derived: run after every data-collection scan so the inventory reflects
    # OS detection, service versions, UDP results, etc. from this run.
    order = 80
    becomes_stale = True
    rerun_on_update = True
    requires_root = False
    is_derived = True

    def run(self, ctx: ScanContext) -> OperationRunResult:
        inventory = build_project_inventory(ctx)
        inv_report.export_all(inventory, ctx.project.inventory_dir, ctx.manifest.name)
        inv_report.write_summary_txt(
            inventory, ctx.project.reports_dir / "summary.txt", ctx.manifest.name
        )
        return OperationRunResult(
            op_id=self.id,
            status="complete",
            message=f"{len(inventory.live_hosts())} live hosts",
        )


class HtmlReportOperation(Operation):
    id = "html_report"
    display_name = "Generate HTML report"
    description = "Produce an HTML scan report (Nmap stylesheet when available)."
    dependencies = ("tcp_top_1000",)
    outputs = ("reports/scan-report.html",)
    order = 90  # derived: after all scans, before the network map
    becomes_stale = True
    rerun_on_update = True
    requires_root = False
    is_derived = True

    def run(self, ctx: ScanContext) -> OperationRunResult:
        inventory = build_project_inventory(ctx)
        tcp_xml = ctx.project.tcp_dir / "top-1000" / "tcp-top-1000.xml"
        xml_path = tcp_xml if tcp_xml.exists() else None
        output = ctx.project.reports_dir / "scan-report.html"
        html_report.generate_report(inventory, output, xml_path, ctx.manifest.name)
        return OperationRunResult(op_id=self.id, status="complete")
