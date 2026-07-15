"""The network map integrates every kind of data a scan may collect."""

from datetime import datetime, timezone

import pytest

from pynmap.models import (
    Inventory,
    HostRecord,
    OSMatch,
    PortRecord,
    TraceHop,
)
from pynmap.reporting import graphviz as gv


def _rich_inventory() -> Inventory:
    inv = Inventory(generated_at=datetime.now(timezone.utc))
    host = HostRecord(
        address="10.0.0.5",
        status="up",
        hostnames=["router.local"],
        mac_address="AA:BB:CC:DD:EE:FF",
        mac_vendor="AcmeNet",
        os_matches=[OSMatch(name="Linux 5.4", accuracy=97, vendor="Linux")],
        ports=[
            PortRecord(
                protocol="tcp", portid=80, state="open",
                service_name="http", product="nginx", version="1.18.0",
                scripts={"http-title": "Welcome"},
            ),
            PortRecord(
                protocol="udp", portid=53, state="open",
                service_name="domain", product="dnsmasq", version="2.80",
            ),
            PortRecord(protocol="tcp", portid=23, state="filtered"),
        ],
        trace=[
            TraceHop(ttl=1, ipaddr="10.0.0.1", rtt="0.42", host="gw.local"),
            TraceHop(ttl=2, ipaddr="10.0.0.5", rtt="0.88"),
        ],
    )
    inv.upsert(host)
    return inv


@pytest.mark.parametrize("builder", [gv.build_dot, gv.build_enhanced_dot])
def test_map_includes_all_collected_data(builder):
    dot = builder(_rich_inventory(), title="Demo")
    for needle in (
        "10.0.0.5",        # address
        "router.local",    # hostname
        "Linux 5.4",       # OS guess
        "AcmeNet",         # MAC vendor
        "nginx",           # TCP service product
        "dnsmasq",         # UDP service product
        "0.42",            # traceroute RTT
        "10.0.0.1",        # traceroute hop
    ):
        assert needle in dot, f"{needle!r} missing from {builder.__name__} output"


def test_enhanced_map_reports_scan_coverage_and_nse():
    dot = gv.build_enhanced_dot(_rich_inventory(), title="Demo")
    assert "Scan coverage" in dot
    assert "NSE" in dot  # script id surfaced on the port row
    assert "Legend" in dot


def test_map_omits_absent_data_gracefully():
    # A bare discovery-only host (no OS, ports, MAC, or trace) still renders.
    inv = Inventory(generated_at=datetime.now(timezone.utc))
    inv.upsert(HostRecord(address="192.168.1.9", status="up"))
    for builder in (gv.build_dot, gv.build_enhanced_dot):
        dot = builder(inv, title="Bare")
        assert "192.168.1.9" in dot
        assert dot.strip().endswith("}")
        assert "AcmeNet" not in dot


def test_generate_map_selects_builder(tmp_path):
    inv = _rich_inventory()
    std = gv.generate_map(inv, tmp_path / "std", style="standard")
    enh = gv.generate_map(inv, tmp_path / "enh", style="enhanced")
    assert std["dot"].read_text(encoding="utf-8").count("TABLE") == 0
    assert "TABLE" in enh["dot"].read_text(encoding="utf-8")
