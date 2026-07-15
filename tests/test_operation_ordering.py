"""Ordering guarantees: data-collection scans run before derived outputs, and
the network map is generated last."""

from pynmap.operations import REGISTRY, resolve_dependencies
from pynmap.operations.base import topo_sort
from pynmap.profiles import RECOMMENDED, COMPREHENSIVE


def _order(selected):
    resolved, _added = resolve_dependencies(list(selected), REGISTRY)
    return resolved


def test_network_map_is_last_and_reports_follow_scans():
    resolved = _order(RECOMMENDED.operations)
    # The graphic is the very last thing produced.
    assert resolved[-1] == "network_map"
    # Derived reporting runs after every real scan operation.
    scan_ops = {
        "discovery", "tcp_top_1000", "tcp_full", "udp_top_50",
        "os_detection", "traceroute",
    }
    last_scan = max(i for i, op in enumerate(resolved) if op in scan_ops)
    for derived in ("inventory", "html_report", "network_map"):
        assert resolved.index(derived) > last_scan


def test_inventory_before_html_before_map():
    resolved = _order(RECOMMENDED.operations)
    assert resolved.index("inventory") < resolved.index("html_report")
    assert resolved.index("html_report") < resolved.index("network_map")


def test_comprehensive_orders_full_tcp_before_reporting():
    resolved = _order(COMPREHENSIVE.operations)
    assert resolved.index("tcp_full") < resolved.index("inventory")
    assert resolved.index("udp_top_50") < resolved.index("network_map")
    assert resolved[-1] == "network_map"


def test_dependencies_always_precede_dependents():
    resolved = _order(RECOMMENDED.operations)
    seen: set[str] = set()
    for op_id in resolved:
        for dep in REGISTRY[op_id].dependencies:
            if dep in resolved:
                assert dep in seen, f"{dep} must precede {op_id}"
        seen.add(op_id)


def test_map_does_not_pull_in_unrelated_scans():
    # Requesting only the map adds its genuine prerequisites (discovery,
    # inventory, traceroute, tcp_top_1000) but never OS/UDP/service scans.
    resolved, added = resolve_dependencies(["network_map"], REGISTRY)
    assert "os_detection" not in resolved
    assert "udp_top_50" not in resolved
    assert "service_detection" not in resolved
    assert resolved[-1] == "network_map"


def test_input_order_does_not_change_result():
    # Whatever order the caller lists operations in, reporting still runs last.
    forward = _order(RECOMMENDED.operations)
    reversed_sel = _order(list(reversed(RECOMMENDED.operations)))
    assert forward[-1] == reversed_sel[-1] == "network_map"
    assert reversed_sel.index("inventory") < reversed_sel.index("network_map")
