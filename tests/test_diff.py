"""Tests for the scan comparison / diff engine."""

from datetime import datetime

from pynmap.comparison.diff import diff_inventories, render_text
from pynmap.models import HostRecord, Inventory, OSMatch, PortRecord, TraceHop


def _host(address, ports=None, hostnames=None, os_name=None, hops=None, status="up"):
    return HostRecord(
        address=address,
        status=status,
        hostnames=hostnames or [],
        os_matches=[OSMatch(name=os_name, accuracy=90)] if os_name else [],
        ports=ports or [],
        trace=[TraceHop(ttl=i + 1, ipaddr=h) for i, h in enumerate(hops or [])],
    )


def _port(protocol, portid, state="open", product=None, version=None, name=None):
    return PortRecord(
        protocol=protocol,
        portid=portid,
        state=state,
        service_name=name,
        product=product,
        version=version,
    )


def _inv(*hosts):
    inv = Inventory(generated_at=datetime.now())
    for host in hosts:
        inv.hosts[host.address] = host
    return inv


def test_host_added_and_removed():
    prev = _inv(_host("10.10.20.17"))
    curr = _inv(_host("10.10.20.41"))
    diff = diff_inventories(prev, curr)
    assert diff.hosts_added == ["10.10.20.41"]
    assert diff.hosts_removed == ["10.10.20.17"]


def test_port_opened_and_closed():
    prev = _inv(_host("10.10.20.12", ports=[_port("tcp", 22)]))
    curr = _inv(_host("10.10.20.12", ports=[_port("tcp", 445)]))
    diff = diff_inventories(prev, curr)
    assert [c.port for c in diff.ports_opened] == ["tcp/445"]
    assert [c.port for c in diff.ports_closed] == ["tcp/22"]


def test_service_changed():
    prev = _inv(_host("10.10.20.9", ports=[
        _port("tcp", 80, product="Apache httpd", version="2.4.57")
    ]))
    curr = _inv(_host("10.10.20.9", ports=[
        _port("tcp", 80, product="nginx", version="1.24.0")
    ]))
    diff = diff_inventories(prev, curr)
    assert len(diff.services_changed) == 1
    change = diff.services_changed[0]
    assert change.before == "Apache httpd 2.4.57"
    assert change.after == "nginx 1.24.0"


def test_hostname_changed():
    prev = _inv(_host("10.10.20.18", hostnames=["WIN-OLD"]))
    curr = _inv(_host("10.10.20.18", hostnames=["DC01"]))
    diff = diff_inventories(prev, curr)
    assert len(diff.hostnames_changed) == 1
    assert diff.hostnames_changed[0].before == "WIN-OLD"
    assert diff.hostnames_changed[0].after == "DC01"


def test_os_changed():
    prev = _inv(_host("10.10.20.22", os_name="Windows 10"))
    curr = _inv(_host("10.10.20.22", os_name="Windows Server 2022"))
    diff = diff_inventories(prev, curr)
    assert len(diff.os_changed) == 1
    assert diff.os_changed[0].after == "Windows Server 2022"


def test_route_added():
    prev = _inv(_host("10.10.20.9", hops=["10.10.20.9"]))
    curr = _inv(_host("10.10.20.9", hops=["10.10.0.254", "10.10.20.9"]))
    diff = diff_inventories(prev, curr)
    assert any(c.hop == "10.10.0.254" for c in diff.routes_added)


def test_empty_diff():
    host = _host("10.10.20.9", ports=[_port("tcp", 80)])
    diff = diff_inventories(_inv(host), _inv(host))
    assert diff.is_empty()
    assert "No changes" in render_text(diff)


def test_render_text_contains_sections():
    prev = _inv(_host("10.10.20.17"))
    curr = _inv(_host("10.10.20.41", ports=[_port("tcp", 445)]))
    text = render_text(diff_inventories(prev, curr))
    assert "Hosts:" in text
    assert "10.10.20.41 appeared" in text
    assert "10.10.20.17 no longer responds" in text
