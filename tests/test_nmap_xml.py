"""Tests for the Nmap XML parser and inventory building."""

import textwrap

import pytest

from netmapper.parsers import nmap_xml


SAMPLE_XML = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
      <host>
        <status state="up" reason="echo-reply"/>
        <address addr="10.10.20.9" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme"/>
        <hostnames>
          <hostname name="web01.example.com" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.57">
              <cpe>cpe:/a:apache:http_server:2.4.57</cpe>
            </service>
          </port>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="9.0"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 5.x" accuracy="95">
            <osclass vendor="Linux" osfamily="Linux" osgen="5.X"/>
          </osmatch>
        </os>
        <trace>
          <hop ttl="1" ipaddr="10.10.0.254" rtt="1.2"/>
          <hop ttl="2" ipaddr="10.10.20.9" rtt="2.4"/>
        </trace>
      </host>
      <host>
        <status state="down" reason="no-response"/>
        <address addr="10.10.20.17" addrtype="ipv4"/>
      </host>
    </nmaprun>
    """
)

NON_NMAP_XML = "<?xml version='1.0'?><rootnode><child/></rootnode>"


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_is_nmap_xml_true(tmp_path):
    path = _write(tmp_path, "scan.xml", SAMPLE_XML)
    assert nmap_xml.is_nmap_xml(path)


def test_is_nmap_xml_false_for_non_nmap(tmp_path):
    path = _write(tmp_path, "other.xml", NON_NMAP_XML)
    assert not nmap_xml.is_nmap_xml(path)


def test_parse_string_returns_hosts():
    hosts = nmap_xml.parse_string(SAMPLE_XML)
    assert len(hosts) == 2


def test_parse_host_details():
    hosts = nmap_xml.parse_string(SAMPLE_XML)
    web = next(h for h in hosts if h.address == "10.10.20.9")
    assert web.status == "up"
    assert web.hostnames == ["web01.example.com"]
    assert web.mac_address == "00:11:22:33:44:55"
    assert web.mac_vendor == "Acme"
    assert {p.key for p in web.open_ports()} == {"tcp/80", "tcp/22"}
    http = next(p for p in web.ports if p.portid == 80)
    assert http.product == "Apache httpd"
    assert http.version == "2.4.57"
    assert http.cpe == ["cpe:/a:apache:http_server:2.4.57"]
    best = web.best_os()
    assert best is not None and best.name == "Linux 5.x" and best.accuracy == 95
    assert len(web.trace) == 2


def test_parse_non_nmap_raises():
    with pytest.raises(nmap_xml.NotNmapXMLError):
        nmap_xml.parse_string(NON_NMAP_XML)


def test_build_inventory_skips_non_nmap(tmp_path):
    good = _write(tmp_path, "good.xml", SAMPLE_XML)
    bad = _write(tmp_path, "bad.xml", NON_NMAP_XML)
    inventory = nmap_xml.build_inventory([good, bad, tmp_path / "missing.xml"])
    assert "10.10.20.9" in inventory.hosts
    assert len(inventory.live_hosts()) == 1


def test_inventory_merges_ports(tmp_path):
    xml_udp = SAMPLE_XML.replace(
        '<port protocol="tcp" portid="22">',
        '<port protocol="udp" portid="53">',
    ).replace('name="ssh" product="OpenSSH" version="9.0"',
              'name="domain"')
    good = _write(tmp_path, "tcp.xml", SAMPLE_XML)
    udp = _write(tmp_path, "udp.xml", xml_udp)
    inventory = nmap_xml.build_inventory([good, udp])
    host = inventory.hosts["10.10.20.9"]
    keys = {p.key for p in host.ports}
    assert "tcp/80" in keys
    assert "udp/53" in keys
