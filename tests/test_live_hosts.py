"""Tests for live-host extraction from discovery output."""

import textwrap

from pynmap.engine import extract_live_hosts
from pynmap.paths import ProjectPaths


GNMAP = textwrap.dedent(
    """\
    # Nmap 7.94 scan initiated as: nmap -sn -oA discovery -iL targets.txt
    Host: 10.10.20.9 (web01.example.com)\tStatus: Up
    Host: 10.10.20.17 ()\tStatus: Down
    Host: 10.10.20.2 ()\tStatus: Up
    Host: 10.10.20.10 (db01.example.com)\tStatus: Up
    # Nmap done at ...
    """
)

DISCOVERY_XML = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
      <host>
        <status state="up" reason="echo-reply"/>
        <address addr="192.168.1.5" addrtype="ipv4"/>
      </host>
      <host>
        <status state="down" reason="no-response"/>
        <address addr="192.168.1.6" addrtype="ipv4"/>
      </host>
    </nmaprun>
    """
)


def _project(tmp_path) -> ProjectPaths:
    project = ProjectPaths(tmp_path)
    project.create_skeleton()
    return project


def test_extract_live_hosts_from_gnmap_only_up(tmp_path):
    project = _project(tmp_path)
    (project.discovery_dir / "discovery.gnmap").write_text(GNMAP, encoding="utf-8")

    count = extract_live_hosts(project)

    assert count == 3
    # Only "Status: Up" hosts, version-sorted and unique (Down host excluded).
    assert project.live_hosts.read_text().splitlines() == [
        "10.10.20.2",
        "10.10.20.9",
        "10.10.20.10",
    ]


def test_extract_live_hosts_dedupes(tmp_path):
    project = _project(tmp_path)
    dup = GNMAP + "Host: 10.10.20.9 ()\tStatus: Up\n"
    (project.discovery_dir / "discovery.gnmap").write_text(dup, encoding="utf-8")

    assert extract_live_hosts(project) == 3


def test_extract_live_hosts_prefers_gnmap_over_xml(tmp_path):
    project = _project(tmp_path)
    (project.discovery_dir / "discovery.gnmap").write_text(GNMAP, encoding="utf-8")
    (project.discovery_dir / "discovery.xml").write_text(DISCOVERY_XML, encoding="utf-8")

    extract_live_hosts(project)

    hosts = project.live_hosts.read_text().split()
    assert "192.168.1.5" not in hosts
    assert "10.10.20.9" in hosts


def test_extract_live_hosts_falls_back_to_xml(tmp_path):
    project = _project(tmp_path)
    (project.discovery_dir / "discovery.xml").write_text(DISCOVERY_XML, encoding="utf-8")

    count = extract_live_hosts(project)

    assert count == 1
    assert project.live_hosts.read_text().split() == ["192.168.1.5"]


def test_extract_live_hosts_falls_back_to_targets(tmp_path):
    project = _project(tmp_path)
    project.targets_normalized.write_text("10.0.0.1\n10.0.0.2\n", encoding="utf-8")

    count = extract_live_hosts(project)

    assert count == 2
    assert project.live_hosts.read_text().split() == ["10.0.0.1", "10.0.0.2"]
