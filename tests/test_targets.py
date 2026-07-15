"""Tests for target parsing and normalisation."""

from pynmap.parsers.targets import (
    classify_target,
    parse_targets_text,
)


def test_single_ipv4():
    entry = classify_target("10.0.0.1")
    assert entry.kind == "ip"
    assert entry.normalized == "10.0.0.1"
    assert entry.address_count == 1


def test_cidr_counts_addresses():
    entry = classify_target("10.0.0.0/24")
    assert entry.kind == "cidr"
    assert entry.address_count == 256
    assert entry.normalized == "10.0.0.0/24"


def test_cidr_non_strict_host_bits():
    entry = classify_target("10.0.0.5/24")
    assert entry.kind == "cidr"
    assert entry.normalized == "10.0.0.0/24"


def test_octet_range():
    entry = classify_target("10.0.0-3.1-254")
    assert entry.kind == "octet-range"
    assert entry.address_count == 4 * 254


def test_octet_out_of_range_invalid():
    entry = classify_target("10.0.0.999")
    assert entry.kind == "invalid"


def test_hyphen_range_short_form():
    entry = classify_target("10.0.0.1-50")
    assert entry.kind == "range"
    assert entry.address_count == 50


def test_hyphen_range_full_form():
    entry = classify_target("10.0.0.1-10.0.1.0")
    assert entry.kind == "range"
    assert entry.address_count == 256


def test_hostname():
    entry = classify_target("scanme.nmap.org")
    assert entry.kind == "hostname"
    assert entry.normalized == "scanme.nmap.org"
    assert entry.address_count == 0


def test_invalid_garbage():
    entry = classify_target("not a target!!")
    assert entry.kind == "invalid"


def test_parse_and_normalize_dedup_and_sort():
    text = """
    # a comment
    10.0.0.2
    10.0.0.1
    10.0.0.1

    10.0.0.0/24
    """
    target_set = parse_targets_text(text)
    normalized = target_set.normalized_lines()
    # Deduplicated and sorted; CIDR sorts by network head 10.0.0.0
    assert normalized == ["10.0.0.0/24", "10.0.0.1", "10.0.0.2"]


def test_hash_stable_regardless_of_order():
    a = parse_targets_text("10.0.0.1\n10.0.0.2\n")
    b = parse_targets_text("10.0.0.2\n10.0.0.1\n")
    assert a.normalized_lines() == b.normalized_lines()


def test_multiple_targets_per_line():
    target_set = parse_targets_text("10.0.0.1 10.0.0.2 10.0.0.3")
    assert len(target_set.valid_entries) == 3


def test_address_and_network_counts():
    target_set = parse_targets_text("10.0.0.0/30\n192.168.1.5\n")
    assert target_set.network_count() == 1
    assert target_set.address_count() == 4 + 1
