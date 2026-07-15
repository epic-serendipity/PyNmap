"""Predefined scan profiles (curated sets of operations)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    description: str
    operations: tuple[str, ...]


RECOMMENDED = Profile(
    id="recommended",
    name="Recommended",
    description="Balanced coverage for most engagements (no full TCP scan).",
    operations=(
        "discovery",
        "tcp_top_1000",
        "service_detection",
        "os_detection",
        "traceroute",
        "udp_top_50",
        "inventory",
        "html_report",
        "network_map",
    ),
)

FAST = Profile(
    id="fast",
    name="Fast",
    description="Quick sweep with light service detection.",
    operations=(
        "discovery",
        "tcp_top_1000",
        "traceroute",
        "inventory",
        "network_map",
    ),
)

COMPREHENSIVE = Profile(
    id="comprehensive",
    name="Comprehensive",
    description="Deep coverage including a full TCP scan (slow, noisy).",
    operations=(
        "discovery",
        "tcp_full",
        "service_detection",
        "os_detection",
        "traceroute",
        "udp_top_50",
        "inventory",
        "html_report",
        "network_map",
    ),
)

PASSIVE = Profile(
    id="passive",
    name="Passive reporting only",
    description="Regenerate inventory, reports and map from existing XML only.",
    operations=(
        "inventory",
        "html_report",
        "network_map",
    ),
)


PROFILES: dict[str, Profile] = {
    p.id: p for p in (RECOMMENDED, FAST, COMPREHENSIVE, PASSIVE)
}


def get_profile(profile_id: str) -> Profile:
    return PROFILES[profile_id]


def all_profiles() -> list[Profile]:
    return list(PROFILES.values())
