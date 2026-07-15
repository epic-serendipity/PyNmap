"""User configuration stored at ``~/.config/pynmap/config.json``."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

from . import SCHEMA_VERSION
from . import paths


DEFAULT_RECOMMENDED_OPERATIONS = [
    "discovery",
    "tcp_top_1000",
    "service_detection",
    "os_detection",
    "traceroute",
    "udp_top_50",
    "inventory",
    "html_report",
    "network_map",
]


@dataclass
class Config:
    schema_version: int = SCHEMA_VERSION
    last_output_directory: str | None = None
    last_selected_operations: list[str] = field(
        default_factory=lambda: list(DEFAULT_RECOMMENDED_OPERATIONS)
    )
    default_timing: str = "T4"
    open_results_after_scan: bool = True
    wsl_browser_command: str = "explorer.exe"
    #: Show the ASCII spinner and spacebar progress report during scans.
    show_progress: bool = True
    #: Network-map style: "enhanced" (rich HTML-table map with per-host port
    #: tables, OS/MAC/NSE details, subnet grouping, legend and coverage node)
    #: or "standard" (compact text-label boxes). Both integrate all data the
    #: scan collected.
    map_style: str = "enhanced"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


def load_config() -> Config:
    path = paths.config_file()
    if not path.exists():
        return Config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return Config()
    return Config.from_dict(data)


def save_config(config: Config) -> None:
    paths.ensure_user_dirs()
    path = paths.config_file()
    path.write_text(
        json.dumps(config.to_dict(), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def reset_operations_to_defaults(config: Config) -> Config:
    config.last_selected_operations = list(DEFAULT_RECOMMENDED_OPERATIONS)
    return config
