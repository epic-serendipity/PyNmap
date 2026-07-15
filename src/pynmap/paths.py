"""Filesystem locations used by PyNmap.

This module centralises the XDG-style directories used for configuration and
the global registry, plus the canonical layout of a generated scan project.
Keeping every path in one place makes it easy to reason about where PyNmap
reads and writes data, and simplifies testing (the base directories can be
overridden through environment variables).
"""

from __future__ import annotations

import os
from pathlib import Path

from . import TOOL_NAME

# Environment variables that let tests (or power users) relocate PyNmap's
# state without touching the real user directories.
ENV_CONFIG_HOME = "PYNMAP_CONFIG_HOME"
ENV_DATA_HOME = "PYNMAP_DATA_HOME"


def _xdg_home(env_var: str, default_subdir: str) -> Path:
    override = os.environ.get(env_var)
    if override:
        return Path(override).expanduser()
    base = os.environ.get(default_subdir[0])
    if base:
        return Path(base).expanduser() / TOOL_NAME
    return Path(default_subdir[1]).expanduser() / TOOL_NAME


def config_dir() -> Path:
    """Directory that holds ``config.json`` (``~/.config/pynmap``)."""
    override = os.environ.get(ENV_CONFIG_HOME)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / TOOL_NAME


def data_dir() -> Path:
    """Directory that holds ``scans.db`` (``~/.local/share/pynmap``)."""
    override = os.environ.get(ENV_DATA_HOME)
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / TOOL_NAME


def config_file() -> Path:
    return config_dir() / "config.json"


def registry_file() -> Path:
    return data_dir() / "scans.db"


def ensure_user_dirs() -> None:
    config_dir().mkdir(parents=True, exist_ok=True)
    data_dir().mkdir(parents=True, exist_ok=True)


# --- Per-project scan directory layout -------------------------------------

MANIFEST_NAME = "manifest.json"


class ProjectPaths:
    """Resolve the canonical layout of a single scan project directory."""

    def __init__(self, root: os.PathLike[str] | str):
        self.root = Path(root)

    # top-level files
    @property
    def manifest(self) -> Path:
        return self.root / MANIFEST_NAME

    # input/
    @property
    def input_dir(self) -> Path:
        return self.root / "input"

    @property
    def targets_original(self) -> Path:
        return self.input_dir / "targets-original.txt"

    @property
    def targets_normalized(self) -> Path:
        return self.input_dir / "targets-normalized.txt"

    @property
    def live_hosts(self) -> Path:
        return self.input_dir / "live-hosts.txt"

    # protocol output dirs (latest canonical output)
    @property
    def discovery_dir(self) -> Path:
        return self.root / "discovery"

    @property
    def tcp_dir(self) -> Path:
        return self.root / "tcp"

    @property
    def udp_dir(self) -> Path:
        return self.root / "udp"

    # derived data
    @property
    def inventory_dir(self) -> Path:
        return self.root / "inventory"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def maps_dir(self) -> Path:
        return self.root / "maps"

    @property
    def changes_dir(self) -> Path:
        return self.root / "changes"

    @property
    def changes_history_dir(self) -> Path:
        return self.changes_dir / "history"

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def log_file(self) -> Path:
        return self.logs_dir / "pynmap.log"

    def run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def create_skeleton(self) -> None:
        """Create the standard directory tree for a fresh project."""
        for directory in (
            self.input_dir,
            self.discovery_dir,
            self.tcp_dir,
            self.udp_dir,
            self.inventory_dir,
            self.reports_dir,
            self.maps_dir,
            self.changes_dir,
            self.changes_history_dir,
            self.runs_dir,
            self.logs_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
