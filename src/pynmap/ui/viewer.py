"""Result viewer: inspect a project's manifest and display its artifacts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from ..config import Config
from ..manifest import Manifest
from ..paths import ProjectPaths

console = Console()


def is_wsl() -> bool:
    """Detect WSL by looking for 'microsoft'/'WSL' in /proc/version."""
    try:
        text = Path("/proc/version").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    lowered = text.lower()
    return "microsoft" in lowered or "wsl" in lowered


def open_external(path: Path, config: Optional[Config] = None) -> bool:
    """Open a file with the platform's default handler (WSL/Linux/mac)."""
    path = Path(path)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        return False
    try:
        if is_wsl():
            browser = (config.wsl_browser_command if config else "explorer.exe")
            win_path = subprocess.run(
                ["wslpath", "-w", str(path)], capture_output=True, text=True
            ).stdout.strip()
            subprocess.Popen([browser, win_path])
            return True
        if os.name == "posix" and _has("xdg-open"):
            subprocess.Popen(["xdg-open", str(path)])
            return True
        if _has("open"):  # macOS
            subprocess.Popen(["open", str(path)])
            return True
    except OSError as exc:
        console.print(f"[red]Could not open {path}: {exc}[/red]")
        return False
    console.print(f"[yellow]No opener available; file is at:[/yellow] {path}")
    return False


def _has(cmd: str) -> bool:
    from shutil import which

    return which(cmd) is not None


def show_text_file(path: Path, use_pager: bool = True) -> None:
    path = Path(path)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    if use_pager and _has("less"):
        try:
            subprocess.run(["less", "-R", str(path)])
            return
        except OSError:
            pass
    with console.pager(styles=True):
        console.print(text)


def summarise_project(manifest: Manifest, project: ProjectPaths) -> Table:
    table = Table(title=f"Project: {manifest.name}", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Project ID", manifest.project_id)
    table.add_row("Path", str(project.root))
    table.add_row("Created", manifest.created_at)
    table.add_row("Updated", manifest.updated_at)
    table.add_row("Profile", manifest.profile or "custom")
    table.add_row("Latest run", manifest.latest_run_id or "-")
    table.add_row(
        "Operations",
        ", ".join(manifest.selected_operations) or "-",
    )
    return table


def artifact_menu(project: ProjectPaths) -> list[tuple[str, Path, str]]:
    """Return available artifacts as (label, path, kind) tuples."""
    items: list[tuple[str, Path, str]] = [
        ("Scan summary", project.reports_dir / "summary.txt", "text"),
        ("Live hosts", project.live_hosts, "text"),
        ("TCP Nmap output", project.tcp_dir / "top-1000" / "tcp-top-1000.nmap", "text"),
        ("UDP Nmap output", project.udp_dir / "top-50" / "udp-top-50.nmap", "text"),
        ("Host inventory", project.inventory_dir / "hosts.csv", "text"),
        ("Service inventory", project.inventory_dir / "services.csv", "text"),
        ("Latest changes", project.changes_dir / "latest-diff.txt", "text"),
        ("Network map SVG", project.maps_dir / "network-map.svg", "external"),
        ("Network map PNG", project.maps_dir / "network-map.png", "external"),
        ("HTML scan report", project.reports_dir / "scan-report.html", "external"),
        ("Project directory", project.root, "dir"),
    ]
    return [(label, path, kind) for label, path, kind in items if path.exists()]
