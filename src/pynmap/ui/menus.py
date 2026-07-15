"""Interactive main menu and workflow flows built on Rich + InquirerPy."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .. import __version__, config as config_mod, engine, manifest as manifest_mod
from .. import progress, registry
from ..config import Config, DEFAULT_RECOMMENDED_OPERATIONS
from ..operations import REGISTRY, resolve_dependencies
from ..operations.base import OperationRunResult
from ..parsers.targets import parse_targets_text
from ..paths import ProjectPaths
from ..profiles import get_profile
from ..progress import ProgressMonitor
from ..runner import is_root
from . import selections, viewer

console = Console()


class RichObserver(engine.Observer):
    """Surface engine progress through the Rich console.

    Also owns the :class:`ProgressMonitor` for the run so an ASCII spinner
    animates while commands run and a progress report can be printed when the
    user presses the spacebar. All console output is routed through the
    monitor so it never garbles the live spinner line.
    """

    def __init__(self) -> None:
        self._monitor: ProgressMonitor | None = None
        # PyNmap runs as root (``sudo pynmap``), so Nmap commands are launched
        # directly with no per-command ``sudo`` password prompt to contend with;
        # the interactive progress keys are therefore always safe to use.
        self._keys_safe = True

    def run_started(self, op_ids) -> None:
        show = getattr(config_mod.load_config(), "show_progress", True)
        names = [
            (REGISTRY[o].display_name if o in REGISTRY else o) for o in op_ids
        ]
        self._monitor = ProgressMonitor(console, show_progress=show)
        self._monitor.set_plan(names)
        self._monitor.start()
        progress.set_active_monitor(self._monitor)

    def run_finished(self) -> None:
        if self._monitor is not None:
            progress.set_active_monitor(None)
            self._monitor.stop()
            self._monitor = None

    def _emit(self, message: str) -> None:
        if self._monitor is not None:
            self._monitor.print(message)
        else:
            console.print(message)

    def info(self, message: str) -> None:
        self._emit(f"[cyan]i[/cyan] {message}")

    def warning(self, message: str) -> None:
        self._emit(f"[yellow]![/yellow] {message}")

    def operation_start(self, op_id: str, index: int, total: int) -> None:
        op = REGISTRY.get(op_id)
        name = op.display_name if op else op_id
        if self._monitor is not None:
            quiet = bool(op and op.requires_root) and not self._keys_safe
            self._monitor.begin_operation(op_id, name, index, total, quiet=quiet)
        self._emit(f"[bold]({index}/{total})[/bold] Running [green]{name}[/green]...")

    def operation_end(self, result: OperationRunResult) -> None:
        if self._monitor is not None:
            self._monitor.end_operation(result.status)
        colour = {
            "complete": "green",
            "failed": "red",
            "cancelled": "yellow",
            "skipped": "dim",
        }.get(result.status, "white")
        extra = f" - {result.message}" if result.message else ""
        self._emit(f"    [{colour}]{result.status}[/{colour}]{extra}")


def banner() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]PyNmap[/bold cyan] [dim]v{__version__}[/dim]\n"
            "Nmap orchestration, inventory & reporting",
            border_style="cyan",
        )
    )


def main_menu() -> None:
    config = config_mod.load_config()
    _privilege_notice()
    while True:
        banner()
        choice = selections.prompt_select(
            "Main menu",
            [
                ("new", "[1] New scan"),
                ("update", "[2] Update existing scan"),
                ("enhance", "[3] Enhance existing scan"),
                ("view", "[4] View scan results"),
                ("history", "[5] Scan history"),
                ("settings", "[6] Settings"),
                ("exit", "[7] Exit"),
            ],
        )
        try:
            if choice == "new":
                flow_new(config)
            elif choice == "update":
                flow_update(config)
            elif choice == "enhance":
                flow_enhance(config)
            elif choice == "view":
                flow_view(config)
            elif choice == "history":
                flow_history(config)
            elif choice == "settings":
                flow_settings(config)
                config = config_mod.load_config()
            elif choice in ("exit", None):
                console.print("Goodbye.")
                return
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted; returning to menu.[/yellow]")


def _privilege_notice() -> None:
    if is_root():
        console.print("[dim]Running as root; privileged scans enabled.[/dim]")
    else:
        console.print(
            "[yellow]Note:[/yellow] PyNmap needs root for host discovery and the "
            "SYN/UDP/OS/traceroute scans. Re-run with [bold]sudo pynmap[/bold]; "
            "otherwise those scans are skipped."
        )


# --- new scan --------------------------------------------------------------

def flow_new(config: Config) -> None:
    console.rule("New scan")
    targets_file = selections.prompt_path("Targets file (one target per line):")
    targets_path = Path(targets_file).expanduser()
    if not targets_path.exists():
        console.print(f"[red]Targets file not found:[/red] {targets_path}")
        return
    targets_text = targets_path.read_text(encoding="utf-8")
    target_set = parse_targets_text(targets_text)
    if not target_set.valid_entries:
        console.print("[red]No valid targets found.[/red]")
        return
    if target_set.invalid_entries:
        console.print(
            f"[yellow]{len(target_set.invalid_entries)} invalid target line(s) ignored.[/yellow]"
        )

    default_out = config.last_output_directory or str(Path.cwd())
    output_parent = selections.prompt_path(
        "Output parent folder:", default=default_out, only_directories=True
    )
    name = selections.prompt_text("Scan name:", default="NetworkScan")

    profile_id = selections.prompt_profile()
    if profile_id:
        selected = list(get_profile(profile_id).operations)
    else:
        selected = selections.prompt_operations(config.last_selected_operations)

    resolved, added = resolve_dependencies(selected, REGISTRY)
    if added:
        console.print(
            f"[yellow]Adding required prerequisites:[/yellow] {', '.join(added)}"
        )
    selected = resolved

    _show_scope(target_set, selected, Path(output_parent).expanduser() / name)
    if not selections.prompt_confirm("Proceed with scan?", default=True):
        console.print("Cancelled.")
        return

    project, manifest, outcome = engine.new_scan(
        name=name,
        output_parent=output_parent,
        targets_text=targets_text,
        selected_operations=selected,
        profile=profile_id,
        config=config,
        observer=RichObserver(),
    )
    _post_run_summary(project, manifest, config)


def _show_scope(target_set, selected, output_path: Path) -> None:
    table = Table(title="Estimated scope", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Networks", str(target_set.network_count()))
    table.add_row("IPv4 addresses", f"{target_set.address_count():,}")
    table.add_row("Operations", str(len([s for s in selected if not REGISTRY[s].is_modifier])))
    table.add_row("Full TCP scan", "Yes" if "tcp_full" in selected else "No")
    table.add_row("UDP scan", "Top 50" if "udp_top_50" in selected else "No")
    table.add_row("Output", str(output_path))
    console.print(table)
    if target_set.address_count() > 65536:
        console.print(
            "[bold yellow]Warning:[/bold yellow] this scans a very large address space."
        )


def _post_run_summary(project: ProjectPaths, manifest, config: Config) -> None:
    console.rule("Summary")
    console.print(viewer.summarise_project(manifest, project))
    summary = project.reports_dir / "summary.txt"
    if summary.exists():
        console.print(summary.read_text(encoding="utf-8"))
    if config.open_results_after_scan:
        report = project.reports_dir / "scan-report.html"
        if report.exists():
            viewer.open_external(report, config)


# --- update ----------------------------------------------------------------

def _prompt_project_path(config: Config, message: str) -> Optional[ProjectPaths]:
    default = config.last_output_directory or str(Path.cwd())
    raw = selections.prompt_path(message, default=default, only_directories=True)
    root = Path(raw).expanduser()
    if not manifest_mod.is_valid_project(root):
        console.print(f"[red]Not a valid PyNmap project:[/red] {root}")
        return None
    return ProjectPaths(root)


def flow_update(config: Config) -> None:
    console.rule("Update existing scan")
    project = _prompt_project_path(config, "Project directory to update:")
    if project is None:
        return
    manifest, outcome, diff = engine.update_scan(
        project.root, config=config, observer=RichObserver()
    )
    console.rule("Changes")
    from ..comparison.diff import render_text

    console.print(render_text(diff))
    _post_run_summary(project, manifest, config)


# --- enhance ---------------------------------------------------------------

def flow_enhance(config: Config) -> None:
    console.rule("Enhance existing scan")
    project = _prompt_project_path(config, "Project directory to enhance:")
    if project is None:
        return
    manifest = manifest_mod.load_manifest(project.root)

    completed = [op_id for op_id in manifest.selected_operations if manifest.is_complete(op_id)]
    console.print("[bold]Previously completed:[/bold]")
    for op_id in completed:
        op = REGISTRY.get(op_id)
        console.print(f"  - {op.display_name if op else op_id}")

    available = engine.available_enhancements(manifest)
    if not available:
        console.print("[green]Nothing left to enhance; all operations complete.[/green]")
        return
    chosen = selections.prompt_operations([])
    chosen = [c for c in chosen if c in available or c not in completed]
    if not chosen:
        console.print("No operations selected.")
        return
    manifest, outcome = engine.enhance_scan(
        project.root, chosen, config=config, observer=RichObserver()
    )
    _post_run_summary(project, manifest, config)


# --- view ------------------------------------------------------------------

def flow_view(config: Config) -> None:
    console.rule("View scan results")
    project = _prompt_project_path(config, "Project directory to view:")
    if project is None:
        return
    manifest = manifest_mod.load_manifest(project.root)
    console.print(viewer.summarise_project(manifest, project))

    while True:
        artifacts = viewer.artifact_menu(project)
        if not artifacts:
            console.print("[yellow]No artifacts available yet.[/yellow]")
            return
        options = [(str(i), label) for i, (label, _p, _k) in enumerate(artifacts)]
        options.append(("back", "Back to menu"))
        choice = selections.prompt_select("Select result to display:", options)
        if choice in ("back", None):
            return
        label, path, kind = artifacts[int(choice)]
        if kind == "text":
            viewer.show_text_file(path)
        elif kind == "external":
            viewer.open_external(path, config)
        elif kind == "dir":
            viewer.open_external(path, config)


# --- history ---------------------------------------------------------------

def flow_history(config: Config) -> None:
    console.rule("Scan history")
    records = registry.refresh_missing_flags()
    if not records:
        console.print("[yellow]No scans registered yet.[/yellow]")
        return
    table = Table(show_header=True)
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Last Updated")
    table.add_column("Path")
    table.add_column("Status")
    for rec in records:
        status = "[red]missing[/red]" if rec.missing else (rec.last_run_status or "-")
        table.add_row(
            rec.project_id[:8], rec.name, rec.updated_at[:16], rec.path, status
        )
    console.print(table)

    missing = [r for r in records if r.missing]
    if missing and selections.prompt_confirm(
        "Relocate a missing scan?", default=False
    ):
        options = [(r.project_id, f"{r.name} ({r.path})") for r in missing]
        pid = selections.prompt_select("Which scan?", options)
        if pid:
            new_path = selections.prompt_path("New path:", only_directories=True)
            if manifest_mod.is_valid_project(Path(new_path).expanduser()):
                registry.relocate(pid, new_path)
                console.print("[green]Relocated.[/green]")
            else:
                console.print("[red]Not a valid project at that path.[/red]")


# --- settings --------------------------------------------------------------

def flow_settings(config: Config) -> None:
    console.rule("Settings")
    table = Table(show_header=False)
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_row("Last output directory", config.last_output_directory or "-")
    table.add_row("Default timing", config.default_timing)
    table.add_row("Open results after scan", str(config.open_results_after_scan))
    table.add_row("Show scan progress spinner", str(config.show_progress))
    table.add_row("WSL browser command", config.wsl_browser_command)
    table.add_row("Last selected operations", ", ".join(config.last_selected_operations))
    console.print(table)

    choice = selections.prompt_select(
        "Change setting",
        [
            ("timing", "Default Nmap timing (T0-T5)"),
            ("open", "Toggle open-results-after-scan"),
            ("progress", "Toggle scan progress spinner"),
            ("browser", "WSL browser command"),
            ("reset", "Reset operations to recommended defaults"),
            ("back", "Back"),
        ],
    )
    if choice == "timing":
        config.default_timing = selections.prompt_text(
            "Timing template:", default=config.default_timing
        )
    elif choice == "open":
        config.open_results_after_scan = not config.open_results_after_scan
    elif choice == "progress":
        config.show_progress = not config.show_progress
    elif choice == "browser":
        config.wsl_browser_command = selections.prompt_text(
            "WSL browser command:", default=config.wsl_browser_command
        )
    elif choice == "reset":
        config.last_selected_operations = list(DEFAULT_RECOMMENDED_OPERATIONS)
        console.print("[green]Reset to recommended defaults.[/green]")
    elif choice in ("back", None):
        return
    config_mod.save_config(config)
    console.print("[green]Saved.[/green]")
