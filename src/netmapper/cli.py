"""Typer-based command line interface.

Running ``netmapper`` with no arguments opens the interactive menu (handled in
:mod:`netmapper.main`). The subcommands below provide scriptable access to the
same workflows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from . import config as config_mod
from . import engine, manifest as manifest_mod
from . import registry
from .operations import REGISTRY, resolve_dependencies
from .paths import ProjectPaths
from .profiles import get_profile, PROFILES

app = typer.Typer(
    add_completion=False,
    help="NetMapper: orchestrate Nmap scans, build inventories, and report.",
    no_args_is_help=False,
)


@app.command()
def new(
    targets: Optional[Path] = typer.Option(
        None, "--targets", "-t", help="Targets file (one target per line)."
    ),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Scan name."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output parent directory."
    ),
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p", help=f"Scan profile ({', '.join(PROFILES)})."
    ),
    operations: Optional[str] = typer.Option(
        None, "--operations", help="Comma-separated operation ids."
    ),
) -> None:
    """Create and run a new scan. Falls back to interactive prompts if needed."""
    if not (targets and name and output):
        from .ui.menus import flow_new

        flow_new(config_mod.load_config())
        raise typer.Exit()

    targets_path = Path(targets).expanduser()
    if not targets_path.exists():
        typer.echo(f"Targets file not found: {targets_path}", err=True)
        raise typer.Exit(code=1)

    if profile:
        if profile not in PROFILES:
            typer.echo(f"Unknown profile: {profile}", err=True)
            raise typer.Exit(code=1)
        selected = list(get_profile(profile).operations)
    elif operations:
        selected = [op.strip() for op in operations.split(",") if op.strip()]
    else:
        selected = list(config_mod.load_config().last_selected_operations)

    resolved, added = resolve_dependencies(selected, REGISTRY)
    if added:
        typer.echo(f"Added prerequisites: {', '.join(added)}")

    from .ui.menus import RichObserver, _post_run_summary

    config = config_mod.load_config()
    project, mf, outcome = engine.new_scan(
        name=name,
        output_parent=output,
        targets_text=targets_path.read_text(encoding="utf-8"),
        selected_operations=resolved,
        profile=profile,
        config=config,
        observer=RichObserver(),
    )
    _post_run_summary(project, mf, config)


@app.command()
def update(
    path: Path = typer.Argument(..., help="Path to an existing scan project."),
) -> None:
    """Rerun mutable operations and generate a change report."""
    root = Path(path).expanduser()
    if not manifest_mod.is_valid_project(root):
        typer.echo(f"Not a valid NetMapper project: {root}", err=True)
        raise typer.Exit(code=1)
    from .ui.menus import RichObserver
    from .comparison.diff import render_text

    config = config_mod.load_config()
    mf, outcome, diff = engine.update_scan(root, config=config, observer=RichObserver())
    typer.echo(render_text(diff))


@app.command()
def enhance(
    path: Path = typer.Argument(..., help="Path to an existing scan project."),
    operations: Optional[str] = typer.Option(
        None, "--operations", help="Comma-separated operation ids to add."
    ),
) -> None:
    """Run additional operations against an existing project."""
    root = Path(path).expanduser()
    if not manifest_mod.is_valid_project(root):
        typer.echo(f"Not a valid NetMapper project: {root}", err=True)
        raise typer.Exit(code=1)
    if not operations:
        from .ui.menus import flow_enhance

        cfg = config_mod.load_config()
        cfg.last_output_directory = str(root.parent)
        flow_enhance(cfg)
        raise typer.Exit()
    chosen = [op.strip() for op in operations.split(",") if op.strip()]
    from .ui.menus import RichObserver

    config = config_mod.load_config()
    engine.enhance_scan(root, chosen, config=config, observer=RichObserver())


@app.command()
def view(
    path: Path = typer.Argument(..., help="Path to an existing scan project."),
) -> None:
    """Inspect a project's manifest and browse its artifacts."""
    root = Path(path).expanduser()
    if not manifest_mod.is_valid_project(root):
        typer.echo(f"Not a valid NetMapper project: {root}", err=True)
        raise typer.Exit(code=1)
    from .ui import viewer
    from .ui.menus import flow_view

    config = config_mod.load_config()
    config.last_output_directory = str(root.parent)
    # Directly view the given project.
    project = ProjectPaths(root)
    mf = manifest_mod.load_manifest(root)
    viewer.console.print(viewer.summarise_project(mf, project))
    artifacts = viewer.artifact_menu(project)
    if not artifacts:
        typer.echo("No artifacts available yet.")
        return
    for label, apath, _kind in artifacts:
        typer.echo(f"  {label}: {apath}")


@app.command()
def history() -> None:
    """List all registered scans."""
    from .ui.menus import flow_history

    flow_history(config_mod.load_config())


@app.command()
def menu() -> None:
    """Open the interactive main menu."""
    from .ui.menus import main_menu

    main_menu()
