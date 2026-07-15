"""Scan orchestration: create, run, update, and enhance projects.

The engine wires together operations, the manifest, the registry, live-host
extraction, run bookkeeping, and change comparison. It is deliberately
UI-agnostic: callers pass an :class:`Observer` to receive progress events, so
the same engine drives the interactive TUI and the scriptable CLI.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

from . import config as config_mod
from . import manifest as manifest_mod
from . import registry
from .log import get_logger
from .manifest import Manifest, TargetsInfo, new_run_id, now_iso, sha256_text
from .models import OperationState
from .operations import REGISTRY, ScanContext, resolve_dependencies
from .operations.base import OperationRunResult
from .parsers import nmap_xml
from .parsers.targets import parse_targets_text, TargetSet
from .paths import ProjectPaths
from .runner import ScanInterrupted
from .comparison.diff import diff_inventories, render_html, write_diff
from .comparison.models import ScanDiff


class Observer:
    """No-op observer; subclass to surface progress in a UI."""

    def info(self, message: str) -> None:  # pragma: no cover - trivial
        pass

    def warning(self, message: str) -> None:  # pragma: no cover - trivial
        pass

    def run_started(self, op_ids: Sequence[str]) -> None:
        """Called once before the first operation with the planned op ids."""
        pass

    def run_finished(self) -> None:
        """Called once after the run finishes (or is interrupted)."""
        pass

    def operation_start(self, op_id: str, index: int, total: int) -> None:
        pass

    def operation_end(self, result: OperationRunResult) -> None:
        pass


@dataclass
class RunOutcome:
    run_id: str
    results: list[OperationRunResult] = field(default_factory=list)
    interrupted: bool = False

    @property
    def completed(self) -> list[str]:
        return [r.op_id for r in self.results if r.status == "complete"]

    @property
    def failed(self) -> list[str]:
        return [r.op_id for r in self.results if r.status == "failed"]


# --- target handling -------------------------------------------------------

def prepare_targets(project: ProjectPaths, targets_text: str) -> tuple[TargetSet, str]:
    """Write original/normalised target files and return (set, sha256)."""
    project.input_dir.mkdir(parents=True, exist_ok=True)
    project.targets_original.write_text(targets_text, encoding="utf-8")
    target_set = parse_targets_text(targets_text)
    normalized_lines = target_set.normalized_lines()
    normalized_text = "\n".join(normalized_lines) + ("\n" if normalized_lines else "")
    project.targets_normalized.write_text(normalized_text, encoding="utf-8")
    return target_set, sha256_text(normalized_text)


def extract_live_hosts(project: ProjectPaths) -> int:
    """Determine live hosts from the discovery scan and write live-hosts.txt.

    Only hosts Nmap explicitly reported as ``Up`` in its greppable output are
    treated as live. This mirrors the authoritative host-discovery verdict::

        awk '/Status: Up/{print $2}' discovery.gnmap | sort -Vu

    Deriving the list from the ``Status: Up`` lines avoids the false positives
    that arise from inferring host state elsewhere. The greppable (``.gnmap``)
    file is preferred; the parser falls back to the XML output and finally to the
    normalised targets when no discovery output is present.
    Returns the number of live hosts written.
    """
    project.input_dir.mkdir(parents=True, exist_ok=True)
    live = _live_hosts_from_gnmap(project.discovery_dir / "discovery.gnmap")
    if live is None:
        live = _live_hosts_from_xml(project.discovery_dir / "discovery.xml")
    if live is not None:
        text = "\n".join(live) + ("\n" if live else "")
        project.live_hosts.write_text(text, encoding="utf-8")
        return len(live)
    # Fallback: use the normalised targets so scans can still proceed.
    if project.targets_normalized.exists():
        shutil.copyfile(project.targets_normalized, project.live_hosts)
    return sum(1 for _ in project.live_hosts.read_text().splitlines()) if project.live_hosts.exists() else 0


def _live_hosts_from_gnmap(gnmap_path: Path) -> Optional[list[str]]:
    """Extract ``Status: Up`` hosts from Nmap greppable output.

    Equivalent to ``awk '/Status: Up/{print $2}' | sort -Vu``: every line
    reporting a host as up contributes its address (the second whitespace field).
    Returns ``None`` when the file is absent so callers can fall back to other
    discovery sources.
    """
    if not gnmap_path.exists():
        return None
    live: set[str] = set()
    for line in gnmap_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "Status: Up" not in line:
            continue
        fields = line.split()
        if len(fields) >= 2:
            live.add(fields[1])
    return sorted(live, key=_ip_key)


def _live_hosts_from_xml(discovery_xml: Path) -> Optional[list[str]]:
    """Extract up hosts from discovery XML, or ``None`` when unavailable."""
    if not discovery_xml.exists() or not nmap_xml.is_nmap_xml(discovery_xml):
        return None
    hosts = nmap_xml.parse_file(discovery_xml)
    live = [h.address for h in hosts if h.status == "up" and h.address != "unknown"]
    return sorted(set(live), key=_ip_key)


def _ip_key(value: str) -> tuple:
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts))
    return (1, value)


# --- project creation ------------------------------------------------------

def create_project(
    *,
    name: str,
    output_parent: Path | str,
    targets_text: str,
    selected_operations: Sequence[str],
    profile: Optional[str] = None,
) -> tuple[ProjectPaths, Manifest]:
    """Create the directory skeleton, manifest, and target files."""
    parent = Path(output_parent).expanduser()
    root = parent / _safe_dirname(name)
    project = ProjectPaths(root)
    project.create_skeleton()

    target_set, target_hash = prepare_targets(project, targets_text)

    manifest = Manifest(
        name=name,
        targets=TargetsInfo(sha256=target_hash),
        profile=profile,
        selected_operations=list(selected_operations),
    )
    manifest_mod.save_manifest(root, manifest)
    registry.upsert_from_manifest(manifest, root, last_run_status="created")
    return project, manifest


def _safe_dirname(name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in name.strip())
    return safe.strip("-_.") or "pynmap-scan"


# --- run loop --------------------------------------------------------------

def run_operations(
    project: ProjectPaths,
    manifest: Manifest,
    op_ids: Sequence[str],
    *,
    config: Optional[config_mod.Config] = None,
    observer: Optional[Observer] = None,
    run_id: Optional[str] = None,
    skip_completed: bool = False,
) -> RunOutcome:
    """Resolve dependencies and execute ``op_ids`` in order.

    When ``skip_completed`` is True (used by *enhance*), prerequisites that are
    already complete are skipped -- only the explicitly requested operations and
    derived outputs are (re)run. Requested operations always run.
    """
    config = config or config_mod.load_config()
    observer = observer or Observer()
    run_id = run_id or new_run_id()

    requested = set(op_ids)
    resolved, added = resolve_dependencies(list(op_ids), REGISTRY)
    if added:
        observer.warning(
            "Automatically added required prerequisites: " + ", ".join(added)
        )

    run_dir = project.run_dir(run_id)
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    logger = get_logger(project.log_file)

    ctx = ScanContext(
        project=project,
        manifest=manifest,
        config=config,
        run_id=run_id,
        selected_operations=resolved,
        logger=logger,
    )

    manifest.latest_run_id = run_id
    outcome = RunOutcome(run_id=run_id)
    run_records: list[dict] = []

    def _should_run(op_id: str) -> bool:
        op = REGISTRY.get(op_id)
        if op is None:
            return False
        if skip_completed and op_id not in requested and not op.is_derived:
            if manifest.is_complete(op_id):
                logger.info("Skipping already-complete prerequisite %s", op_id)
                return False
        return True

    to_execute = [op_id for op_id in resolved if _should_run(op_id)]
    total = len(to_execute)

    observer.run_started(to_execute)
    try:
        for index, op_id in enumerate(to_execute, start=1):
            op = REGISTRY[op_id]
            observer.operation_start(op_id, index, total)
            logger.info("Starting operation %s", op_id)

            if op.uses_live_hosts and not project.live_hosts.exists():
                extract_live_hosts(project)

            manifest.mark_operation(op_id, OperationState.RUNNING.value)
            manifest_mod.save_manifest(project.root, manifest)

            started = now_iso()
            try:
                result = op.run(ctx)
            except ScanInterrupted:
                manifest.mark_operation(op_id, OperationState.CANCELLED.value)
                manifest_mod.save_manifest(project.root, manifest)
                run_records.append({
                    "operation": op_id,
                    "started_at": started,
                    "finished_at": now_iso(),
                    "status": "cancelled",
                })
                observer.warning(f"Operation {op_id} cancelled (Ctrl+C).")
                outcome.interrupted = True
                outcome.results.append(
                    OperationRunResult(op_id=op_id, status="cancelled")
                )
                break

            manifest.mark_operation(op_id, result.status, result.return_code)
            manifest_mod.save_manifest(project.root, manifest)

            if op_id == "discovery" and result.status == "complete":
                live_count = extract_live_hosts(project)
                observer.info(f"Discovery found {live_count} live host(s).")

            run_records.append({
                "operation": op_id,
                "started_at": started,
                "finished_at": now_iso(),
                "return_code": result.return_code,
                "status": result.status,
                "command": result.command,
            })
            outcome.results.append(result)
            observer.operation_end(result)
            logger.info("Finished operation %s -> %s", op_id, result.status)
    finally:
        observer.run_finished()

    _write_run_record(run_dir, run_id, run_records)
    status = "interrupted" if outcome.interrupted else (
        "failed" if outcome.failed else "complete"
    )
    manifest_mod.save_manifest(project.root, manifest)
    registry.upsert_from_manifest(manifest, project.root, last_run_status=status)
    return outcome


def _write_run_record(run_dir: Path, run_id: str, records: list[dict]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "generated_at": now_iso(),
        "operations": records,
    }
    (run_dir / "run.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


# --- high level workflows --------------------------------------------------

def new_scan(
    *,
    name: str,
    output_parent: Path | str,
    targets_text: str,
    selected_operations: Sequence[str],
    profile: Optional[str] = None,
    config: Optional[config_mod.Config] = None,
    observer: Optional[Observer] = None,
) -> tuple[ProjectPaths, Manifest, RunOutcome]:
    project, manifest = create_project(
        name=name,
        output_parent=output_parent,
        targets_text=targets_text,
        selected_operations=selected_operations,
        profile=profile,
    )
    outcome = run_operations(
        project, manifest, selected_operations, config=config, observer=observer
    )
    # Persist the last-used operation set for next time.
    if config is not None:
        config.last_selected_operations = list(selected_operations)
        config.last_output_directory = str(Path(output_parent).expanduser())
        config_mod.save_config(config)
    return project, manifest, outcome


def _snapshot_inventory(project: ProjectPaths):
    from .operations.reports import collect_scan_xml

    return nmap_xml.build_inventory(collect_scan_xml(project))


def _archive_current_outputs(project: ProjectPaths, run_id: str) -> None:
    """Copy current canonical outputs into the run dir before overwriting."""
    archive_root = project.run_dir(run_id) / "previous"
    for sub in ("discovery", "tcp", "udp", "os", "traceroute", "inventory",
                "reports", "maps"):
        src = project.root / sub
        if src.exists():
            dst = archive_root / sub
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dst, dirs_exist_ok=True)


def update_scan(
    root: Path | str,
    *,
    config: Optional[config_mod.Config] = None,
    observer: Optional[Observer] = None,
) -> tuple[Manifest, RunOutcome, ScanDiff]:
    """Rerun mutable operations, compare against the previous inventory."""
    observer = observer or Observer()
    project = ProjectPaths(root)
    manifest = manifest_mod.load_manifest(root)

    previous_inventory = _snapshot_inventory(project)

    run_id = new_run_id()
    _archive_current_outputs(project, run_id)

    # Rerun the operations that were previously selected and are mutable, plus
    # derived outputs.
    to_run = [
        op_id
        for op_id in manifest.selected_operations
        if REGISTRY.get(op_id) is not None
        and (REGISTRY[op_id].rerun_on_update or REGISTRY[op_id].id in
             ("inventory", "html_report", "network_map"))
    ]
    outcome = run_operations(
        project, manifest, to_run, config=config, observer=observer, run_id=run_id
    )

    current_inventory = _snapshot_inventory(project)
    diff = diff_inventories(previous_inventory, current_inventory)
    _write_change_report(project, run_id, diff, manifest.name)
    manifest_mod.save_manifest(project.root, manifest)
    return manifest, outcome, diff


def _write_change_report(
    project: ProjectPaths, run_id: str, diff: ScanDiff, name: str
) -> None:
    project.changes_dir.mkdir(parents=True, exist_ok=True)
    project.changes_history_dir.mkdir(parents=True, exist_ok=True)
    latest_json = project.changes_dir / "latest-diff.json"
    latest_txt = project.changes_dir / "latest-diff.txt"
    write_diff(diff, latest_json, latest_txt)
    # Timestamped copies in history + reports/changes.html
    hist_json = project.changes_history_dir / f"{run_id}.json"
    hist_txt = project.changes_history_dir / f"{run_id}.txt"
    write_diff(diff, hist_json, hist_txt)
    (project.reports_dir / "changes.html").write_text(
        render_html(diff, name), encoding="utf-8"
    )


def enhance_scan(
    root: Path | str,
    additional_operations: Sequence[str],
    *,
    config: Optional[config_mod.Config] = None,
    observer: Optional[Observer] = None,
) -> tuple[Manifest, RunOutcome]:
    """Run additional operations against the existing live-host list."""
    observer = observer or Observer()
    project = ProjectPaths(root)
    manifest = manifest_mod.load_manifest(root)

    if not project.live_hosts.exists():
        extract_live_hosts(project)

    # Ensure derived outputs refresh after new scan data arrives.
    to_run = list(dict.fromkeys(list(additional_operations)))
    for derived in ("inventory", "html_report", "network_map"):
        if derived in manifest.selected_operations and derived not in to_run:
            to_run.append(derived)

    outcome = run_operations(
        project, manifest, to_run, config=config, observer=observer,
        skip_completed=True,
    )

    # Record newly selected operations in the manifest.
    for op_id in additional_operations:
        if op_id not in manifest.selected_operations:
            manifest.selected_operations.append(op_id)
    manifest_mod.save_manifest(project.root, manifest)
    return manifest, outcome


def available_enhancements(manifest: Manifest) -> list[str]:
    """Operations that are not yet complete for the project."""
    return [
        op_id
        for op_id in REGISTRY
        if not manifest.is_complete(op_id) and not REGISTRY[op_id].is_modifier
    ]
