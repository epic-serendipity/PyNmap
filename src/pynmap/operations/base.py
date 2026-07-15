"""Base classes for scan operations and the shared execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ..paths import ProjectPaths
from ..runner import SUDO_HINT, CommandResult, is_root, run_command

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..config import Config
    from ..manifest import Manifest


@dataclass
class ScanContext:
    """Everything an operation needs to run against a project."""

    project: ProjectPaths
    manifest: "Manifest"
    config: "Config"
    run_id: str
    selected_operations: list[str] = field(default_factory=list)
    logger: object | None = None

    @property
    def run_dir(self) -> Path:
        return self.project.run_dir(self.run_id)

    @property
    def run_logs_dir(self) -> Path:
        return self.run_dir / "logs"

    def log(self, message: str) -> None:
        if self.logger is not None and hasattr(self.logger, "info"):
            self.logger.info(message)  # type: ignore[attr-defined]

    def service_detection_enabled(self) -> bool:
        return "service_detection" in self.selected_operations

    def timing_flag(self) -> str:
        timing = getattr(self.config, "default_timing", "T4") or "T4"
        return f"-{timing}" if not timing.startswith("-") else timing


@dataclass
class OperationRunResult:
    op_id: str
    status: str  # complete / failed / cancelled / skipped
    command: list[str] = field(default_factory=list)
    return_code: Optional[int] = None
    message: str = ""


class Operation:
    """Base class describing a single scan operation.

    Concrete subclasses must set the metadata attributes and either implement
    :meth:`build_command` (for Nmap operations) or override :meth:`run`
    (for derived operations such as inventory/report/map generation).
    """

    id: str = ""
    display_name: str = ""
    description: str = ""
    dependencies: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()  # relative to project root
    becomes_stale: bool = False
    rerun_on_update: bool = False
    requires_root: bool = False
    #: Modifiers change other operations' commands rather than running Nmap.
    is_modifier: bool = False
    #: True for scan operations that read the discovered live-host list.
    uses_live_hosts: bool = False
    #: Derived operations (inventory/report/map) always regenerate from data.
    is_derived: bool = False

    # --- command construction ---------------------------------------------
    def build_command(self, ctx: ScanContext) -> Optional[list[str]]:
        """Return the Nmap argument list, or ``None`` for non-Nmap ops."""
        return None

    # --- completion validation --------------------------------------------
    def output_paths(self, ctx: ScanContext) -> list[Path]:
        return [ctx.project.root / rel for rel in self.outputs]

    def is_complete(self, ctx: ScanContext) -> bool:
        outs = self.output_paths(ctx)
        if not outs:
            return ctx.manifest.is_complete(self.id)
        return all(p.exists() and p.stat().st_size > 0 for p in outs)

    # --- execution ---------------------------------------------------------
    def run(self, ctx: ScanContext) -> OperationRunResult:
        command = self.build_command(ctx)
        if command is None:
            return OperationRunResult(
                op_id=self.id, status="skipped", message="no command"
            )
        # PyNmap expects to be launched with the privileges its scans need
        # (``sudo pynmap``); privileged operations inherit the process's root
        # rather than being individually wrapped in ``sudo``. Fail fast with a
        # clear hint when a privileged operation is requested unprivileged.
        if self.requires_root and not is_root():
            ctx.log(f"Cannot run {self.id} without root -- {SUDO_HINT}")
            return OperationRunResult(
                op_id=self.id,
                status="failed",
                message=f"needs root -- {SUDO_HINT}",
            )
        log_file = ctx.run_logs_dir / f"{self.id}.log"
        ctx.log(f"Running {self.id}: {' '.join(command)}")
        result = run_command(command, log_file=log_file)
        status = "complete" if self._accept_return_code(result) else "failed"
        return OperationRunResult(
            op_id=self.id,
            status=status,
            command=command,
            return_code=result.return_code,
        )

    def _accept_return_code(self, result: CommandResult) -> bool:
        return result.ok


def resolve_dependencies(
    selected: list[str], registry: dict[str, "Operation"]
) -> tuple[list[str], list[str]]:
    """Expand ``selected`` to include all transitive prerequisites.

    Returns ``(resolved, added)`` where ``resolved`` is the full ordered list
    (dependencies before dependents) and ``added`` lists the prerequisite ids
    that were not originally selected. Only genuine prerequisites are added --
    unrelated operations are never pulled in.
    """
    added: list[str] = []
    wanted = set(selected)

    def visit(op_id: str, stack: set[str]) -> None:
        op = registry.get(op_id)
        if op is None:
            return
        for dep in op.dependencies:
            if dep not in wanted:
                wanted.add(dep)
                if dep not in added:
                    added.append(dep)
            if dep not in stack:
                visit(dep, stack | {op_id})

    for op_id in list(selected):
        visit(op_id, {op_id})

    ordered = topo_sort(sorted(wanted), registry)
    return ordered, added


def topo_sort(op_ids: list[str], registry: dict[str, "Operation"]) -> list[str]:
    """Order operations so dependencies precede dependents (stable)."""
    result: list[str] = []
    visited: set[str] = set()
    temp: set[str] = set()

    def visit(op_id: str) -> None:
        if op_id in visited or op_id not in op_ids:
            return
        if op_id in temp:  # cycle guard
            return
        temp.add(op_id)
        op = registry.get(op_id)
        if op is not None:
            for dep in op.dependencies:
                if dep in op_ids:
                    visit(dep)
        temp.discard(op_id)
        visited.add(op_id)
        result.append(op_id)

    for op_id in op_ids:
        visit(op_id)
    return result
