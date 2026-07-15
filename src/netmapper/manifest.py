"""Read, validate, and write the per-project ``manifest.json``.

The manifest is what makes ``update``, ``enhance``, and ``view`` work reliably.
A directory is only treated as a valid NetMapper project when it contains a
manifest with the correct ``tool`` marker and a supported ``schema_version`` --
never merely because it happens to contain an ``.xml`` file.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import SCHEMA_VERSION, TOOL_NAME
from .paths import ProjectPaths


class InvalidProjectError(Exception):
    """Raised when a directory is not a recognised NetMapper project."""


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def new_run_id(when: Optional[datetime] = None) -> str:
    when = when or datetime.now()
    return when.strftime("%Y-%m-%dT%H%M%S")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class OperationStatus:
    status: str = "pending"
    last_run: Optional[str] = None
    return_code: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        data = {"status": self.status}
        if self.last_run is not None:
            data["last_run"] = self.last_run
        if self.return_code is not None:
            data["return_code"] = self.return_code
        return data


@dataclass
class TargetsInfo:
    original_file: str = "input/targets-original.txt"
    normalized_file: str = "input/targets-normalized.txt"
    sha256: str = ""


@dataclass
class Manifest:
    schema_version: int = SCHEMA_VERSION
    tool: str = TOOL_NAME
    project_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    targets: TargetsInfo = field(default_factory=TargetsInfo)
    profile: Optional[str] = None
    selected_operations: list[str] = field(default_factory=list)
    completed_operations: dict[str, OperationStatus] = field(default_factory=dict)
    latest_run_id: Optional[str] = None

    # --- (de)serialisation -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": self.tool,
            "project_id": self.project_id,
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "targets": asdict(self.targets),
            "profile": self.profile,
            "selected_operations": list(self.selected_operations),
            "completed_operations": {
                k: v.to_dict() for k, v in self.completed_operations.items()
            },
            "latest_run_id": self.latest_run_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Manifest":
        targets_raw = data.get("targets", {}) or {}
        targets = TargetsInfo(
            original_file=targets_raw.get("original_file", "input/targets-original.txt"),
            normalized_file=targets_raw.get("normalized_file", "input/targets-normalized.txt"),
            sha256=targets_raw.get("sha256", ""),
        )
        completed = {}
        for key, value in (data.get("completed_operations", {}) or {}).items():
            if isinstance(value, dict):
                completed[key] = OperationStatus(
                    status=value.get("status", "pending"),
                    last_run=value.get("last_run"),
                    return_code=value.get("return_code"),
                )
        return cls(
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            tool=data.get("tool", TOOL_NAME),
            project_id=data.get("project_id", str(uuid.uuid4())),
            name=data.get("name", ""),
            created_at=data.get("created_at", now_iso()),
            updated_at=data.get("updated_at", now_iso()),
            targets=targets,
            profile=data.get("profile"),
            selected_operations=list(data.get("selected_operations", [])),
            completed_operations=completed,
            latest_run_id=data.get("latest_run_id"),
        )

    # --- helpers -----------------------------------------------------------
    def mark_operation(self, op_id: str, status: str, return_code: Optional[int] = None) -> None:
        self.completed_operations[op_id] = OperationStatus(
            status=status, last_run=now_iso(), return_code=return_code
        )
        self.updated_at = now_iso()

    def operation_state(self, op_id: str) -> str:
        entry = self.completed_operations.get(op_id)
        return entry.status if entry else "pending"

    def is_complete(self, op_id: str) -> bool:
        return self.operation_state(op_id) == "complete"


def load_manifest(root: Path | str) -> Manifest:
    project = ProjectPaths(root)
    if not project.manifest.exists():
        raise InvalidProjectError(
            f"No manifest.json found in {project.root} -- not a NetMapper project."
        )
    try:
        data = json.loads(project.manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise InvalidProjectError(f"Could not read manifest: {exc}") from exc
    if data.get("tool") != TOOL_NAME:
        raise InvalidProjectError("manifest.json is not a NetMapper manifest.")
    version = data.get("schema_version")
    if version is None or int(version) > SCHEMA_VERSION:
        raise InvalidProjectError(
            f"Unsupported manifest schema version: {version!r}."
        )
    return Manifest.from_dict(data)


def save_manifest(root: Path | str, manifest: Manifest) -> None:
    project = ProjectPaths(root)
    project.root.mkdir(parents=True, exist_ok=True)
    manifest.updated_at = now_iso()
    project.manifest.write_text(
        json.dumps(manifest.to_dict(), indent=2) + "\n", encoding="utf-8"
    )


def is_valid_project(root: Path | str) -> bool:
    try:
        load_manifest(root)
        return True
    except InvalidProjectError:
        return False
