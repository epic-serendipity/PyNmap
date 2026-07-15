"""Global SQLite registry of scan projects.

Stored at ``~/.local/share/netmapper/scans.db``. The registry is a convenience
index only -- the portable ``manifest.json`` inside each project directory
remains the authoritative per-project metadata, so a project stays usable even
if it is moved to another machine and the registry is lost.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from . import paths
from .manifest import Manifest

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_run_status TEXT,
    target_hash TEXT,
    missing INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass
class ScanRecord:
    project_id: str
    name: str
    path: str
    created_at: str
    updated_at: str
    last_run_status: Optional[str] = None
    target_hash: Optional[str] = None
    missing: int = 0


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    paths.ensure_user_dirs()
    conn = sqlite3.connect(str(paths.registry_file()))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_from_manifest(
    manifest: Manifest, project_path: Path | str, last_run_status: str | None = None
) -> None:
    record = ScanRecord(
        project_id=manifest.project_id,
        name=manifest.name,
        path=str(Path(project_path).resolve()),
        created_at=manifest.created_at,
        updated_at=manifest.updated_at,
        last_run_status=last_run_status,
        target_hash=manifest.targets.sha256,
        missing=0,
    )
    upsert(record)


def upsert(record: ScanRecord) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scans
                (project_id, name, path, created_at, updated_at,
                 last_run_status, target_hash, missing)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id) DO UPDATE SET
                name=excluded.name,
                path=excluded.path,
                updated_at=excluded.updated_at,
                last_run_status=excluded.last_run_status,
                target_hash=excluded.target_hash,
                missing=excluded.missing
            """,
            (
                record.project_id,
                record.name,
                record.path,
                record.created_at,
                record.updated_at,
                record.last_run_status,
                record.target_hash,
                record.missing,
            ),
        )


def list_scans() -> list[ScanRecord]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY updated_at DESC"
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def get_scan(project_id: str) -> Optional[ScanRecord]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE project_id = ?", (project_id,)
        ).fetchone()
    return _row_to_record(row) if row else None


def relocate(project_id: str, new_path: Path | str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE scans SET path = ?, missing = 0 WHERE project_id = ?",
            (str(Path(new_path).resolve()), project_id),
        )


def mark_missing(project_id: str, missing: bool = True) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE scans SET missing = ? WHERE project_id = ?",
            (1 if missing else 0, project_id),
        )


def refresh_missing_flags() -> list[ScanRecord]:
    """Update the ``missing`` flag for every registered scan and return them."""
    records = list_scans()
    for record in records:
        missing = not (Path(record.path) / "manifest.json").exists()
        if bool(record.missing) != missing:
            mark_missing(record.project_id, missing)
            record.missing = 1 if missing else 0
    return records


def _row_to_record(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        project_id=row["project_id"],
        name=row["name"],
        path=row["path"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_run_status=row["last_run_status"],
        target_hash=row["target_hash"],
        missing=row["missing"],
    )
