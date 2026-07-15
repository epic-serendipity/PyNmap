"""Tests for orchestration decisions made by the scan run loop."""

from pynmap import engine
from pynmap.config import Config
from pynmap.engine import Observer, run_operations
from pynmap.manifest import Manifest
from pynmap.operations.base import Operation, OperationRunResult
from pynmap.paths import ProjectPaths


class RecordingObserver(Observer):
    def __init__(self):
        self.warnings = []

    def warning(self, message: str) -> None:
        self.warnings.append(message)


class EmptyDiscovery(Operation):
    id = "discovery"

    def run(self, ctx):
        (ctx.project.discovery_dir / "discovery.gnmap").write_text(
            "Host: 10.0.0.1 ()\tStatus: Down\n", encoding="utf-8"
        )
        return OperationRunResult(op_id=self.id, status="complete")


class FailedDiscovery(Operation):
    id = "discovery"

    def run(self, _ctx):
        return OperationRunResult(op_id=self.id, status="failed", return_code=1)


class LiveHostProbe(Operation):
    id = "probe"
    dependencies = ("discovery",)
    uses_live_hosts = True

    def __init__(self):
        self.ran = False

    def run(self, _ctx):
        self.ran = True
        return OperationRunResult(op_id=self.id, status="complete")


def _project(tmp_path):
    project = ProjectPaths(tmp_path / "scan")
    project.create_skeleton()
    project.targets_normalized.write_text("10.0.0.1\n", encoding="utf-8")
    return project


def _run(tmp_path, monkeypatch, discovery):
    project = _project(tmp_path)
    probe = LiveHostProbe()
    monkeypatch.setattr(
        engine, "REGISTRY", {"discovery": discovery, "probe": probe}
    )
    monkeypatch.setattr(engine.registry, "upsert_from_manifest", lambda *_a, **_k: None)
    observer = RecordingObserver()

    outcome = run_operations(
        project,
        Manifest(name="test"),
        ["probe"],
        config=Config(),
        observer=observer,
        run_id="run-1",
    )
    return project, probe, observer, outcome


def test_live_host_operation_skipped_when_discovery_finds_none(tmp_path, monkeypatch):
    project, probe, observer, outcome = _run(
        tmp_path, monkeypatch, EmptyDiscovery()
    )

    assert [result.status for result in outcome.results] == ["complete", "skipped"]
    assert outcome.results[-1].message == "discovery did not identify any live hosts"
    assert probe.ran is False
    assert project.live_hosts.exists()
    assert any("Skipping probe" in warning for warning in observer.warnings)


def test_failed_discovery_prevents_use_of_stale_live_hosts(tmp_path, monkeypatch):
    project = _project(tmp_path)
    project.live_hosts.write_text("10.0.0.99\n", encoding="utf-8")
    probe = LiveHostProbe()
    monkeypatch.setattr(
        engine,
        "REGISTRY",
        {"discovery": FailedDiscovery(), "probe": probe},
    )
    monkeypatch.setattr(engine.registry, "upsert_from_manifest", lambda *_a, **_k: None)

    outcome = run_operations(
        project,
        Manifest(name="test"),
        ["probe"],
        config=Config(),
        run_id="run-1",
    )

    assert [result.status for result in outcome.results] == ["failed", "skipped"]
    assert outcome.results[-1].message == "discovery did not complete successfully"
    assert probe.ran is False
