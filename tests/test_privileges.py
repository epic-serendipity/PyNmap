"""Tests for the root-privilege model (assumes ``sudo pynmap``)."""

from pynmap.operations import base
from pynmap.operations.base import ScanContext
from pynmap.operations.discovery import DiscoveryOperation
from pynmap.operations.reports import InventoryOperation
from pynmap.paths import ProjectPaths
from pynmap.runner import CommandResult


def _ctx(tmp_path) -> ScanContext:
    project = ProjectPaths(tmp_path)
    project.create_skeleton()
    project.targets_normalized.write_text("10.0.0.1\n", encoding="utf-8")
    return ScanContext(
        project=project, manifest=None, config=None, run_id="run-1"
    )


def _fake_ok(*_args, **_kwargs) -> CommandResult:
    return CommandResult(
        command=["nmap"], return_code=0, started_at="", finished_at=""
    )


def test_privileged_op_skipped_without_root(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "is_root", lambda: False)
    called = {"ran": False}

    def _boom(*_a, **_k):  # pragma: no cover - should never be reached
        called["ran"] = True
        return _fake_ok()

    monkeypatch.setattr(base, "run_command", _boom)

    result = DiscoveryOperation().run(_ctx(tmp_path))

    assert result.status == "failed"
    assert "sudo pynmap" in result.message
    assert called["ran"] is False


def test_privileged_op_runs_directly_as_root(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "is_root", lambda: True)
    captured = {}

    def _capture(command, **_kwargs):
        captured["command"] = command
        return _fake_ok()

    monkeypatch.setattr(base, "run_command", _capture)

    result = DiscoveryOperation().run(_ctx(tmp_path))

    assert result.status == "complete"
    # Runs nmap directly -- no per-command sudo prefix when already root.
    assert captured["command"][0] == "nmap"
    assert "sudo" not in captured["command"]


def test_non_privileged_op_ignores_root_check(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "is_root", lambda: False)
    # A derived/report op declares requires_root = False and must not be gated.
    assert InventoryOperation.requires_root is False
