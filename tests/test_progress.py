"""Tests for the run progress monitor (spinner + spacebar report)."""

import io

from rich.console import Console

from pynmap import progress
from pynmap.progress import ProgressMonitor, format_elapsed


def _make_monitor() -> ProgressMonitor:
    # A non-TTY console keeps the monitor a no-op thread-wise, so the tests are
    # deterministic and never touch real terminal state.
    console = Console(file=io.StringIO(), force_terminal=False)
    return ProgressMonitor(console, show_progress=True)


def test_format_elapsed():
    assert format_elapsed(0) == "0:00:00"
    assert format_elapsed(5) == "0:00:05"
    assert format_elapsed(65) == "0:01:05"
    assert format_elapsed(3661) == "1:01:01"
    assert format_elapsed(-3) == "0:00:00"


def test_disabled_without_tty():
    monitor = _make_monitor()
    # StringIO is not a TTY, so the interactive features are off.
    assert monitor.enabled is False
    assert monitor.keys_enabled is False
    # Lifecycle stays a harmless no-op.
    monitor.start()
    monitor.stop()


def test_report_reflects_plan_and_current_operation():
    monitor = _make_monitor()
    monitor.set_plan([
        "Host discovery",
        "Common TCP ports",
        "TCP service detection",
    ])
    monitor.begin_operation("discovery", "Host discovery", 1, 3)

    lines = monitor.progress_report_lines()
    assert lines[0].startswith("Stats:")
    assert "0/3 operations complete" in lines[0]
    assert any("Current: Host discovery" in ln for ln in lines)
    # Everything after the current operation is still outstanding.
    remaining = [ln for ln in lines if ln.startswith("Remaining:")]
    assert remaining
    assert "Common TCP ports" in remaining[0]
    assert "TCP service detection" in remaining[0]


def test_report_counts_completed_operations():
    monitor = _make_monitor()
    monitor.set_plan(["Host discovery", "Common TCP ports"])
    monitor.begin_operation("discovery", "Host discovery", 1, 2)
    monitor.end_operation("complete")
    monitor.begin_operation("tcp_top_1000", "Common TCP ports", 2, 2)

    lines = monitor.progress_report_lines()
    assert "1/2 operations complete" in lines[0]
    assert any("Current: Common TCP ports" in ln for ln in lines)


def test_active_subprocess_context_is_safe_when_disabled():
    monitor = _make_monitor()
    monitor.begin_operation("discovery", "Host discovery", 1, 1)
    # Should not raise or block even though no background thread is running.
    with monitor.active_subprocess():
        pass


def test_module_active_monitor_registration():
    monitor = _make_monitor()
    assert progress.get_active_monitor() is None
    progress.set_active_monitor(monitor)
    assert progress.get_active_monitor() is monitor
    # The module-level context manager delegates to the active monitor.
    with progress.active_subprocess():
        pass
    progress.set_active_monitor(None)
    assert progress.get_active_monitor() is None


def test_print_routes_through_console():
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False)
    monitor = ProgressMonitor(console, show_progress=True)
    monitor.print("hello world")
    assert "hello world" in buffer.getvalue()
