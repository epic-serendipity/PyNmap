"""Interactive run progress: an ASCII spinner and on-demand status report.

While a scan operation's external command (Nmap, ``dot``, ``xsltproc``) is
running, the main thread blocks inside :func:`pynmap.runner.run_command`. This
module drives a small background thread that, for interactive terminals:

* animates an ASCII loading symbol so the user can see work is happening, and
* prints a brief progress report (elapsed time, current operation, what is
  left) whenever the user presses the spacebar -- mirroring the way Nmap
  itself prints a status line when you press a key mid-scan.

Everything degrades gracefully: when stdout/stdin are not TTYs (pipes, log
files, test runs) the monitor becomes a no-op that still records state, so the
same code path works for the scriptable CLI and the pytest suite.

The runner stays UI-agnostic by consulting a single module-level "active"
monitor rather than importing any UI code.
"""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from typing import Iterator, Optional

# --- single-key input support (best effort, per platform) ------------------
try:  # POSIX (Linux/macOS/WSL) -- the primary target platforms.
    import select
    import termios
    import tty

    _POSIX_KEYS = True
except ImportError:  # pragma: no cover - non-POSIX
    _POSIX_KEYS = False

try:  # Windows fallback.
    import msvcrt

    _WIN_KEYS = True
except ImportError:
    _WIN_KEYS = False

_KEY_SUPPORT = _POSIX_KEYS or _WIN_KEYS

#: ASCII spinner frames (kept strictly ASCII so any terminal can render them).
SPINNER_FRAMES = ("|", "/", "-", "\\")

#: Keys that trigger a progress report.
_REPORT_KEYS = {" ", "\n", "\r"}


def _isatty(stream) -> bool:
    try:
        return bool(stream) and stream.isatty()
    except (ValueError, OSError):
        return False


def format_elapsed(seconds: float) -> str:
    """Format a duration as ``H:MM:SS`` (Nmap-style)."""
    seconds = int(max(0, seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}"


class ProgressMonitor:
    """Animate a spinner and print a status report on a spacebar keypress.

    The monitor is created once per run. Call :meth:`start` before the run and
    :meth:`stop` afterwards. During the run, the observer reports the current
    operation via :meth:`begin_operation` / :meth:`end_operation`, and the
    runner wraps each external command in :meth:`active_subprocess` so the
    spinner only spins (and keys are only captured) while a command is live.
    """

    def __init__(self, console=None, *, show_progress: bool = True) -> None:
        self._console = console
        self.enabled = bool(show_progress) and _isatty(sys.stdout)
        self.keys_enabled = self.enabled and _isatty(sys.stdin) and _KEY_SUPPORT

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._engage = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._frame = 0
        self._line_dirty = False

        # Terminal state used while capturing single keypresses.
        self._fd: Optional[int] = None
        self._old_term = None

        # Run/operation bookkeeping (guarded by ``_lock``).
        self._run_start = time.monotonic()
        self._plan: list[str] = []
        self._total = 0
        self._index = 0
        self._current_name: Optional[str] = None
        self._current_start = 0.0
        self._quiet = False
        self._completed: list[tuple[str, str]] = []

    # --- lifecycle ---------------------------------------------------------
    def set_plan(self, names: list[str]) -> None:
        with self._lock:
            self._plan = list(names)
            self._total = len(self._plan)

    def start(self) -> None:
        self._run_start = time.monotonic()
        if not self.enabled:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="pynmap-progress", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._engage.clear()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=1.5)
            self._thread = None
        with self._lock:
            self._clear_line_locked()

    # --- operation reporting ----------------------------------------------
    def begin_operation(
        self, op_id: str, name: str, index: int, total: int, *, quiet: bool = False
    ) -> None:
        with self._lock:
            self._current_name = name
            self._index = index
            if total:
                self._total = total
            self._current_start = time.monotonic()
            self._quiet = quiet
            self._frame = 0

    def end_operation(self, status: str) -> None:
        with self._lock:
            if self._current_name is not None:
                self._completed.append((self._current_name, status))
            self._current_name = None
            self._quiet = False

    @contextmanager
    def active_subprocess(self) -> Iterator[None]:
        """Spin (and capture keys) while an external command is running."""
        if not self.enabled or self._quiet:
            yield
            return
        self._engage.set()
        try:
            yield
        finally:
            self._engage.clear()

    # --- console output (thread-safe with the spinner) --------------------
    def print(self, renderable) -> None:
        """Print a message without letting the spinner line garble it."""
        with self._lock:
            self._clear_line_locked()
            if self._console is not None:
                self._console.print(renderable)
            else:  # pragma: no cover - console always supplied in practice
                sys.stdout.write(f"{renderable}\n")
                sys.stdout.flush()

    # --- progress report ---------------------------------------------------
    def progress_report_lines(self) -> list[str]:
        """Build the brief, Nmap-style progress report as plain text lines."""
        with self._lock:
            now = time.monotonic()
            done = len(self._completed)
            total = self._total or (done + (1 if self._current_name else 0))
            lines = [
                f"Stats: {format_elapsed(now - self._run_start)} elapsed; "
                f"{done}/{total} operations complete"
            ]
            if self._current_name is not None:
                pos = f"{self._index}/{total}" if total else f"{self._index}"
                lines.append(
                    f"Current: {self._current_name} - "
                    f"{format_elapsed(now - self._current_start)} elapsed [{pos}]"
                )
            if self._plan and self._index:
                remaining = self._plan[self._index:]
                if remaining:
                    lines.append("Remaining: " + ", ".join(remaining))
        return lines

    def _emit_report(self) -> None:
        lines = self.progress_report_lines()
        with self._lock:
            self._clear_line_locked()
            if self._console is not None:
                body = "\n".join(f"  {ln}" for ln in lines)
                self._console.print(
                    f"[dim]-- progress --[/dim]\n{body}", highlight=False
                )
            else:  # pragma: no cover
                sys.stdout.write("-- progress --\n")
                for ln in lines:
                    sys.stdout.write(f"  {ln}\n")
                sys.stdout.flush()

    # --- background loop ---------------------------------------------------
    def _loop(self) -> None:
        in_cbreak = False
        was_engaged = False
        try:
            while not self._stop.is_set():
                engaged = self._engage.is_set()
                if was_engaged and not engaged:
                    with self._lock:
                        self._clear_line_locked()
                was_engaged = engaged

                want_keys = engaged and self.keys_enabled
                if want_keys and not in_cbreak:
                    in_cbreak = self._enter_cbreak()
                elif not want_keys and in_cbreak:
                    self._exit_cbreak()
                    in_cbreak = False

                if not engaged:
                    self._stop.wait(0.1)
                    continue

                self._render_spinner()
                if in_cbreak:
                    key = self._read_key(0.12)
                    if key in _REPORT_KEYS:
                        self._emit_report()
                else:
                    self._stop.wait(0.12)
        finally:
            if in_cbreak:
                self._exit_cbreak()

    def _render_spinner(self) -> None:
        with self._lock:
            if not self._engage.is_set():
                return
            frame = SPINNER_FRAMES[self._frame % len(SPINNER_FRAMES)]
            self._frame += 1
            name = self._current_name or "operation"
            pos = f"({self._index}/{self._total}) " if self._total else ""
            elapsed = format_elapsed(time.monotonic() - self._current_start)
            hint = "  (press SPACE for progress)" if self.keys_enabled else ""
            text = f"{frame} {pos}{name} - {elapsed}{hint}"
            sys.stdout.write("\r\033[K" + text)
            sys.stdout.flush()
            self._line_dirty = True

    def _clear_line_locked(self) -> None:
        if self._line_dirty and _isatty(sys.stdout):
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
        self._line_dirty = False

    # --- single-key input --------------------------------------------------
    def _enter_cbreak(self) -> bool:
        if not _POSIX_KEYS:
            return _WIN_KEYS  # Windows needs no mode change.
        try:
            self._fd = sys.stdin.fileno()
            self._old_term = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)
            return True
        except (termios.error, ValueError, OSError):
            self._old_term = None
            return False

    def _exit_cbreak(self) -> None:
        if _POSIX_KEYS and self._old_term is not None and self._fd is not None:
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_term)
            except (termios.error, ValueError, OSError):
                pass
        self._old_term = None

    def _read_key(self, timeout: float) -> Optional[str]:
        if _POSIX_KEYS:
            try:
                ready, _, _ = select.select([sys.stdin], [], [], timeout)
            except (ValueError, OSError):
                return None
            if ready:
                try:
                    return sys.stdin.read(1)
                except (ValueError, OSError):
                    return None
            return None
        if _WIN_KEYS:  # pragma: no cover - Windows only
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if msvcrt.kbhit():
                    try:
                        return msvcrt.getwch()
                    except OSError:
                        return None
                time.sleep(0.02)
            return None
        return None  # pragma: no cover


# --- module-level "active" monitor consulted by the runner -----------------
_active: Optional[ProgressMonitor] = None


def set_active_monitor(monitor: Optional[ProgressMonitor]) -> None:
    global _active
    _active = monitor


def get_active_monitor() -> Optional[ProgressMonitor]:
    return _active


@contextmanager
def active_subprocess() -> Iterator[None]:
    """Engage the active monitor's spinner for the duration of a command."""
    monitor = _active
    if monitor is None:
        yield
        return
    with monitor.active_subprocess():
        yield
