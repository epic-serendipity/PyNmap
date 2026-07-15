"""Safe execution of external commands (Nmap, dot, xsltproc).

Commands are always passed as an argument list -- never a shell string -- so
user-controlled paths cannot cause command injection or quoting problems.
PyNmap is meant to be launched with the privileges its scans require (i.e.
``sudo pynmap``), so privileged Nmap operations run directly and inherit the
process's root privileges rather than being individually prefixed with
``sudo``. The runner also handles:

* Root/privilege detection.
* Ctrl+C handling: the active child is terminated, the partial output is left
  in place, and a :class:`ScanInterrupted` is raised so callers can mark the
  operation cancelled instead of complete.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from . import progress


class ScanInterrupted(Exception):
    """Raised when the user interrupts a running command with Ctrl+C."""


#: Hint shown when a privileged scan is requested without root privileges.
SUDO_HINT = "run PyNmap as root, e.g. `sudo pynmap`"


@dataclass
class CommandResult:
    command: list[str]
    return_code: int
    started_at: str
    finished_at: str
    log_file: Optional[str] = None
    stdout: str = ""

    @property
    def ok(self) -> bool:
        return self.return_code == 0


def is_root() -> bool:
    """True when the current process has effective UID 0."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def has_command(name: str) -> bool:
    return shutil.which(name) is not None


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def run_command(
    command: Sequence[str],
    *,
    log_file: Optional[Path] = None,
    check: bool = False,
    capture: bool = False,
    cwd: Optional[Path] = None,
) -> CommandResult:
    """Run ``command`` as an argument list.

    Output is streamed to ``log_file`` when provided; otherwise, if ``capture``
    is True the combined stdout/stderr is returned in the result. Ctrl+C stops
    the child process and raises :class:`ScanInterrupted`.
    """
    cmd = list(command)
    started_at = _now_iso()
    stdout_text = ""

    log_handle = None
    proc: Optional[subprocess.Popen] = None
    try:
        if log_file is not None:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            log_handle = log_file.open("a", encoding="utf-8")
            log_handle.write(f"\n$ {' '.join(cmd)}\n")
            log_handle.flush()
            stdout_target = log_handle
            stderr_target = subprocess.STDOUT
        elif capture:
            stdout_target = subprocess.PIPE
            stderr_target = subprocess.STDOUT
        else:
            stdout_target = None
            stderr_target = None

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=stderr_target,
            text=True,
            cwd=str(cwd) if cwd else None,
        )
        try:
            # Spin the ASCII progress indicator (and listen for the spacebar)
            # while the child command runs. This is a no-op when no interactive
            # monitor is active.
            with progress.active_subprocess():
                out, _ = proc.communicate()
        except KeyboardInterrupt:
            _terminate(proc)
            raise ScanInterrupted(" ".join(cmd))
        if capture and out:
            stdout_text = out
    finally:
        if log_handle is not None:
            log_handle.close()

    finished_at = _now_iso()
    result = CommandResult(
        command=cmd,
        return_code=proc.returncode if proc else -1,
        started_at=started_at,
        finished_at=finished_at,
        log_file=str(log_file) if log_file else None,
        stdout=stdout_text,
    )
    if check and not result.ok:
        raise subprocess.CalledProcessError(result.return_code, cmd)
    return result


def _terminate(proc: subprocess.Popen) -> None:
    """Terminate a child process (and its group) as gracefully as possible."""
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
            except OSError:
                pass
