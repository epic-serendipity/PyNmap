"""The non-root launch warning and WSL detection."""

from pynmap import cli
from pynmap import runner
from pynmap.runner import privilege_warning_lines


def test_privilege_warning_mentions_sudo(monkeypatch):
    monkeypatch.setattr(runner, "is_wsl", lambda: False)
    lines = privilege_warning_lines()
    joined = " ".join(lines)
    assert "not running as root" in lines[0]
    assert "sudo pynmap" in joined
    # No WSL-specific guidance when not on WSL.
    assert not any("WSL" in line for line in lines)


def test_privilege_warning_adds_wsl_note(monkeypatch):
    monkeypatch.setattr(runner, "is_wsl", lambda: True)
    lines = privilege_warning_lines()
    assert any("WSL" in line for line in lines)


def test_cli_warns_when_not_root(monkeypatch, capsys):
    monkeypatch.setattr(runner, "is_root", lambda: False)
    monkeypatch.setattr(runner, "is_wsl", lambda: False)
    cli._warn_if_unprivileged()
    err = capsys.readouterr().err
    assert "Warning:" in err
    assert "sudo pynmap" in err


def test_cli_silent_when_root(monkeypatch, capsys):
    monkeypatch.setattr(runner, "is_root", lambda: True)
    cli._warn_if_unprivileged()
    assert capsys.readouterr().err == ""


def test_is_wsl_reads_proc_version(monkeypatch, tmp_path):
    fake = tmp_path / "version"
    fake.write_text("Linux version 5.15.0-microsoft-standard-WSL2", encoding="utf-8")
    monkeypatch.setattr(runner, "Path", lambda _p: fake)
    assert runner.is_wsl() is True

    fake.write_text("Linux version 6.1.0-generic", encoding="utf-8")
    assert runner.is_wsl() is False
