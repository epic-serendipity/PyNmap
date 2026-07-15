"""Interactive prompts: paths, operation checkboxes, profiles, confirmations.

Wraps InquirerPy so the rest of the UI can request input without depending on
its API directly. If InquirerPy is unavailable, falls back to plain ``input``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from ..operations import REGISTRY
from ..profiles import all_profiles

try:  # pragma: no cover - interactive dependency
    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice
    _HAS_INQUIRER = True
except ImportError:  # pragma: no cover
    inquirer = None  # type: ignore
    Choice = None  # type: ignore
    _HAS_INQUIRER = False


def prompt_text(message: str, default: str = "") -> str:
    if _HAS_INQUIRER:
        return inquirer.text(message=message, default=default).execute()
    raw = input(f"{message} [{default}]: ").strip()
    return raw or default


def prompt_path(message: str, default: str = "", only_directories: bool = False) -> str:
    if _HAS_INQUIRER:
        return inquirer.filepath(
            message=message,
            default=default,
            only_directories=only_directories,
        ).execute()
    raw = input(f"{message} [{default}]: ").strip()
    return raw or default


def prompt_confirm(message: str, default: bool = True) -> bool:
    if _HAS_INQUIRER:
        return inquirer.confirm(message=message, default=default).execute()
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{message} ({suffix}): ").strip().lower()
    if not raw:
        return default
    return raw.startswith("y")


def prompt_operations(preselected: Sequence[str]) -> list[str]:
    """Checkbox selection of operations, honouring previous selection."""
    preselected = set(preselected)
    if _HAS_INQUIRER:
        choices = [
            Choice(
                value=op.id,
                name=f"{op.display_name} - {op.description}",
                enabled=op.id in preselected,
            )
            for op in REGISTRY.values()
            if not op.is_modifier or op.id in ("service_detection",)
        ]
        result = inquirer.checkbox(
            message="Select operations (space to toggle, enter to confirm):",
            choices=choices,
            cycle=True,
            transformer=lambda res: f"{len(res)} selected",
        ).execute()
        return list(result)
    # Fallback: accept everything preselected.
    print("Operations:")
    for op in REGISTRY.values():
        mark = "X" if op.id in preselected else " "
        print(f"  [{mark}] {op.id}: {op.display_name}")
    raw = input("Comma-separated operation ids (blank = keep preselected): ").strip()
    if not raw:
        return list(preselected)
    return [tok.strip() for tok in raw.split(",") if tok.strip()]


def prompt_profile() -> Optional[str]:
    profiles = all_profiles()
    if _HAS_INQUIRER:
        choices = [Choice(value=None, name="Custom (choose operations manually)")]
        choices += [
            Choice(value=p.id, name=f"{p.name} - {p.description}") for p in profiles
        ]
        return inquirer.select(
            message="Choose a scan profile:", choices=choices, default=None
        ).execute()
    print("Profiles:")
    print("  0) Custom")
    for idx, prof in enumerate(profiles, start=1):
        print(f"  {idx}) {prof.name}: {prof.description}")
    raw = input("Select profile [0]: ").strip()
    if not raw or raw == "0":
        return None
    try:
        return profiles[int(raw) - 1].id
    except (ValueError, IndexError):
        return None


def prompt_select(message: str, options: list[tuple[str, str]], default=None):
    """Generic single-select. ``options`` is a list of (value, label)."""
    if _HAS_INQUIRER:
        choices = [Choice(value=value, name=label) for value, label in options]
        return inquirer.select(message=message, choices=choices, default=default).execute()
    print(message)
    for idx, (_value, label) in enumerate(options, start=1):
        print(f"  {idx}) {label}")
    raw = input("Select: ").strip()
    try:
        return options[int(raw) - 1][0]
    except (ValueError, IndexError):
        return default
