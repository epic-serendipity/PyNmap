"""Program entry point.

With no arguments, PyNmap opens the interactive menu. With arguments, it
dispatches to the Typer CLI so the tool remains scriptable.
"""

from __future__ import annotations

import sys

from .cli import app
from .paths import ensure_user_dirs


def main() -> None:
    ensure_user_dirs()
    if len(sys.argv) == 1:
        from .ui.menus import main_menu

        main_menu()
        return
    app()


if __name__ == "__main__":
    main()
