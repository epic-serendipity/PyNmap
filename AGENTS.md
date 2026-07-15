# AGENTS.md

## Cursor Cloud specific instructions

PyNmap is a Python 3.11+ CLI/TUI (Typer + Rich + InquirerPy) that orchestrates
the `nmap` binary via `subprocess`, parses its XML, and generates inventories,
HTML reports, and Graphviz network maps. It is a single local tool — there is no
server/backend/frontend split.

### Environment already provided by the startup update script
- A virtualenv lives at `.venv/` (gitignored). Activate it with
  `. .venv/bin/activate`, or call tools directly via `.venv/bin/<tool>`.
- The package is installed editable with dev extras (`pip install -e '.[dev,lxml]'`),
  so source edits under `src/pynmap/` take effect without reinstalling.

### Required system tools (installed in the VM image, NOT by the update script)
- `nmap` (required to run scans), `dot`/`graphviz` (network maps), and `xsltproc`
  (standard Nmap HTML reports). These are captured in the VM snapshot; if a fresh
  environment ever lacks them, install with
  `sudo apt-get install -y nmap graphviz xsltproc`.

### Commands
- Tests (this is the only automated check — there is no separate linter/formatter
  configured): `. .venv/bin/activate && python -m pytest` (see `pyproject.toml`
  `[tool.pytest.ini_options]`).
- Run the tool: `pynmap <subcommand>` (see README for `new`, `update`, `enhance`,
  `view`, `history`, `menu`). No args opens the interactive TUI menu.

### Non-obvious gotchas
- Privilege split matters. Scan-running commands (`new`/`update`/`enhance`) need
  root for raw-socket probes (SYN, UDP, OS detection, traceroute) — run them via
  `sudo .venv/bin/pynmap ...` (use the venv binary explicitly so sudo keeps the
  venv). Read-only commands (`view`, `history`) do not need root.
- The scan registry is per-user under `~/.local/share/pynmap/scans.db`. A scan
  run as root registers under root's home, so plain `pynmap history` (as the
  `ubuntu` user) will NOT list it; use `sudo .venv/bin/pynmap history` to see
  root-run scans. Override with `PYNMAP_DATA_HOME` / `PYNMAP_CONFIG_HOME` for
  isolated testing.
- Generated scan directories are self-contained; write them to a scratch dir
  (e.g. `/tmp/...`) via `-o`, not into the repo. Root-run scans produce
  root-owned files — clean up with `sudo rm -rf`.
- For a safe end-to-end smoke test, scan localhost:
  `echo 127.0.0.1 > /tmp/t.txt && sudo .venv/bin/pynmap new -t /tmp/t.txt -n Smoke -o /tmp/out --profile fast`.
- When run as root, PyNmap tries to open generated reports in a browser and may
  print a harmless Chromium "Running as root without --no-sandbox" error to
  stderr; it does not affect the scan.
