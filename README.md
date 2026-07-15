# PyNmap

PyNmap is an interactive **CLI/TUI** that orchestrates [Nmap](https://nmap.org/)
through `subprocess`, parses Nmap XML into a normalised internal model, keeps
portable per-scan metadata, compares runs over time, and generates reports and
Graphviz network maps.

It is designed for network reconnaissance / CTF-style workflows on Kali, WSL,
and headless SSH sessions: a good terminal interface that still opens SVG and
HTML files in Windows or a Linux desktop when available.

```
PyNmap

[1] New scan
[2] Update existing scan
[3] Enhance existing scan
[4] View scan results
[5] Scan history
[6] Settings
[7] Exit
```

## Features

- **Interactive menu** (Rich + InquirerPy) *and* scriptable subcommands (Typer).
- **Nmap orchestration** via argument lists (never `shell=True`); run the tool
  as root (`sudo pynmap`) so its privileged scans can use raw sockets.
- **Nmap XML is the source of truth** — normalised into an internal
  host/port/OS/route model, then exported to JSON, CSV, HTML, and Graphviz.
- **Portable projects**: every scan directory is self-contained with a
  `manifest.json` that identifies it as a valid PyNmap project.
- **Global SQLite registry** of all scans, with relocate / missing tracking.
- **Operations as independent modules** with dependencies resolved
  automatically (only real prerequisites are added — never unrelated scans).
- **Update & diff**: rerun mutable operations, archive prior results, and
  produce host/port/service/hostname/OS/route change reports.
- **Enhance**: add missing operations against the existing live-host list
  without redundantly rescanning completed work.
- **Scan profiles**: recommended, fast, comprehensive, and passive
  (regenerate reports from existing XML only).
- **Reporting runs last**: operations are ordered so every data-collection
  scan finishes before the inventory, HTML report, and network map are built.
  Generating the graphic is the very last step, so the map always reflects
  *all* data the run gathered (OS guesses, service versions, UDP ports,
  MAC/vendor, NSE script output, and traceroute paths) regardless of the order
  operations were requested in.
- **Two network-map styles**: an `enhanced` map (default) with per-host
  HTML-table nodes — colour-coded open TCP/UDP ports, service versions, OS,
  MAC, NSE scripts, per-/24 subnet grouping, a legend, and a scan-coverage
  node — and a compact `standard` text-label map. Toggle in **Settings**
  (`map_style`).
- **Resumable**: operation states (`pending`/`running`/`complete`/`failed`/
  `cancelled`/`stale`) are written immediately; Ctrl+C stops the active Nmap
  process, marks the operation cancelled, and preserves partial files.
- **Live progress feedback**: while an operation runs, an ASCII loading spinner
  shows work is happening, and pressing **space** prints a brief Nmap-style
  progress report (elapsed time, current operation, and what is left). This is
  automatic in an interactive terminal and can be toggled in **Settings**
  (`show_progress`); it is skipped for non-interactive output (pipes/logs).

## Requirements

- Python **3.11+**
- Python packages: `typer`, `rich`, `InquirerPy` (`lxml` optional, used if present)
- System tools: `nmap` (required), `graphviz` (`dot`, for maps),
  `xsltproc` (for standard Nmap HTML reports)

```bash
python3 -m pip install typer rich InquirerPy
sudo apt install -y nmap graphviz xsltproc
```

## Installation

### Quick install (Linux & WSL)

The bundled installer sets up the system tools (`nmap`, `graphviz`,
`xsltproc`) and the `pynmap` command in one step. Run it as your normal user
(it uses `sudo` only for the system-package step):

```bash
git clone <this-repo> && cd PyNmap
./install.sh
```

The installer auto-detects your package manager (apt, dnf/yum, pacman, zypper,
apk) and installs PyNmap with `pipx` when available, otherwise into a
self-contained virtualenv at `.venv/` linked onto your `PATH` at
`~/.local/bin/pynmap`. Useful flags:

```bash
./install.sh --method venv   # force a virtualenv install
./install.sh --method pipx   # force a pipx install
./install.sh --dev           # editable install with dev + lxml extras
./install.sh --skip-system   # leave system packages untouched
```

### Manual install

```bash
python3 -m pip install .
# or, for development:
python3 -m pip install -e '.[dev]'
```

This installs the `pynmap` command.

### Windows Subsystem for Linux (WSL)

PyNmap is designed to run comfortably under WSL. Install it inside your WSL
distribution with `./install.sh` (or the manual steps above) and run scans
from the WSL shell. Generated SVG maps and HTML reports open in your Windows
default browser automatically via `explorer.exe`; you can change the opener in
**Settings** (`wsl_browser_command`). The installer detects WSL and prints
these notes for you.

### The non-root warning

Because its scans need raw sockets, PyNmap warns the moment you launch it
without root — both in the interactive menu and before the `new`, `update`,
and `enhance` subcommands — and reminds you to re-run with `sudo pynmap`.
Read-only commands (`view`, `history`) never need root and are not gated.

## Usage

Run with no arguments to open the interactive menu:

```bash
sudo pynmap
```

Or use the direct subcommands:

```bash
sudo pynmap new                              # interactive prompts
sudo pynmap new -t targets.txt -n MyScan -o /out --profile recommended
sudo pynmap update /path/to/scan
sudo pynmap enhance /path/to/scan --operations udp_top_50,tcp_full
pynmap view /path/to/scan                    # read-only; no root needed
pynmap history                               # read-only; no root needed
```

### Privileges

**Run PyNmap as root — `sudo pynmap`.** Host discovery (its ICMP/`-PE`/`-PP`,
TCP ACK `-PA`, and UDP `-PU` ping probes), SYN (`-sS`), UDP (`-sU`), OS detection
(`-O`), and traceroute all need raw sockets, which require root. Running them
unprivileged makes Nmap silently downgrade to TCP connect() probes, which report
false-positive live hosts and unreliable results.

PyNmap assumes it is launched with the privileges its scans need, so it runs the
Nmap commands directly (no per-command `sudo` prefixing). If a scan-running
command is invoked without root, the privileged operations are skipped with a
notice to re-run with `sudo pynmap`. Read-only commands (`view`, `history`) do
not need root. Because the whole program runs as root, generated scan files are
owned by root; use `sudo chown` afterwards if you need them owned by your user.

## Generated scan directory

Each scan is self-contained and portable:

```
MyNetworkScan/
├── manifest.json          # identifies a valid PyNmap project
├── input/                 # original + normalised targets, live hosts
├── discovery/             # host discovery Nmap output (.nmap/.gnmap/.xml)
├── tcp/ udp/ os/ traceroute/   # per-protocol canonical output
├── inventory/             # hosts.json, hosts.csv, services.csv, routes.json
├── reports/               # scan-report.html, changes.html, summary.txt
├── maps/                  # network-map.dot/.svg/.png
├── changes/               # latest-diff.json/.txt + history/
├── runs/<timestamp>/      # run.json (exact commands) + logs, archived outputs
└── logs/pynmap.log
```

Raw Nmap XML is treated as **immutable**: updates archive the prior canonical
outputs under the new `runs/<timestamp>/previous/` before regenerating.

## State locations

- Config: `~/.config/pynmap/config.json`
- Registry: `~/.local/share/pynmap/scans.db`

Both honour `XDG_CONFIG_HOME` / `XDG_DATA_HOME`, and can be overridden for
testing with `PYNMAP_CONFIG_HOME` / `PYNMAP_DATA_HOME`.

## Operations & dependencies

| ID | Operation | Depends on |
|----|-----------|-----------|
| `discovery` | Host discovery | — |
| `tcp_top_1000` | Common TCP ports | discovery |
| `service_detection` | TCP service detection (`-sV`) | tcp_top_1000 |
| `tcp_full` | Full TCP port scan | discovery |
| `udp_top_50` | Common UDP ports | discovery |
| `os_detection` | OS detection | discovery |
| `traceroute` | Traceroute | discovery |
| `inventory` | Build host inventory | discovery, tcp_top_1000 |
| `html_report` | Generate HTML report | tcp_top_1000 |
| `network_map` | Generate network map | discovery, inventory, traceroute |

Selecting an operation automatically pulls in its prerequisites. For example,
selecting **Network map** re-selects discovery, inventory, and traceroute.

Operations also carry a run-order priority so that, whatever set is selected,
data-collection scans always run before the derived outputs. The inventory is
built after every scan, then the HTML report, and finally the network map —
ensuring the graphic captures everything the run collected. Only genuine
prerequisites are ever added: requesting the map does **not** silently pull in
unrelated scans such as OS detection or UDP.

## Project layout

```
src/pynmap/
├── main.py cli.py config.py models.py paths.py manifest.py
├── registry.py runner.py engine.py profiles.py log.py progress.py
├── operations/   # base + discovery/tcp/udp/os_detection/traceroute/reports/mapping
├── parsers/      # nmap_xml, targets
├── comparison/   # diff, models
├── reporting/    # inventory, html, graphviz
└── ui/           # menus, selections, viewer
```

## Development

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest
```

## License

MIT
