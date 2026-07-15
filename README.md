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
- **Nmap orchestration** via argument lists (never `shell=True`), with optional
  `sudo` prefixing only for privileged scans.
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
- **Resumable**: operation states (`pending`/`running`/`complete`/`failed`/
  `cancelled`/`stale`) are written immediately; Ctrl+C stops the active Nmap
  process, marks the operation cancelled, and preserves partial files.

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

```bash
python3 -m pip install .
# or, for development:
python3 -m pip install -e '.[dev]'
```

This installs the `pynmap` command.

## Usage

Run with no arguments to open the interactive menu:

```bash
pynmap
```

Or use the direct subcommands:

```bash
pynmap new                              # interactive prompts
pynmap new -t targets.txt -n MyScan -o /out --profile recommended
pynmap update /path/to/scan
pynmap enhance /path/to/scan --operations udp_top_50,tcp_full
pynmap view /path/to/scan
pynmap history
```

### Privileges

SYN (`-sS`), UDP (`-sU`), OS detection (`-O`), and traceroute need root.
PyNmap runs the Python program as your normal user and prefixes only the
privileged Nmap commands with `sudo`, so project files stay owned by you. Run
with passwordless `sudo` configured for a smooth experience, or launch the whole
program with `sudo` if you prefer.

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

## Project layout

```
src/pynmap/
├── main.py cli.py config.py models.py paths.py manifest.py
├── registry.py runner.py engine.py profiles.py log.py
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
