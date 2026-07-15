#!/usr/bin/env bash
#
# PyNmap installer for Linux (including WSL).
#
# Installs the system tools PyNmap orchestrates (nmap, graphviz, xsltproc) and
# the `pynmap` command itself, then prints how to use it. Designed to be run as
# your normal user (it uses `sudo` only for the package-manager step):
#
#     ./install.sh              # auto: pipx if available, else a virtualenv
#     ./install.sh --method venv
#     ./install.sh --method pipx
#     ./install.sh --dev        # editable install with dev + lxml extras
#     ./install.sh --skip-system # don't touch system packages
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_DIR="$SCRIPT_DIR"
VENV_DIR="$REPO_DIR/.venv"
BIN_DIR="${HOME}/.local/bin"

METHOD="auto"
DEV=0
SKIP_SYSTEM=0

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
info()  { printf '%s==>%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s!  %s%s\n' "$YELLOW" "$*" "$RESET"; }
error() { printf '%sxx %s%s\n' "$RED" "$*" "$RESET" >&2; }

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --method) METHOD="${2:-}"; shift 2 ;;
        --method=*) METHOD="${1#*=}"; shift ;;
        --dev) DEV=1; shift ;;
        --skip-system) SKIP_SYSTEM=1; shift ;;
        -h|--help) usage 0 ;;
        *) error "Unknown option: $1"; usage 1 ;;
    esac
done

# --- sanity checks ---------------------------------------------------------

if [ "$(uname -s)" != "Linux" ]; then
    error "PyNmap's installer targets Linux (including WSL). Detected: $(uname -s)."
    exit 1
fi

is_wsl() { grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; }
if is_wsl; then
    info "Windows Subsystem for Linux detected."
fi

# Run privileged commands with sudo only when we are not already root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

# --- system dependencies ---------------------------------------------------

install_system_deps() {
    if [ "$SKIP_SYSTEM" -eq 1 ]; then
        warn "Skipping system package installation (--skip-system)."
        return
    fi
    local pm
    if command -v apt-get >/dev/null 2>&1; then pm=apt
    elif command -v dnf >/dev/null 2>&1;    then pm=dnf
    elif command -v yum >/dev/null 2>&1;    then pm=yum
    elif command -v pacman >/dev/null 2>&1; then pm=pacman
    elif command -v zypper >/dev/null 2>&1; then pm=zypper
    elif command -v apk >/dev/null 2>&1;    then pm=apk
    else
        warn "No supported package manager found. Install nmap, graphviz and"
        warn "xsltproc manually, then re-run with --skip-system."
        return
    fi

    info "Installing system tools (nmap, graphviz, xsltproc) via $pm ..."
    case "$pm" in
        apt)
            $SUDO apt-get update -y
            $SUDO apt-get install -y nmap graphviz xsltproc python3 python3-venv python3-pip
            ;;
        dnf)  $SUDO dnf install -y nmap graphviz libxslt python3 python3-pip ;;
        yum)  $SUDO yum install -y nmap graphviz libxslt python3 python3-pip ;;
        pacman) $SUDO pacman -Sy --needed --noconfirm nmap graphviz libxslt python python-pip ;;
        zypper) $SUDO zypper install -y nmap graphviz libxslt-tools python3 python3-pip ;;
        apk)  $SUDO apk add --no-cache nmap graphviz libxslt python3 py3-pip ;;
    esac
}

# --- python / pynmap install ----------------------------------------------

check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        error "python3 not found. Install Python 3.11+ and re-run."
        exit 1
    fi
    if ! python3 - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
    then
        error "Python 3.11+ is required (found $(python3 -V 2>&1))."
        exit 1
    fi
}

install_via_venv() {
    info "Creating virtualenv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
    if [ "$DEV" -eq 1 ]; then
        "$VENV_DIR/bin/pip" install -e "$REPO_DIR[dev,lxml]"
    else
        "$VENV_DIR/bin/pip" install "$REPO_DIR"
    fi
    mkdir -p "$BIN_DIR"
    ln -sf "$VENV_DIR/bin/pynmap" "$BIN_DIR/pynmap"
    info "Linked $BIN_DIR/pynmap -> $VENV_DIR/bin/pynmap"
    INSTALLED_BIN="$BIN_DIR/pynmap"
}

install_via_pipx() {
    if ! command -v pipx >/dev/null 2>&1; then
        info "pipx not found; installing it for the current user ..."
        python3 -m pip install --user pipx >/dev/null
        python3 -m pipx ensurepath >/dev/null 2>&1 || true
    fi
    local pipx_cmd
    pipx_cmd="$(command -v pipx || echo "python3 -m pipx")"
    if [ "$DEV" -eq 1 ]; then
        $pipx_cmd install --force --editable "$REPO_DIR"
    else
        $pipx_cmd install --force "$REPO_DIR"
    fi
    INSTALLED_BIN="$(command -v pynmap || echo "$HOME/.local/bin/pynmap")"
}

check_python
install_system_deps

case "$METHOD" in
    auto)
        if command -v pipx >/dev/null 2>&1; then install_via_pipx; else install_via_venv; fi
        ;;
    venv) install_via_venv ;;
    pipx) install_via_pipx ;;
    *) error "Unknown --method: $METHOD (use auto, venv or pipx)"; exit 1 ;;
esac

# --- post-install guidance -------------------------------------------------

echo
info "${BOLD}PyNmap installed.${RESET}"

if ! command -v pynmap >/dev/null 2>&1; then
    warn "'$BIN_DIR' is not on your PATH yet. Add it with:"
    echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
fi

cat <<EOF

${BOLD}Usage${RESET}
  Run scans as root so raw-socket probes work:
    sudo pynmap                         # interactive menu
    sudo pynmap new -t targets.txt -n MyScan -o ./out --profile recommended

  Read-only commands do not need root:
    pynmap view ./out/MyScan
    pynmap history

  Tip: to keep a virtualenv's binary under sudo, use:
    sudo \$(command -v pynmap) ...
EOF

if is_wsl; then
    cat <<EOF

${BOLD}WSL notes${RESET}
  * Run the commands above from your WSL (Linux) shell.
  * Generated SVG/HTML reports open in your Windows default browser
    automatically (via explorer.exe); change the opener in Settings if needed.
EOF
fi
