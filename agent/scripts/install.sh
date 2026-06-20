#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# CleanShift Server Agent — Installer
# ═══════════════════════════════════════════════════════════════
#
# Installs the CleanShift agent on a cPanel/WHM server.
#
# Usage:
#   curl -sL https://install.wpcleanshift.com | bash
#   # OR
#   bash install.sh
#
# Requirements:
#   - Python 3.9+
#   - pip
#   - Root access (for server-wide scanning)
#

set -euo pipefail

# ── Configuration ───────────────────────────────────────────────

INSTALL_DIR="${WPCLEANSHIFT_DIR:-/opt/wpcleanshift}"
VENV_DIR="${INSTALL_DIR}/venv"
AGENT_DIR="${INSTALL_DIR}/agent"
SERVICE_NAME="wpcleanshift-agent"
MIN_PYTHON_VERSION="3.9"

# ── Colors ──────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Helper Functions ────────────────────────────────────────────

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
error() { echo -e "${RED}✗${NC}  $*"; exit 1; }

banner() {
    echo -e "${BOLD}"
    echo "  ╔═══════════════════════════════════════════╗"
    echo "  ║  🛡️  CleanShift Server Agent Installer   ║"
    echo "  ╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Pre-flight Checks ──────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root. Some features may not work."
        warn "Run with sudo for full server-wide scanning capabilities."
    fi
}

check_python() {
    info "Checking Python version..."

    # Try python3 first, then python
    PYTHON_CMD=""
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
            if [[ -n "$version" ]]; then
                major=$(echo "$version" | cut -d. -f1)
                minor=$(echo "$version" | cut -d. -f2)

                if [[ "$major" -ge 3 ]] && [[ "$minor" -ge 9 ]]; then
                    PYTHON_CMD="$cmd"
                    ok "Found $cmd $version"
                    return 0
                fi
            fi
        fi
    done

    error "Python ${MIN_PYTHON_VERSION}+ is required but not found.
    Install Python 3.9+ and try again:
      - CentOS/RHEL: yum install python39
      - Ubuntu/Debian: apt install python3.9
      - CloudLinux: yum install alt-python39"
}

check_pip() {
    info "Checking pip..."
    if "$PYTHON_CMD" -m pip --version &>/dev/null; then
        ok "pip is available"
    else
        warn "pip not found, attempting to install..."
        "$PYTHON_CMD" -m ensurepip --upgrade 2>/dev/null || \
            error "Could not install pip. Install manually: $PYTHON_CMD -m ensurepip"
        ok "pip installed"
    fi
}

check_wp_cli() {
    info "Checking wp-cli..."
    if command -v wp &>/dev/null; then
        wp_version=$(wp --version 2>/dev/null || echo "unknown")
        ok "wp-cli found: $wp_version"
    else
        warn "wp-cli not found. Some scanning features will use fallbacks."
        warn "Install wp-cli: curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
        warn "               chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp"
    fi
}

# ── Installation ────────────────────────────────────────────────

install_agent() {
    info "Installing CleanShift agent to ${INSTALL_DIR}..."

    # Create installation directory
    mkdir -p "${INSTALL_DIR}"

    # Copy agent files
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(dirname "$SCRIPT_DIR")"

    if [[ -d "${REPO_ROOT}/src" ]]; then
        cp -r "${REPO_ROOT}/src" "${AGENT_DIR}/src" 2>/dev/null || true
        cp -r "${REPO_ROOT}/config" "${AGENT_DIR}/config" 2>/dev/null || true
        cp "${REPO_ROOT}/requirements.txt" "${AGENT_DIR}/" 2>/dev/null || true
        ok "Agent files copied"
    else
        warn "Source directory not found at ${REPO_ROOT}/src"
        warn "Make sure you're running this from the agent/scripts/ directory"
    fi

    # Copy intelligence directory
    INTEL_DIR="$(dirname "$REPO_ROOT")/intelligence"
    if [[ -d "${INTEL_DIR}" ]]; then
        cp -r "${INTEL_DIR}" "${INSTALL_DIR}/intelligence"
        ok "Intelligence database copied"
    else
        warn "Intelligence directory not found at ${INTEL_DIR}"
    fi

    # Copy scripts
    SCRIPTS_DIR="$(dirname "$REPO_ROOT")/scripts"
    if [[ -d "${SCRIPTS_DIR}" ]]; then
        mkdir -p "${INSTALL_DIR}/scripts"
        cp "${SCRIPTS_DIR}"/*.sh "${INSTALL_DIR}/scripts/" 2>/dev/null || true
        chmod +x "${INSTALL_DIR}/scripts/"*.sh 2>/dev/null || true
        ok "Scripts copied (daily-scan, post-migration-scan, health-check)"
    fi

    # Copy cPanel hooks
    HOOKS_DIR="$(dirname "$REPO_ROOT")/cpanel/hooks"
    if [[ -d "${HOOKS_DIR}" ]]; then
        mkdir -p "${INSTALL_DIR}/cpanel/hooks"
        cp "${HOOKS_DIR}"/*.sh "${INSTALL_DIR}/cpanel/hooks/" 2>/dev/null || true
        chmod +x "${INSTALL_DIR}/cpanel/hooks/"*.sh 2>/dev/null || true
        ok "cPanel hooks copied"
    fi

    # Setup log directories
    mkdir -p /var/log/wpcleanshift/{scans,health,reports}
    ok "Log directories created"
}

create_virtualenv() {
    info "Creating Python virtual environment..."

    if [[ -d "${VENV_DIR}" ]]; then
        warn "Virtual environment already exists at ${VENV_DIR}"
        read -rp "  Recreate? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "${VENV_DIR}"
        else
            info "Keeping existing virtualenv"
            return 0
        fi
    fi

    "$PYTHON_CMD" -m venv "${VENV_DIR}"
    ok "Virtual environment created at ${VENV_DIR}"
}

install_dependencies() {
    info "Installing Python dependencies..."

    local pip_cmd="${VENV_DIR}/bin/pip"
    local req_file="${AGENT_DIR}/requirements.txt"

    if [[ ! -f "$req_file" ]]; then
        req_file="${SCRIPT_DIR}/../requirements.txt"
    fi

    if [[ -f "$req_file" ]]; then
        "$pip_cmd" install --upgrade pip setuptools wheel --quiet
        "$pip_cmd" install -r "$req_file" --quiet
        ok "Dependencies installed"
    else
        error "requirements.txt not found"
    fi
}

setup_config() {
    info "Setting up configuration..."

    local config_file="${AGENT_DIR}/config/config.yaml"

    if [[ -f "$config_file" ]]; then
        # Generate unique agent ID if not set
        local agent_id
        agent_id=$(python3 -c "import uuid; print(str(uuid.uuid4())[:8])" 2>/dev/null || echo "agent-$(date +%s)")
        local hostname
        hostname=$(hostname -f 2>/dev/null || hostname)

        # Update config with this server's details
        "${VENV_DIR}/bin/python" -c "
import yaml
with open('${config_file}', 'r') as f:
    config = yaml.safe_load(f) or {}
config.setdefault('agent', {})
if not config['agent'].get('agent_id'):
    config['agent']['agent_id'] = '${agent_id}'
if not config['agent'].get('server_hostname'):
    config['agent']['server_hostname'] = '${hostname}'
config.setdefault('intelligence', {})
config['intelligence']['directory'] = '${INSTALL_DIR}/intelligence'
with open('${config_file}', 'w') as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
"
        ok "Configuration updated (agent_id=${agent_id}, hostname=${hostname})"
    else
        warn "Config file not found at ${config_file}"
    fi
}

create_wrapper_script() {
    info "Creating wrapper script..."

    cat > /usr/local/bin/wpcleanshift << EOF
#!/usr/bin/env bash
# CleanShift CLI wrapper
exec "${VENV_DIR}/bin/python" -m src.agent "\$@"
EOF

    chmod +x /usr/local/bin/wpcleanshift
    ok "CLI available as 'wpcleanshift' command"
}

setup_systemd_service() {
    if [[ ! -d /etc/systemd/system ]]; then
        info "systemd not available — skipping service setup"
        return 0
    fi

    read -rp "  Install as systemd service? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Skipping systemd service setup"
        return 0
    fi

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=CleanShift Security Agent
After=network.target mysql.service

[Service]
Type=simple
ExecStart=${VENV_DIR}/bin/python -m src.agent scan --server
WorkingDirectory=${AGENT_DIR}
Restart=on-failure
RestartSec=30
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    ok "systemd service installed and enabled"
    info "Start with: systemctl start ${SERVICE_NAME}"
}

# ── Main ────────────────────────────────────────────────────────

main() {
    banner
    echo ""

    check_root
    check_python
    check_pip
    check_wp_cli
    echo ""

    install_agent
    create_virtualenv
    install_dependencies
    setup_config
    echo ""

    # Only create wrapper and service if running as root
    if [[ $EUID -eq 0 ]]; then
        create_wrapper_script
        setup_systemd_service
    else
        info "Run as root to install the 'wpcleanshift' CLI command and systemd service"
    fi

    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  ✅ CleanShift agent installed successfully!  ${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════${NC}"
    echo ""
    echo "  Quick start:"
    echo "    wpcleanshift status                    # Check agent status"
    echo "    wpcleanshift scan --site /path/to/wp   # Scan a single site"
    echo "    wpcleanshift scan --server             # Scan all sites (detect + clean)"
    echo ""
    echo "  Configuration: ${AGENT_DIR}/config/config.yaml"
    echo "  Intelligence:  ${INSTALL_DIR}/intelligence/"
    echo ""

    # ── Setup daily cron ──
    if [[ $EUID -eq 0 ]]; then
        info "Setting up daily scan cron job..."
        CRON_CMD="0 3 * * * ${INSTALL_DIR}/scripts/daily-scan.sh >> /var/log/wpcleanshift/cron.log 2>&1"
        if crontab -l 2>/dev/null | grep -q "daily-scan.sh"; then
            ok "Daily scan cron already exists"
        else
            (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
            ok "Daily scan cron installed (3:00 AM)"
        fi
    fi

    # ── Verify installation ──
    info "Running verification scan..."
    if "${VENV_DIR}/bin/python" -m src.agent status 2>&1 | grep -q "CleanShift"; then
        ok "Agent responds correctly"
    else
        warn "Agent may not be configured correctly — run 'wpcleanshift status' to check"
    fi

}

main "$@"
