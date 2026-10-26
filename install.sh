#!/bin/bash
# HackPilot shell script

# HackPilot Enterprise Installation Script
# Installs all dependencies for enterprise penetration testing platform
# Version: 2.0.0 (Production-Ready)

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Ensure we operate from repository root directory
SCRIPT_DIR="$(cd -- "$(case "${BASH_SOURCE[0]}" in */*) echo "${BASH_SOURCE[0]%/*}" ;; *) echo "." ;; esac)" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

INSTALL_CONTEXT="${HACKPILOT_INSTALL_CONTEXT:-host}"
case "$INSTALL_CONTEXT" in
    host)
        if [ "$(id -u)" -eq 0 ]; then
            ROOT=()
        elif command -v sudo >/dev/null 2>&1; then
            ROOT=(sudo)
        else
            error "'sudo' command not found and script is not running as root."
            error "Please install 'sudo' or run this script as root."
            exit 1
        fi
        ;;
    container)
        ROOT=()
        ;;
    *)
        error "Unsupported HACKPILOT_INSTALL_CONTEXT: $INSTALL_CONTEXT (expected host or container)"
        exit 2
        ;;
esac

run_root() {
    "${ROOT[@]}" "$@"
}

# Banner
echo -e "${PURPLE}"
echo "██╗  ██╗ █████╗  ██████╗██╗  ██╗██████╗ ██╗██╗      ██████╗ ████████╗"
echo "██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝"
echo "███████║███████║██║     █████╔╝ ██████╔╝██║██║     ██║   ██║   ██║   "
echo "██╔══██║██╔══██║██║     ██╔═██╗ ██╔═══╝ ██║██║     ██║   ██║   ██║   "
echo "██║  ██║██║  ██║╚██████╗██║  ██╗██║     ██║███████╗╚██████╔╝   ██║   "
echo "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝   "
echo -e "${NC}"
echo -e "${CYAN}Enterprise AI-Powered Penetration Testing Platform v2.0${NC}"
echo -e "${GREEN}Production-Ready | Cloud-Native | AI-Enhanced${NC}"
echo

# Update package metadata. A full host upgrade remains an explicit host-install action;
# container images should be reproducible from their declared base image instead.
if ! command -v apt-get >/dev/null 2>&1; then
    error "'apt-get' package manager not found. HackPilot installation requires a Debian/Ubuntu/Kali-based system."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Ensure basic core utilities and compiler symlinks are healthy (especially in PRoot environments)
if ! chgrp --version >/dev/null 2>&1 || ! readlink --version >/dev/null 2>&1; then
    if [ -x "/usr/bin/gnuchgrp" ] && [ -x "/usr/bin/gnureadlink" ]; then
        warn "Coreutils symlinks appear broken. Restoring GNU coreutils symlinks..."
        run_root ln -sf gnuchgrp /usr/bin/chgrp 2>/dev/null || true
        run_root ln -sf gnureadlink /usr/bin/readlink 2>/dev/null || true
    fi
fi

if [ -L "/usr/bin/cc" ] && ! /usr/bin/cc --version >/dev/null 2>&1; then
    if [ -x "/usr/bin/gcc-15" ]; then
        run_root ln -sf /usr/bin/gcc-15 /usr/bin/cc 2>/dev/null || true
    elif [ -x "/usr/bin/gcc" ]; then
        run_root ln -sf /usr/bin/gcc /usr/bin/cc 2>/dev/null || true
    fi
fi

echo "[+] Updating system packages..."
run_root apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=15 update
if [ "$INSTALL_CONTEXT" = "host" ]; then
    run_root apt-get upgrade -y
else
    info "Container install: skipping full distribution upgrade"
fi

# Docker installs requirements in a cacheable layer before copying the source tree.
# Keep the historical host installer behavior unchanged for direct installations.
if [ "$INSTALL_CONTEXT" = "host" ]; then
    echo "[+] Installing Python dependencies..."
    PIP_CMD=""
    if command -v pip3 >/dev/null 2>&1; then
        PIP_CMD="pip3"
    elif command -v pip >/dev/null 2>&1; then
        PIP_CMD="pip"
    elif command -v python3 >/dev/null 2>&1; then
        PIP_CMD="python3 -m pip"
    fi

    if [ -n "$PIP_CMD" ]; then
        BREAK_FLAG=""
        if [ -z "$VIRTUAL_ENV" ]; then
            if $PIP_CMD install --help 2>&1 | grep -q -- '--break-system-packages'; then
                BREAK_FLAG="--break-system-packages"
            fi
        fi
        $PIP_CMD install -r requirements.txt $BREAK_FLAG || warn "Some Python packages failed to install"
    else
        warn "pip/pip3 not found. Please install Python dependencies manually: pip install -r requirements.txt"
    fi
else
    info "Container install: Python dependencies are provided by the Docker requirements layer"
fi

# Install one apt package, retrying with fresh apt-get invocations (not just
# apt's internal --Retries, which keeps reconnecting to the SAME already-
# resolved mirror). Kali's CDN redirector occasionally hands a single file
# to a dead backend (seen repeatedly: mirror.us.cdn-perfprod.com); a brand
# new apt-get process re-resolves the redirector and usually lands on a
# different, reachable mirror.
install_tool() {
    tool="$1"
    attempt=1
    while [ "$attempt" -le 3 ]; do
        if run_root apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=15 install -y "$tool"; then
            return 0
        fi
        warn "Tool '$tool' install attempt $attempt/3 failed, retrying..."
        attempt=$((attempt + 1))
    done
    warn "Tool '$tool' could not be installed after 3 attempts (missing/unmet dependency or persistent mirror failure)"
    return 1
}

# Install available pentesting tools one at a time (skip unavailable ones).
# apt-get install pkg1 pkg2 ... is all-or-nothing: if ANY single package has
# an unmet dependency, NONE of them get installed. Looping installs each tool
# independently so one broken dependency chain (e.g. wireshark's Qt6 stack)
# doesn't silently take every other tool down with it.
echo "[+] Installing available pentesting tools..."
for tool in nmap masscan nikto gobuster sqlmap whatweb dnsenum whois \
    netcat-traditional curl wget git john tshark; do
    # hydra pulls ~15 extra libs (FreeRDP, MariaDB, memcached clients, etc.)
    # for protocols nothing we wire up brute-forces; on this flaky network
    # that's 15x the chances of hitting a dead mirror on one build. Add it
    # back if a phase needs online brute-forcing later.
    # wireshark (GUI, Qt6 widgets/multimedia), hashcat (full LLVM/Clang
    # toolchain + 64MB OpenCL runtime for its GPU JIT backend), and
    # aircrack-ng (pulls the same GTK/multimedia stack as wireshark via
    # airgraph-ng) each drag in several hundred MB nothing we wire up uses.
    # tshark (CLI) covers scripted packet capture; wireless auditing and GPU
    # cracking can be added later if a phase actually needs them.
    install_tool "$tool"
done

# Install additional security tools that are available
echo "[+] Installing additional security tools..."
EXIFTOOL_PKG="exiftool"
if ! apt-cache show exiftool >/dev/null 2>&1 && apt-cache show libimage-exiftool-perl >/dev/null 2>&1; then
    EXIFTOOL_PKG="libimage-exiftool-perl"
fi
for tool in binwalk foremost steghide "$EXIFTOOL_PKG" tcpdump ncat socat proxychains4; do
    install_tool "$tool"
done

# Sprint 1 recon/vuln tools (exploitation/tools/*). All ship as apt packages
# on current Kali; whatweb is already in the first loop above.
echo "[+] Installing Sprint 1 recon/vuln tools..."
for tool in subfinder amass nuclei testssl.sh wapiti; do
    install_tool "$tool"
done

# nuclei's own runtime template update (`nuclei -ut`, called once per Phase 3
# run from nuclei_runner.py) is unreliable in this environment - confirmed
# against a real target it silently fetched zero templates ("context deadline
# exceeded... while reading body") even with network egress working fine.
# Bundle the templates at build time instead so a scan always has something
# to run even if the runtime update keeps failing; nuclei_runner.py's -ut
# call still runs too, as a best-effort refresh on top of this baseline.
echo "[+] Bundling nuclei-templates (runtime -ut is unreliable here)..."
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git \
    /root/.local/nuclei-templates \
    || warn "Could not clone nuclei-templates - nuclei will have no templates until 'nuclei -ut' succeeds at runtime"

# Sprint 2 active-exploitation tools (gated at runtime by
# ENABLE_AUTO_EXPLOIT/ENABLE_ADVANCED_EXPLOITATION + ALLOWED_TARGETS -
# installing the binary doesn't turn anything on by itself).
# seclists installs under /usr/share/seclists/ (ffuf_runner.py's vhost
# wordlist default); dirb installs under /usr/share/dirb/wordlists/
# (ffuf_runner.py's dir-fuzzing default) - confirmed via `dpkg -L`, neither
# package uses /usr/share/wordlists/.
# metasploit-framework is large (~1GB+) - it's the one tool here the
# operator may reasonably want to skip on a constrained image; it is only
# ever driven through `check` on auxiliary/scanner modules (msf_check_runner.py).
echo "[+] Installing Sprint 2 active-exploitation tools..."
for tool in ffuf dirb seclists metasploit-framework; do
    install_tool "$tool"
done

# Local-model provisioning is a user-controlled host action. Baking a daemon and a
# multi-GB model download into the image build is non-deterministic and makes offline
# image builds impossible. The Workbench remains usable in deterministic no-AI mode.
if [ "$INSTALL_CONTEXT" = "host" ]; then
    echo "[+] Installing ollama for local AI support..."
    curl -fsSL https://ollama.ai/install.sh | sh || warn "Failed to install Ollama - you can install it manually from https://ollama.com"

    echo "[+] Starting ollama service..."
    ollama serve &
    OLLAMA_PID=$!
    sleep 5

    if kill -0 "$OLLAMA_PID" 2>/dev/null; then
        echo "[+] Downloading local AI model..."
        ollama pull llama2:7b || warn "Failed to download AI model - you can do this later with 'ollama pull llama2:7b'"
    else
        warn "Ollama service failed to start - you can start it manually with 'ollama serve'"
    fi
else
    info "Container install: skipping Ollama installer, daemon start and model download"
fi

# Create reports directory
echo "[+] Creating reports directory..."
mkdir -p reports
mkdir -p logs
mkdir -p templates
mkdir -p database/migrations

# Create configuration files
echo "[+] Creating configuration files..."
if [ ! -f "config.ini" ]; then
    cat > config.ini << 'EOF'
[app]
debug = false
log_level = INFO

[database]
url = postgresql://hackpilot:hackpilot123@localhost:5432/hackpilot

[cache]
redis_url = redis://localhost:6379/0

[ai]
openai_api_key = 
local_model = llama2:7b

[security]
secret_key = 
jwt_algorithm = HS256
jwt_expiry = 3600

[features]
enable_voice = true
enable_web_dashboard = true
enable_realtime_dashboard = true
EOF
    log "Configuration file created"
fi

# Create .env template if it doesn't exist
if [ ! -f ".env.example" ]; then
    cat > .env.example << 'EOF'
# HackPilot Enterprise Environment Variables
OPENAI_API_KEY=your_openai_api_key_here
DATABASE_URL=postgresql://hackpilot:hackpilot123@localhost:5432/hackpilot
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_key_here
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
EOF
    log "Environment template created"
fi

# Make scripts executable
for script in hackpilot.py hackpilot_v2.py advance_hackpilot.py demo.py install.sh usage_examples.sh test_installation.py; do
    [ -f "$script" ] && chmod +x "$script" || true
done

# Host installs keep the historical global command. Container entrypoints are declared
# by the image itself and do not need a host-style symlink.
if [ "$INSTALL_CONTEXT" = "host" ]; then
    echo "[+] Creating global command..."
    run_root ln -sf "$(pwd)/hackpilot.py" /usr/local/bin/hackpilot || warn "Failed to create global symlink"
else
    info "Container install: using the Docker entrypoint instead of a global symlink"
fi

echo ""
echo "✅ Installation Complete!"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    INSTALLATION COMPLETE                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo -e "  1. Copy ${YELLOW}.env.example${NC} to ${YELLOW}.env${NC} and configure your API keys"
echo -e "  2. Edit ${YELLOW}config.ini${NC} to customize settings"
echo -e "  3. Run HackPilot: ${YELLOW}python3 advance_hackpilot.py${NC}"
echo ""
echo "Usage:"
echo "  ./advance_hackpilot.py           # Interactive mode"
echo "  ./advance_hackpilot.py --web     # Web dashboard"
echo "  ./advance_hackpilot.py --voice   # Voice command mode"
echo "  hackpilot                        # Global command (if symlink created)"
echo ""
echo "Set OpenAI API key (optional):"
echo "  export OPENAI_API_KEY='your-api-key-here'"
echo ""
echo -e "${GREEN}Happy Hacking! 🚀${NC}"
