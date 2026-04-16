#!/bin/bash
# ============================================================
#  Cyberburg — Installation Script
#  Developer: Faiz Zyhon
#  GitHub: github.com/faizzyhon
#  Website: faizzyhon.online
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
cat << 'EOF'
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗██████╗  ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝██║  ███╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██║   ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝██║  ██║╚██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
                    Advanced Web Penetration Testing Suite
                  Developer: Faiz Zyhon | github.com/faizzyhon
EOF
}

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  ◆  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${NC}\n"; }

# ── Check root ────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warning "Not running as root — some tools may require sudo"
        warning "Re-run with: sudo bash install.sh"
    else
        success "Running as root"
    fi
}

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt-get"
        PKG_INSTALL="apt-get install -y"
        info "Package manager: apt-get (Debian/Ubuntu/Kali)"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        PKG_INSTALL="dnf install -y"
        info "Package manager: dnf (Fedora/CentOS/RHEL)"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
        PKG_INSTALL="pacman -S --noconfirm"
        info "Package manager: pacman (Arch Linux)"
    else
        error "No supported package manager found"
        exit 1
    fi
}

# ── Install apt packages ──────────────────────────────────────────────────────
install_apt_tools() {
    section "Installing APT Tools"

    APT_PACKAGES=(
        "python3"
        "python3-pip"
        "nmap"
        "nikto"
        "sqlmap"
        "gobuster"
        "dirb"
        "ffuf"
        "wpscan"
        "sslscan"
        "whatweb"
        "whois"
        "dnsutils"
        "curl"
        "wget"
        "openssl"
        "hydra"
        "amass"
        "theharvester"
        "dnsenum"
        "netcat-traditional"
        "wfuzz"
        "net-tools"
        "git"
        "golang-go"
    )

    info "Updating package lists..."
    $PKG_MGR update -qq 2>/dev/null

    for pkg in "${APT_PACKAGES[@]}"; do
        if command -v "${pkg}" &>/dev/null || dpkg -l "${pkg}" &>/dev/null 2>&1; then
            success "${pkg} — already installed"
        else
            info "Installing ${pkg}..."
            if $PKG_INSTALL "${pkg}" -qq &>/dev/null 2>&1; then
                success "${pkg} — installed"
            else
                warning "${pkg} — installation failed (may not be in repos)"
            fi
        fi
    done
}

# ── Install Python packages ────────────────────────────────────────────────────
install_python_packages() {
    section "Installing Python Packages"

    PIP_PACKAGES=(
        "rich"
        "requests"
        "wafw00f"
        "sublist3r"
        "wfuzz"
        "shodan"
        "fierce"
        "dnspython"
        "beautifulsoup4"
        "urllib3"
    )

    for pkg in "${PIP_PACKAGES[@]}"; do
        info "pip3 install ${pkg}..."
        pip3 install "${pkg}" -q 2>/dev/null && success "${pkg} installed" || warning "${pkg} failed"
    done
}

# ── Install Go tools ───────────────────────────────────────────────────────────
install_go_tools() {
    section "Installing Go-Based Tools"

    if ! command -v go &>/dev/null; then
        warning "Go not found — skipping Go tools"
        warning "Install Go: https://go.dev/dl/"
        return
    fi

    info "Go found: $(go version)"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"

    GO_TOOLS=(
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/tomnomnom/httprobe@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
    )

    for tool in "${GO_TOOLS[@]}"; do
        tool_name=$(basename "${tool}" | cut -d'@' -f1)
        info "Installing ${tool_name}..."
        if go install "${tool}" 2>/dev/null; then
            success "${tool_name} installed"
        else
            warning "${tool_name} installation failed"
        fi
    done

    # Add Go bin to PATH permanently
    if ! grep -q 'export PATH.*go/bin' ~/.bashrc 2>/dev/null; then
        echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
        info "Added Go bin to PATH in ~/.bashrc"
    fi
}

# ── Install Cyberburg Python requirements ─────────────────────────────────────
install_requirements() {
    section "Installing Cyberburg Requirements"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        info "Installing from requirements.txt..."
        pip3 install -r "${SCRIPT_DIR}/requirements.txt" -q
        success "Requirements installed"
    fi

    # Create reports directory
    mkdir -p "${SCRIPT_DIR}/reports"
    success "Reports directory created"

    # Make executable
    chmod +x "${SCRIPT_DIR}/cyberburg.py"
    success "cyberburg.py made executable"

    # Create symlink
    if [[ -w /usr/local/bin ]]; then
        ln -sf "${SCRIPT_DIR}/cyberburg.py" /usr/local/bin/cyberburg 2>/dev/null
        success "Symlink created: /usr/local/bin/cyberburg"
    fi
}

# ── SecLists ─────────────────────────────────────────────────────────────────
install_seclists() {
    section "Installing SecLists Wordlists"

    if [[ -d /usr/share/seclists ]]; then
        success "SecLists already installed"
        return
    fi

    if $PKG_INSTALL seclists -qq &>/dev/null 2>&1; then
        success "SecLists installed via package manager"
    elif command -v git &>/dev/null; then
        info "Cloning SecLists from GitHub..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
            /usr/share/seclists 2>/dev/null && success "SecLists cloned" || warning "SecLists clone failed"
    else
        warning "Could not install SecLists"
    fi
}

# ── Verify installation ───────────────────────────────────────────────────────
verify_install() {
    section "Verification"

    CRITICAL_TOOLS=("python3" "nmap" "nikto" "sqlmap" "curl" "whois" "dig" "openssl")

    all_good=true
    for tool in "${CRITICAL_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            success "${tool} ✓"
        else
            error "${tool} ✗ — MISSING"
            all_good=false
        fi
    done

    echo ""
    if $all_good; then
        success "All critical tools installed!"
    else
        warning "Some critical tools are missing — Cyberburg will still run with available tools"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    clear
    banner
    echo ""

    check_root
    detect_os
    install_apt_tools
    install_python_packages
    install_go_tools
    install_seclists
    install_requirements
    verify_install

    echo ""
    section "Installation Complete!"
    success "Cyberburg is ready to use!"
    echo ""
    info "Usage:"
    echo "    python3 cyberburg.py              # Interactive menu"
    echo "    python3 cyberburg.py -t TARGET    # Scan a target"
    echo "    python3 cyberburg.py --help       # Show help"
    echo "    cyberburg                          # If symlink created"
    echo ""
    info "Developer: Faiz Zyhon"
    info "GitHub: github.com/faizzyhon"
    info "Website: faizzyhon.online"
    echo ""
    echo -e "${RED}${BOLD}⚠  Always get written authorization before testing!${NC}"
    echo ""
}

main "$@"
