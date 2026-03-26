#!/usr/bin/env bash
# WardenStrike - Security Tools Installer
# Installs required and optional pentesting tools
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

install_go_tool() {
    local name="$1"
    local pkg="$2"

    if command -v "$name" &>/dev/null; then
        success "$name already installed"
        return 0
    fi

    info "Installing $name..."
    if command -v go &>/dev/null; then
        go install "$pkg" 2>/dev/null && success "$name installed" || warning "Failed to install $name"
    else
        warning "Go not installed, skipping $name"
    fi
}

install_pip_tool() {
    local name="$1"
    local pkg="$2"

    if command -v "$name" &>/dev/null; then
        success "$name already installed"
        return 0
    fi

    info "Installing $name..."
    pip3 install "$pkg" 2>/dev/null && success "$name installed" || warning "Failed to install $name"
}

# Check Go installation
if ! command -v go &>/dev/null; then
    warning "Go is not installed. Many tools require Go."
    warning "Install Go from: https://golang.org/dl/"
    echo ""
fi

echo ""
echo -e "${CYAN}Installing Required Tools${NC}"
echo "========================="

# Nmap
if ! command -v nmap &>/dev/null; then
    info "Installing nmap..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y nmap 2>/dev/null && success "nmap installed"
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm nmap 2>/dev/null && success "nmap installed"
    else
        warning "Please install nmap manually"
    fi
else
    success "nmap already installed"
fi

# Go-based tools
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

echo ""
echo -e "${CYAN}Installing Optional Tools${NC}"
echo "========================="

install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "uncover" "github.com/projectdiscovery/uncover/cmd/uncover@latest"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"
install_go_tool "gospider" "github.com/jaeles-project/gospider@latest"
install_go_tool "hakrawler" "github.com/hakluke/hakrawler@latest"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_go_tool "dalfox" "github.com/hahwul/dalfox/v2@latest"
install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
install_go_tool "feroxbuster" "github.com/epi052/feroxbuster@latest" 2>/dev/null || true

# Python tools
install_pip_tool "sqlmap" "sqlmap"
install_pip_tool "arjun" "arjun"

echo ""
echo -e "${GREEN}Tool installation complete!${NC}"
echo "Run 'wardenstrike status' to verify."
