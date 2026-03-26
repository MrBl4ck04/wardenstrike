#!/usr/bin/env bash
# WardenStrike - Installation Script
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

banner() {
    echo -e "${RED}"
    echo " __        ___    ____  ____  _____ _   _"
    echo " \ \      / / \  |  _ \|  _ \| ____| \ | |"
    echo "  \ \ /\ / / _ \ | |_) | | | |  _| |  \| |"
    echo "   \ V  V / ___ \|  _ <| |_| | |___| |\  |"
    echo "    \_/\_/_/   \_\_| \_\____/|_____|_| \_|"
    echo -e "${NC}${CYAN}"
    echo " ____ _____ ____  ___ _  _______"
    echo "/ ___|_   _|  _ \|_ _| |/ / ____|"
    echo "\___ \ | | | |_) || || ' /|  _|"
    echo " ___) || | |  _ < | || . \| |___"
    echo "|____/ |_| |_| \_\___|_|\_\_____|"
    echo -e "${NC}"
    echo -e "${BOLD}    AI-Powered Pentesting Framework - Installer${NC}"
    echo -e "    by Warden Security | mrbl4ck"
    echo ""
}

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

banner

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================================================
# Step 1: Python dependencies
# ============================================================================
info "Installing Python dependencies..."
if command -v pip3 &>/dev/null; then
    pip3 install -e . 2>/dev/null || pip3 install -r requirements.txt
    success "Python dependencies installed"
else
    error "pip3 not found. Please install Python 3.10+"
    exit 1
fi

# ============================================================================
# Step 2: Create .env if not exists
# ============================================================================
if [ ! -f .env ]; then
    cp .env.example .env
    warning "Created .env file - please edit it with your API keys"
fi

# ============================================================================
# Step 3: Create data directories
# ============================================================================
mkdir -p data reports

# ============================================================================
# Step 4: Install Claude Code integration (optional)
# ============================================================================
CLAUDE_DIR="$HOME/.claude"
if [ -d "$CLAUDE_DIR" ]; then
    info "Installing Claude Code integration..."

    # Copy skills
    mkdir -p "$CLAUDE_DIR/skills"
    if [ -d "claude/skills" ]; then
        cp -r claude/skills/* "$CLAUDE_DIR/skills/" 2>/dev/null || true
    fi

    # Copy commands
    mkdir -p "$CLAUDE_DIR/commands"
    if [ -d "claude/commands" ]; then
        cp -r claude/commands/* "$CLAUDE_DIR/commands/" 2>/dev/null || true
    fi

    success "Claude Code integration installed"
else
    warning "Claude Code not found (~/.claude). Skipping integration."
fi

# ============================================================================
# Step 5: Check for security tools
# ============================================================================
echo ""
info "Checking security tools..."

check_tool() {
    if command -v "$1" &>/dev/null; then
        success "$1 found"
        return 0
    else
        warning "$1 not found"
        return 1
    fi
}

echo ""
echo -e "${BOLD}Required tools:${NC}"
MISSING_REQUIRED=0
for tool in subfinder httpx nmap nuclei; do
    check_tool "$tool" || MISSING_REQUIRED=$((MISSING_REQUIRED + 1))
done

echo ""
echo -e "${BOLD}Optional tools:${NC}"
for tool in amass gau katana ffuf dalfox gospider hakrawler waybackurls sqlmap feroxbuster arjun; do
    check_tool "$tool" || true
done

if [ $MISSING_REQUIRED -gt 0 ]; then
    echo ""
    warning "Some required tools are missing. Run: wardenstrike install-tools"
fi

# ============================================================================
# Done
# ============================================================================
echo ""
echo -e "${GREEN}${BOLD}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your API keys"
echo "  2. Run: wardenstrike status"
echo "  3. Run: wardenstrike engage new <name> --scope <domain>"
echo "  4. Run: wardenstrike hunt <target>"
echo ""
echo "For Burp Suite integration:"
echo "  1. Enable REST API in Burp: User options → Misc → REST API"
echo "  2. Set WARDENSTRIKE_BURP_URL and WARDENSTRIKE_BURP_KEY in .env"
echo "  3. Run: wardenstrike burp status"
echo ""
