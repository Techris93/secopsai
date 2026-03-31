#!/bin/bash
# Unified SecOpsAI Installer
# Installs the main secopsai CLI with supply-chain module bundled

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
SECOPSAI_HOME="$HOME/.secopsai"

echo -e "${BLUE}"
cat << 'EOF'
   _____             _____       _
  / ____|           / ____|     | |
 | (___   ___  ___ | |  __  ___ | | ___   _
  \___ \ / _ \/ _ \| | |_ |/ _ \| |/ / | | |
  ____) |  __/ (_) | |__| | (_) |   <| |_| |
 |_____/ \___|\___/ \_____|\___/|_|\_\\__,_|
                                            
EOF
echo -e "${NC}"
echo "Unified Security Operations Platform"
echo "===================================="
echo ""

# Check Python
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is required but not installed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Python 3 found: $(python3 --version)${NC}"
}

# Install main CLI
install_cli() {
    echo -e "${BLUE}[*] Installing SecOpsAI CLI...${NC}"
    
    # Create bin directory if needed
    mkdir -p "$INSTALL_DIR"
    
    # Copy main CLI
    CLI_SOURCE="$SCRIPT_DIR/secopsai"
    CLI_TARGET="$INSTALL_DIR/secopsai"
    
    if [ -f "$CLI_SOURCE" ]; then
        cp "$CLI_SOURCE" "$CLI_TARGET"
        chmod +x "$CLI_TARGET"
        echo -e "${GREEN}✓ CLI installed to $CLI_TARGET${NC}"
    else
        echo -e "${RED}❌ CLI source not found at $CLI_SOURCE${NC}"
        exit 1
    fi
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo -e "${YELLOW}[!] $INSTALL_DIR is not in your PATH${NC}"
        
        SHELL_RC=""
        if [ -f "$HOME/.zshrc" ]; then
            SHELL_RC="$HOME/.zshrc"
        elif [ -f "$HOME/.bashrc" ]; then
            SHELL_RC="$HOME/.bashrc"
        fi
        
        if [ -n "$SHELL_RC" ]; then
            echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$SHELL_RC"
            echo -e "${GREEN}✓ Added $INSTALL_DIR to PATH in $SHELL_RC${NC}"
            echo -e "${YELLOW}  Run 'source $SHELL_RC' to use secopsai now${NC}"
        fi
    fi
}

# Install supply-chain module
install_supply_chain_module() {
    echo -e "${BLUE}[*] Installing supply-chain security module...${NC}"
    
    # Create module directory
    MODULE_DIR="$SECOPSAI_HOME/modules/supply-chain"
    mkdir -p "$MODULE_DIR"
    
    # Copy module files
    if [ -d "$SCRIPT_DIR/agents" ]; then
        cp -r "$SCRIPT_DIR/agents" "$MODULE_DIR/"
        cp -r "$SCRIPT_DIR/rules" "$MODULE_DIR/"
        cp -r "$SCRIPT_DIR/playbooks" "$MODULE_DIR/"
        cp -r "$SCRIPT_DIR/configs" "$MODULE_DIR/"
        
        # Make scripts executable
        find "$MODULE_DIR" -name "*.py" -exec chmod +x {} \;
        find "$MODULE_DIR" -name "*.sh" -exec chmod +x {} \;
        
        echo -e "${GREEN}✓ Supply-chain module installed${NC}"
    else
        echo -e "${YELLOW}[!] Running in development mode - using current directory${NC}"
        # Create symlinks for development
        ln -sf "$SCRIPT_DIR/agents" "$MODULE_DIR/agents" 2>/dev/null || true
        ln -sf "$SCRIPT_DIR/rules" "$MODULE_DIR/rules" 2>/dev/null || true
        ln -sf "$SCRIPT_DIR/playbooks" "$MODULE_DIR/playbooks" 2>/dev/null || true
        ln -sf "$SCRIPT_DIR/configs" "$MODULE_DIR/configs" 2>/dev/null || true
    fi
}

# Install Python dependencies
install_deps() {
    echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
    
    pip3 install --user psutil requests pyyaml 2>/dev/null || {
        echo -e "${YELLOW}[!] pip install failed, trying without --user${NC}"
        pip3 install psutil requests pyyaml || true
    }
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Setup directories
setup_directories() {
    echo -e "${BLUE}[*] Setting up directories...${NC}"
    
    mkdir -p "$SECOPSAI_HOME"/{modules,logs,quarantine,dumps,incidents}
    
    echo -e "${GREEN}✓ Directories created:${NC}"
    echo "  $SECOPSAI_HOME"
}

# Verify installation
verify_install() {
    echo -e "${BLUE}[*] Verifying installation...${NC}"
    
    if command -v secopsai &> /dev/null; then
        echo -e "${GREEN}✓ secopsai CLI is available${NC}"
        secopsai status
    else
        echo -e "${YELLOW}[!] secopsai not in PATH yet${NC}"
        echo -e "   Run: $INSTALL_DIR/secopsai status"
    fi
}

# Print usage
print_usage() {
    echo ""
    echo -e "${GREEN}===================================="
    echo -e "   Installation Complete!"
    echo -e "====================================${NC}"
    echo ""
    echo "Quick Start:"
    echo ""
    echo "  # Check status"
    echo "  secopsai status"
    echo ""
    echo "  # Scan current project for supply chain threats"
    echo "  secopsai supply-chain scan"
    echo ""
    echo "  # Check a specific package"
    echo "  secopsai supply-chain check axios"
    echo ""
    echo "  # Start runtime monitoring"
    echo "  secopsai supply-chain monitor"
    echo ""
    echo "  # Validate SBOM"
    echo "  secopsai supply-chain validate"
    echo ""
    echo "  # List incident response playbooks"
    echo "  secopsai supply-chain respond"
    echo ""
    echo "Documentation:"
    echo "  - Research Report: $SCRIPT_DIR/../research/supply-chain-exploits-report.md"
    echo "  - Module Location: $SECOPSAI_HOME/modules/supply-chain/"
    echo ""
}

# Main
main() {
    check_python
    setup_directories
    install_deps
    install_cli
    install_supply_chain_module
    verify_install
    print_usage
}

main "$@"
