#!/bin/bash
# SecOpsAI Supply Chain Module Installer
# Integrates with existing SecOpsAI installation

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECOPSAI_DIR="${SECOPSAI_DIR:-$HOME/secopsai}"
MODULE_NAME="supply-chain"
MODULE_DIR="$SECOPSAI_DIR/modules/$MODULE_NAME"

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
echo "Supply Chain Security Module for SecOpsAI"
echo "========================================="
echo ""

# Check if SecOpsAI is installed
check_secopsai() {
    if [ ! -d "$SECOPSAI_DIR" ]; then
        echo -e "${RED}❌ SecOpsAI not found at $SECOPSAI_DIR${NC}"
        echo ""
        echo "Please install SecOpsAI first:"
        echo "  curl -fsSL https://secopsai.dev/install.sh | bash"
        echo ""
        echo "Then run this installer again."
        exit 1
    fi
    
    echo -e "${GREEN}✓ SecOpsAI found at $SECOPSAI_DIR${NC}"
}

# Check virtualenv
check_venv() {
    if [ ! -d "$SECOPSAI_DIR/.venv" ]; then
        echo -e "${RED}❌ SecOpsAI virtualenv not found${NC}"
        echo "Please ensure SecOpsAI is properly installed."
        exit 1
    fi
    
    echo -e "${GREEN}✓ SecOpsAI virtualenv found${NC}"
}

# Install module
install_module() {
    echo -e "${BLUE}[*] Installing supply chain module...${NC}"
    
    # Create modules directory
    mkdir -p "$SECOPSAI_DIR/modules"
    
    # Remove existing module if present
    if [ -d "$MODULE_DIR" ] || [ -L "$MODULE_DIR" ]; then
        echo -e "${YELLOW}[!] Removing existing module...${NC}"
        rm -rf "$MODULE_DIR"
    fi
    
    # Copy module files
    cp -r "$SCRIPT_DIR" "$MODULE_DIR"
    
    # Make scripts executable
    find "$MODULE_DIR" -name "*.py" -exec chmod +x {} \;
    find "$MODULE_DIR" -name "*.sh" -exec chmod +x {} \;
    
    echo -e "${GREEN}✓ Module installed to $MODULE_DIR${NC}"
}

# Install Python dependencies
install_deps() {
    echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
    
    # Activate virtualenv and install
    (
        source "$SECOPSAI_DIR/.venv/bin/activate"
        pip install psutil requests pyyaml
    )
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Create module integration
create_integration() {
    echo -e "${BLUE}[*] Creating SecOpsAI integration...${NC}"
    
    # Create wrapper script that integrates with secopsai CLI
    WRAPPER="$SECOPSAI_DIR/secopsai-supply-chain"
    
    cat > "$WRAPPER" << EOF
#!/bin/bash
# SecOpsAI Supply Chain Module Wrapper
# Usage: secopsai check-supply-chain (after adding to PATH)

source "$SECOPSAI_DIR/.venv/bin/activate"
python3 "$MODULE_DIR/supply_chain_module.py" "\$@"
EOF
    
    chmod +x "$WRAPPER"
    
    # Create symlink in bin directory if it exists
    if [ -d "$SECOPSAI_DIR/bin" ]; then
        ln -sf "$WRAPPER" "$SECOPSAI_DIR/bin/secopsai-supply-chain"
    fi
    
    echo -e "${GREEN}✓ Integration created${NC}"
}

# Add to secopsai CLI (if extensible)
register_with_secopsai() {
    echo -e "${BLUE}[*] Registering with SecOpsAI...${NC}"
    
    # Check if secopsai supports modules
    if [ -f "$SECOPSAI_DIR/config/modules.txt" ]; then
        if ! grep -q "^$MODULE_NAME$" "$SECOPSAI_DIR/config/modules.txt" 2>/dev/null; then
            echo "$MODULE_NAME" >> "$SECOPSAI_DIR/config/modules.txt"
            echo -e "${GREEN}✓ Module registered${NC}"
        else
            echo -e "${GREEN}✓ Module already registered${NC}"
        fi
    else
        echo -e "${YELLOW}[!] SecOpsAI module registry not found${NC}"
        echo "  Module will work but may not appear in 'secopsai status'"
    fi
}

# Create activation helper
create_activation_helper() {
    cat > "$SECOPSAI_DIR/activate-supply-chain" << 'EOF'
#!/bin/bash
# Activate SecOpsAI with supply chain module

echo "Activating SecOpsAI with Supply Chain module..."
cd ~/secopsai
source .venv/bin/activate

echo ""
echo "Available commands:"
echo "  secopsai-supply-chain check              # Check supply chain"
echo "  secopsai-supply-chain check --output sc.json"
echo "  python3 ~/secopsai/modules/supply-chain/supply_chain_module.py check"
echo ""
echo "Or use directly with SecOpsAI:"
echo "  secopsai refresh  # (if supply chain is integrated)"
echo ""
EOF
    
    chmod +x "$SECOPSAI_DIR/activate-supply-chain"
}

# Verify installation
verify_install() {
    echo -e "${BLUE}[*] Verifying installation...${NC}"
    
    if [ -f "$MODULE_DIR/supply_chain_module.py" ]; then
        echo -e "${GREEN}✓ Module files present${NC}"
    else
        echo -e "${RED}❌ Module files missing${NC}"
        return 1
    fi
    
    # Test Python dependencies
    if (
        source "$SECOPSAI_DIR/.venv/bin/activate"
        python3 -c "import psutil, requests" 2>/dev/null
    ); then
        echo -e "${GREEN}✓ Python dependencies working${NC}"
    else
        echo -e "${YELLOW}[!] Python dependencies may need installation${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}Installation verified!${NC}"
}

# Print usage
print_usage() {
    echo ""
    echo -e "${GREEN}========================================="
    echo -e "   Installation Complete!"
    echo -e "=========================================${NC}"
    echo ""
    echo "The supply chain module is now integrated with SecOpsAI."
    echo ""
    echo "Usage:"
    echo ""
    echo "  1. Activate SecOpsAI environment:"
    echo "     source ~/secopsai/.venv/bin/activate"
    echo ""
    echo "  2. Run supply chain checks:"
    echo "     secopsai-supply-chain check"
    echo ""
    echo "  3. Or run from project directory:"
    echo "     python3 ~/secopsai/modules/supply-chain/supply_chain_module.py check -p ."
    echo ""
    echo "  4. With SecOpsAI (if integrated):"
    echo "     secopsai refresh"
    echo "     secopsai list --severity high"
    echo ""
    echo "Configuration:"
    echo "  Module location: $MODULE_DIR"
    echo "  Wrapper script:  $SECOPSAI_DIR/secopsai-supply-chain"
    echo ""
    echo "Documentation:"
    echo "  - Integration: $MODULE_DIR/SECOPSAI_INTEGRATION.md"
    echo "  - Research:    $MODULE_DIR/../research/supply-chain-exploits-report.md"
    echo ""
}

# Main
main() {
    check_secopsai
    check_venv
    install_module
    install_deps
    create_integration
    register_with_secopsai
    create_activation_helper
    verify_install
    print_usage
}

main "$@"
