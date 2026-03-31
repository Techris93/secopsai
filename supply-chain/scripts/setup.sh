#!/bin/bash
# SecOpsAI - Master Setup Script
# Sets up the complete SecOpsAI detection and mitigation toolkit

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/secopsai"
CONFIG_DIR="/etc/secopsai"
LOG_DIR="/var/log/secopsai"
USER_BIN="/usr/local/bin"

echo -e "${BLUE}"
echo "  ____            _            ____   ___   ___  ______  "
echo " / ___|  ___  ___| |__   ___  / ___| / _ \ / _ \|  _ \ \ "
echo " \___ \ / _ \/ __| '_ \ / _ \ \___ \| | | | | | | |_) | |"
echo "  ___) |  __/ (__| | | | (_) |___) | |_| | |_| |  __/| |"
echo " |____/ \___|\___|_| |_|\___/|____/ \___/ \___/|_|   | |"
echo "                                                    |_|  "
echo -e "${NC}"
echo "Supply Chain Attack Detection & Mitigation Toolkit"
echo "==================================================="
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}⚠️  Warning: Not running as root. Some features may be limited.${NC}"
   echo "   For full installation, run: sudo $0"
   echo ""
fi

# Detect OS
OS="unknown"
PACKAGE_MANAGER=""

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &> /dev/null; then
        OS="debian"
        PACKAGE_MANAGER="apt-get"
    elif command -v yum &> /dev/null; then
        OS="redhat"
        PACKAGE_MANAGER="yum"
    elif command -v dnf &> /dev/null; then
        OS="redhat"
        PACKAGE_MANAGER="dnf"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PACKAGE_MANAGER="brew"
fi

echo "Detected OS: $OS"
echo ""

# Function to print section headers
section() {
    echo -e "${BLUE}[$1/7]${NC} $2"
    echo "-------------------------------------------"
}

# [1/7] Check dependencies
check_dependencies() {
    section "1" "Checking dependencies"
    
    MISSING_DEPS=()
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        MISSING_DEPS+=("python3")
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        MISSING_DEPS+=("python3-pip")
    fi
    
    # Check psutil (optional but recommended)
    if ! python3 -c "import psutil" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  psutil not installed. Installing...${NC}"
        pip3 install psutil 2>/dev/null || MISSING_DEPS+=("python3-psutil")
    fi
    
    # Check yara (optional)
    if ! command -v yara &> /dev/null; then
        echo -e "${YELLOW}⚠️  YARA not installed (optional for file scanning)${NC}"
    fi
    
    if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Missing dependencies: ${MISSING_DEPS[*]}${NC}"
        echo "Please install them and run again."
        exit 1
    fi
    
    echo -e "${GREEN}✅ All dependencies satisfied${NC}"
    echo ""
}

# [2/7] Create directories
setup_directories() {
    section "2" "Setting up directories"
    
    if [[ $EUID -eq 0 ]]; then
        mkdir -p "$INSTALL_DIR"/{agents,rules,playbooks,scripts,configs}
        mkdir -p "$CONFIG_DIR"/{rules/sigma,rules/yara}
        mkdir -p "$LOG_DIR"
        chmod 755 "$LOG_DIR"
        
        echo "Created system directories:"
        echo "  $INSTALL_DIR"
        echo "  $CONFIG_DIR"
        echo "  $LOG_DIR"
    else
        # User install
        INSTALL_DIR="$HOME/.secopsai"
        CONFIG_DIR="$HOME/.secopsai/config"
        LOG_DIR="$HOME/.secopsai/logs"
        USER_BIN="$HOME/.local/bin"
        
        mkdir -p "$INSTALL_DIR"/{agents,rules,playbooks,scripts,configs}
        mkdir -p "$CONFIG_DIR"
        mkdir -p "$LOG_DIR"
        mkdir -p "$USER_BIN"
        
        echo "Created user directories:"
        echo "  $INSTALL_DIR"
        echo "  $CONFIG_DIR"
        echo "  $LOG_DIR"
    fi
    
    echo -e "${GREEN}✅ Directories created${NC}"
    echo ""
}

# [3/7] Install Python packages
install_python_deps() {
    section "3" "Installing Python dependencies"
    
    pip3 install --user psutil requests pyyaml 2>/dev/null || pip3 install psutil requests pyyaml
    
    echo -e "${GREEN}✅ Python dependencies installed${NC}"
    echo ""
}

# [4/7] Copy toolkit files
copy_files() {
    section "4" "Installing SecOpsAI toolkit"
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copy agents
    if [[ -f "$SCRIPT_DIR/../agents/npm_registry_monitor.py" ]]; then
        cp "$SCRIPT_DIR/../agents/"*.py "$INSTALL_DIR/agents/"
        chmod +x "$INSTALL_DIR/agents/"*.py
    fi
    
    # Copy rules
    if [[ -f "$SCRIPT_DIR/../rules/sigma-supply-chain-rules.yml" ]]; then
        cp "$SCRIPT_DIR/../rules/"*.yml "$CONFIG_DIR/rules/sigma/" 2>/dev/null || true
        cp "$SCRIPT_DIR/../rules/"*.yar "$CONFIG_DIR/rules/yara/" 2>/dev/null || true
    fi
    
    # Copy playbooks
    if [[ -f "$SCRIPT_DIR/../playbooks/response_playbook.py" ]]; then
        cp "$SCRIPT_DIR/../playbooks/"*.py "$INSTALL_DIR/playbooks/"
        chmod +x "$INSTALL_DIR/playbooks/"*.py
    fi
    
    # Copy scripts
    if [[ -f "$SCRIPT_DIR/../scripts/harden_environment.sh" ]]; then
        cp "$SCRIPT_DIR/../scripts/"*.sh "$INSTALL_DIR/scripts/"
        chmod +x "$INSTALL_DIR/scripts/"*.sh
    fi
    
    # Copy config
    if [[ -f "$SCRIPT_DIR/../configs/secopsai-config.yaml" ]]; then
        cp "$SCRIPT_DIR/../configs/secopsai-config.yaml" "$CONFIG_DIR/config.yaml"
    fi
    
    echo -e "${GREEN}✅ Toolkit files installed${NC}"
    echo ""
}

# [5/7] Create command wrappers
create_wrappers() {
    section "5" "Creating command wrappers"
    
    # secopsai-npm-monitor
    cat > "$USER_BIN/secopsai-npm-monitor" << EOF
#!/bin/bash
exec python3 "$INSTALL_DIR/agents/npm_registry_monitor.py" "\$@"
EOF
    chmod +x "$USER_BIN/secopsai-npm-monitor"
    
    # secopsai-runtime-monitor
    cat > "$USER_BIN/secopsai-runtime-monitor" << EOF
#!/bin/bash
exec python3 "$INSTALL_DIR/agents/runtime_monitor.py" "\$@"
EOF
    chmod +x "$USER_BIN/secopsai-runtime-monitor"
    
    # secopsai-sbom-validator
    cat > "$USER_BIN/secopsai-sbom-validator" << EOF
#!/bin/bash
exec python3 "$INSTALL_DIR/agents/sbom_validator.py" "\$@"
EOF
    chmod +x "$USER_BIN/secopsai-sbom-validator"
    
    # secopsai-response
    cat > "$USER_BIN/secopsai-response" << EOF
#!/bin/bash
exec python3 "$INSTALL_DIR/playbooks/response_playbook.py" "\$@"
EOF
    chmod +x "$USER_BIN/secopsai-response"
    
    # secopsai-harden
    cat > "$USER_BIN/secopsai-harden" << EOF
#!/bin/bash
exec bash "$INSTALL_DIR/scripts/harden_environment.sh" "\$@"
EOF
    chmod +x "$USER_BIN/secopsai-harden"
    
    echo "Created commands:"
    echo "  secopsai-npm-monitor     - Monitor npm registry for threats"
    echo "  secopsai-runtime-monitor - Monitor system for suspicious activity"
    echo "  secopsai-sbom-validator  - Validate SBOMs against security policies"
    echo "  secopsai-response        - Execute incident response playbooks"
    echo "  secopsai-harden          - Harden development environment"
    
    echo -e "${GREEN}✅ Command wrappers created${NC}"
    echo ""
}

# [6/7] Setup systemd service (Linux only)
setup_service() {
    section "6" "Setting up monitoring service"
    
    if [[ "$OS" == "debian" || "$OS" == "redhat" ]] && [[ $EUID -eq 0 ]]; then
        cat > /etc/systemd/system/secopsai-monitor.service << EOF
[Unit]
Description=SecOpsAI Supply Chain Attack Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/agents/runtime_monitor.py --daemon
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        echo -e "${GREEN}✅ Systemd service created${NC}"
        echo "   Start: sudo systemctl start secopsai-monitor"
        echo "   Enable: sudo systemctl enable secopsai-monitor"
    else
        echo -e "${YELLOW}⚠️  Skipping systemd service (not Linux or not root)${NC}"
    fi
    
    echo ""
}

# [7/7] Final setup and verification
finalize() {
    section "7" "Finalizing setup"
    
    # Update PATH if needed
    if [[ $EUID -ne 0 ]]; then
        if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
            echo "export PATH=\"$USER_BIN:\$PATH\"" >> ~/.bashrc
            echo -e "${YELLOW}⚠️  Added $USER_BIN to PATH in ~/.bashrc${NC}"
            echo "   Run: source ~/.bashrc"
        fi
    fi
    
    # Create uninstall script
    cat > "$INSTALL_DIR/uninstall.sh" << EOF
#!/bin/bash
echo "Uninstalling SecOpsAI..."
rm -rf "$INSTALL_DIR"
rm -rf "$CONFIG_DIR"
rm -f "$USER_BIN"/secopsai-*
[[ $EUID -eq 0 ]] && rm -f /etc/systemd/system/secopsai-monitor.service
echo "✅ Uninstalled"
EOF
    chmod +x "$INSTALL_DIR/uninstall.sh"
    
    echo -e "${GREEN}✅ Setup complete!${NC}"
    echo ""
    echo "=================================================="
    echo "🎉 SecOpsAI Toolkit Installed Successfully"
    echo "=================================================="
    echo ""
    echo "📁 Installation Directory: $INSTALL_DIR"
    echo "📁 Configuration: $CONFIG_DIR/config.yaml"
    echo "📁 Logs: $LOG_DIR"
    echo ""
    echo "🚀 Quick Start Commands:"
    echo ""
    echo "  # Monitor npm registry for threats"
    echo "  secopsai-npm-monitor --package axios --watch"
    echo ""
    echo "  # Validate SBOM before deployment"
    echo "  secopsai-sbom-validator --sbom package-lock.json --policy strict"
    echo ""
    echo "  # Start runtime monitoring"
    echo "  sudo secopsai-runtime-monitor --daemon"
    echo ""
    echo "  # Execute incident response"
    echo "  secopsai-response --incident npm-supply-chain-compromise --dry-run"
    echo ""
    echo "  # Harden your environment"
    echo "  secopsai-harden"
    echo ""
    echo "📖 Documentation: $INSTALL_DIR/README.md"
    echo "🗑️  Uninstall: $INSTALL_DIR/uninstall.sh"
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT: Run 'secopsai-harden' to secure your environment${NC}"
    echo ""
}

# Main execution
main() {
    check_dependencies
    setup_directories
    install_python_deps
    copy_files
    create_wrappers
    setup_service
    finalize
}

main "$@"
