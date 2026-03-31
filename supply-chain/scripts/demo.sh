#!/bin/bash
# SecOpsAI - Demo and Test Suite
# Tests detection capabilities with safe examples

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "  ____            _            ____   ___   ___  ______  "
echo " / ___|  ___  ___| |__   ___  / ___| / _ \ / _ \|  _ \ \ "
echo " \___ \ / _ \/ __| '_ \ / _ \ \___ \| | | | | | | |_) | |"
echo "  ___) |  __/ (__| | | | (_) |___) | |_| | |_| |  __/| |"
echo " |____/ \___|\___|_| |_|\___/|____/ \___/ \___/|_|   | |"
echo "                                                    |_|  "
echo -e "${NC}"
echo "Detection Capability Demo"
echo "========================="
echo ""

# Create test directory
TEST_DIR=$(mktemp -d)
echo "Test directory: $TEST_DIR"
cd "$TEST_DIR"

# Demo 1: SBOM Validation
demo_sbom_validation() {
    echo -e "${YELLOW}[Demo 1/4] SBOM Validation${NC}"
    echo "----------------------------------------"
    
    # Create a test SBOM with known malicious packages
    cat > test-sbom.json << 'EOF'
{
  "packages": {
    "node_modules/axios": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",
      "integrity": "sha512-malicious=="
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-valid=="
    },
    "node_modules/plain-crypto-js": {
      "version": "4.2.1",
      "resolved": "https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz",
      "integrity": "sha512-malicious=="
    }
  }
}
EOF
    
    echo "Created test SBOM with malicious packages:"
    echo "  - axios@1.14.1 (known compromised)"
    echo "  - plain-crypto-js@4.2.1 (RAT dropper)"
    echo "  - lodash@4.17.21 (legitimate)"
    echo ""
    
    if command -v secopsai-sbom-validator &> /dev/null; then
        secopsai-sbom-validator --sbom test-sbom.json --policy strict || true
    else
        echo "⚠️  secopsai-sbom-validator not in PATH"
        echo "   Run setup.sh first or use: python3 ../agents/sbom_validator.py --sbom test-sbom.json"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    echo ""
}

# Demo 2: npm Registry Monitoring
demo_npm_monitor() {
    echo -e "${YELLOW}[Demo 2/4] npm Registry Monitoring${NC}"
    echo "----------------------------------------"
    
    echo "Checking known malicious package: plain-crypto-js"
    echo ""
    
    if command -v secopsai-npm-monitor &> /dev/null; then
        secopsai-npm-monitor --package plain-crypto-js --version 4.2.1 || true
    else
        echo "⚠️  secopsai-npm-monitor not in PATH"
    fi
    
    echo ""
    echo "Expected output:"
    echo "  🚨 CRITICAL: KNOWN_MALICIOUS"
    echo "  Package: plain-crypto-js@4.2.1 is a known compromised version"
    echo ""
    
    read -p "Press Enter to continue..."
    echo ""
}

# Demo 3: YARA Rule Testing
demo_yara_rules() {
    echo -e "${YELLOW}[Demo 3/4] YARA Rule Testing${NC}"
    echo "----------------------------------------"
    
    # Create test files matching YARA rules
    echo "Creating test files..."
    
    # Simulated Axios RAT dropper
    mkdir -p node_modules/plain-crypto-js
    cat > node_modules/plain-crypto-js/setup.js << 'EOF'
// Simulated malicious setup.js (for testing only)
const https = require('https');
const { exec } = require('child_process');

// C2 domain pattern
const C2 = 'sfrclak.com';
const PORT = 8000;

// Platform detection
const platform = process.platform;
if (platform === 'darwin') {
    // macOS payload path
    const payload = '/Library/Caches/com.apple.act.mond';
}
EOF
    
    echo "Created test file: node_modules/plain-crypto-js/setup.js"
    echo "  Contains: C2 domain (sfrclak.com), platform detection"
    echo ""
    
    if command -v yara &> /dev/null; then
        echo "Scanning with YARA rules..."
        if [[ -f /etc/secopsai/rules/yara/yara-supply-chain-rules.yar ]]; then
            yara /etc/secopsai/rules/yara/yara-supply-chain-rules.yar . || true
        else
            echo "⚠️  YARA rules not found in /etc/secopsai/rules/yara/"
        fi
    else
        echo "⚠️  YARA not installed"
        echo "   Install with: apt-get install yara (Debian/Ubuntu)"
        echo "                 brew install yara (macOS)"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    echo ""
}

# Demo 4: Incident Response Playbook
demo_response_playbook() {
    echo -e "${YELLOW}[Demo 4/4] Incident Response Playbook (Dry Run)${NC}"
    echo "----------------------------------------"
    
    echo "Simulating npm supply chain compromise response..."
    echo ""
    
    if command -v secopsai-response &> /dev/null; then
        secopsai-response --incident npm-supply-chain-compromise --dry-run
    else
        echo "⚠️  secopsai-response not in PATH"
        echo ""
        echo "Expected playbook steps:"
        echo "  1. Immediate Containment - Block C2, isolate containers"
        echo "  2. Credential Rotation - Revoke npm tokens, rotate cloud creds"
        echo "  3. Artifact Cleanup - Remove packages, regenerate lockfiles"
        echo "  4. Forensic Collection - Process dumps, network logs"
        echo "  5. Verification - Malware scans, SBOM validation"
        echo "  6. Recovery - Deploy clean artifacts"
    fi
    
    echo ""
}

# Demo 5: Security Hardening (Informational)
demo_hardening() {
    echo -e "${YELLOW}[Bonus] Security Hardening Preview${NC}"
    echo "----------------------------------------"
    
    echo "The hardening script will:"
    echo ""
    echo "npm:"
    echo "  ✓ Disable install scripts by default"
    echo "  ✓ Enable strict SSL"
    echo "  ✓ Set official registry only"
    echo ""
    echo "Vim:"
    echo "  ✓ Disable modelines (CVE-2019-12735, CVE-2025-53905)"
    echo "  ✓ Disable tar.vim plugin (CVE-2025-27423)"
    echo "  ✓ Disable zip.vim plugin (CVE-2025-53906)"
    echo ""
    echo "Emacs:"
    echo "  ✓ Disable man: URI handler (CVE-2025-1244)"
    echo "  ✓ Secure browse-url functionality"
    echo ""
    echo "Python:"
    echo "  ✓ Secure pip configuration"
    echo "  ✓ Monitor .pth file execution"
    echo ""
    echo "To run hardening: secopsai-harden"
}

# Main menu
show_menu() {
    echo "Select demo to run:"
    echo "  1) SBOM Validation"
    echo "  2) npm Registry Monitoring"
    echo "  3) YARA Rule Testing"
    echo "  4) Incident Response Playbook"
    echo "  5) All demos"
    echo "  6) Hardening Preview"
    echo "  0) Exit"
    echo ""
    read -p "Enter choice [0-6]: " choice
    
    case $choice in
        1) demo_sbom_validation ;;
        2) demo_npm_monitor ;;
        3) demo_yara_rules ;;
        4) demo_response_playbook ;;
        5) 
            demo_sbom_validation
            demo_npm_monitor
            demo_yara_rules
            demo_response_playbook
            ;;
        6) demo_hardening ;;
        0) exit 0 ;;
        *) echo "Invalid choice"; show_menu ;;
    esac
}

# Check if being run with arguments
if [[ $# -eq 0 ]]; then
    show_menu
else
    case $1 in
        sbom) demo_sbom_validation ;;
        npm) demo_npm_monitor ;;
        yara) demo_yara_rules ;;
        response) demo_response_playbook ;;
        harden) demo_hardening ;;
        all)
            demo_sbom_validation
            demo_npm_monitor
            demo_yara_rules
            demo_response_playbook
            demo_hardening
            ;;
        *) echo "Usage: $0 [sbom|npm|yara|response|harden|all]" ;;
    esac
fi

# Cleanup
cd -
rm -rf "$TEST_DIR"
echo ""
echo -e "${GREEN}Demo complete!${NC}"
