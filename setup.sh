#!/bin/bash
#
# secopsai Setup Script
# Installs and configures the OpenClaw security detection pipeline with optional features.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Techris93/secopsai/main/setup.sh | bash
#   OR
#   bash setup.sh
#

if [ -z "${BASH_VERSION:-}" ]; then
  echo "This installer requires bash."
  echo "Run: curl -fsSL https://raw.githubusercontent.com/Techris93/secopsai/main/setup.sh | bash"
  exit 1
fi

set -euo pipefail

AUTO_YES=0
NON_INTERACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      cat <<'EOF'
secopsai setup

Usage:
  bash setup.sh
  bash setup.sh --yes
  bash setup.sh --non-interactive
  bash setup.sh --help

What it does:
  1. Validates local prerequisites
  2. Creates .venv and installs dependencies
  3. Enables optional benchmark and live-export features
  4. Runs validation and initial setup tasks

Notes:
  - If run via curl pipe, defaults are used automatically
  - OpenClaw CLI is optional for base install
EOF
      exit 0
      ;;
    --yes)
      AUTO_YES=1
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      ;;
    *)
      echo "Unknown option: $1"
      echo "Run 'bash setup.sh --help' for usage."
      exit 2
      ;;
  esac
  shift
done

if [[ ! -t 0 ]]; then
  NON_INTERACTIVE=1
fi

# Colors for output
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  NC=''
fi

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
BACKUP_DIR="${SCRIPT_DIR}/.backups"

# Logging functions
log_info() {
  echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
  echo -e "${GREEN}✓${NC} $1"
}

log_error() {
  echo -e "${RED}✗${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}⚠${NC} $1"
}

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-N}"

  if [[ "$AUTO_YES" == "1" ]]; then
    [[ "$default" == "Y" ]]
    return
  fi

  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    if [[ "$default" == "Y" ]]; then
      log_info "$prompt -> defaulting to Yes (non-interactive mode)"
      return 0
    fi
    log_info "$prompt -> defaulting to No (non-interactive mode)"
    return 1
  fi
  
  if [[ "$default" == "Y" ]]; then
    echo -ne "${prompt} (Y/n) "
  else
    echo -ne "${prompt} (y/N) "
  fi
  
  local response=""
  if [[ -r /dev/tty ]]; then
    read -r response </dev/tty || response=""
  else
    response=""
  fi
  
  if [[ "$default" == "Y" ]]; then
    [[ -z "$response" || "$response" == "y" || "$response" == "Y" ]]
  else
    [[ "$response" == "y" || "$response" == "Y" ]]
  fi
}

# ============================================================================
# PHASE 1: PRE-FLIGHT CHECKS
# ============================================================================

phase_preflight_checks() {
  log_info "Running pre-flight checks..."
  echo ""
  
  local all_passed=true
  
  # Check Python 3
  if command -v python3 &> /dev/null; then
    local python_version
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    log_success "Python 3 found (version $python_version)"
  else
    log_error "Python 3 is required but not installed"
    all_passed=false
  fi
  
  # Check pip
  if command -v pip3 &> /dev/null; then
    log_success "pip3 found"
  else
    log_error "pip3 is required but not installed"
    all_passed=false
  fi
  
  # Check OpenClaw
  if command -v openclaw &> /dev/null; then
    log_success "OpenClaw CLI found"
  else
    log_warn "OpenClaw CLI not found. Install from: https://docs.openclaw.ai/install"
  fi
  
  # Check git
  if python3 -m pip --version &> /dev/null; then
    log_success "Python pip module found"
  else
    log_error "python3 -m pip is required but not installed"
    all_passed=false
  fi
  
  echo ""
  
  if [[ "$all_passed" == false ]]; then
    log_error "Some prerequisites are missing. Please install them and re-run this script."
    exit 1
  fi
  
  log_success "All pre-flight checks passed!"
  echo ""
}

# ============================================================================
# PHASE 2: PYTHON ENVIRONMENT SETUP
# ============================================================================

phase_setup_environment() {
  log_info "Setting up Python environment..."
  echo ""
  
  # Create virtual environment
  if [[ ! -d "$VENV_DIR" ]]; then
    log_info "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    log_success "Virtual environment created"
  else
    log_success "Virtual environment already exists"
  fi
  
  # Activate virtual environment
  source "$VENV_DIR/bin/activate"
  
  # Upgrade pip
  log_info "Upgrading pip..."
  python3 -m pip install --quiet --upgrade pip setuptools wheel
  log_success "pip upgraded"
  
  # Install requirements
  if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
    log_info "Installing dependencies from requirements.txt..."
    python3 -m pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
    python3 -m pip install --quiet pytest
    log_success "Dependencies installed"
  else
    log_warn "requirements.txt not found, skipping dependency installation"
  fi
  
  echo ""
}

# ============================================================================
# PHASE 3: FEATURE CONFIGURATION
# ============================================================================

phase_feature_configuration() {
  log_info "Configuring optional features..."
  echo ""
  
  # Feature 1: Enable optional telemetry surfaces
  log_info "Feature 1: Optional Native Telemetry Surfaces"
  echo "  Enables detection of additional attack surfaces:"
  echo "  - exec_events: Process-level command execution"
  echo "  - pairing_events: Agent pairing/approval workflows"
  echo "  - skills_events: Skill installation/source drift"
  echo ""
  
  if prompt_yes_no "Enable optional native surfaces?" "N"; then
    export SECOPS_ENABLE_OPTIONAL_SURFACES=1
    log_success "Optional surfaces enabled"
  else
    export SECOPS_ENABLE_OPTIONAL_SURFACES=0
    log_success "Optional surfaces disabled"
  fi
  
  echo ""
  
  # Feature 2: Benchmark validation
  log_info "Feature 2: Benchmark Attack-Mix Generation"
  echo "  Generates reproducible labeled attack corpus for validation:"
  echo "  - 80-event dataset with 22 simulated attacks"
  echo "  - Tests detection rules with known attack patterns"
  echo "  - Validates F1 score and rule accuracy"
  echo ""
  
  if prompt_yes_no "Enable benchmark validation on setup?" "Y"; then
    export SECOPS_ENABLE_BENCHMARK=1
    log_success "Benchmark validation enabled"
  else
    export SECOPS_ENABLE_BENCHMARK=0
    log_success "Benchmark validation disabled"
  fi
  
  echo ""
  
  # Feature 3: Live telemetry export
  log_info "Feature 3: Live Telemetry Export"
  echo "  Exports your local OpenClaw audit logs for detection:"
  echo "  - Requires OpenClaw CLI and ~/.openclaw/ directory"
  echo "  - Runs detection pipeline on live telemetry"
  echo "  - Reports security findings"
  echo ""
  
  if prompt_yes_no "Enable live telemetry export?" "N"; then
    if ! command -v openclaw &> /dev/null; then
      log_error "OpenClaw CLI not found, cannot enable live export"
      export SECOPS_ENABLE_LIVE_EXPORT=0
    else
      export SECOPS_ENABLE_LIVE_EXPORT=1
      log_success "Live telemetry export enabled"
    fi
  else
    export SECOPS_ENABLE_LIVE_EXPORT=0
    log_success "Live telemetry export disabled"
  fi
  
  echo ""
}

# ============================================================================
# PHASE 4: INITIALIZATION & VALIDATION
# ============================================================================

phase_initialization() {
  log_info "Initializing secopsai..."
  echo ""
  
  # Create backup directory
  mkdir -p "$BACKUP_DIR"
  
  # Create data directories
  mkdir -p "$SCRIPT_DIR/data/openclaw/raw"
  mkdir -p "$SCRIPT_DIR/data/openclaw/replay/labeled"
  mkdir -p "$SCRIPT_DIR/data/openclaw/replay/unlabeled"
  log_success "Data directories created"
  
  # Run validation tests
  log_info "Running validation tests..."
  source "$VENV_DIR/bin/activate"
  
  if python3 -m pytest tests/ -q 2>/dev/null; then
    log_success "All validation tests passed"
  else
    log_warn "Some validation tests failed (this may be OK on first setup)"
  fi
  
  echo ""
}

# ============================================================================
# PHASE 5: FEATURE EXECUTION
# ============================================================================

phase_feature_execution() {
  log_info "Executing enabled features..."
  echo ""
  
  source "$VENV_DIR/bin/activate"
  
  # Benchmark validation
  if [[ "$SECOPS_ENABLE_BENCHMARK" == "1" ]]; then
    log_info "Generating attack-mix benchmark..."
    if python3 generate_openclaw_attack_mix.py --stats > /tmp/benchmark.log 2>&1; then
      log_success "Attack-mix benchmark generated"
      echo ""
      python3 generate_openclaw_attack_mix.py --stats
    else
      log_warn "Failed to generate benchmark (install may continue)"
    fi
    echo ""
  fi
  
  # Live telemetry export
  if [[ "$SECOPS_ENABLE_LIVE_EXPORT" == "1" ]]; then
    log_info "Exporting live OpenClaw telemetry..."
    if python3 export_real_openclaw_native.py > /tmp/export.log 2>&1; then
      log_success "Live telemetry exported"
    else
      log_warn "Failed to export live telemetry"
    fi
    echo ""
  fi
}

# ============================================================================
# CLEANUP & SUMMARY
# ============================================================================

summary() {
  echo ""
  echo "======================================================================="
  log_success "Setup complete!"
  echo "======================================================================="
  echo ""
  
  echo "Next steps:"
  echo ""
  echo "1. Activate the virtual environment:"
  echo "   ${BLUE}source $VENV_DIR/bin/activate${NC}"
  echo ""
  
  echo "2. Run detection on your OpenClaw logs:"
  echo "   ${BLUE}python detect.py${NC}"
  echo ""
  
  echo "3. Evaluate benchmark performance:"
  echo "   ${BLUE}python evaluate.py --labeled data/openclaw/replay/labeled/attack_mix.json --mode benchmark${NC}"
  echo ""
  
  echo "4. Build and view findings:"
  echo "   ${BLUE}python findings.py${NC}"
  echo ""
  
  echo "Documentation:"
  echo "   ${BLUE}https://docs.secopsai.dev${NC}"
  echo ""
  
  echo "Git repository:"
  echo "   ${BLUE}https://github.com/Techris93/secopsai${NC}"
  echo ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════════════╗"
  echo "║          secopsai Setup & Configuration                             ║"
  echo "║                                                                    ║"
  echo "║  Installs the OpenClaw security detection pipeline with           ║"
  echo "║  automated attack detection and benchmark validation.             ║"
  echo "╚════════════════════════════════════════════════════════════════════╝"
  echo ""
  
  phase_preflight_checks
  phase_setup_environment
  phase_feature_configuration
  phase_initialization
  phase_feature_execution
  summary
}

# Run main
main "$@"
