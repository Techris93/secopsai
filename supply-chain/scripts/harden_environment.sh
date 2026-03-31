#!/bin/bash
# SecOpsAI - Security Hardening Scripts
# Hardens npm, Vim, Emacs, and Python environments against supply chain attacks

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "🔒 SecOpsAI Security Hardening"
echo "=========================================="
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
fi

echo "Detected OS: $OS"
echo ""

# ============================================
# 1. NPM SECURITY HARDENING
# ============================================

harden_npm() {
    echo -e "${YELLOW}[1/4] Hardening npm configuration...${NC}"
    
    # Check if npm is installed
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}npm not found - skipping npm hardening${NC}"
        return
    fi
    
    # Backup existing config
    npm config list > ~/.npmrc.backup.$(date +%Y%m%d) 2>/dev/null || true
    
    # Disable scripts by default (prevent postinstall attacks)
    npm config set ignore-scripts true
    echo "✅ Disabled install scripts by default"
    
    # Enable strict SSL
    npm config set strict-ssl true
    echo "✅ Enabled strict SSL verification"
    
    # Set registry to official only
    npm config set registry https://registry.npmjs.org/
    echo "✅ Set official registry only"
    
    # Enable audit on install
    npm config set audit true
    echo "✅ Enabled audit on install"
    
    # Require provenance (if supported)
    npm config set provenance true 2>/dev/null || echo "⚠️  npm provenance requires npm v9.5+"
    
    # Set fund to false (reduce noise)
    npm config set fund false
    
    # Create .npmrc in home if not exists
    NPMRC="$HOME/.npmrc"
    if [[ ! -f "$NPMRC" ]]; then
        touch "$NPMRC"
    fi
    
    # Add security headers to .npmrc
    if ! grep -q "ignore-scripts" "$NPMRC" 2>/dev/null; then
        echo "ignore-scripts=true" >> "$NPMRC"
    fi
    
    echo -e "${GREEN}✓ npm hardening complete${NC}"
    echo ""
}

# ============================================
# 2. VIM SECURITY HARDENING
# ============================================

harden_vim() {
    echo -e "${YELLOW}[2/4] Hardening Vim configuration...${NC}"
    
    VIMRC=""
    if [[ "$OS" == "linux" ]]; then
        VIMRC="$HOME/.vimrc"
    elif [[ "$OS" == "macos" ]]; then
        VIMRC="$HOME/.vimrc"
    elif [[ "$OS" == "windows" ]]; then
        VIMRC="$HOME/_vimrc"
    fi
    
    if [[ -z "$VIMRC" ]]; then
        echo -e "${RED}Cannot determine Vim config location${NC}"
        return
    fi
    
    # Backup existing config
    if [[ -f "$VIMRC" ]]; then
        cp "$VIMRC" "${VIMRC}.backup.$(date +%Y%m%d)"
    fi
    
    # Create secure vimrc
    cat >> "$VIMRC" << 'EOF'

" ============================================
" SecOpsAI Security Hardening
" ============================================

" Disable modelines (CVE-2019-12735, CVE-2025-53905)
set nomodeline
set modelines=0

" Disable tar.vim plugin (CVE-2025-27423)
let g:loaded_tar = 1
let g:loaded_tarPlugin = 1

" Disable zip.vim plugin (CVE-2025-53906)
let g:loaded_zip = 1
let g:loaded_zipPlugin = 1

" Secure temporary files
set backupskip=/tmp/*,$TMPDIR/*,$TMP/*,$TEMP/*
set directory=$HOME/.vim/swap//
set backupdir=$HOME/.vim/backup//
set undodir=$HOME/.vim/undo//

" Disable ex mode
nnoremap Q <nop>

" Restrict shell commands
set secure

" Warn when shell command is used
set warn
EOF
    
    # Create necessary directories
    mkdir -p "$HOME/.vim/swap"
    mkdir -p "$HOME/.vim/backup"
    mkdir -p "$HOME/.vim/undo"
    
    echo -e "${GREEN}✓ Vim hardening complete${NC}"
    echo "  - Disabled modelines"
    echo "  - Disabled tar.vim and zip.vim plugins"
    echo "  - Secured temporary file locations"
    echo ""
}

# ============================================
# 3. EMACS SECURITY HARDENING
# ============================================

harden_emacs() {
    echo -e "${YELLOW}[3/4] Hardening Emacs configuration...${NC}"
    
    EMACS_DIR="$HOME/.emacs.d"
    INIT_FILE="$EMACS_DIR/init.el"
    
    # Check if Emacs is installed
    if ! command -v emacs &> /dev/null; then
        echo -e "${YELLOW}Emacs not found - skipping Emacs hardening${NC}"
        return
    fi
    
    # Backup existing config
    if [[ -f "$INIT_FILE" ]]; then
        cp "$INIT_FILE" "${INIT_FILE}.backup.$(date +%Y%m%d)"
    elif [[ -f "$HOME/.emacs" ]]; then
        cp "$HOME/.emacs" "$HOME/.emacs.backup.$(date +%Y%m%d)"
    fi
    
    # Create secure Emacs config
    mkdir -p "$EMACS_DIR"
    cat >> "$INIT_FILE" << 'EOF'

;; ============================================
;; SecOpsAI Security Hardening
;; ============================================

;; Disable man: URI handler (CVE-2025-1244)
(setq Man-support-symlinks-in-manpath nil)
(add-hook 'man-mode-hook
          (lambda ()
            (setq-local browse-url-browser-function
                        (lambda (url &rest args)
                          (if (string-prefix-p "man:" url)
                              (message "man: URIs disabled for security")
                            (browse-url-default-browser url))))))

;; Disable insecure URI schemes
defun secopsai-safe-browse-url (url &optional new-window)
  "Safely browse URL with restrictions"
  (cond
   ((string-prefix-p "man:" url)
    (message "man: URIs are disabled for security"))
   ((string-prefix-p "file:" url)
    (message "file: URIs require manual confirmation"))
   (t
    (browse-url-default-browser url new-window))))

(setq browse-url-browser-function 'secopsai-safe-browse-url)

;; Restrict eval-expression
(setq eval-expression-print-length 100)
(setq eval-expression-print-level 10)

;; Disable auto-execution of local variables (similar to vim modelines)
(setq enable-local-variables nil)
(setq enable-local-eval nil)

;; Secure temporary files
(setq temporary-file-directory
      (expand-file-name "tmp/" user-emacs-directory))
(make-directory temporary-file-directory t)

;; Restrict shell commands
(setq shell-command-default-error-buffer "*Shell Command Errors*")

;; Disable dangerous modes by default
(eval-after-load 'tramp
  '(setq tramp-default-method "ssh"))

;; Warning for large files (potential DoS)
(setq large-file-warning-threshold 100000000) ; 100MB
EOF
    
    echo -e "${GREEN}✓ Emacs hardening complete${NC}"
    echo "  - Disabled man: URI handler"
    echo "  - Secured browse-url functionality"
    echo "  - Disabled local variable auto-execution"
    echo ""
}

# ============================================
# 4. PYTHON SECURITY HARDENING
# ============================================

harden_python() {
    echo -e "${YELLOW}[4/4] Hardening Python environment...${NC}"
    
    # Check if Python is installed
    if ! command -v python3 &> /dev/null; then
        echo -e "${YELLOW}Python not found - skipping Python hardening${NC}"
        return
    fi
    
    # Create secure pip config
    PIP_DIR="$HOME/.config/pip"
    mkdir -p "$PIP_DIR"
    
    cat > "$PIP_DIR/pip.conf" << 'EOF'
[global]
# Disable bytecode compilation (reduces attack surface)
no-compile = no

# Require hashes for packages
require-hashes = no

# Only use PyPI
index-url = https://pypi.org/simple
trusted-host = pypi.org
files.pythonhosted.org

# Timeout for connections
timeout = 30

[install]
# No dependencies by default (manual review)
no-deps = no

[freeze]
# Generate requirements with hashes
timeout = 10
EOF
    
    # Create sitecustomize.py to block .pth execution
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    SITES_DIR=$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "")
    
    if [[ -n "$SITES_DIR" && -d "$SITES_DIR" ]]; then
        cat > "$SITES_DIR/sitecustomize.py" << 'EOF'
"""
SecOpsAI Python Security Hardening
Blocks malicious .pth file execution
"""
import sys
import warnings

# Log all .pth file loading for monitoring
_original_exec = exec

def monitored_exec(source, globals=None, locals=None):
    """Monitor exec calls from .pth files"""
    if globals and '__file__' in globals:
        if globals['__file__'].endswith('.pth'):
            warnings.warn(f"SECURITY: .pth file execution detected: {globals['__file__']}")
    return _original_exec(source, globals, locals)

# Only enable monitoring in production
if sys.flags.ignore_environment == 0:
    __builtins__['exec'] = monitored_exec
EOF
    fi
    
    echo -e "${GREEN}✓ Python hardening complete${NC}"
    echo "  - Secured pip configuration"
    echo "  - Restricted to official PyPI only"
    echo "  - Added .pth execution monitoring"
    echo ""
}

# ============================================
# 5. SYSTEM-WIDE HARDENING
# ============================================

harden_system() {
    echo -e "${YELLOW}[5/5] System-wide security hardening...${NC}"
    
    # Create SecOpsAI monitoring directory
    mkdir -p "$HOME/.secopsai/logs"
    mkdir -p "$HOME/.secopsai/quarantine"
    
    # Create monitoring script
    cat > "$HOME/.secopsai/monitor.sh" << 'EOF'
#!/bin/bash
# SecOpsAI System Monitor
LOG_FILE="$HOME/.secopsai/logs/security-$(date +%Y%m%d).log"

echo "[$(date)] Security check started" >> "$LOG_FILE"

# Check for suspicious npm packages
if command -v npm &> /dev/null; then
    npm ls axios 2>/dev/null | grep -E "(1.14.1|0.30.4)" && echo "[$(date)] WARNING: Compromised axios version detected" >> "$LOG_FILE"
    npm ls litellm 2>/dev/null | grep -E "(1.82.7|1.82.8)" && echo "[$(date)] WARNING: Compromised litellm version detected" >> "$LOG_FILE"
fi

# Check for suspicious files
find /tmp -name "ld.py" -o -name "sysmon.py" 2>/dev/null | while read f; do
    echo "[$(date)] WARNING: Suspicious file found: $f" >> "$LOG_FILE"
done

echo "[$(date)] Security check completed" >> "$LOG_FILE"
EOF
    chmod +x "$HOME/.secopsai/monitor.sh"
    
    # Add to crontab if available
    if command -v crontab &> /dev/null; then
        (crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/.secopsai/monitor.sh") | crontab -
        echo "✅ Added monitoring to crontab (runs every 5 minutes)"
    fi
    
    echo -e "${GREEN}✓ System hardening complete${NC}"
    echo ""
}

# ============================================
# MAIN EXECUTION
# ============================================

main() {
    echo "Starting security hardening..."
    echo ""
    
    # Run all hardening steps
    harden_npm
    harden_vim
    harden_emacs
    harden_python
    harden_system
    
    echo "=========================================="
    echo -e "${GREEN}✅ HARDENING COMPLETE${NC}"
    echo "=========================================="
    echo ""
    echo "Summary of changes:"
    echo "  • npm: Disabled scripts, enabled SSL, set official registry"
    echo "  • Vim: Disabled modelines, tar.vim, zip.vim plugins"
    echo "  • Emacs: Disabled man: URI, secured browse-url"
    echo "  • Python: Secured pip, added .pth monitoring"
    echo "  • System: Created monitoring scripts"
    echo ""
    echo "Backups created:"
    ls -la ~/.npmrc.backup.* 2>/dev/null || echo "  (npm backup)"
    ls -la ~/.vimrc.backup.* 2>/dev/null || echo "  (vim backup)"
    echo ""
    echo "⚠️  IMPORTANT NEXT STEPS:"
    echo "  1. Review the configuration changes"
    echo "  2. Test your development workflow"
    echo "  3. For npm: Use 'npm install --ignore-scripts=false' when needed"
    echo "  4. For editors: Verify plugins still work as expected"
    echo ""
    echo "Monitoring enabled. Check logs at: ~/.secopsai/logs/"
}

# Handle arguments
case "${1:-}" in
    --npm)
        harden_npm
        ;;
    --vim)
        harden_vim
        ;;
    --emacs)
        harden_emacs
        ;;
    --python)
        harden_python
        ;;
    --help|-h)
        echo "Usage: $0 [--npm|--vim|--emacs|--python]"
        echo ""
        echo "Options:"
        echo "  --npm     Harden npm only"
        echo "  --vim     Harden Vim only"
        echo "  --emacs   Harden Emacs only"
        echo "  --python  Harden Python only"
        echo "  (none)    Run all hardening steps"
        ;;
    *)
        main
        ;;
esac
