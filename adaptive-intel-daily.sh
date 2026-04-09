#!/bin/bash
# SecOpsAI Adaptive Intelligence Pipeline
# Runs daily to learn from new threats and adapt detection rules

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="/Users/chrixchange/.openclaw/workspace"
SECOPSAI_DIR="$SCRIPT_DIR"
LOG_DIR="$WORKSPACE/logs"
DATE_STAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOG_DIR/adaptive-intel-$DATE_STAMP.log"
VENV_PYTHON="$SECOPSAI_DIR/.venv/bin/python3"
VENV_PIP="$SECOPSAI_DIR/.venv/bin/pip"

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] $1" | tee -a "$LOG_FILE"
}

send_telegram() {
    local msg="$1"
    if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID" \
            -d "text=$msg" \
            -d "parse_mode=Markdown" > /dev/null 2>&1 || true
    fi
}

log "🧠 SecOpsAI Adaptive Intelligence Pipeline Started"
log "📅 $(date)"
log "🖥️  Host: $(hostname)"

cd "$SECOPSAI_DIR" || {
    log "❌ Cannot navigate to $SECOPSAI_DIR"
    send_telegram "❌ *Adaptive Intel Failed*\n\nCannot navigate to workspace"
    exit 1
}

if [[ ! -x "$VENV_PYTHON" ]]; then
    log "❌ Missing Python runtime at $VENV_PYTHON"
    send_telegram "❌ *Adaptive Intel Failed*\n\nMissing SecOpsAI venv python at \`$VENV_PYTHON\`"
    exit 1
fi

# Sync latest changes safely on main only.
if [[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]]; then
    log "📥 Fetching latest changes..."
    git fetch origin main >> "$LOG_FILE" 2>&1 || log "⚠️  Git fetch failed, continuing"
    if [[ -z "$(git status --porcelain)" ]]; then
        log "📦 Fast-forwarding main if needed..."
        git merge --ff-only origin/main >> "$LOG_FILE" 2>&1 || log "⚠️  Fast-forward merge failed, continuing"
    else
        log "⚠️  Worktree is dirty; skipping fast-forward merge"
    fi
else
    log "⚠️  Current branch is $(git rev-parse --abbrev-ref HEAD); skipping git sync"
fi

# Install dependencies if needed
log "📦 Checking dependencies..."
"$VENV_PIP" install feedparser requests -q >> "$LOG_FILE" 2>&1 || true

# Run the adaptive intelligence pipeline
log "🧠 Running adaptive intelligence pipeline..."
"$VENV_PYTHON" adaptive_intelligence_pipeline.py >> "$LOG_FILE" 2>&1

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    log "✅ Pipeline completed successfully"
    
    # Check if new rules were deployed
    if grep -q "Rules DEPLOYED" "$LOG_FILE" 2>/dev/null; then
        send_telegram "🧠 *SecOpsAI Adapted!*\n\nNew threat intelligence processed and rules deployed.\n\n📁 Log: \`$LOG_FILE\`"
    else
        send_telegram "🧠 *SecOpsAI Intelligence Check*\n\nNo improvement from new rules. System is current.\n\n📁 Log: \`$LOG_FILE\`"
    fi
else
    log "❌ Pipeline failed with exit code $EXIT_CODE"
    send_telegram "❌ *Adaptive Intel Failed*\n\nExit code: $EXIT_CODE\n\n📁 Log: \`$LOG_FILE\`"
fi

log "════════════════════════════════════════════════════════════"
log "  🧠 Adaptive Intelligence Complete"
log "════════════════════════════════════════════════════════════"

exit $EXIT_CODE
