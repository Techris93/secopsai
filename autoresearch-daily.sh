#!/bin/bash
#
# SecOpsAI Autoresearch Daily Runner
# Runs detection experiments and tunes rules based on results
#

set -euo pipefail

# Configuration
WORKSPACE_DIR="/Users/chrixchange/.openclaw/workspace/secopsai"
RESULTS_DIR="$WORKSPACE_DIR/results"
LOGS_DIR="$WORKSPACE_DIR/logs"
BASELINE_F1_FILE="$WORKSPACE_DIR/.baseline_f1"

# Telegram notification settings (from environment)
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# Create directories
mkdir -p "$RESULTS_DIR" "$LOGS_DIR"

# Timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOGS_DIR/autoresearch-$TIMESTAMP.log"

cd "$WORKSPACE_DIR"

# Helper function: Extract F1 score from evaluation output
extract_f1_score() {
    local output="$1"
    # Extract just the numeric value from "F1_SCORE=0.875036"
    # Handles formats like: ">>> F1_SCORE=0.875036 <<<" or "F1_SCORE=0.875036"
    echo "$output" | grep -oE 'F1_SCORE=[0-9]+(\.[0-9]+)?' | head -1 | cut -d'=' -f2
}

# Helper function: Send Telegram notification
send_telegram_notification() {
    local message="$1"
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID" \
            -d "text=$message" \
            -d "parse_mode=Markdown" > /dev/null || true
    fi
}

# Helper function: Compare F1 scores
compare_f1() {
    local baseline="$1"
    local new="$2"
    
    # Use Python for proper float comparison
    python3 << EOF
import sys
baseline = float("$baseline")
new = float("$new")

if new > baseline:
    print("improved")
elif abs(new - baseline) < 0.0001:
    print("same")
else:
    print("decreased")
EOF
}

{
    echo "=============================================="
    echo "SecOpsAI Autoresearch - $(date)"
    echo "=============================================="
    
    # Step 1: Get baseline F1 (from file or run once)
    if [[ -f "$BASELINE_F1_FILE" ]]; then
        BASELINE_F1=$(cat "$BASELINE_F1_FILE")
        echo "📊 Baseline F1: $BASELINE_F1"
    else
        echo "🔄 No baseline found. Running initial evaluation..."
        INITIAL_OUTPUT=$(python3 evaluate.py 2>&1)
        BASELINE_F1=$(extract_f1_score "$INITIAL_OUTPUT")
        echo "$BASELINE_F1" > "$BASELINE_F1_FILE"
        echo "📊 Baseline set to: $BASELINE_F1"
    fi
    
    # Step 2: Run experiment search (find better rules/thresholds)
    echo ""
    echo "🔍 Running autoresearch experiments..."
    
    # Run the search script
    python3 scripts/autoresearch_search.py 2>&1 | tee -a "$LOG_FILE"
    
    # Step 3: Apply any found improvements
    echo ""
    echo "🔧 Applying optimizations..."
    python3 scripts/autoresearch_tune_apply.py 2>&1 | tee -a "$LOG_FILE" || true
    
    # Step 4: Evaluate new performance
    echo ""
    echo "📊 Evaluating new rules..."
    NEW_OUTPUT=$(python3 evaluate.py 2>&1)
    NEW_F1=$(extract_f1_score "$NEW_OUTPUT")
    
    echo "New F1 Score: $NEW_F1"
    
    # Step 5: Compare and report
    COMPARISON=$(compare_f1 "$BASELINE_F1" "$NEW_F1")
    
    case "$COMPARISON" in
        "improved")
            echo "✅ F1 improved: $BASELINE_F1 → $NEW_F1"
            echo "$NEW_F1" > "$BASELINE_F1_FILE"
            
            # Save experiment results
            echo "$NEW_OUTPUT" > "$RESULTS_DIR/improvement-$TIMESTAMP.txt"
            
            # Send notification
            send_telegram_notification "🚀 SecOpsAI Improvement!

F1 Score improved: \`$BASELINE_F1\` → \`$NEW_F1\`

Experiment saved to: improvement-$TIMESTAMP.txt"
            ;;
            
        "same")
            echo "➡️ F1 unchanged: $NEW_F1"
            ;;
            
        "decreased")
            echo "⚠️ F1 decreased: $BASELINE_F1 → $NEW_F1 (keeping baseline)"
            
            # Revert changes
            git checkout detect.py 2>/dev/null || true
            ;;
    esac
    
    echo ""
    echo "=============================================="
    echo "Autoresearch complete at $(date)"
    echo "=============================================="
    
} 2>&1 | tee -a "$LOG_FILE"

# Cleanup old logs (keep last 30 days)
find "$LOGS_DIR" -name "autoresearch-*.log" -mtime +30 -delete 2>/dev/null || true

exit 0
