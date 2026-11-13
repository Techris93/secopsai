#!/bin/bash
# Install (or update) the auto-remediation LaunchAgent on the operator's Mac.
#   scripts/install_auto_remediation.sh [off|observe|pr|merge]
set -euo pipefail
MODE="${1:-observe}"
CLONE="$HOME/secopsai-remediation"
DATA="$HOME/.secopsai-remediation"
LABEL_NAME="ai.secopsai.auto-remediation"
PLIST="$HOME/Library/LaunchAgents/$LABEL_NAME.plist"
LOGS="$HOME/Library/Logs/SecOpsAI"
[ -d "$CLONE/.git" ] || git clone --quiet https://github.com/Techris93/secopsai.git "$CLONE"
mkdir -p "$DATA" "$LOGS"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL_NAME</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$CLONE/scripts/auto_remediation_tick.sh</string></array>
  <key>StartInterval</key><integer>1800</integer>
  <key>RunAtLoad</key><true/>
  <key>WorkingDirectory</key><string>$CLONE</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>$HOME/.local/node-current/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>SECOPSAI_AUTO_REMEDIATION</key><string>$MODE</string>
    <key>SECOPSAI_REMEDIATION_DB</key><string>$DATA/remediation.db</string>
    <key>SECOPSAI_BRIDGE_MODEL</key><string>anthropic/claude-haiku-5-5</string>
    <key>SECOPSAI_BRIDGE_FALLBACK_MODELS</key><string>xai/grok-4.7,gpt-6.1-terra</string>
    <key>SECOPSAI_BRIDGE_FALLBACK_MODE</key><string>any_provider</string>
  </dict>
  <key>StandardOutPath</key><string>$LOGS/auto-remediation.out.log</string>
  <key>StandardErrorPath</key><string>$LOGS/auto-remediation.err.log</string>
</dict></plist>
PLIST
launchctl bootout "gui/$(id -u)/$LABEL_NAME" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed $LABEL_NAME in mode $MODE"
