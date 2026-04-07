#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/com.secopsai.triage-orchestrator.plist"

mkdir -p "$PLIST_DIR"
mkdir -p "$ROOT_DIR/reports/triage/orchestrator"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.secopsai.triage-orchestrator</string>

  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT_DIR/scripts/run_triage_orchestrator.sh</string>
  </array>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>3</integer>
    <key>Minute</key>
    <integer>20</integer>
  </dict>

  <key>RunAtLoad</key>
  <false/>

  <key>StandardOutPath</key>
  <string>$ROOT_DIR/reports/triage/orchestrator/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>$ROOT_DIR/reports/triage/orchestrator/launchd.err.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl load "$PLIST_PATH"

cat <<MSG
Installed triage orchestrator scheduler:
  $PLIST_PATH

Quick checks:
  launchctl list | grep secopsai.triage-orchestrator
  tail -f "$ROOT_DIR/reports/triage/orchestrator/launchd.out.log"
MSG
