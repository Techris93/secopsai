#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/com.secopsai.triage-summary-notify.plist"

mkdir -p "$PLIST_DIR"
mkdir -p "$ROOT_DIR/reports/triage/summary"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.secopsai.triage-summary-notify</string>

  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT_DIR/scripts/run_triage_summary_notify.sh</string>
  </array>

  <key>StartInterval</key>
  <integer>600</integer>

  <key>RunAtLoad</key>
  <true/>

  <key>StandardOutPath</key>
  <string>$ROOT_DIR/reports/triage/summary/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>$ROOT_DIR/reports/triage/summary/launchd.err.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl load "$PLIST_PATH"

cat <<MSG
Installed triage summary notifier scheduler:
  $PLIST_PATH

Cadence:
  every 10 minutes

Quick checks:
  launchctl list | grep secopsai.triage-summary-notify
  tail -f "$ROOT_DIR/reports/triage/summary/launchd.out.log"
MSG