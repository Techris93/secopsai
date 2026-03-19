#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/com.secops.autoresearch.openclaw.daily.plist"

mkdir -p "$PLIST_DIR"
mkdir -p "$ROOT_DIR/data/openclaw/logs"
chmod 700 "$ROOT_DIR/data/openclaw/logs"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.secops.autoresearch.openclaw.daily</string>

  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT_DIR/scripts/openclaw_daily.sh</string>
    <string>--skip-export</string>
  </array>

  <key>Umask</key>
  <integer>63</integer>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>9</integer>
    <key>Minute</key><integer>0</integer>
  </dict>

  <key>RunAtLoad</key>
  <true/>

  <key>StandardOutPath</key>
  <string>$ROOT_DIR/data/openclaw/logs/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>$ROOT_DIR/data/openclaw/logs/launchd.err.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl load "$PLIST_PATH"

cat <<MSG
Installed daily scheduler:
  $PLIST_PATH

Default schedule:
  Every day at 09:00 local time

Quick checks:
  launchctl list | grep secops.autoresearch.openclaw.daily
  tail -f "$ROOT_DIR/data/openclaw/logs/launchd.out.log"
MSG
