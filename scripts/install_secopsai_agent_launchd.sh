#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/com.secopsai.agent.plist"
LOG_DIR="$ROOT_DIR/logs"
PYTHON_PATH="$ROOT_DIR/.venv/bin/python"
REFRESH_PLATFORMS="${SECOPSAI_REFRESH_PLATFORMS:-macos,openclaw}"
REFRESH_INTERVAL="${SECOPSAI_REFRESH_INTERVAL_SECONDS:-300}"

if [[ ! -x "$PYTHON_PATH" ]]; then
    cat <<MSG >&2
Missing Python runtime at:
  $PYTHON_PATH

Create the repo virtual environment before installing the launchd job.
MSG
    exit 1
fi

if ! [[ "$REFRESH_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$REFRESH_INTERVAL" -lt 60 ]]; then
    cat <<MSG >&2
SECOPSAI_REFRESH_INTERVAL_SECONDS must be an integer >= 60.
Current value:
  $REFRESH_INTERVAL
MSG
    exit 1
fi

mkdir -p "$PLIST_DIR"
mkdir -p "$LOG_DIR"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.secopsai.agent</string>

  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON_PATH</string>
    <string>$ROOT_DIR/cli.py</string>
    <string>refresh</string>
    <string>--platform</string>
    <string>$REFRESH_PLATFORMS</string>
  </array>

  <key>StartInterval</key>
  <integer>$REFRESH_INTERVAL</integer>

  <key>RunAtLoad</key>
  <true/>

  <key>StandardOutPath</key>
  <string>$LOG_DIR/agent.log</string>

  <key>StandardErrorPath</key>
  <string>$LOG_DIR/agent.error.log</string>

  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl load "$PLIST_PATH"

cat <<MSG
Installed SecOpsAI refresh scheduler:
  $PLIST_PATH

Platforms:
  $REFRESH_PLATFORMS

Interval:
  every $REFRESH_INTERVAL seconds

Quick checks:
  launchctl print gui/$(id -u)/com.secopsai.agent
  tail -f "$LOG_DIR/agent.log"
MSG