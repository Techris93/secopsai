#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/com.secops.autoresearch.openclaw.daily.plist"
RUN_HOUR="${SECOPSAI_OPENCLAW_HOUR:-5}"
RUN_MINUTE="${SECOPSAI_OPENCLAW_MINUTE:-45}"
SKIP_EXPORT="${SECOPSAI_OPENCLAW_SKIP_EXPORT:-0}"
PROGRAM_ARGS=$(cat <<EOF
  <array>
    <string>/bin/bash</string>
    <string>$ROOT_DIR/scripts/openclaw_daily.sh</string>
EOF
)

if [[ "$SKIP_EXPORT" == "1" ]]; then
PROGRAM_ARGS+=$'\n    <string>--skip-export</string>'
fi

PROGRAM_ARGS+=$'\n  </array>'

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
${PROGRAM_ARGS}

  <key>Umask</key>
  <integer>63</integer>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>$RUN_HOUR</integer>
    <key>Minute</key><integer>$RUN_MINUTE</integer>
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
  Every day at $(printf "%02d:%02d" "$RUN_HOUR" "$RUN_MINUTE") local time

Export mode:
  $([[ "$SKIP_EXPORT" == "1" ]] && echo "reuse previously exported native logs" || echo "export fresh native logs from ~/.openclaw")

Quick checks:
  launchctl list | grep secops.autoresearch.openclaw.daily
  tail -f "$ROOT_DIR/data/openclaw/logs/launchd.out.log"
MSG
