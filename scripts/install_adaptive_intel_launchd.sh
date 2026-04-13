#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/com.openclaw.secopsai.adaptive-intel.plist"
LOG_DIR="$HOME/.openclaw/workspace/logs"

read_plist_value() {
    local plist_path="$1"
    local key_path="$2"

    /usr/libexec/PlistBuddy -c "Print ${key_path}" "$plist_path" 2>/dev/null || true
}

existing_token=""
existing_chat_id=""
if [[ -f "$PLIST_PATH" ]]; then
    existing_token="$(read_plist_value "$PLIST_PATH" ':EnvironmentVariables:TELEGRAM_BOT_TOKEN')"
    existing_chat_id="$(read_plist_value "$PLIST_PATH" ':EnvironmentVariables:TELEGRAM_CHAT_ID')"
fi

telegram_token="${TELEGRAM_BOT_TOKEN:-$existing_token}"
telegram_chat_id="${TELEGRAM_CHAT_ID:-$existing_chat_id}"

if [[ -z "$telegram_token" || "$telegram_token" == "SET_ME_LOCALLY" ]]; then
    cat <<MSG >&2
Missing TELEGRAM_BOT_TOKEN.

Provide it for first-time setup:
  TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... bash scripts/install_adaptive_intel_launchd.sh

If a local plist already exists, this installer preserves its Telegram values automatically.
MSG
    exit 1
fi

if [[ -z "$telegram_chat_id" ]]; then
    cat <<MSG >&2
Missing TELEGRAM_CHAT_ID.

Provide it for first-time setup:
  TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... bash scripts/install_adaptive_intel_launchd.sh
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
  <string>com.openclaw.secopsai.adaptive-intel</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT_DIR/adaptive-intel-daily.sh</string>
  </array>

  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>

  <key>StandardOutPath</key>
  <string>$LOG_DIR/adaptive-intel-out.log</string>

  <key>StandardErrorPath</key>
  <string>$LOG_DIR/adaptive-intel-err.log</string>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>23</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>

  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin</string>
    <key>HOME</key>
    <string>$HOME</string>
    <key>TELEGRAM_BOT_TOKEN</key>
    <string>$telegram_token</string>
    <key>TELEGRAM_CHAT_ID</key>
    <string>$telegram_chat_id</string>
  </dict>

  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
EOF

launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl load "$PLIST_PATH"

cat <<MSG
Installed adaptive-intel scheduler:
  $PLIST_PATH

Schedule:
  daily at 23:00

Working directory:
  $ROOT_DIR

Quick checks:
  launchctl print gui/$(id -u)/com.openclaw.secopsai.adaptive-intel
  tail -f "$LOG_DIR/adaptive-intel-out.log"
MSG