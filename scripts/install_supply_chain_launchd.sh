#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/com.secopsai.supply-chain-monitor.plist"

mkdir -p "$PLIST_DIR"
mkdir -p "$ROOT_DIR/data/supply_chain"
chmod 700 "$ROOT_DIR/data/supply_chain"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.secopsai.supply-chain-monitor</string>

  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$ROOT_DIR/scripts/supply_chain_monitor.sh</string>
  </array>

  <key>Umask</key>
  <integer>63</integer>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>$ROOT_DIR/data/supply_chain/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>$ROOT_DIR/data/supply_chain/launchd.err.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl load "$PLIST_PATH"

cat <<MSG
Installed supply-chain scheduler:
  $PLIST_PATH

Quick checks:
  launchctl list | grep secopsai.supply-chain-monitor
  tail -f "$ROOT_DIR/data/supply_chain/launchd.out.log"
MSG
