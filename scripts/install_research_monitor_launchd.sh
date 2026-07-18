#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="ai.secopsai.research-monitor"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/SecOpsAI"
OUT_LOG="$LOG_DIR/research-monitor.out.log"
ERR_LOG="$LOG_DIR/research-monitor.err.log"
PYTHON="$ROOT_DIR/.venv/bin/python"
INTERVAL="${SECOPSAI_RESEARCH_MONITOR_TRIGGER_SECONDS:-900}"
ACTION="${1:-install}"

if [[ ! "$INTERVAL" =~ ^[0-9]+$ ]] || (( INTERVAL < 300 )); then
  echo "SECOPSAI_RESEARCH_MONITOR_TRIGGER_SECONDS must be an integer of at least 300" >&2
  exit 2
fi

service_target="gui/$(id -u)/$LABEL"

print_status() {
  if launchctl print "$service_target" >/dev/null 2>&1; then
    launchctl print "$service_target" | grep -E 'state =|runs =|last exit code|run interval' || true
  else
    echo "$LABEL is not installed"
    return 1
  fi
}

case "$ACTION" in
  install)
    if [[ ! -x "$PYTHON" ]]; then
      echo "Core virtual environment is missing: $PYTHON" >&2
      exit 2
    fi
    mkdir -p "$PLIST_DIR" "$LOG_DIR"
    chmod 700 "$LOG_DIR"
    cat >"$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>WorkingDirectory</key><string>$ROOT_DIR</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON</string>
    <string>-c</string>
    <string>import json; from secopsai.research_discovery import run_due_monitors; print(json.dumps(run_due_monitors(limit=25), indent=2))</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>$HOME</string>
    <key>PATH</key><string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>PYTHONPATH</key><string>$ROOT_DIR</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
    <key>TMPDIR</key><string>/tmp</string>
  </dict>
  <key>StartInterval</key><integer>$INTERVAL</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>ThrottleInterval</key><integer>60</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>$OUT_LOG</string>
  <key>StandardErrorPath</key><string>$ERR_LOG</string>
</dict>
</plist>
EOF
    plutil -lint "$PLIST_PATH"
    launchctl bootout "$service_target" >/dev/null 2>&1 || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
    echo "Installed $LABEL with a ${INTERVAL}-second trigger."
    print_status
    ;;
  status)
    print_status
    ;;
  run-now)
    launchctl start "$LABEL"
    echo "Requested one due-monitor run."
    ;;
  logs)
    echo "stdout: $OUT_LOG"
    echo "stderr: $ERR_LOG"
    tail -n 80 "$OUT_LOG" "$ERR_LOG" 2>/dev/null || true
    ;;
  uninstall)
    launchctl bootout "$service_target" >/dev/null 2>&1 || true
    if [[ -f "$PLIST_PATH" ]]; then
      mv "$PLIST_PATH" "$PLIST_PATH.disabled"
    fi
    echo "Uninstalled $LABEL. Logs were retained in $LOG_DIR."
    ;;
  *)
    echo "usage: $0 {install|status|run-now|logs|uninstall}" >&2
    exit 2
    ;;
esac
