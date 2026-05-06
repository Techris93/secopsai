#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$repo_dir/.venv/bin/python"
log_dir="$HOME/.openclaw/cron-scripts/logs"
mkdir -p "$log_dir"

if [[ ! -x "$python_bin" ]]; then
  echo "Missing venv python at $python_bin" >&2
  exit 1
fi

tmp_cron="$(mktemp)"
trap 'rm -f "$tmp_cron"' EXIT

crontab -l 2>/dev/null | grep -v 'secopsai_send_report.py --kind' > "$tmp_cron" || true
cat >> "$tmp_cron" <<CRON
0 6 * * * cd "$repo_dir" && "$python_bin" scripts/secopsai_send_report.py --kind daily-intel >> "$log_dir/daily-intel.log" 2>&1
0 12 * * * cd "$repo_dir" && "$python_bin" scripts/secopsai_send_report.py --kind status-summary >> "$log_dir/status-summary.log" 2>&1
0 21 * * * cd "$repo_dir" && "$python_bin" scripts/secopsai_send_report.py --kind daily-brief >> "$log_dir/daily-summary.log" 2>&1
CRON

crontab "$tmp_cron"
echo "Installed SecOpsAI deterministic report crons."
