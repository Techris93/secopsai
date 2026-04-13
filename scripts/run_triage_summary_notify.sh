#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
LOG_DIR="${ROOT_DIR}/reports/triage/summary"
TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
LOG_FILE="${LOG_DIR}/triage-summary-${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

cd "$ROOT_DIR"

echo "[info] $(date -u +"%Y-%m-%dT%H:%M:%SZ") starting triage summary notifier" | tee -a "$LOG_FILE"
PYTHONPATH="$ROOT_DIR" "$PYTHON_BIN" - <<'PY' 2>&1 | tee -a "$LOG_FILE"
import json

from secopsai.alerts import alert_new_triage_findings
from secopsai.triage import generate_summary

payload = generate_summary(summary_dir="reports/triage/summary", limit=1000)
active_findings = [
    finding
    for finding in payload.get("findings", [])
    if str(finding.get("status", "")).lower() in {"open", "in_review"}
]
meta = alert_new_triage_findings(
    active_findings,
    open_count=int(payload.get("open_findings", 0)),
    in_review_count=int(payload.get("in_review_findings", 0)),
)
print(json.dumps({
    "summary_json": payload.get("summary_json"),
    "summary_markdown": payload.get("summary_markdown"),
    "open_findings": payload.get("open_findings", 0),
    "in_review_findings": payload.get("in_review_findings", 0),
    "triage_alerts": meta,
}, indent=2, sort_keys=True))
PY