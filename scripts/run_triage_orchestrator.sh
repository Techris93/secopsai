#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

cd "$ROOT_DIR"
PYTHONPATH="$ROOT_DIR" "$PYTHON_BIN" -m secopsai.cli triage orchestrate \
  --search-root "$ROOT_DIR" \
  --summary-dir "$ROOT_DIR/reports/triage/orchestrator"
PYTHONPATH="$ROOT_DIR" "$PYTHON_BIN" -m secopsai.cli triage summary \
  --summary-dir "$ROOT_DIR/reports/triage/orchestrator"
