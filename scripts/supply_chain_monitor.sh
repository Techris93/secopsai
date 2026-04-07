#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/data/supply_chain"
TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
LOG_FILE="$LOG_DIR/monitor-$TIMESTAMP.log"

mkdir -p "$LOG_DIR"

cd "$ROOT_DIR"
source "$ROOT_DIR/.venv/bin/activate"

echo "[info] $(date -u +"%Y-%m-%dT%H:%M:%SZ") starting secopsai supply-chain monitor" | tee -a "$LOG_FILE"
python -m secopsai.cli supply-chain monitor --slack "$@" 2>&1 | tee -a "$LOG_FILE"
