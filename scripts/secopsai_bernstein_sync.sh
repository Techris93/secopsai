#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_EXEC="${PYTHON_EXEC:-$PROJECT_ROOT/.venv/bin/python}"

if [[ ! -x "$PYTHON_EXEC" ]]; then
  echo "Python executable not found: $PYTHON_EXEC"
  exit 1
fi

cd "$PROJECT_ROOT"

"$PYTHON_EXEC" "$SCRIPT_DIR/secopsai_to_bernstein.py" \
  --severity high \
  --limit 10 \
  --output-plan "$PROJECT_ROOT/.sdd/plans/secopsai-remediation.yaml" \
  --findings-dir "$PROJECT_ROOT/.sdd/secopsai/findings"

echo "Bernstein remediation plan refreshed at .sdd/plans/secopsai-remediation.yaml"
