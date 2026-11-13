#!/bin/bash
# One auto-remediation pass, run by the ai.secopsai.auto-remediation LaunchAgent.
# It works from its own clone kept at origin/main, never the shared checkout.
set -euo pipefail
CLONE="${SECOPSAI_REMEDIATION_CLONE:-$HOME/secopsai-remediation}"
PYTHON="${SECOPSAI_REMEDIATION_PYTHON:-$HOME/secopsai/.venv/bin/python}"
cd "$CLONE"
git fetch --quiet origin main
git checkout --quiet --detach origin/main
git worktree prune
exec "$PYTHON" -m secopsai.cli remediation tick
