#!/bin/sh
set -eu

MIN_VERSION="0.18.2"
CORE_HOME="${SECOPSAI_HOME:-"$HOME/secopsai"}"
HERMES_DATA_HOME="${HERMES_HOME:-"$HOME/.hermes"}"
INTERVAL="${SECOPSAI_HERMES_REFRESH_SECONDS:-300}"
PLUGIN="Techris93/secopsai/integrations/hermes"

fail() {
  echo "Error: $*" >&2
  exit 1
}

for command in hermes git bash python3 curl; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

python3 -m pip --version >/dev/null 2>&1 || fail "python3 -m pip is required"

version_output=$(hermes --version 2>&1 | sed -n '1p')
version=$(printf '%s\n' "$version_output" | sed -n 's/.*Hermes Agent v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
[ -n "$version" ] || fail "could not determine the Hermes Agent version"

if ! python3 - "$version" "$MIN_VERSION" <<'PY'
import sys

def version(value):
    return tuple(int(part) for part in value.split("."))

raise SystemExit(0 if version(sys.argv[1]) >= version(sys.argv[2]) else 1)
PY
then
  fail "Hermes Agent $MIN_VERSION or later is required (found $version)"
fi

[ -d "$HERMES_DATA_HOME" ] || fail "Hermes home not found: $HERMES_DATA_HOME"

temporary=$(mktemp "${TMPDIR:-/tmp}/secopsai-hermes.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

echo "Installing SecOpsAI Core for Hermes Agent..."
curl -fsSL https://secopsai.dev/install.sh -o "$temporary"
SECOPSAI_HOME="$CORE_HOME" SECOPSAI_SETUP_PROFILE=hermes bash "$temporary"

PYTHON="$CORE_HOME/.venv/bin/python"
[ -x "$PYTHON" ] || fail "SecOpsAI virtual environment was not created: $PYTHON"

echo "Installing the read-only SecOpsAI Hermes plugin..."
hermes plugins install "$PLUGIN" --force --enable

echo "Running the first bounded Hermes telemetry refresh..."
HERMES_HOME="$HERMES_DATA_HOME" "$PYTHON" -m secopsai.cli --json hermes refresh --hermes-home "$HERMES_DATA_HOME"

echo "Installing persistent monitoring..."
HERMES_HOME="$HERMES_DATA_HOME" "$PYTHON" -m secopsai.cli --json hermes service install \
  --hermes-home "$HERMES_DATA_HOME" \
  --interval "$INTERVAL"

echo "Verifying the complete integration..."
HERMES_HOME="$HERMES_DATA_HOME" "$PYTHON" -m secopsai.cli --json hermes doctor --hermes-home "$HERMES_DATA_HOME"

cat <<EOF

SecOpsAI for Hermes Agent is installed.

Status:
  $PYTHON -m secopsai.cli hermes doctor

Hermes findings:
  $PYTHON -m secopsai.cli list --platform hermes --no-refresh

Service controls:
  $PYTHON -m secopsai.cli hermes service status
  $PYTHON -m secopsai.cli hermes service logs
  $PYTHON -m secopsai.cli hermes service run-now

Updates:
  hermes plugins update secopsai
  Re-run: curl -fsSL https://secopsai.dev/install-hermes.sh | bash

Uninstall integration components while retaining findings and logs:
  $PYTHON -m secopsai.cli hermes service uninstall
  hermes plugins remove secopsai

Documentation:
  https://docs.secopsai.dev/Hermes-Integration/
EOF
