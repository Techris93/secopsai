#!/bin/sh
set -eu

# Bootstrap installer for secopsai.dev. Keeps the public one-liner stable
# while delegating to the latest maintained installer in the main branch.
INSTALL_URL="https://raw.githubusercontent.com/Techris93/secopsai/main/setup.sh"

if command -v curl >/dev/null 2>&1; then
  FETCH_CMD="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  FETCH_CMD="wget -qO-"
else
  echo "Error: curl or wget is required to install secopsai." >&2
  exit 1
fi

if ! command -v bash >/dev/null 2>&1; then
  echo "Error: bash is required to install secopsai." >&2
  exit 1
fi

# shellcheck disable=SC2086
exec sh -c "$FETCH_CMD \"$INSTALL_URL\" | bash"