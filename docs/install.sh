#!/bin/sh
set -eu

# Bootstrap installer for secopsai.dev.
# Optional controls:
#   SECOPSAI_INSTALL_REF=<git ref/commit>   (default: pinned immutable commit)
#   SECOPSAI_HOME=<install dir>            (default: $HOME/secopsai)
#
# This script:
#   1. Clones or updates the secopsai repo at SECOPSAI_HOME
#   2. Checks out the requested ref
#   3. Runs setup.sh from the repo root (non-interactive-safe by default)

INSTALL_REF="${SECOPSAI_INSTALL_REF:-a93a042df0cbe593ea64d9002b9556fe0533d537}"
REPO_URL="https://github.com/Techris93/secopsai.git"
REPO_DIR="${SECOPSAI_HOME:-"$HOME/secopsai"}"

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is required to install secopsai." >&2
  exit 1
fi

if ! command -v bash >/dev/null 2>&1; then
  echo "Error: bash is required to install secopsai." >&2
  exit 1
fi

# Clone or update repo
if [ ! -d "$REPO_DIR/.git" ]; then
  echo "Cloning secopsai into $REPO_DIR..."
  git clone "$REPO_URL" "$REPO_DIR"
else
  echo "Using existing secopsai checkout at $REPO_DIR..."
fi

cd "$REPO_DIR"

echo "Checking out $INSTALL_REF..."
git fetch --tags origin >/dev/null 2>&1 || true
git checkout "$INSTALL_REF" >/dev/null 2>&1 || git checkout -B main "$INSTALL_REF"

echo "Running setup.sh..."
exec bash setup.sh --non-interactive
