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

INSTALL_REF="${SECOPSAI_INSTALL_REF:-v1.0.0}"
REPO_URL="https://github.com/Techris93/secopsai.git"
REPO_DIR="${SECOPSAI_HOME:-"$HOME/secopsai"}"
SETUP_PROFILE="${SECOPSAI_SETUP_PROFILE:-default}"

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

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Error: the existing SecOpsAI checkout has local tracked changes." >&2
  echo "Commit or preserve those changes, or set SECOPSAI_HOME to a dedicated install directory." >&2
  exit 1
fi

echo "Checking out $INSTALL_REF..."
git fetch --tags origin >/dev/null 2>&1
git checkout --detach "$INSTALL_REF" >/dev/null 2>&1

echo "Running setup.sh..."
exec bash setup.sh --non-interactive --profile "$SETUP_PROFILE"
