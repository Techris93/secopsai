#!/bin/sh
set -eu

# Bootstrap installer for secopsai.dev.
# Optional hardening controls:
#   SECOPSAI_INSTALL_REF=<git ref/commit>         (default: pinned immutable commit)
#   SECOPSAI_INSTALL_SHA256=<expected sha256 sum> (optional)
INSTALL_REF="${SECOPSAI_INSTALL_REF:-3f82360ccca20f1f453aa7e744edc752a4ae85f3}"
INSTALL_URL="https://raw.githubusercontent.com/Techris93/secopsai/${INSTALL_REF}/setup.sh"

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

tmp_file="$(mktemp)"
cleanup() {
  rm -f "$tmp_file"
}
trap cleanup EXIT INT TERM

# shellcheck disable=SC2086
if ! sh -c "$FETCH_CMD \"$INSTALL_URL\"" > "$tmp_file"; then
  echo "Error: failed to download setup script from $INSTALL_URL" >&2
  exit 1
fi

if [ -n "${SECOPSAI_INSTALL_SHA256:-}" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    actual_sum="$(sha256sum "$tmp_file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual_sum="$(shasum -a 256 "$tmp_file" | awk '{print $1}')"
  else
    echo "Error: SECOPSAI_INSTALL_SHA256 is set but no sha256 tool is available." >&2
    exit 1
  fi

  if [ "$actual_sum" != "$SECOPSAI_INSTALL_SHA256" ]; then
    echo "Error: setup.sh checksum mismatch." >&2
    exit 1
  fi
fi

exec bash "$tmp_file"