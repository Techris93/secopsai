#!/usr/bin/env bash
# Fetch third-party YARA rule packs at pinned commits (git verifies content by
# commit hash).  Rules are used, not redistributed: they are not committed to
# this repository.  Prints the directories to put in SECOPSAI_YARA_RULE_DIRS.
#
# Neo23x0/signature-base (Nextron Systems' open rules, including the generic
# SUSP_ tradecraft rules) is under the Detection Rule License 1.1: matches
# keep each rule's author and reference in SecOpsAI findings.
#
# SECOPSAI_RULE_PACKS selects the packs (comma separated):
#   signature-base       Nextron's repository at a pinned commit (default)
#   yara-forge-extended  YARA Forge's curated bundle of ~40 public rule sets
#                        (includes signature-base, renamed; use it instead of,
#                        not with, signature-base). Licences per rule: DRL 1.1,
#                        CC BY-SA 4.0, BSD, Apache-2.0, MIT; attribution kept.
set -euo pipefail
dest="${1:-${RUNNER_TEMP:-/tmp}/secopsai-rule-packs}"
packs="${SECOPSAI_RULE_PACKS:-signature-base}"
YARA_FORGE_RELEASE="20261004"
YARA_FORGE_SHA256="9f89b42e7a5991982a6f5ca0e3a7c3d30fd48cdacc2c5c4f12a7c54e34d63117"
dirs=()
SIGNATURE_BASE_COMMIT="94a1c48d7ab499879287ff611dfe7f9c56376030"  # 2026-09-08
mkdir -p "$dest"
fetch_signature_base() {
  if [ ! -d "$dest/signature-base/.git" ]; then
    git init -q "$dest/signature-base"
    git -C "$dest/signature-base" remote add origin https://github.com/Neo23x0/signature-base.git
  fi
  git -C "$dest/signature-base" fetch -q --depth 1 origin "$SIGNATURE_BASE_COMMIT"
  git -C "$dest/signature-base" -c advice.detachedHead=false checkout -q FETCH_HEAD
  test "$(git -C "$dest/signature-base" rev-parse HEAD)" = "$SIGNATURE_BASE_COMMIT"
  dirs+=("$dest/signature-base/yara")
}

fetch_yara_forge() {
  local zip="$dest/yara-forge-extended.zip" out="$dest/yara-forge-extended"
  curl -fsSL -o "$zip" "https://github.com/YARAHQ/yara-forge/releases/download/$YARA_FORGE_RELEASE/yara-forge-rules-extended.zip"
  if command -v sha256sum >/dev/null; then echo "$YARA_FORGE_SHA256  $zip" | sha256sum -c --quiet - >&2; else echo "$YARA_FORGE_SHA256  $zip" | shasum -a 256 -c --quiet - >&2; fi
  rm -rf "$out" && mkdir -p "$out" && unzip -qo "$zip" -d "$out"
  dirs+=("$out/packages/extended")
}

IFS=',' read -ra wanted <<< "$packs"
for pack in "${wanted[@]}"; do
  case "$pack" in
    signature-base) fetch_signature_base ;;
    yara-forge-extended) fetch_yara_forge ;;
    *) echo "unknown rule pack: $pack" >&2; exit 2 ;;
  esac
done
(IFS=:; echo "${dirs[*]}")
