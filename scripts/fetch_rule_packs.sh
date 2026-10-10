#!/usr/bin/env bash
# Fetch third-party YARA rule packs at pinned commits (git verifies content by
# commit hash).  Rules are used, not redistributed: they are not committed to
# this repository.  Prints the directories to put in SECOPSAI_YARA_RULE_DIRS.
#
# Neo23x0/signature-base (Nextron Systems' open rules, including the generic
# SUSP_ tradecraft rules) is under the Detection Rule License 1.1: matches
# keep each rule's author and reference in SecOpsAI findings.
set -euo pipefail
dest="${1:-${RUNNER_TEMP:-/tmp}/secopsai-rule-packs}"
SIGNATURE_BASE_COMMIT="94a1c48d7ab499879287ff611dfe7f9c56376030"  # 2026-09-08
mkdir -p "$dest"
if [ ! -d "$dest/signature-base/.git" ]; then
  git init -q "$dest/signature-base"
  git -C "$dest/signature-base" remote add origin https://github.com/Neo23x0/signature-base.git
fi
git -C "$dest/signature-base" fetch -q --depth 1 origin "$SIGNATURE_BASE_COMMIT"
git -C "$dest/signature-base" -c advice.detachedHead=false checkout -q FETCH_HEAD
test "$(git -C "$dest/signature-base" rev-parse HEAD)" = "$SIGNATURE_BASE_COMMIT"
echo "$dest/signature-base/yara"
