#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "::error::$1" >&2
  exit 2
}

safe_ref_re='^[A-Za-z0-9._/-]+$'
safe_number_re='^[0-9]+$'
safe_ecosystem_re='^[A-Za-z0-9_.-]+$'

mode="${SECOPSAI_ACTION_MODE:-supply-chain-scan}"
ref="${SECOPSAI_REF:-main}"
scan_path="${SECOPSAI_SCAN_PATH:-.}"
ecosystem="${SECOPSAI_ECOSYSTEM:-}"
package_name="${SECOPSAI_PACKAGE:-}"
version="${SECOPSAI_VERSION:-}"
previous_version="${SECOPSAI_PREVIOUS_VERSION:-}"
since="${SECOPSAI_SINCE:-24h}"
limit="${SECOPSAI_LIMIT:-10}"
output_format="${SECOPSAI_OUTPUT_FORMAT:-json}"
output_file="${SECOPSAI_OUTPUT_FILE:-secopsai-results.json}"
fail_on="${SECOPSAI_FAIL_ON_SEVERITY:-critical}"

[[ "$ref" =~ $safe_ref_re ]] || fail "Invalid secopsai-ref"
[[ "$ref" != *".."* ]] || fail "Invalid secopsai-ref"
[[ "$output_format" == "json" ]] || fail "Only json output is supported"
[[ "$limit" =~ $safe_number_re ]] || fail "limit must be a number"
[[ "$fail_on" =~ ^(none|high|critical)$ ]] || fail "fail-on-severity must be none, high, or critical"
[[ "$mode" =~ ^(supply-chain-scan|advisory-check|discover-campaigns|triage-summary)$ ]] || fail "Unsupported mode: $mode"

if [[ "$scan_path" == -* ]]; then
  fail "path must not start with '-'"
fi
if [[ ! -e "$scan_path" ]]; then
  fail "path does not exist: $scan_path"
fi
if [[ "$output_file" == -* || "$output_file" == *$'\n'* || "$output_file" == *$'\r'* ]]; then
  fail "Invalid output-file"
fi

python -m pip install --upgrade pip
python -m pip install "git+https://github.com/Techris93/secopsai.git@${ref}"

cmd=(secopsai --json)
case "$mode" in
  supply-chain-scan)
    [[ -n "$ecosystem" && "$ecosystem" =~ $safe_ecosystem_re ]] || fail "ecosystem is required for supply-chain-scan"
    [[ -n "$package_name" && "$package_name" != -* ]] || fail "package is required for supply-chain-scan"
    [[ -n "$version" && "$version" != -* ]] || fail "version is required for supply-chain-scan"
    cmd+=(supply-chain scan --ecosystem "$ecosystem" --package "$package_name" --version "$version" --metadata-only --no-report)
    if [[ -n "$previous_version" ]]; then
      [[ "$previous_version" != -* ]] || fail "previous-version must not start with '-'"
      cmd+=(--previous-version "$previous_version")
    fi
    ;;
  advisory-check)
    [[ -n "$ecosystem" && "$ecosystem" =~ $safe_ecosystem_re ]] || fail "ecosystem is required for advisory-check"
    [[ -n "$package_name" && "$package_name" != -* ]] || fail "package is required for advisory-check"
    [[ -n "$version" && "$version" != -* ]] || fail "version is required for advisory-check"
    cmd+=(supply-chain advisory check --ecosystem "$ecosystem" --package "$package_name" --version "$version")
    ;;
  discover-campaigns)
    cmd+=(supply-chain discover-campaigns --since "$since" --limit "$limit" --orchestrate)
    ;;
  triage-summary)
    cmd+=(triage summary)
    ;;
esac

display_cmd="${cmd[*]}"
if [[ -n "$package_name" ]]; then
  display_cmd="${display_cmd//$package_name/<package>}"
fi
echo "Running: $display_cmd"
"${cmd[@]}" > "$output_file"
echo "result-file=$output_file" >> "$GITHUB_OUTPUT"

if [[ "$fail_on" != "none" ]]; then
  python - "$output_file" "$fail_on" <<'PY'
import json
import sys

path, threshold = sys.argv[1], sys.argv[2]
order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

severities = []
def walk(value):
    if isinstance(value, dict):
        sev = value.get("severity")
        if isinstance(sev, str):
            severities.append(sev.lower())
        verdict = str(value.get("verdict") or value.get("package_verdict") or "").lower()
        if "malicious" in verdict:
            severities.append("critical")
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

walk(payload)
max_seen = max((order.get(item, 0) for item in severities), default=0)
if max_seen >= order[threshold]:
    print(f"SecOpsAI result reached fail-on-severity={threshold}: {sorted(set(severities))}")
    sys.exit(1)
PY
fi
