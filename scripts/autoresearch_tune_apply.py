#!/usr/bin/env python3
"""Autoresearch helper: run tune.py and apply best thresholds into detect.py.

Goal: keep an automated loop (run locally) that results in a reviewable git diff.

This script:
1) runs `python tune.py` (quick/full)
2) reads data/tune_results.json
3) applies recommended params into detect.py RULE_THRESHOLDS in-place

It only edits the numeric values inside RULE_THRESHOLDS blocks.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[1]
DETECT_PY = REPO_ROOT / "detect.py"
RESULTS_JSON = REPO_ROOT / "data" / "tune_results.json"


def run_tune(*, quick: bool) -> None:
    cmd = [sys.executable, str(REPO_ROOT / "tune.py")]
    if quick:
        cmd.append("--quick")
    subprocess.check_call(cmd, cwd=str(REPO_ROOT))


def load_recommendations() -> Dict[str, Dict[str, Any]]:
    data = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
    best = data.get("best_per_rule", {})
    rec: Dict[str, Dict[str, Any]] = {}
    for rule_id, payload in best.items():
        params = payload.get("params", {})
        if params:
            rec[str(rule_id)] = params
    return rec


def apply_to_detect(recs: Dict[str, Dict[str, Any]]) -> None:
    lines = DETECT_PY.read_text(encoding="utf-8").splitlines(keepends=True)

    def is_rule_start(line: str, rule: str) -> bool:
        return f'"{rule}":' in line and "{" in line

    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)

        # Find the start of each RULE_THRESHOLDS[rule] block
        for rule_id, params in recs.items():
            if is_rule_start(line, rule_id):
                # Walk until we exit this dict block (a line that starts with "    }," at same indent)
                j = i + 1
                while j < len(lines):
                    cur = lines[j]
                    replaced = cur
                    for k, v in params.items():
                        # Replace lines like: "KEY": 123,
                        needle = f'"{k}"'
                        if needle in cur:
                            # keep trailing comma/comment
                            prefix, rest = cur.split(needle, 1)
                            # find ':'
                            if ":" in rest:
                                after_colon = rest.split(":", 1)[1]
                                # preserve everything after the value (comma/comments)
                                # best effort: value is up to first comma
                                tail = ""
                                if "," in after_colon:
                                    tail = after_colon.split(",", 1)[1]
                                    tail = "," + tail
                                new_val = f" {v}" if isinstance(v, (int, float)) else f" {json.dumps(v)}"
                                replaced = f"{prefix}{needle}:" + new_val + tail
                    out.append(replaced)
                    if cur.lstrip().startswith("},") or cur.lstrip().startswith("},"):
                        break
                    # End of this rule dict is usually a line like "    },"
                    if cur.startswith("    },"):
                        break
                    j += 1
                i = j
                break

        i += 1

    DETECT_PY.write_text("".join(out), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--quick", action="store_true", help="Use tune.py --quick")
    p.add_argument("--apply-only", action="store_true", help="Skip tune.py run, only apply existing results")
    args = p.parse_args()

    if not args.apply_only:
        run_tune(quick=args.quick)

    recs = load_recommendations()
    if not recs:
        print("No recommendations found in data/tune_results.json")
        return 2

    apply_to_detect(recs)
    print(f"Applied recommendations for rules: {', '.join(sorted(recs.keys()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
