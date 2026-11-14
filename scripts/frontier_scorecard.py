#!/usr/bin/env python3
"""Score SecOpsAI against the pre-registered frontier targets.

Inputs: a Recall Benchmark result (``--benchmark``) and the live coverage
block (``--live`` file, or fetched from Core's research operation projection
with ``SECOPSAI_CORE_BRIDGE_TOKEN``). Writes a JSON scorecard and a Markdown
table (also to the GitHub job summary). It reports; it never fails a run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai.frontier_metrics import benchmark_scores, evaluate_targets  # noqa: E402

CORE = "https://core.secopsai.dev/api/v1/research/operation"


def fetch_live() -> dict:
    """Live coverage: the stream scan's statistics (the whole registry stream) when
    the ledger store is reachable, otherwise the worker's projection in Core."""
    store_token = os.environ.get("LEDGER_STORE_TOKEN", "")
    if store_token:
        from secopsai.stream_scan import coverage_from_stats

        store = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")
        request = urllib.request.Request(f"{store}/stream/stats", headers={"Authorization": f"Bearer {store_token}",
                                                                            "User-Agent": "secopsai-scorecard"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return coverage_from_stats(json.load(response))
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
    token = os.environ.get("SECOPSAI_CORE_BRIDGE_TOKEN", "")
    if not token:
        return {}
    request = urllib.request.Request(CORE, headers={"Authorization": f"Bearer {token}", "User-Agent": "secopsai-scorecard"})
    with urllib.request.urlopen(request, timeout=30) as response:
        projection = json.load(response)
    return ((projection.get("coverage") or {}).get("health") or {}).get("scan_coverage") or {}


def render(results: list, meta: dict) -> str:
    marks = {"pass": "✅ pass", "fail": "❌ fail", "not measured": "— not measured"}
    lines = ["## Frontier scorecard", "", f"Benchmark: {meta.get('benchmark') or 'none'}. Live window: {meta.get('live') or 'none'}.",
             "Recall targets use held-out samples only. Targets were fixed before the work began (`eval/frontier/targets.json`).", "",
             "| Phase | Target | Baseline | Goal | Measured | Result |", "| --- | --- | --- | --- | --- | --- |"]
    for row in results:
        measured = "" if row["measured"] is None else row["measured"]
        lines.append(f"| {row['phase']} | {row['name']} | {'' if row['baseline'] is None else row['baseline']} | "
                     f"{row['op']} {row['target']} | {measured} | {marks[row['outcome']]} |")
    passed = sum(1 for row in results if row["outcome"] == "pass")
    lines += ["", f"{passed} of {len(results)} targets met."]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--benchmark", type=Path)
    parser.add_argument("--live", type=Path)
    parser.add_argument("--enforcement", type=Path, help="scripts/firewall_check.py output")
    parser.add_argument("--targets", type=Path, default=ROOT / "eval" / "frontier" / "targets.json")
    parser.add_argument("--out", type=Path, default=Path("frontier-scorecard.json"))
    args = parser.parse_args()
    targets = json.loads(args.targets.read_text(encoding="utf-8"))
    measured: dict = {}
    meta: dict = {}
    if args.benchmark and args.benchmark.exists():
        data = json.loads(args.benchmark.read_text(encoding="utf-8"))
        measured["benchmark"] = benchmark_scores(data.get("rows") or [], cutoff=targets["held_out_cutoff"])
        meta["benchmark"] = (data.get("meta") or {}).get("generated_at", "")
    if args.live and args.live.exists():
        measured["live"] = json.loads(args.live.read_text(encoding="utf-8"))
    else:
        try:
            measured["live"] = fetch_live()
        except Exception as exc:  # the scorecard reports what it could measure
            print(f"live coverage unavailable: {type(exc).__name__}", file=sys.stderr)
    if args.enforcement and args.enforcement.exists():
        measured["enforcement"] = json.loads(args.enforcement.read_text(encoding="utf-8"))
    if measured.get("live"):
        meta["live"] = f"last {measured['live'].get('window_hours')} h"
    results = evaluate_targets(targets, measured)
    args.out.write_text(json.dumps({"meta": meta, "measured": measured, "results": results}, indent=1, sort_keys=True), encoding="utf-8")
    text = render(results, meta)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("\n" + text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
