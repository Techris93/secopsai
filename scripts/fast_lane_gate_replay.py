#!/usr/bin/env python3
"""Run the frozen Fast Lane behaviour-floor test (eval/fast_lane_gate/PLAN.md).

``--mode selection`` (from 2026-12-02) labels the selection window and writes
the V2 keep-list, to be committed as eval/fast_lane_gate/v2-keep-list.json
before any held-out label is read. ``--mode held_out`` (from 2026-12-09) labels
the held-out window and applies the plan's gates once.

Reads only: ledger digest entries, the install-firewall shards, registry
metadata and a recall-benchmark artifact. No model calls, no email, no package
downloads, and nothing in the Fast Lane changes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import threading
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai import alert_digest, blocklist  # noqa: E402
from secopsai import fast_lane_gate as gate  # noqa: E402

PLAN = ROOT / "eval" / "fast_lane_gate" / "PLAN.md"
PLAN_SHA256 = "f460789d08a472bec7ce53049d1d4d78dc080e66924d6f69526bcb676e88235f"
KEEP_LIST = ROOT / "eval" / "fast_lane_gate" / "v2-keep-list.json"


def _client():
    """The digest script's ledger client (paged day reads with retries)."""
    spec = importlib.util.spec_from_file_location("alert_digest_client", ROOT / "scripts" / "alert_digest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_entries(client, start: datetime, end: datetime, token: str) -> List[Dict[str, Any]]:
    raw: List[Dict[str, Any]] = []
    for day in alert_digest.days(start, end):
        raw += client._digest_day(day, token).get("entries") or []
    out = []
    for entry in raw:
        when = gate._when(entry.get("occurred_at"))
        if when is not None and start <= when < end:
            out.append(entry)
    return out


def label(client, entries: List[Dict[str, Any]], token: str) -> List[Dict[str, Any]]:
    """The digest's triage on the label date: ossf-listed (known_malicious), gone from the registry (removed)."""
    shards: Dict[str, Optional[dict]] = {}
    npm_docs: Dict[str, Optional[dict]] = {}
    guard, name_locks = threading.Lock(), {}  # triage runs 16 workers: one registry read per npm package

    def blocked(eco: str, name: str, version: str) -> Optional[List[str]]:
        key = f"{eco}/{blocklist.shard_of(eco, name)}"
        if key not in shards:
            try:
                shards[key] = client._get(f"{client.STORE}/firewall/{key}", token=token)
            except urllib.error.HTTPError as exc:
                shards[key] = {} if exc.code == 404 else None
            except (OSError, ValueError):
                shards[key] = None
        if shards[key] is None:
            return None
        entry = shards[key].get(blocklist.normalize(eco, name))
        return (entry.get("ids") or ["listed"]) if entry and (entry.get("all") or version in (entry.get("versions") or [])) else []

    def published(eco: str, name: str, version: str) -> Optional[bool]:
        try:
            if eco == "npm":
                with guard:
                    lock = name_locks.setdefault(name, threading.Lock())
                with lock:
                    if name not in npm_docs:
                        try:
                            npm_docs[name] = client._get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"),
                                                         accept="application/vnd.npm.install-v1+json")
                        except urllib.error.HTTPError as exc:
                            if exc.code != 404:
                                raise
                            npm_docs[name] = {"versions": {}}
                return version in ((npm_docs[name] or {}).get("versions") or {})
            client._get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
            return True
        except urllib.error.HTTPError as exc:
            return False if exc.code == 404 else None
        except (OSError, ValueError):
            return None

    return alert_digest.triage(entries, blocked=blocked, published=published)


def plan_unchanged() -> bool:
    return hashlib.sha256(PLAN.read_bytes()).hexdigest() == PLAN_SHA256


def summary(report: Dict[str, Any]) -> str:
    lines = [f"### Fast Lane gate replay ({report['mode']})", "",
             f"Window {report['window'][0]} to {report['window'][1]}, labelled {report['labelled_at']}. "
             f"Alerts {report['live']['alerts']}, behaviour-only {report['live']['behaviour_only']}, "
             f"confirmed packages {report['live']['confirmed_packages']} (ossf {report['live']['ossf_packages']}). "
             f"Unchecked labels: {report['unchecked']}.", ""]
    if "decision" in report:
        d = report["decision"]
        lines += [f"**Decision: {d['result']}{(' ' + d['variant']) if d.get('variant') else ''}**: {d['note']}", ""]
    lines += ["| Variant | Medium+ (behaviour only) | Cut | Confirmed kept | ossf lost | Delivered a day | npm drop | PyPI drop | Pass |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for v in gate.VARIANTS:
        row, bench = report["live"]["variants"][v], (report.get("benchmark") or {}).get(v, {})
        drop = bench.get("b1_drop_points") or {}
        passed = "" if v == "V0" else ("yes" if row.get("a1") and row.get("a2") and bench.get("b1") and bench.get("b2") else "no")
        lines.append(f"| {v} | {row['behaviour_only_medium_plus']} | {row.get('a1_cut', '')} | {row['confirmed_kept']} | "
                     f"{len(row['ossf_lost'])} | {row['delivered_per_day']} | {drop.get('npm', '')} | {drop.get('pypi', '')} | {passed} |")
    if report.get("keep_list"):
        lines += ["", f"Keep-list: {', '.join(report['keep_list']['keep'])}", "",
                  f"Lowered: {', '.join(report['keep_list']['lowered']) or 'none'}"]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--mode", choices=["selection", "held_out"], required=True)
    parser.add_argument("--extensions", type=int, default=0, help="held-out extensions under A3 (0-2)")
    parser.add_argument("--benchmark", type=Path, required=True, help="recall-benchmark.json from a run on main")
    parser.add_argument("--out", type=Path, default=Path("reports/fast-lane-gate.json"))
    parser.add_argument("--keep-out", type=Path, default=Path("reports/v2-keep-list.json"))
    args = parser.parse_args()

    if not plan_unchanged():
        print("eval/fast_lane_gate/PLAN.md no longer matches the frozen plan; refusing to run", file=sys.stderr)
        return 2
    start, end = gate.windows(args.mode, args.extensions)
    now = datetime.now(timezone.utc)
    if not gate.labels_ready(end, now):
        print(f"labels for this window are taken from {(end + gate.LABEL_DELAY).isoformat()}; refusing to run early", file=sys.stderr)
        return 2
    bench = json.loads(args.benchmark.read_text(encoding="utf-8"))
    if (bench.get("meta") or {}).get("seed") != gate.BENCHMARK_SEED:
        print(f"benchmark seed must be {gate.BENCHMARK_SEED}", file=sys.stderr)
        return 2
    keep_doc = None
    if args.mode == "held_out":
        if not KEEP_LIST.exists():
            print(f"{KEEP_LIST.relative_to(ROOT)} must be committed before the held-out run", file=sys.stderr)
            return 2
        keep_doc = json.loads(KEEP_LIST.read_text(encoding="utf-8"))

    client = _client()
    token = os.environ["LEDGER_STORE_TOKEN"]
    history_entries = read_entries(client, max(gate.LIVE_SINCE, start - gate.HISTORY), end, token)
    window_entries = [e for e in history_entries if start <= gate._when(e.get("occurred_at")) < end]
    labelled = label(client, [e for e in window_entries if e.get("source") == "fast_lane"], token)
    window, history = gate.alerts(labelled), gate.alerts(history_entries)
    rows = bench.get("rows") or []
    keep_list = gate.keep_list(window, rows) if args.mode == "selection" else None
    keep = keep_list["keep"] if keep_list else keep_doc["keep"]
    days = (end - start).total_seconds() / 86400
    report: Dict[str, Any] = {
        "mode": args.mode, "plan_sha256": PLAN_SHA256, "window": [start.isoformat(), end.isoformat()],
        "extensions": args.extensions, "labelled_at": now.isoformat(), "benchmark_meta": bench.get("meta"),
        "unchecked": sum(1 for e in labelled if e.get("group") == "unchecked"),
        "live": gate.live_report(window, history, keep, days), "benchmark": gate.benchmark_report(rows, keep),
        "rules": gate.rule_table(window),
    }
    if keep_list:
        report["keep_list"] = keep_list
        args.keep_out.parent.mkdir(parents=True, exist_ok=True)
        args.keep_out.write_text(json.dumps({"plan_sha256": PLAN_SHA256, "selection": report["window"], "labelled_at": report["labelled_at"],
                                             "benchmark_meta": bench.get("meta"), **keep_list}, indent=1) + "\n", encoding="utf-8")
    else:
        report["keep_list_used"] = keep
        report["decision"] = gate.decide(report["live"], report["benchmark"], args.extensions)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1, default=sorted) + "\n", encoding="utf-8")
    text = summary(report)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
