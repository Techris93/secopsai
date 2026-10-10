#!/usr/bin/env python3
"""Re-scan recent npm and PyPI releases from the ledger with today's rules.

Rules improve; releases scanned last month were judged by older rules (or
only by metadata).  This restores a read-only copy of the production ledger,
takes the releases the collectors recorded in the last ``--days`` days,
re-downloads each artifact and scans it in memory with the current YARA and
behaviour rules.  Nothing is written back to the ledger and no alerts are
raised: the output is a ranked hit list, with the matching code, for an
analyst to review.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cloudflare" / "secopsai-research-runner" / "container"))

from secopsai import yara_engine  # noqa: E402
from secopsai.research_content_funnel import scan_release  # noqa: E402
from secopsai.research_intake import SafeFetcher  # noqa: E402

LEVEL_RANK = {"none": 0, "notice": 1, "warning": 2, "alert": 3}


def releases(db_path: Path, days: int, limit: int) -> List[Dict[str, str]]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as connection:
        rows = connection.execute(
            """SELECT ecosystem, package, version, MAX(registry_timestamp) FROM registry_feed_events
               WHERE ecosystem IN ('npm', 'pypi') AND version <> '' AND registry_timestamp >= ?
                 AND event_type NOT LIKE '%removed%' AND event_type NOT LIKE '%yank%'
               GROUP BY ecosystem, package, version ORDER BY MAX(registry_timestamp) DESC LIMIT ?""",
            (since, limit),
        ).fetchall()
    return [{"ecosystem": eco, "package": pkg, "version": ver, "seen": ts} for eco, pkg, ver, ts in rows]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--limit", type=int, default=20000)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--max-seconds", type=int, default=5 * 3600)
    parser.add_argument("--db", type=Path, default=None, help="Use a local ledger copy instead of downloading one")
    parser.add_argument("--out", type=Path, default=Path("backscan.json"))
    args = parser.parse_args()

    if not yara_engine.load().get("available"):
        raise SystemExit("YARA rules unavailable")
    started = time.time()
    workdir = Path(tempfile.mkdtemp(prefix="backscan-"))
    db_path = args.db
    if db_path is None:
        from supervisor import LedgerStore

        db_path = workdir / "ledger.db"
        if not LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"]).download(db_path):
            raise SystemExit("no ledger snapshot")
    targets = releases(db_path, args.days, args.limit)
    print(f"{len(targets)} releases from the last {args.days} days", flush=True)

    fetcher = SafeFetcher(timeout=30)
    results: List[Dict[str, Any]] = []
    counts = {"scanned": 0, "hit": 0, "clean": 0, "skipped": 0, "error": 0, "not_reached": 0}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_release, fetcher, item["ecosystem"], item["package"], item["version"]): item for item in targets}
        for future in as_completed(futures):
            item = futures[future]
            if time.time() - started > args.max_seconds:
                counts["not_reached"] += 1
                future.cancel()
                continue
            try:
                result = future.result()
            except Exception as exc:  # one bad release must not stop the hunt
                result = {"status": "error", "reason": str(exc)[:200]}
            counts["scanned"] += 1
            counts[result.get("status", "error") if result.get("status") in counts else "error"] += 1
            if result.get("status") == "hit":
                results.append({**item, "score": result.get("score"), "level": result.get("level"), "rules": result.get("rules_matched"),
                                "behaviours": result.get("features"),
                                "evidence": [{key: finding.get(key) for key in ("rule_id", "file_path", "safe_context", "rule_author")}
                                             for finding in result.get("findings") or []][:6]})
            if counts["scanned"] % 1000 == 0:
                print(json.dumps(counts), flush=True)
    results.sort(key=lambda row: (LEVEL_RANK.get(str(row.get("level")), 0), int(row.get("score") or 0)), reverse=True)
    args.out.write_text(json.dumps({"days": args.days, "counts": counts, "elapsed_seconds": round(time.time() - started), "hits": results}, indent=1), encoding="utf-8")
    lines = ["## Backscan", "", f"{counts['scanned']} releases re-scanned from the last {args.days} days in {round(time.time() - started)} s: "
             + ", ".join(f"{key} {value}" for key, value in counts.items()), "", "| Release | Level | Score | Rules |", "| --- | --- | --- | --- |"]
    lines += [f"| {row['ecosystem']}:{row['package']}@{row['version']} | {row['level']} | {row['score']} | {', '.join(row.get('rules') or [])} |" for row in results[:100]]
    report = "\n".join(lines)
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(report + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
