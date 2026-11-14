#!/usr/bin/env python3
"""Match the stream scan's takeover flags against ossf/malicious-packages reports.

    python scripts/takeover_followup.py --osv osv/malicious/npm --osv osv/malicious/pypi [--stats stats.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai import takeover_followup  # noqa: E402


def fetch_stats() -> dict:
    store = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")
    request = urllib.request.Request(f"{store}/stream/stats", headers={"Authorization": f"Bearer {os.environ['LEDGER_STORE_TOKEN']}",
                                                                        "User-Agent": "secopsai-takeover-followup"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--osv", type=Path, action="append", default=[])
    parser.add_argument("--stats", type=Path, help="stream stats JSON (default: fetch from the ledger store)")
    parser.add_argument("--settle-days", type=int, default=3)
    parser.add_argument("--out", type=Path, default=Path("reports/takeover-followup.json"))
    args = parser.parse_args()
    stats = json.loads(args.stats.read_text()) if args.stats else fetch_stats()
    now = datetime.now(timezone.utc)
    hours = sorted((stats.get("hours") or {}).keys())
    # Reports can only be judged for releases published while the stream was running.
    stream_start = datetime.strptime(hours[0], "%Y-%m-%dT%H").replace(tzinfo=timezone.utc) if hours else now
    corpus = takeover_followup.reports(args.osv, since=stream_start - timedelta(days=1))
    result = takeover_followup.evaluate(stats.get("takeover_flagged") or [], corpus, stream_start=stream_start, now=now,
                                        settle_days=args.settle_days)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if not key.endswith("_examples")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
