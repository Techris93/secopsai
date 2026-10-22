#!/usr/bin/env python3
"""Acknowledge bounded Fast Lane target outcomes to the durable R2 queue."""
from __future__ import annotations

import json
import time
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

COMPLETION_ATTEMPTS = 3
COMPLETION_BACKOFF_SECONDS = 10


def main() -> int:
    path = Path(os.environ.get("FAST_LANE_REPORT_PATH", "reports/fast-lane-results.json"))
    if not path.is_file():
        print("Fast Lane produced no result report; durable dispatch leases will recover targets after expiry.")
        return 0
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("Fast Lane result report is unavailable or invalid.", file=sys.stderr)
        return 1
    if report.get("schema_version") != "secopsai.fast-lane.results.v1" or not isinstance(report.get("results"), list):
        print("Fast Lane result report has an unsupported contract.", file=sys.stderr)
        return 1
    results = []
    for item in report["results"]:
        if not item.get("queue_id"):
            continue
        results.append({key: item.get(key) for key in ("queue_id", "status", "failure_category", "http_status", "reasons")})
    if not results:
        return 0
    token = os.environ.get("LEDGER_STORE_TOKEN", "")
    base = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")
    if not token or not base.startswith("https://"):
        print("Fast Lane completion endpoint is not configured.", file=sys.stderr)
        return 1
    body = json.dumps({"run_id": os.environ.get("GITHUB_RUN_ID", ""), "results": results}, separators=(",", ":")).encode()
    # The Ledger Store treats a resend of the same run's outcomes as already
    # completed, so transient network and server failures are retried.
    receipt = None
    for attempt in range(COMPLETION_ATTEMPTS):
        request = urllib.request.Request(base + "/fastlane/complete", data=body, method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                      "User-Agent": "SecOpsAI-Fast-Lane/1"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise ValueError("completion endpoint rejected target results")
                receipt = json.loads(response.read(8192))
            break
        except urllib.error.HTTPError as error:
            retryable = error.code == 429 or error.code >= 500
            error.close()
            if not retryable:
                break
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
            pass
        if attempt + 1 < COMPLETION_ATTEMPTS:
            time.sleep(COMPLETION_BACKOFF_SECONDS * (attempt + 1))
    if receipt is None:
        print("Fast Lane target completion could not be acknowledged; dispatch leases remain recoverable.", file=sys.stderr)
        return 1
    print(json.dumps({key: receipt.get(key) for key in ("status", "completed", "retried", "unresolved")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
