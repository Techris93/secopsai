#!/usr/bin/env python3
"""Tell the durable queue this Fast Lane run's job started.

A batch whose run never reports a start is re-queued after a short wait,
because GitHub can accept a dispatch and then fail before any job runs.
This report is best effort: if it fails, the batch is simply re-queued and
scanned again, so the step never fails the run.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

QUEUE_ID = re.compile(r"^[a-f0-9]{64}$")


def main() -> int:
    try:
        targets = json.loads(os.environ.get("FAST_LANE_TARGETS", "[]"))
    except ValueError:
        print("Fast Lane targets are not valid JSON; no start receipt sent.")
        return 0
    ids = [t.get("_queue_id") for t in targets if isinstance(t, dict) and QUEUE_ID.match(str(t.get("_queue_id") or ""))]
    if not ids:
        return 0
    token = os.environ.get("LEDGER_STORE_TOKEN", "")
    base = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")
    if not token or not base.startswith("https://"):
        print("Fast Lane start endpoint is not configured; the batch may be re-queued.")
        return 0
    body = json.dumps({"run_id": os.environ.get("GITHUB_RUN_ID", ""), "queue_ids": ids[:20]}, separators=(",", ":")).encode()
    request = urllib.request.Request(base + "/fastlane/start", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "User-Agent": "SecOpsAI-Fast-Lane/1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            print(response.read(4096).decode("utf-8", "replace")[:300])
    except urllib.error.HTTPError as error:
        print(f"Fast Lane start receipt was not stored (HTTP {error.code}); the batch may be re-queued.")
        error.close()
    except (OSError, urllib.error.URLError) as error:
        print(f"Fast Lane start receipt was not sent ({type(error).__name__}); the batch may be re-queued.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
