#!/usr/bin/env python3
"""Run one stream-scan pass (see secopsai/stream_scan.py).

State and statistics live in the ledger store (LEDGER_STORE_URL,
LEDGER_STORE_TOKEN). Alerts go to Core with the research alert webhook
secret, as in the Fast Lane.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from secopsai import stream_scan  # noqa: E402
from secopsai.research_intake import SafeFetcher  # noqa: E402

STORE = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")


def _store(method: str, name: str, value: Any = None) -> Dict[str, Any]:
    token = os.environ["LEDGER_STORE_TOKEN"]
    data = None if value is None else json.dumps(value, separators=(",", ":")).encode()
    request = urllib.request.Request(f"{STORE}/stream/{name}", data=data, method=method,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "User-Agent": "secopsai-stream-scan"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and method == "GET":
            return {}
        raise
    return json.loads(body or b"{}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--budget-seconds", type=float, default=900)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--report", type=Path, default=Path("reports/stream-scan.json"))
    args = parser.parse_args()

    fetcher = SafeFetcher(timeout=60)

    def fetch_json(url: str) -> Dict[str, Any]:
        _final, _headers, body = fetcher.get(url, allowed_hosts=stream_scan.NPM_HOSTS, max_bytes=48 * 1024 * 1024,
                                             headers={"Accept": "application/json"})
        return json.loads(body.decode("utf-8"))

    from secopsai.research_content_funnel import scan_release

    def scan(target: Dict[str, Any]) -> Dict[str, Any]:
        return scan_release(fetcher, target["ecosystem"], target["package"], target["version"])

    import fast_lane

    def escalate(target: Dict[str, Any], prescan: Dict[str, Any]) -> Dict[str, Any]:
        """Prescan warning or alert: diff against the previous version and alert when the delta is risky."""
        release = fast_lane.resolve_release(fetcher, target["ecosystem"], target["package"], target["version"])
        with tempfile.TemporaryDirectory(prefix="stream-scan-") as tmp:
            result = fast_lane.investigate(target, release, Path(tmp))
        decision = fast_lane.assess(result)
        if decision["severity"] == "none":
            return {"alerted": False}
        fast_lane.deliver(target, release, decision, stream_scan._now())
        return {"alerted": True, "severity": decision["severity"]}

    changelog, last_serial = stream_scan.pypi_client()
    state = _store("GET", "state")
    stats = _store("GET", "stats")
    summary = stream_scan.run(state=state, stats=stats, fetch_json=fetch_json, pypi_changelog=changelog,
                              pypi_last_serial=last_serial, scan=scan, escalate=escalate,
                              budget_seconds=args.budget_seconds, workers=args.workers)
    # State last: a crash before this point rescans the same releases next run.
    _store("PUT", "stats", stats)
    _store("PUT", "state", state)
    coverage = stream_scan.coverage_from_stats(stats)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"summary": summary, "coverage": coverage}, indent=1), encoding="utf-8")
    lines = ["### Stream scan", "", f"Discovered {summary['discovered']}, scanned {summary['scanned']}, hits {summary['hits']}, "
             f"escalated {summary['escalated']}, alerts {summary['alerts']}, errors {summary['errors']}, "
             f"backlog {summary['backlog_before']} -> {summary['backlog_after']} (dropped {summary['dropped']}), "
             f"{summary['elapsed_seconds']} s.", "", "| Ecosystem | Published (24 h) | Scanned | Coverage | p50 min | p95 min |",
             "| --- | --- | --- | --- | --- | --- |"]
    for ecosystem, block in coverage["ecosystems"].items():
        lines.append(f"| {ecosystem} | {block['published']} | {block['scanned']} | {block['coverage']} | {block['p50_minutes']} | {block['p95_minutes']} |")
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
