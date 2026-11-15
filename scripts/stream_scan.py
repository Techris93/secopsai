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


def _post(path: str, value: Any) -> Dict[str, Any]:
    request = urllib.request.Request(f"{STORE}{path}", data=json.dumps(value).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {os.environ['LEDGER_STORE_TOKEN']}",
                                              "Content-Type": "application/json", "User-Agent": "secopsai-stream-scan"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read() or b"{}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--budget-seconds", type=float, default=900)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--report", type=Path, default=Path("reports/stream-scan.json"))
    args = parser.parse_args()

    fetcher = SafeFetcher(timeout=60)

    def fetch_json(url: str) -> Dict[str, Any]:
        _final, _headers, body = fetcher.get(url, allowed_hosts=stream_scan.NPM_HOSTS + stream_scan.MCP_HOSTS, max_bytes=48 * 1024 * 1024,
                                             headers={"Accept": "application/json"})
        return json.loads(body.decode("utf-8"))

    from secopsai.research_content_funnel import scan_release

    from secopsai import takeover_signals

    def pypi_takeover(target: Dict[str, Any]) -> Dict[str, Any]:
        _final, _headers, body = fetcher.get(f"https://pypi.org/simple/{target['package']}/", allowed_hosts=("pypi.org",),
                                             max_bytes=16 * 1024 * 1024, headers={"Accept": "application/vnd.pypi.simple.v1+json"})
        files = takeover_signals.pypi_files_by_version(json.loads(body), takeover_signals.pypi_version_of)
        signals = takeover_signals.pypi_signals(files, target["version"], role_added_at=stream_scan._parse(target.get("role_added_at")),
                                                published_at=stream_scan._parse(target["published_at"]))
        return {key: signals[key] for key in ("signals", "score")}

    def scan(target: Dict[str, Any]) -> Dict[str, Any]:
        if target["ecosystem"] == "mcp-registry":
            return stream_scan.scan_mcp(lambda package: scan_release(fetcher, package["ecosystem"], package["package"], package["version"]), target)
        result = scan_release(fetcher, target["ecosystem"], target["package"], target["version"])
        if target["ecosystem"] == "pypi":
            try:
                result = {**result, "takeover": pypi_takeover(target)}
            except Exception:  # noqa: BLE001 - the content verdict stands without metadata
                pass
        return result

    handoff = []

    def escalate(target: Dict[str, Any], prescan: Dict[str, Any]) -> Dict[str, Any]:
        """Prescan warning/alert or a takeover signal: the Fast Lane runs the diff and alert in its own jobs."""
        reasons = list(prescan.get("rules_matched") or [])[:5] + list((prescan.get("takeover") or target.get("takeover") or {}).get("signals") or [])
        handoff.append({"ecosystem": target["ecosystem"], "package": target["package"], "version": target["version"], "reasons": reasons})
        return {"alerted": False, "queued": True}

    changelog, last_serial = stream_scan.pypi_client()
    state = _store("GET", "state")
    stats = _store("GET", "stats")
    summary = stream_scan.run(state=state, stats=stats, fetch_json=fetch_json, pypi_changelog=changelog,
                              pypi_last_serial=last_serial, scan=scan, escalate=escalate,
                              budget_seconds=args.budget_seconds, workers=args.workers,
                              mcp=os.environ.get("SECOPSAI_STREAM_MCP", "1") != "0")
    queued = 0
    for start in range(0, len(handoff), 50):
        queued += int(_post("/fastlane/enqueue", {"targets": handoff[start:start + 50]}).get("queued") or 0)
    summary["handed_to_fast_lane"] = queued
    # State last: a crash before this point rescans the same releases next run.
    _store("PUT", "stats", stats)
    _store("PUT", "state", state)
    coverage = stream_scan.coverage_from_stats(stats)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"summary": summary, "coverage": coverage}, indent=1), encoding="utf-8")
    lines = ["### Stream scan", "", f"Discovered {summary['discovered']}, scanned {summary['scanned']}, hits {summary['hits']}, "
             f"escalated {summary['escalated']} (handed to the Fast Lane: {summary.get('handed_to_fast_lane', 0)}), errors {summary['errors']}, "
             f"backlog {summary['backlog_before']} -> {summary['backlog_after']} (dropped {summary['dropped']}), "
             f"{summary['elapsed_seconds']} s.", "", "| Ecosystem | Published (24 h) | Scanned | Coverage | p50 min | p95 min |",
             "| --- | --- | --- | --- | --- | --- |"]
    for ecosystem, block in coverage["ecosystems"].items():
        lines.append(f"| {ecosystem}{' (+%d unscannable)' % block['unscannable'] if block.get('unscannable') else ''} | {block['published']} | {block['scanned']} | {block['coverage']} | {block['p50_minutes']} | {block['p95_minutes']} |")
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
