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
import time
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
    """GET or PUT one ledger object. Both are idempotent, so a dropped
    connection or timeout is retried twice before the run fails."""
    for attempt in range(3):
        try:
            return _store_once(method, name, value)
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))
    return {}


def _store_once(method: str, name: str, value: Any = None) -> Dict[str, Any]:
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
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read() or b"{}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--budget-seconds", type=float, default=900)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--report", type=Path, default=Path("reports/stream-scan.json"))
    parser.add_argument("--phase", choices=("all", "plan", "scan", "merge"), default="all",
                        help="all: one process; plan/scan/merge: split across parallel jobs")
    parser.add_argument("--shards", type=int, default=4, help="plan: how many scan jobs")
    parser.add_argument("--dir", type=Path, default=Path("stream-shards"), help="plan/scan/merge: shard and result files")
    parser.add_argument("--shard", type=int, default=0, help="scan: which shard")
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

    mcp = os.environ.get("SECOPSAI_STREAM_MCP", "1") != "0"

    def save_and_hand_off(state: Dict[str, Any], stats: Dict[str, Any], summary: Dict[str, Any]) -> None:
        # Verdicts and state first, with the escalations recorded as pending; then the
        # Fast Lane hand-off, whose failures stay pending for the next run.
        pending = list(state.get("handoff_pending") or []) + handoff
        state["handoff_pending"] = pending[-stream_scan.MAX_HANDOFF_PENDING:]
        _store("PUT", "stats", stats)
        _store("PUT", "state", state)
        queued, failed = stream_scan.deliver_handoff(lambda chunk: _post("/fastlane/enqueue", {"targets": chunk}), state["handoff_pending"])
        summary.update(handed_to_fast_lane=queued, handoff_pending=len(failed))
        if failed != state["handoff_pending"]:
            state["handoff_pending"] = failed
            _store("PUT", "state", state)

    if args.phase == "scan":
        shard = json.loads((args.dir / f"shard-{args.shard}.json").read_text(encoding="utf-8"))
        results, remaining = stream_scan.scan_queue(shard, scan, budget_seconds=args.budget_seconds, workers=args.workers)
        (args.dir / f"result-{args.shard}.json").write_text(json.dumps({"results": results, "remaining": remaining}), encoding="utf-8")
        print(f"shard {args.shard}: {len(results)} scanned, {len(remaining)} left")
        return 0

    if args.phase == "plan":
        changelog, last_serial = stream_scan.pypi_client()
        state = _store("GET", "state")
        stats = _store("GET", "stats")
        queue, summary = stream_scan.discover(state=state, stats=stats, fetch_json=fetch_json, pypi_changelog=changelog,
                                              pypi_last_serial=last_serial, workers=args.workers, mcp=mcp)
        # Saved before any scan: the whole queue is the backlog until the merge records what was done.
        _store("PUT", "stats", stats)
        _store("PUT", "state", state)
        args.dir.mkdir(parents=True, exist_ok=True)
        for index, shard in enumerate(stream_scan.shard_queue(queue, args.shards)):
            (args.dir / f"shard-{index}.json").write_text(json.dumps(shard), encoding="utf-8")
        (args.dir / "plan.json").write_text(json.dumps(summary), encoding="utf-8")
        print(f"plan: {summary['discovered']}, queue {len(queue)} in {args.shards} shards")
        return 0

    if args.phase == "merge":
        summary = json.loads((args.dir / "plan.json").read_text(encoding="utf-8"))
        state = _store("GET", "state")
        stats = _store("GET", "stats")
        results: list = []
        remaining: list = []
        missing = []
        for path in sorted(args.dir.glob("shard-*.json")):
            index = path.stem.split("-", 1)[1]
            result_path = args.dir / f"result-{index}.json"
            if result_path.exists():
                data = json.loads(result_path.read_text(encoding="utf-8"))
                results += data["results"]
                remaining += data["remaining"]
            else:  # that scan job failed: its whole shard waits for the next run
                missing.append(index)
                remaining += json.loads(path.read_text(encoding="utf-8"))
        stream_scan.apply_results(stats, results, escalate, summary)
        stream_scan.finish(state, stats, remaining, summary)
        summary.update(missing_shards=missing, elapsed_seconds=0)
        save_and_hand_off(state, stats, summary)
    else:
        changelog, last_serial = stream_scan.pypi_client()
        state = _store("GET", "state")
        stats = _store("GET", "stats")
        summary = stream_scan.run(state=state, stats=stats, fetch_json=fetch_json, pypi_changelog=changelog,
                                  pypi_last_serial=last_serial, scan=scan, escalate=escalate,
                                  budget_seconds=args.budget_seconds, workers=args.workers, mcp=mcp)
        # A crash before this point rescans the same releases next run.
        save_and_hand_off(state, stats, summary)
    coverage = stream_scan.coverage_from_stats(stats)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"summary": summary, "coverage": coverage}, indent=1), encoding="utf-8")
    lines = ["### Stream scan", "", f"Discovered {summary['discovered']}, scanned {summary['scanned']}, hits {summary['hits']}, "
             f"escalated {summary['escalated']} (handed to the Fast Lane: {summary.get('handed_to_fast_lane', 0)}, pending {summary.get('handoff_pending', 0)}), errors {summary['errors']}, "
             f"backlog {summary['backlog_before']} -> {summary['backlog_after']} (dropped {summary['dropped']})"
             + (f", failed shards {summary['missing_shards']}" if summary.get("missing_shards") else "")
             + (f", {summary['elapsed_seconds']} s." if summary.get("elapsed_seconds") else "."), "", "| Ecosystem | Published (24 h) | Scanned | Coverage | p50 min | p95 min |",
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
