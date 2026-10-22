#!/usr/bin/env python3
"""Publish the final hosted research-operation snapshot for this worker run."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

from secopsai.core_edge_client import CoreEdgeClient, CoreEdgeHTTPError
from secopsai.research_operation import hosted_projection


class FinalProjectionError(RuntimeError):
    def __init__(self, message: str, report: dict[str, Any]):
        super().__init__(message)
        self.report = report


def _projection_freshness_gaps(projection: dict[str, Any]) -> list[str]:
    coverage = projection.get("coverage")
    if not isinstance(coverage, dict) or not isinstance(coverage.get("sources"), list):
        raise ValueError("final operation projection has no source coverage rows")
    health = coverage.get("health")
    if not isinstance(health, dict):
        raise ValueError("final operation projection has no source health summary")
    if "freshness_gaps" not in health:
        raise ValueError("final operation projection has no freshness-gap result")
    reported = health["freshness_gaps"]
    if not isinstance(reported, list) or any(not isinstance(name, str) for name in reported):
        raise ValueError("final operation projection has invalid freshness gaps")
    gaps = set(reported)
    for source in coverage["sources"]:
        if not isinstance(source, dict):
            raise ValueError("final operation projection has an invalid source row")
        if type(source.get("enabled")) is not bool:
            raise ValueError("final operation projection has a source row with invalid enablement")
        if source["enabled"] and type(source.get("fresh")) is not bool:
            raise ValueError("final operation projection has a source row with invalid freshness")
        if source["enabled"] and not source["fresh"]:
            gaps.add(str(source.get("name") or source.get("source_id") or "unnamed enabled source"))
    return sorted(gaps)


def sync_final_projection(
    client: Any,
    *,
    projection_builder: Callable[[], dict[str, Any]] = hosted_projection,
    environment: dict[str, str] | None = None,
    require_fresh_sources: bool = False,
) -> dict[str, Any]:
    """Store a current snapshot and prove it belongs to this completed run."""
    environment = environment or os.environ
    if not client.enabled:
        raise RuntimeError("Core operation projection is not configured")

    projection = projection_builder()
    runtime = projection.get("runtime") if isinstance(projection, dict) else None
    runtime = runtime if isinstance(runtime, dict) else {}
    expected_run_id = str(environment.get("GITHUB_RUN_ID") or "").strip()
    expected_attempt = str(environment.get("GITHUB_RUN_ATTEMPT") or "").strip()
    if not expected_run_id or not expected_attempt:
        raise RuntimeError("GitHub worker run identity is unavailable")
    if str(runtime.get("worker_run_id") or "") != expected_run_id:
        raise RuntimeError("operation projection does not identify the current worker run")
    if runtime.get("worker_run_attempt") != int(expected_attempt):
        raise RuntimeError("operation projection does not identify the current worker attempt")

    report: dict[str, Any] = {
        "status": "pending",
        "worker_run_id": expected_run_id,
        "worker_run_attempt": int(expected_attempt),
    }
    if require_fresh_sources:
        try:
            freshness_gaps = _projection_freshness_gaps(projection)
        except (TypeError, ValueError) as exc:
            report.update(status="failed", blockers=[str(exc)])
            raise FinalProjectionError(str(exc), report) from exc
        report["source_freshness_gaps"] = freshness_gaps
        if freshness_gaps:
            blocker = "enabled sources remain outside freshness targets: " + ", ".join(freshness_gaps)
            report.update(status="failed", blockers=[blocker])
            raise FinalProjectionError(blocker, report)

    # Mark this as the run's final snapshot so the watchdog can tell it from a
    # mid-run snapshot without comparing against GitHub's completion time.
    projection["runtime"] = {**runtime, "projection_phase": "final"}
    result = client.sync_research_operation(projection)
    if not isinstance(result, dict) or result.get("status") != "stored":
        raise RuntimeError("Core did not confirm durable storage of the final operation projection")
    report["status"] = "stored"
    return report


def _write_report(path: str, report: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    environment = os.environ
    report_path = environment.get("SECOPSAI_FINAL_PROJECTION_REPORT", "reports/research/final-projection.json")
    try:
        result = sync_final_projection(
            CoreEdgeClient(),
            environment=environment,
            require_fresh_sources=(environment.get("SECOPSAI_VERIFY_REFRESH_STALE_SOURCES") == "1"
                                   and environment.get("SECOPSAI_VERIFY_DELIVERY_ONLY", "0") != "1"),
        )
    except Exception as exc:
        diagnostic: dict[str, Any] = dict(getattr(exc, "report", {}))
        diagnostic.update({
            "event": "final_operation_projection_failed",
            "status": "failed",
            "error_type": type(exc).__name__,
        })
        if isinstance(exc, CoreEdgeHTTPError):
            diagnostic.update({"http_status": exc.status, "error_code": exc.error_code})
        _write_report(report_path, diagnostic)
        print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr, flush=True)
        return 1
    report = {"event": "final_operation_projection", **result}
    _write_report(report_path, report)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
