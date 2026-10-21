#!/usr/bin/env python3
"""Publish the final hosted research-operation snapshot for this worker run."""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable

from secopsai.core_edge_client import CoreEdgeClient, CoreEdgeHTTPError
from secopsai.research_operation import hosted_projection


def sync_final_projection(
    client: Any,
    *,
    projection_builder: Callable[[], dict[str, Any]] = hosted_projection,
    environment: dict[str, str] | None = None,
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

    result = client.sync_research_operation(projection)
    if not isinstance(result, dict) or result.get("status") != "stored":
        raise RuntimeError("Core did not confirm durable storage of the final operation projection")
    return {
        "status": "stored",
        "worker_run_id": expected_run_id,
        "worker_run_attempt": int(expected_attempt),
    }


def main() -> int:
    try:
        result = sync_final_projection(CoreEdgeClient())
    except Exception as exc:
        diagnostic: dict[str, Any] = {
            "event": "final_operation_projection_failed",
            "status": "failed",
            "error_type": type(exc).__name__,
        }
        if isinstance(exc, CoreEdgeHTTPError):
            diagnostic.update({"http_status": exc.status, "error_code": exc.error_code})
        print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr, flush=True)
        return 1
    print(json.dumps({"event": "final_operation_projection", **result}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
