"""Independent read-only liveness checks. Never starts work or writes the ledger."""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DELIVERY_SERVICE_WINDOW_SECONDS = 2 * 60 * 60
DELIVERY_STALL_WINDOW_SECONDS = 60 * 60


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("watchdog endpoint redirects are not allowed")


def fetch(url, token="", *, opener=None):
    endpoint = urlparse(url)
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError("watchdog endpoints require HTTPS")
    opener = opener or urllib.request.build_opener(NoRedirect()).open
    request = urllib.request.Request(url, headers={"User-Agent": "SecOpsAI-Research-Watchdog/1", **({"Authorization": f"Bearer {token}"} if token else {})})
    for attempt in range(3):
        try:
            with opener(request, timeout=15) as response:
                if response.status != 200:
                    raise ValueError("non-successful endpoint")
                raw = response.read(131073)
                if len(raw) > 131072:
                    raise ValueError("watchdog response exceeds budget")
                return raw
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def inspect(*, reader=fetch, now=None, scope="all", worker_active=None,
            upstream_worker_conclusion="", upstream_worker_completed_at="", upstream_worker_run_id="") -> dict:
    if scope not in {"all", "delivery"}:
        raise ValueError("watchdog scope must be 'all' or 'delivery'")
    now = now or datetime.now(timezone.utc)
    if worker_active is None:
        worker_active = os.environ.get("SECOPSAI_WATCHDOG_WORKER_ACTIVE", "0").strip().lower() in {"1", "true", "yes"}
    checks, blockers, warnings = {}, [], []
    stale_projection = False
    if worker_active:
        checks["research_worker"] = {"active": True, "run_id": upstream_worker_run_id or None}
        warnings.append("Research Worker is still running; the current operation snapshot is provisional")
    elif upstream_worker_run_id:
        checks["research_worker"] = {"active": False, "run_id": upstream_worker_run_id,
                                      "conclusion": upstream_worker_conclusion or "unknown"}
    if upstream_worker_conclusion and upstream_worker_conclusion != "success":
        blockers.append(f"Research Worker run {upstream_worker_run_id or 'unknown'} concluded {upstream_worker_conclusion}")
    for name, url, token in (
        ("checkpoint", os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev") + "/status", os.environ.get("LEDGER_STORE_TOKEN", "")),
        ("research_operation", os.environ.get("SECOPSAI_CORE_COORDINATOR_URL", "https://core.secopsai.dev") + "/api/v1/research/operation", os.environ.get("SECOPSAI_CORE_BRIDGE_TOKEN", "")),
        ("public_blog", os.environ.get("SECOPSAI_PUBLIC_BLOG_URL", "https://blog.secopsai.dev/"), ""),
    ):
        try:
            raw = reader(url, token)
            if name == "public_blog":
                if b"<html" not in raw.lower() and b"<!doctype html" not in raw.lower():
                    raise ValueError("public blog did not return HTML")
                checks[name] = {"available": True}
                continue
            value = json.loads(raw)
            key = "uploaded_at" if name == "checkpoint" else "synced_at"
            observed = value.get(key)
            if not observed:
                raise ValueError("missing durable freshness timestamp")
            age = (now - datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
            if name == "checkpoint" and (not value.get("checkpoint_available") or value.get("completion_retry_safe") is not True):
                raise ValueError("checkpoint protocol is not ready")
            if age < -300 or age > 5400:
                if name == "research_operation" and age > 5400:
                    stale_projection = True
                    warnings.append("research operation snapshot is stale and cannot be treated as a final health result")
                else:
                    blockers.append(f"{name} freshness is outside the operational limit")
            checks[name] = {"available": True, "age_seconds": round(age), "rpo_target_met": None}
            if name == "checkpoint":
                captured = value.get("captured_at")
                capture_age = (now - datetime.fromisoformat(captured.replace("Z", "+00:00"))).total_seconds() if captured else None
                checks[name].update(protocol=value.get("protocol"), capture_age_seconds=capture_age,
                                    snapshot_age_within_300_seconds=capture_age is not None and 0 <= capture_age <= 300,
                                    rpo_limitation="Snapshot age is a freshness measurement; committed event loss requires a verified crash drill.")
            if name == "research_operation":
                health = value.get("coverage", {}).get("health", {})
                freshness_gaps = health.get("freshness_gaps", [])
                checks[name]["freshness_gaps"] = freshness_gaps
                source_status = "degraded" if freshness_gaps else "healthy"
                if worker_active or stale_projection:
                    # A worker can refresh these collectors while the shared
                    # operation snapshot still describes the prior cycle.
                    # Preserve any gaps, but do not treat this provisional
                    # snapshot as the post-run source verdict.
                    source_status = "provisional"
                checks[name]["source_freshness_status"] = source_status
                checks[name]["dead_letters"] = health.get("dead_letters", 0)
                checks[name]["artifact_backup_pending"] = health.get("artifact_backup_pending")
                if freshness_gaps:
                    warnings.append("enabled source freshness needs review: " + ", ".join(freshness_gaps))
                if health.get("dead_letters"):
                    blockers.append("research delivery has dead-letter items requiring review")
                if freshness_gaps and scope == "all" and not (worker_active or stale_projection):
                    blockers.append("enabled research sources are outside their freshness targets")
                if health.get("artifact_backup_pending"):
                    blockers.append("registered public artifacts lack completed durable backups")
                checks[name]["ontology_pending"] = health.get("ontology_pending")
                checks[name]["ontology_due_pending"] = health.get("ontology_due_pending")
                checks[name]["ontology_oldest_age_seconds"] = health.get("ontology_oldest_age_seconds")
                checks[name]["ontology_max_attempts"] = health.get("ontology_max_attempts")
                checks[name]["ontology_validation_failures"] = health.get("ontology_validation_failures", 0)
                checks[name]["ontology_authorization_failures"] = health.get("ontology_authorization_failures", 0)
                checks[name]["ontology_last_acknowledged_at"] = health.get("ontology_last_acknowledged_at")
                checks[name]["ontology_new_unique_chunks_24h"] = health.get("ontology_new_unique_chunks_24h")
                checks[name]["ontology_acknowledged_chunks_24h"] = health.get("ontology_acknowledged_chunks_24h")
                checks[name]["ontology_last_batch"] = health.get("ontology_last_batch")
                if (health.get("ontology_pending") and
                    health.get("ontology_new_unique_chunks_24h") is not None and
                    health.get("ontology_acknowledged_chunks_24h") is not None and
                    health.get("ontology_new_unique_chunks_24h") > health.get("ontology_acknowledged_chunks_24h")):
                    warnings.append("semantic delivery ingress exceeds acknowledgements over the last 24 hours")
                if health.get("ontology_validation_failures"):
                    blockers.append("Core rejected semantic chunks for validation; retained work needs repair")
                if health.get("ontology_authorization_failures"):
                    blockers.append("Core semantic delivery is unauthorized; retained work needs credential repair")
                pending = health.get("ontology_pending") or 0
                if pending:
                    oldest_age = health.get("ontology_oldest_age_seconds")
                    last_ack = health.get("ontology_last_acknowledged_at")
                    last_ack_age = None
                    if last_ack:
                        last_ack_age = max(0, (now - datetime.fromisoformat(last_ack.replace("Z", "+00:00"))).total_seconds())
                    stalled_age = min(last_ack_age, oldest_age) if last_ack_age is not None and oldest_age is not None else oldest_age
                    if scope == "delivery":
                        blockers.append("semantic delivery has unacknowledged durable chunks")
                    elif oldest_age is None:
                        blockers.append("pending semantic delivery has no measurable age")
                    elif not worker_active and oldest_age is not None and oldest_age > DELIVERY_SERVICE_WINDOW_SECONDS:
                        blockers.append("oldest semantic delivery exceeds the two-hour service window")
                    elif not worker_active and stalled_age is not None and stalled_age > DELIVERY_STALL_WINDOW_SECONDS:
                        blockers.append("semantic delivery has stopped acknowledging work for over one hour")
                    else:
                        warnings.append(f"semantic delivery is in progress with {pending} durable chunk(s) pending")
                if upstream_worker_completed_at and observed and not worker_active:
                    completed_at = datetime.fromisoformat(upstream_worker_completed_at.replace("Z", "+00:00"))
                    synced_at = datetime.fromisoformat(observed.replace("Z", "+00:00"))
                    if synced_at.timestamp() + 60 < completed_at.timestamp():
                        blockers.append("research operation snapshot predates the completed Research Worker run")
        except Exception as exc:
            # Never print endpoint bodies, credential-bearing errors or tokens.
            checks[name] = {"available": False, "error_category": type(exc).__name__}
            blockers.append(f"{name} availability/freshness check failed")
    in_progress = worker_active or stale_projection or (scope == "all" and any("semantic delivery is in progress" in item for item in warnings))
    status = "failed" if blockers else "in_progress" if in_progress else "passed"
    operational_status = "degraded" if blockers else "in_progress" if in_progress else "degraded" if warnings else "healthy"
    return {"as_of": now.isoformat(), "scope": scope, "status": status,
            "operational_status": operational_status, "checks": checks,
            "decision_final": status != "in_progress", "warnings": warnings, "blockers": blockers}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--scope", choices=("all", "delivery"), default="all",
                        help="Gate all operational checks, or only the delivery path while reporting unrelated source-freshness warnings")
    parser.add_argument("--worker-active", action="store_true", default=None,
                        help="Mark the current health snapshot provisional while a Research Worker run is active")
    parser.add_argument("--upstream-worker-conclusion", default="")
    parser.add_argument("--upstream-worker-completed-at", default="")
    parser.add_argument("--upstream-worker-run-id", default="")
    args = parser.parse_args()
    report = inspect(scope=args.scope, worker_active=args.worker_active,
                     upstream_worker_conclusion=args.upstream_worker_conclusion,
                     upstream_worker_completed_at=args.upstream_worker_completed_at,
                     upstream_worker_run_id=args.upstream_worker_run_id)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(json.dumps({"status": report["status"], "operational_status": report["operational_status"],
                      "warnings": report["warnings"], "blockers": report["blockers"]}))
    if report["status"] == "passed":
        return 0
    if report["status"] == "in_progress" and args.scope == "all":
        return 0  # routine reporting can safely say the assessment is provisional
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
