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
PROVISIONAL_MAX_SECONDS = 90 * 60


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


def _parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else None
    except (TypeError, ValueError):
        return None


def _worker_snapshot_pending_reason(value, *, run_id, run_attempt, completed_at):
    runtime = value.get("runtime") or {}
    if str(runtime.get("worker_run_id") or "") != str(run_id):
        return "waiting for the matching Research Worker run to appear in the operation snapshot"
    if run_attempt is not None and runtime.get("worker_run_attempt") != run_attempt:
        return "waiting for the matching Research Worker attempt to appear in the operation snapshot"
    synced_at = _parse_time(value.get("synced_at"))
    completed = _parse_time(completed_at)
    if not synced_at or not completed:
        return "waiting for a valid operation snapshot and worker completion timestamp"
    if synced_at.timestamp() + 60 < completed.timestamp():
        return "waiting for the operation snapshot to advance past Research Worker completion"
    return ""


def inspect(*, reader=fetch, now=None, scope="all", worker_active=None,
            upstream_worker_conclusion="", upstream_worker_completed_at="", upstream_worker_run_id="",
            upstream_worker_started_at="", upstream_worker_run_attempt=None,
            upstream_worker_cancelled_before_start=False, active_worker_run_id="", active_worker_started_at="",
            allow_pending=False, projection_wait_seconds=0, projection_poll_interval_seconds=15) -> dict:
    if scope not in {"all", "delivery"}:
        raise ValueError("watchdog scope must be 'all' or 'delivery'")
    if allow_pending and scope != "delivery":
        raise ValueError("--allow-pending is valid only for delivery scope")
    if not 0 <= projection_wait_seconds <= 600:
        raise ValueError("projection wait must be between 0 and 600 seconds")
    if not 1 <= projection_poll_interval_seconds <= 60:
        raise ValueError("projection poll interval must be between 1 and 60 seconds")
    now = now or datetime.now(timezone.utc)
    if worker_active is None:
        worker_active = os.environ.get("SECOPSAI_WATCHDOG_WORKER_ACTIVE", "0").strip().lower() in {"1", "true", "yes"}
    checks, blockers, warnings = {}, [], []
    stale_projection = False
    provisional_expires_at = None
    if worker_active:
        active_started = _parse_time(active_worker_started_at)
        active_age = (now - active_started).total_seconds() if active_started else None
        checks["research_worker"] = {"active": True, "run_id": active_worker_run_id or None,
                                      "started_at": active_worker_started_at or None,
                                      "age_seconds": round(active_age) if active_age is not None else None}
        warnings.append("Research Worker is still running; the current operation snapshot is provisional")
        if active_started:
            expires = active_started.timestamp() + PROVISIONAL_MAX_SECONDS
            provisional_expires_at = datetime.fromtimestamp(expires, timezone.utc).isoformat().replace("+00:00", "Z")
            if active_age is not None and active_age > PROVISIONAL_MAX_SECONDS:
                blockers.append("Research Worker exceeded the 90-minute provisional health deadline")
        else:
            blockers.append("active Research Worker has no authoritative start time; provisional expiry cannot be enforced")
    elif upstream_worker_run_id:
        checks["research_worker"] = {"active": False, "run_id": upstream_worker_run_id,
                                      "conclusion": upstream_worker_conclusion or "unknown",
                                      "started_at": upstream_worker_started_at or None,
                                      "run_attempt": upstream_worker_run_attempt}
    # A cancellation is superseded only when GitHub confirms it never started.
    superseded = upstream_worker_conclusion == "cancelled" and upstream_worker_cancelled_before_start is True
    if superseded:
        warnings.append(f"Research Worker run {upstream_worker_run_id or 'unknown'} was superseded by a newer run; the next run decides health")
    elif upstream_worker_conclusion and upstream_worker_conclusion != "success":
        blockers.append(f"Research Worker run {upstream_worker_run_id or 'unknown'} concluded {upstream_worker_conclusion}")
    provisional = worker_active or superseded
    for name, url, token in (
        ("checkpoint", os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev") + "/status", os.environ.get("LEDGER_STORE_TOKEN", "")),
        ("research_operation", os.environ.get("SECOPSAI_CORE_COORDINATOR_URL", "https://core.secopsai.dev") + "/api/v1/research/operation", os.environ.get("SECOPSAI_CORE_BRIDGE_TOKEN", "")),
        ("public_blog", os.environ.get("SECOPSAI_PUBLIC_BLOG_URL", "https://blog.secopsai.dev/"), ""),
    ):
        try:
            raw = reader(url, token)
            worker_snapshot_wait = None
            if name == "research_operation":
                value = json.loads(raw)
                if (upstream_worker_conclusion == "success" and upstream_worker_run_id and
                        projection_wait_seconds > 0):
                    wait_started = time.monotonic()
                    wait_attempts = 1
                    pending_reason = _worker_snapshot_pending_reason(
                        value, run_id=upstream_worker_run_id,
                        run_attempt=upstream_worker_run_attempt,
                        completed_at=upstream_worker_completed_at,
                    )
                    while pending_reason:
                        remaining = projection_wait_seconds - (time.monotonic() - wait_started)
                        if remaining <= 0:
                            worker_snapshot_wait = {
                                "status": "timed_out", "attempts": wait_attempts,
                                "waited_seconds": round(time.monotonic() - wait_started),
                                "last_reason": pending_reason,
                            }
                            warnings.append("research operation snapshot did not become current before the bounded projection wait expired")
                            break
                        time.sleep(min(projection_poll_interval_seconds, remaining))
                        raw = reader(url, token)
                        value = json.loads(raw)
                        wait_attempts += 1
                        pending_reason = _worker_snapshot_pending_reason(
                            value, run_id=upstream_worker_run_id,
                            run_attempt=upstream_worker_run_attempt,
                            completed_at=upstream_worker_completed_at,
                        )
                    if not pending_reason:
                        worker_snapshot_wait = {
                            "status": "ready", "attempts": wait_attempts,
                            "waited_seconds": round(time.monotonic() - wait_started),
                        }
            if name == "public_blog":
                if b"<html" not in raw.lower() and b"<!doctype html" not in raw.lower():
                    raise ValueError("public blog did not return HTML")
                checks[name] = {"available": True}
                continue
            if name != "research_operation":
                value = json.loads(raw)
            key = "uploaded_at" if name == "checkpoint" else "synced_at"
            observed = value.get(key)
            if not observed:
                raise ValueError("missing durable freshness timestamp")
            age = (now - datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
            if name == "checkpoint" and (not value.get("checkpoint_available") or value.get("completion_retry_safe") is not True):
                raise ValueError("checkpoint protocol is not ready")
            if age < -300 or age > 5400:
                if name == "research_operation" and age > 5400 and provisional:
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
                if worker_snapshot_wait is not None:
                    checks[name]["worker_snapshot_wait"] = worker_snapshot_wait
                health = value.get("coverage", {}).get("health", {})
                freshness_gaps = health.get("freshness_gaps", [])
                source_rows = value.get("coverage", {}).get("sources", [])
                checks[name]["stale_sources"] = [
                    {key: source.get(key) for key in ("source_id", "name", "last_success_at", "last_attempt_at",
                     "last_attempt_status", "interval_seconds", "delay_seconds", "error_category", "consecutive_failures", "last_collection")}
                    for source in source_rows if source.get("enabled") and not source.get("fresh")
                ]
                checks[name]["freshness_gaps"] = freshness_gaps
                source_status = "degraded" if freshness_gaps else "healthy"
                if provisional or stale_projection:
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
                if freshness_gaps and scope == "all" and not (provisional or stale_projection):
                    blockers.append("enabled research sources are outside their freshness targets")
                if health.get("artifact_backup_pending"):
                    blockers.append("registered public artifacts lack completed durable backups")
                for key in ("primary_intel_pending_preparation", "primary_intel_awaiting_human_review",
                            "primary_intel_preparation_dead_letters", "primary_intel_oldest_preparation_age_seconds"):
                    checks[name][key] = health.get(key)
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
                    if scope == "delivery" and not allow_pending:
                        blockers.append("semantic delivery has unacknowledged durable chunks")
                    elif oldest_age is None:
                        blockers.append("pending semantic delivery has no measurable age")
                    elif not provisional and oldest_age is not None and oldest_age > DELIVERY_SERVICE_WINDOW_SECONDS:
                        blockers.append("oldest semantic delivery exceeds the two-hour service window")
                    elif not provisional and stalled_age is not None and stalled_age > DELIVERY_STALL_WINDOW_SECONDS:
                        blockers.append("semantic delivery has stopped acknowledging work for over one hour")
                    else:
                        warnings.append(f"semantic delivery is in progress with {pending} durable chunk(s) pending")
                if upstream_worker_run_id and not provisional:
                    runtime = value.get("runtime") or {}
                    expected_attempt = int(upstream_worker_run_attempt) if upstream_worker_run_attempt is not None else None
                    if str(runtime.get("worker_run_id") or "") != str(upstream_worker_run_id):
                        blockers.append("research operation snapshot is not correlated to the completed Research Worker run")
                    elif expected_attempt is not None and runtime.get("worker_run_attempt") != expected_attempt:
                        blockers.append("research operation snapshot belongs to a different Research Worker attempt")
                    else:
                        completed_at = _parse_time(upstream_worker_completed_at)
                        started_at = _parse_time(upstream_worker_started_at)
                        synced_at = _parse_time(observed)
                        if not completed_at or not started_at or not synced_at or synced_at.timestamp() + 60 < started_at.timestamp():
                            blockers.append("Research Worker completion or matching operation snapshot timestamp is missing or invalid")
                        elif synced_at.timestamp() + 60 < completed_at.timestamp():
                            blockers.append("research operation snapshot predates the completed Research Worker run")
        except Exception as exc:
            # Never print endpoint bodies, credential-bearing errors or tokens.
            checks[name] = {"available": False, "error_category": type(exc).__name__}
            blockers.append(f"{name} availability/freshness check failed")
    in_progress = provisional or stale_projection or ((scope == "all" or allow_pending) and any("semantic delivery is in progress" in item for item in warnings))
    status = "failed" if blockers else "in_progress" if in_progress else "passed"
    operational_status = "degraded" if blockers else "in_progress" if in_progress else "degraded" if warnings else "healthy"
    return {"as_of": now.isoformat(), "scope": scope, "status": status,
            "operational_status": operational_status, "checks": checks,
            "decision_final": status != "in_progress", "provisional_expires_at": provisional_expires_at,
            "warnings": warnings, "blockers": blockers}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--scope", choices=("all", "delivery"), default="all",
                        help="Gate all operational checks, or only the delivery path while reporting unrelated source-freshness warnings")
    parser.add_argument("--allow-pending", action="store_true",
                        help="For a routine worker cycle, pass healthy delivery that is still progressing; dead letters, rejected work, and overdue/stalled chunks still fail")
    parser.add_argument("--worker-active", action="store_true", default=None,
                        help="Mark the current health snapshot provisional while a Research Worker run is active")
    parser.add_argument("--upstream-worker-conclusion", default="")
    parser.add_argument("--upstream-worker-completed-at", default="")
    parser.add_argument("--upstream-worker-run-id", default="")
    parser.add_argument("--upstream-worker-started-at", default="")
    parser.add_argument("--upstream-worker-run-attempt", type=int)
    parser.add_argument("--upstream-worker-cancelled-before-start", action="store_true")
    parser.add_argument("--projection-wait-seconds", type=int, default=0,
                        help="For a completed worker run, wait within this bound for its matching final operation snapshot")
    parser.add_argument("--active-worker-run-id", default="")
    parser.add_argument("--active-worker-started-at", default="")
    args = parser.parse_args()
    report = inspect(scope=args.scope, worker_active=args.worker_active,
                     upstream_worker_conclusion=args.upstream_worker_conclusion,
                     upstream_worker_completed_at=args.upstream_worker_completed_at,
                     upstream_worker_run_id=args.upstream_worker_run_id,
                     upstream_worker_started_at=args.upstream_worker_started_at,
                     upstream_worker_run_attempt=args.upstream_worker_run_attempt,
                     upstream_worker_cancelled_before_start=args.upstream_worker_cancelled_before_start,
                     active_worker_run_id=args.active_worker_run_id,
                     active_worker_started_at=args.active_worker_started_at,
                     allow_pending=args.allow_pending,
                     projection_wait_seconds=args.projection_wait_seconds)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(json.dumps({"status": report["status"], "operational_status": report["operational_status"],
                      "warnings": report["warnings"], "blockers": report["blockers"]}))
    if report["status"] == "passed":
        return 0
    if report["status"] == "in_progress" and (args.scope == "all" or args.allow_pending):
        return 0  # routine reporting can safely say the assessment is provisional
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
