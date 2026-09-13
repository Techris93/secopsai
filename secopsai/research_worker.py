"""Continuous surveillance worker: run collectors, scoring, and recovery.

The worker turns the on-demand collector commands into an appliance. It
computes which collectors are due from their last run timestamps, runs
them sequentially, scores any new feed events, retries dead letters, and
recovers interrupted runs. One failing registry never stops the cycle:
errors are isolated per collector and recorded in the run history.
"""

from __future__ import annotations

import signal
import json
import secrets
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import soc_store
from secopsai.investigation_autopilot import run_due as run_due_investigations
from secopsai.observability import capture_exception, initialize_observability
from secopsai.research_delivery import deliver_pending_operational_alerts
from secopsai.research_external_intel import refresh_and_sync
from secopsai.research_intake import SafeFetcher
from secopsai.research_npm_enrichment import run_npm_enrichment_cycle
from secopsai.research_scoring import score_pending_events
from secopsai.research_storage import (
    DEFAULT_MAX_USED_PERCENT,
    DEFAULT_WARNING_USED_PERCENT,
    ResearchStorageCapacityError,
    maintain_research_storage,
    storage_status,
)
from secopsai.research_surveillance import (
    COLLECTOR_DEFINITIONS,
    CollectorError,
    ensure_collectors,
    recover_interrupted_runs,
    retry_dead_letters,
    run_registry_collector,
)
from secopsai.research_discovery import sync_actionable_alert_findings
from secopsai.ontology import materialize_recent
from secopsai.sqlite_writer_lock import sqlite_writer_lock

DEFAULT_CYCLE_INTERVAL_SECONDS = 60
MAX_PAGES_PER_CYCLE = 25
# Dense registries need a complete bounded pass before their durable cursor can
# advance. These per-source budgets are measured below the collector hard cap.
COLLECTOR_MAX_PAGES_PER_CYCLE = {
    "rubygems": 250,
    "open-vsx": 400,
}


def collector_page_budget(ecosystem: str, requested: int) -> int:
    """Return the bounded worker budget needed for one safe source pass."""
    return max(requested, COLLECTOR_MAX_PAGES_PER_CYCLE.get(ecosystem, requested))


# Scoring performs deterministic watchlist persistence per event. Keep the
# worker cycle bounded on the production ledger; backlog is drained over
# successive cycles instead of holding the SQLite writer for several minutes.
SCORE_BATCH_LIMIT = 25


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _writer_stage(db_path: Optional[str], operation: Callable[[], Any]) -> Any:
    """Serialize one bounded Research Monitor persistence stage."""
    with sqlite_writer_lock(db_path):
        return operation()


def _parse_started_at(value: str) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _record_collector_degraded_alert(result: Dict[str, Any], *, db_path: Optional[str]) -> Optional[str]:
    """Create one actionable collector-health alert per ecosystem and day."""
    status = str(result.get("status") or "unknown")
    coverage = str(result.get("coverage") or "unknown")
    incomplete = bool(result.get("window_incomplete") or result.get("diff_truncated"))
    ecosystem = str(result.get("ecosystem") or "unknown")
    now = _utcnow().isoformat().replace("+00:00", "Z")

    soc_store.init_db(db_path)
    if status == "completed" and coverage == "complete" and not incomplete:
        with sqlite_writer_lock(db_path):
            with closing(soc_store.connect(db_path)) as connection:
                with connection:
                    connection.execute(
                        """UPDATE research_alerts
                           SET status = 'resolved', updated_at = ?
                           WHERE alert_type = 'collector_degraded'
                             AND status = 'open'
                             AND dedupe_key LIKE ?""",
                        (now, f"collector-degraded:{ecosystem}:%"),
                    )
        return None

    collector_id = result.get("collector_id")
    if collector_id:
        import os
        threshold = int(os.environ.get("SECOPSAI_COLLECTOR_ALERT_THRESHOLD", "3"))
        with closing(soc_store.connect(db_path)) as connection:
            history = connection.execute(
                """SELECT status, error_message
                   FROM registry_ingestion_runs
                   WHERE collector_id = ?
                   ORDER BY started_at DESC
                   LIMIT ?""",
                (collector_id, threshold),
            ).fetchall()
        
        consecutive_degraded = True
        if len(history) >= threshold:
            for row in history:
                r_status = str(row["status"])
                r_err = row["error_message"]
                if r_status == 'completed' and not r_err:
                    consecutive_degraded = False
                    break
        else:
            consecutive_degraded = False
        if not consecutive_degraded:
            return None

    dedupe_key = f"collector-degraded:{ecosystem}:{now[:10]}"
    reason = f"{ecosystem} registry coverage is degraded: status={status}, coverage={coverage}"
    evidence = {
        "ecosystem": ecosystem,
        "status": status,
        "coverage": coverage,
        "run_id": result.get("run_id"),
        "window_incomplete": bool(result.get("window_incomplete")),
        "diff_truncated": bool(result.get("diff_truncated")),
        "error": str(result.get("error") or "")[:1000],
    }
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                connection.execute(
                """INSERT INTO research_alerts
                (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
                 reason, evidence_json, status, owner, created_at, updated_at)
                VALUES (?, 'collector_degraded', 'high', NULL, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
                ON CONFLICT(dedupe_key) DO UPDATE SET reason=excluded.reason,
                    evidence_json=excluded.evidence_json, updated_at=excluded.updated_at, status='open'""",
                (f"RAL-{secrets.token_hex(8).upper()}", dedupe_key, reason, json.dumps(evidence, sort_keys=True), now, now),
            )
            row = connection.execute("SELECT alert_id FROM research_alerts WHERE dedupe_key = ?", (dedupe_key,)).fetchone()
    return str(row["alert_id"]) if row else None


def _record_npm_enrichment_alert(result: Dict[str, Any], *, db_path: Optional[str]) -> Optional[str]:
    """Surface exact-version enrichment or artifact-analysis backlogs.

    Registry collection can be healthy while the second-stage package work is
    failing.  Keep that state distinct and deliver a minimized alert through
    the same signed Core webhook used for source-backed intelligence.
    """
    failures = int(result.get("failures") or 0)
    soc_store.init_db(db_path)
    now = _utcnow().isoformat().replace("+00:00", "Z")
    if failures <= 0:
        with sqlite_writer_lock(db_path):
            with closing(soc_store.connect(db_path)) as connection:
                with connection:
                    connection.execute(
                        """UPDATE research_alerts SET status='resolved', updated_at=?
                           WHERE alert_type='npm_enrichment_degraded' AND status='open'""",
                        (now,),
                    )
        return None
    run_id = str(result.get("run_id") or "")
    dedupe_key = f"npm-enrichment-degraded:{now[:10]}"
    evidence = {
        "ecosystem": "npm",
        "run_id": run_id,
        "status": result.get("status") or "degraded",
        "events_seen": int(result.get("events_seen") or 0),
        "packages_fetched": int(result.get("packages_fetched") or 0),
        "versions_created": int(result.get("versions_created") or 0),
        "analyses_started": int((result.get("static") or {}).get("analyses_started") or 0),
        "enrichment_failures": int(result.get("enrichment_failures") or 0),
        "analysis_failures": int(result.get("analysis_failures") or 0),
        "failure_count": failures,
    }
    reason = (
        "npm exact-version enrichment or bounded artifact analysis is degraded; "
        f"{failures} item(s) require retry and coverage is not complete."
    )
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                connection.execute(
                """INSERT INTO research_alerts
                   (alert_id, alert_type, severity, candidate_id, campaign_id, case_id,
                    dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
                   VALUES (?, 'npm_enrichment_degraded', 'high', NULL, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
                   ON CONFLICT(dedupe_key) DO UPDATE SET reason=excluded.reason,
                    evidence_json=excluded.evidence_json, updated_at=excluded.updated_at, status='open'""",
                (f"RAL-{secrets.token_hex(8).upper()}", dedupe_key, reason, json.dumps(evidence, sort_keys=True), now, now),
            )
            row = connection.execute("SELECT * FROM research_alerts WHERE dedupe_key=?", (dedupe_key,)).fetchone()
    # Keep local operator views in sync even when the Core API is not running.
    sync_actionable_alert_findings(db_path=db_path)
    return str(row["alert_id"]) if row else None


def _record_storage_capacity_alert(storage: Dict[str, Any], *, db_path: Optional[str]) -> Optional[str]:
    """Warn at the early disk threshold and escalate at the pressure limit."""
    after = (
        storage.get("after")
        if isinstance(storage, dict) and isinstance(storage.get("after"), dict)
        else storage
    )
    state = after if isinstance(after, dict) else {}
    warning = bool(state.get("warning"))
    now = _utcnow().isoformat().replace("+00:00", "Z")
    soc_store.init_db(db_path)
    if not warning:
        with sqlite_writer_lock(db_path):
            with closing(soc_store.connect(db_path)) as connection:
                with connection:
                    connection.execute(
                        """UPDATE research_alerts SET status='resolved', updated_at=?
                           WHERE alert_type='storage_capacity_warning' AND status='open'""",
                        (now,),
                    )
        return None

    used_percent = float(state.get("filesystem_used_percent") or 0.0)
    warning_threshold = float(state.get("warning_used_percent") or DEFAULT_WARNING_USED_PERCENT)
    pressure = bool(state.get("pressure"))
    severity = "high" if pressure else "medium"
    dedupe_key = f"storage-capacity-warning:{now[:10]}"
    reason = (
        f"Research storage is {used_percent:.2f}% full; "
        f"early warning begins at {warning_threshold:.2f}% and pressure at "
        f"{float(state.get('maximum_used_percent') or DEFAULT_MAX_USED_PERCENT):.2f}%."
    )
    evidence = {
        "filesystem_used_percent": round(used_percent, 2),
        "warning_used_percent": round(warning_threshold, 2),
        "maximum_used_percent": float(state.get("maximum_used_percent") or DEFAULT_MAX_USED_PERCENT),
        "filesystem_free_bytes": int(state.get("filesystem_free_bytes") or 0),
        "filesystem_total_bytes": int(state.get("filesystem_total_bytes") or 0),
        "database_bytes": int(state.get("database_bytes") or 0),
        "pressure": pressure,
    }
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                connection.execute(
                    """INSERT INTO research_alerts
                       (alert_id, alert_type, severity, candidate_id, campaign_id, case_id,
                        dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
                       VALUES (?, 'storage_capacity_warning', ?, NULL, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
                       ON CONFLICT(dedupe_key) DO UPDATE SET severity=excluded.severity,
                        reason=excluded.reason, evidence_json=excluded.evidence_json,
                        updated_at=excluded.updated_at, status='open'""",
                    (
                        f"RAL-{secrets.token_hex(8).upper()}",
                        severity,
                        dedupe_key,
                        reason,
                        json.dumps(evidence, sort_keys=True),
                        now,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT alert_id FROM research_alerts WHERE dedupe_key=?", (dedupe_key,)
                ).fetchone()
    sync_actionable_alert_findings(db_path=db_path)
    return str(row["alert_id"]) if row else None


def collector_schedules() -> Dict[str, int]:
    """Effective per-collector run intervals in seconds."""
    return {
        ecosystem: int(definition.get("interval_seconds", 3600))
        for ecosystem, definition in COLLECTOR_DEFINITIONS.items()
    }


def due_collectors(*, db_path: Optional[str] = None, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Enabled collectors whose interval has elapsed since their last run.

    Disabled collectors are reported as paused so operators can see the
    surveillance hole instead of assuming coverage. The due computation is
    read-only and survives restarts because it derives from run history.
    """
    collectors = ensure_collectors(db_path=db_path)
    now = now or _utcnow()
    schedules = collector_schedules()
    due: List[Dict[str, Any]] = []
    with closing(soc_store.connect(db_path)) as connection:
        for collector in collectors:
            ecosystem = collector["ecosystem"]
            interval = schedules.get(ecosystem, 3600)
            last_run = connection.execute(
                """SELECT status, started_at FROM registry_ingestion_runs
                WHERE collector_id = ? ORDER BY started_at DESC LIMIT 1""",
                (collector["collector_id"],),
            ).fetchone()
            last_started = _parse_started_at(last_run["started_at"]) if last_run else None
            elapsed = (now - last_started).total_seconds() if last_started else None
            is_due = last_started is None or (elapsed is not None and elapsed >= interval)
            due.append(
                {
                    "collector_id": collector["collector_id"],
                    "ecosystem": ecosystem,
                    "enabled": bool(collector["enabled"]),
                    "interval_seconds": interval,
                    "last_run_status": last_run["status"] if last_run else None,
                    "last_started_at": last_run["started_at"] if last_run else None,
                    "seconds_since_last_run": elapsed,
                    "due": is_due and bool(collector["enabled"]),
                    "paused": not bool(collector["enabled"]),
                }
            )
    return due


def _run_worker_cycle_unlocked(
    *,
    db_path: Optional[str] = None,
    fetcher: Optional[SafeFetcher] = None,
    ecosystems: Optional[List[str]] = None,
    max_pages: int = MAX_PAGES_PER_CYCLE,
    score_limit: int = SCORE_BATCH_LIMIT,
    include_investigations: bool = True,
    include_alert_delivery: bool = True,
    include_automation: bool = True,
) -> Dict[str, Any]:
    """Run one worker cycle: due collectors, scoring, retries, recovery."""
    initialize_observability(service="secopsai-research-worker")
    # Storage maintenance serializes only its bounded write sections.  Do not
    # wrap it in the worker lock: capacity probes (notably freelist_count) are
    # read-only but can scan a multi-gigabyte database for minutes.
    storage = maintain_research_storage(db_path=db_path)
    storage_alert_id = _writer_stage(
        db_path,
        lambda: _record_storage_capacity_alert(storage, db_path=db_path),
    )
    fetcher = fetcher or SafeFetcher()
    try:
        # External threat-intel is a separate signal from registry telemetry.
        # Refreshing it before scoring means a public campaign can become an
        # actionable, source-backed lead even when no local dependency exists.
        # Advisory feeds perform remote I/O. Keep writer serialization inside
        # their short persistence transactions instead of holding the shared
        # lock while a feed request is in flight.
        external_intel = refresh_and_sync(db_path=db_path, fetcher=fetcher)
    except Exception as exc:  # advisory feeds must never stop registry collection
        capture_exception(exc, context={"component": "research_external_intel"})
        external_intel = {"status": "degraded", "error": str(exc)[:500]}
    selected = {item.lower() for item in ecosystems} if ecosystems else None
    results: List[Dict[str, Any]] = []
    due = due_collectors(db_path=db_path)
    for item in due:
        if not item["due"]:
            continue
        if selected and item["ecosystem"] not in selected:
            continue
        try:
            outcome = run_registry_collector(
                ecosystem=item["ecosystem"],
                max_pages=collector_page_budget(item["ecosystem"], max_pages),
                db_path=db_path,
                fetcher=fetcher,
            )
            results.append(
                {
                    "ecosystem": item["ecosystem"],
                    "run_id": outcome.get("run_id"),
                    "status": outcome.get("status"),
                    "events_stored": outcome.get("events_stored", 0),
                    "coverage": outcome.get("coverage"),
                    "error": outcome.get("error"),
                    "window_incomplete": bool(outcome.get("window_incomplete")),
                    "diff_truncated": bool(outcome.get("diff_truncated")),
                    "collector_id": item["collector_id"],
                }
            )
        except (CollectorError, ValueError) as exc:
            results.append({
                "ecosystem": item["ecosystem"],
                "status": "error",
                "error": str(exc),
                "collector_id": item["collector_id"],
            })
        except Exception as exc:  # one registry must never stop the cycle
            capture_exception(exc, context={"component": "research_collector", "ecosystem": item["ecosystem"]})
            results.append({
                "ecosystem": item["ecosystem"],
                "status": "error",
                "error": f"unexpected: {exc}",
                "collector_id": item["collector_id"],
            })

    alert_ids = _writer_stage(
        db_path,
        lambda: [
            alert_id
            for result in results
            if (alert_id := _record_collector_degraded_alert(result, db_path=db_path))
        ],
    )

    try:
        # The npm changes feed identifies package documents, not versions.
        # Resolve exact releases and inspect explainable metadata signals before
        # the normal watchlist scorer and investigation autopilot run.
        npm_enrichment = run_npm_enrichment_cycle(db_path=db_path, fetcher=fetcher)
    except Exception as exc:  # enrichment must not stop other registries
        capture_exception(exc, context={"component": "research_npm_enrichment"})
        npm_enrichment = {
            "status": "degraded",
            "error": str(exc)[:500],
            "failures": 1,
            "enrichment_failures": 1,
            "analysis_failures": 0,
        }

    try:
        npm_alert_id = _writer_stage(
            db_path,
            lambda: _record_npm_enrichment_alert(npm_enrichment, db_path=db_path),
        )
    except Exception as exc:  # an exhausted disk must not terminate other collectors
        capture_exception(exc, context={"component": "research_npm_enrichment_alert"})
        npm_alert_id = None

    scoring = _writer_stage(
        db_path,
        lambda: score_pending_events(limit=score_limit, db_path=db_path),
    )
    retries = retry_dead_letters(limit=50, db_path=db_path, fetcher=fetcher)
    recovery = _writer_stage(
        db_path,
        lambda: recover_interrupted_runs(db_path=db_path),
    )
    if include_investigations:
        try:
            # The research worker is the durable 24/7 control loop. Keep evidence
            # investigations on the same bounded cadence as registry collection so
            # queued supply-chain alerts do not depend on a dashboard click.
            investigations = run_due_investigations(db_path=db_path)
        except Exception as exc:  # investigation work must not stop surveillance
            capture_exception(exc, context={"component": "research_investigation_autopilot"})
            investigations = {"status": "degraded", "processed": 0, "error": str(exc)[:500]}
    else:
        investigations = {"status": "skipped", "reason": "coordinated_by_daily_automation"}
    if include_alert_delivery:
        try:
            deliveries = deliver_pending_operational_alerts(db_path=db_path)
        except Exception as exc:  # alerting must not stop registry surveillance
            capture_exception(exc, context={"component": "research_alert_delivery"})
            deliveries = {"enabled": True, "attempted": 0, "sent": 0, "failed": 1, "error": "operational alert delivery failed"}
    else:
        deliveries = {"status": "skipped", "reason": "coordinated_by_daily_automation"}
    if include_automation:
        try:
            from secopsai.daily_automation import run_due as run_due_daily_automation

            daily_automation = run_due_daily_automation(
                db_path=db_path,
                trigger="research-worker",
                fetcher=fetcher,
            )
        except Exception as exc:  # the coordinator must never stop surveillance
            capture_exception(exc, context={"component": "daily_automation"})
            daily_automation = {"status": "degraded", "error": str(exc)[:500]}
    else:
        daily_automation = {"status": "skipped", "reason": "coordinated_by_daily_automation"}

    # Publish an honest cycle state.  The previous summary had no top-level
    # status, so the coordinator defaulted to ``succeeded`` even when every
    # collector had failed or a downstream stage returned a degraded result.
    # Keep the individual component payloads for diagnosis while deriving a
    # bounded aggregate state for heartbeats and Mission Control.
    degraded_statuses = {"failed", "degraded", "error", "blocked", "awaiting_provider", "writer_busy"}

    def component_degraded(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        status = str(value.get("status") or "").strip().lower()
        if status in degraded_statuses or bool(value.get("error")):
            return True
        if isinstance(value.get("refresh"), dict) and component_degraded(value["refresh"]):
            return True
        if isinstance(value.get("sync"), dict) and component_degraded(value["sync"]):
            return True
        return False

    cycle_degraded = any(
        str(item.get("status") or "").strip().lower() in degraded_statuses
        or bool(item.get("error"))
        or bool(item.get("window_incomplete"))
        or bool(item.get("diff_truncated"))
        for item in results
        if isinstance(item, dict)
    )
    cycle_degraded = cycle_degraded or any(
        component_degraded(component)
        for component in (external_intel, npm_enrichment, scoring, recovery, investigations, daily_automation)
    )
    if isinstance(retries, dict) and int(retries.get("failed") or 0) > 0:
        cycle_degraded = True
    if isinstance(deliveries, dict) and int(deliveries.get("failed") or 0) > 0:
        cycle_degraded = True
    if isinstance(storage, dict) and bool(storage.get("pressure")):
        cycle_degraded = True

    return {
        "status": "degraded" if cycle_degraded else "succeeded",
        "external_intel": external_intel,
        "collectors_run": len(results),
        "collector_results": results,
        "npm_enrichment": npm_enrichment,
        "scoring": scoring,
        "retries": retries,
        "recovery": recovery,
        "investigations": investigations,
        "operational_alert_ids": alert_ids + ([storage_alert_id] if storage_alert_id else []),
        "npm_enrichment_alert_id": npm_alert_id,
        "alert_delivery": deliveries,
        "daily_automation": daily_automation,
        "storage": storage,
        "completed_at": _utcnow().isoformat().replace("+00:00", "Z"),
    }


def run_worker_cycle(
    *,
    db_path: Optional[str] = None,
    fetcher: Optional[SafeFetcher] = None,
    ecosystems: Optional[List[str]] = None,
    max_pages: int = MAX_PAGES_PER_CYCLE,
    score_limit: int = SCORE_BATCH_LIMIT,
    include_investigations: bool = True,
    include_alert_delivery: bool = True,
    include_automation: bool = True,
) -> Dict[str, Any]:
    """Run one cycle with the shared lock around each persisted stage."""
    return _run_worker_cycle_unlocked(
        db_path=db_path,
        fetcher=fetcher,
        ecosystems=ecosystems,
        max_pages=max_pages,
        score_limit=score_limit,
        include_investigations=include_investigations,
        include_alert_delivery=include_alert_delivery,
        include_automation=include_automation,
    )


def run_worker_loop(
    *,
    db_path: Optional[str] = None,
    fetcher: Optional[SafeFetcher] = None,
    interval_seconds: int = DEFAULT_CYCLE_INTERVAL_SECONDS,
    max_cycles: Optional[int] = None,
    on_cycle: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Run cycles forever until SIGTERM/SIGINT or max_cycles is reached."""
    interval = max(15, int(interval_seconds))
    initialize_observability(service="secopsai-research-worker")
    stop = {"requested": False}

    def _handle_signal(signum, frame):
        stop["requested"] = True

    previous_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            previous_handlers[signum] = signal.signal(signum, _handle_signal)
        except (ValueError, OSError):
            pass  # not in main thread; rely on max_cycles

    cycles = 0
    last_summary: Dict[str, Any] = {}
    # The hosted Core coordinator is optional.  A missing or temporarily
    # unreachable control plane must never stop registry surveillance.
    from secopsai.core_edge_client import coordinator_client

    core_edge = coordinator_client()
    try:
        while not stop["requested"]:
            if core_edge.enabled:
                try:
                    flush_outbox = getattr(core_edge, "flush_ontology_outbox", None)
                    if callable(flush_outbox):
                        flush_outbox(db_path=db_path, max_items=3)
                except Exception as exc:  # outbox recovery is optional control-plane work
                    capture_exception(exc, context={"component": "research_ontology_outbox"})
                try:
                    core_edge.pull_and_apply_settings(db_path=db_path)
                except Exception as exc:  # coordinator outages must not stop surveillance
                    capture_exception(exc, context={"component": "research_coordinator_settings"})
            try:
                last_summary = run_worker_cycle(db_path=db_path, fetcher=fetcher)
            except ResearchStorageCapacityError as exc:
                capture_exception(exc, context={"component": "research_worker_storage"})
                last_summary = {
                    "status": "degraded",
                    "error_code": "storage_capacity_exhausted",
                    "error": str(exc),
                    "storage": storage_status(db_path=db_path),
                    "completed_at": _utcnow().isoformat().replace("+00:00", "Z"),
                }
            except Exception as exc:
                capture_exception(exc, context={"component": "research_worker_cycle"})
                # A single local writer/collector fault must not terminate the
                # always-on process.  Keep the failure visible in the cycle
                # summary and let the next bounded iteration retry after the
                # normal interval.  This is especially important for transient
                # SQLite lock/busy errors during storage maintenance.
                try:
                    failed_storage = storage_status(db_path=db_path)
                except Exception:
                    failed_storage = {"status": "degraded"}
                last_summary = {
                    "status": "degraded",
                    "error_code": "worker_cycle_failed",
                    "error": str(exc)[:500],
                    "storage": failed_storage,
                    "completed_at": _utcnow().isoformat().replace("+00:00", "Z"),
                }
            cycles += 1
            if core_edge.enabled:
                # Publish the final heartbeat only after ontology sync and
                # command processing below.  A pre-sync heartbeat made the
                # hosted dashboard report a healthy cycle even when the data
                # plane was empty or the coordinator result was still pending.
                remote_state = {"runner": None}
                # Materialize only the bounded, redacted semantic projection for
                # the hosted operating picture.  Full evidence and artifacts
                # remain on the local research ledger or R2.
                try:
                    ontology_result = materialize_recent(db_path=db_path, limit=100)
                    ontology_sync = core_edge.sync_ontology(ontology_result.get("snapshot") or {})
                    if ontology_sync.get("status") == "degraded":
                        try:
                            enqueue_outbox = getattr(core_edge, "enqueue_ontology_snapshot", None)
                            if callable(enqueue_outbox):
                                enqueue_outbox(ontology_result.get("snapshot") or {}, db_path=db_path, error=ontology_sync.get("error"))
                        except Exception as outbox_error:
                            capture_exception(outbox_error, context={"component": "research_ontology_outbox_enqueue"})
                    last_summary = dict(last_summary)
                    last_summary["ontology"] = {
                        "status": ontology_sync.get("status", "accepted"),
                        "entities": ontology_result.get("counts", {}).get("entities", 0),
                        "relationships": ontology_result.get("counts", {}).get("relationships", 0),
                        "events": ontology_result.get("counts", {}).get("events", 0),
                        "counts": ontology_sync.get("counts") or ontology_result.get("counts", {}),
                        "chunks": ontology_sync.get("chunks", 0),
                        "accepted_chunks": ontology_sync.get("accepted_chunks", 0),
                        "rejected_chunks": ontology_sync.get("rejected_chunks", 0),
                        "accepted_chunk_ids": ontology_sync.get("accepted_chunk_ids", []),
                        "rejected_chunk_ids": ontology_sync.get("rejected_chunk_ids", []),
                        "error": str(ontology_sync.get("error") or "")[:500],
                    }
                except Exception as exc:  # semantic sync must not stop surveillance
                    capture_exception(exc, context={"component": "research_ontology_sync"})
                    last_summary = dict(last_summary)
                    last_summary["ontology"] = {"status": "degraded", "error": str(exc)[:500]}
                try:
                    commands = core_edge.process_commands(db_path=db_path)
                except Exception as exc:  # command polling is optional control-plane work
                    capture_exception(exc, context={"component": "research_coordinator_commands"})
                    commands = []
                if commands:
                    last_summary = dict(last_summary)
                    last_summary["hosted_coordinator"] = {
                        "commands": commands,
                        "state": remote_state.get("runner") if isinstance(remote_state, dict) else None,
                    }
                # Always publish one post-sync heartbeat, including cycles
                # where no command was claimed.  This records ontology status,
                # queue age and the latest collector result atomically from the
                # operator's perspective.
                command_failed = any(item.get("status") == "failed" for item in commands)
                ontology_degraded = (last_summary.get("ontology") or {}).get("status") == "degraded"
                # A cycle can be degraded because a collector, storage
                # maintenance step, or delivery component reported a
                # degraded result without raising an exception.  Use the
                # cycle's explicit status as part of the hosted heartbeat so
                # the operator view cannot call a partially failed cycle
                # healthy merely because synchronization succeeded.
                cycle_degraded = str(last_summary.get("status") or "").strip().lower() == "degraded"
                final_status = "degraded" if last_summary.get("error") or command_failed or ontology_degraded or cycle_degraded else "healthy"
                remote_state = core_edge.sync_state(last_summary, status=final_status)
            if on_cycle:
                on_cycle(last_summary)
            if max_cycles is not None and cycles >= max_cycles:
                break
            slept = 0.0
            while slept < interval and not stop["requested"]:
                time.sleep(min(1.0, interval - slept))
                slept += 1.0
    finally:
        for signum, handler in previous_handlers.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):
                pass
    return {"cycles": cycles, "stopped_by_signal": stop["requested"], "last_cycle": last_summary}
