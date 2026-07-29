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
from secopsai.observability import capture_exception, initialize_observability
from secopsai.research_delivery import deliver_pending_operational_alerts
from secopsai.research_intake import SafeFetcher
from secopsai.research_scoring import score_pending_events
from secopsai.research_storage import ResearchStorageCapacityError, maintain_research_storage, storage_status
from secopsai.research_surveillance import (
    COLLECTOR_DEFINITIONS,
    CollectorError,
    ensure_collectors,
    recover_interrupted_runs,
    retry_dead_letters,
    run_registry_collector,
)

DEFAULT_CYCLE_INTERVAL_SECONDS = 60
MAX_PAGES_PER_CYCLE = 25
SCORE_BATCH_LIMIT = 500


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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


def run_worker_cycle(
    *,
    db_path: Optional[str] = None,
    fetcher: Optional[SafeFetcher] = None,
    ecosystems: Optional[List[str]] = None,
    max_pages: int = MAX_PAGES_PER_CYCLE,
    score_limit: int = SCORE_BATCH_LIMIT,
) -> Dict[str, Any]:
    """Run one worker cycle: due collectors, scoring, retries, recovery."""
    initialize_observability(service="secopsai-research-worker")
    storage = maintain_research_storage(db_path=db_path)
    fetcher = fetcher or SafeFetcher()
    selected = {item.lower() for item in ecosystems} if ecosystems else None
    results: List[Dict[str, Any]] = []
    for item in due_collectors(db_path=db_path):
        if not item["due"]:
            continue
        if selected and item["ecosystem"] not in selected:
            continue
        try:
            outcome = run_registry_collector(
                ecosystem=item["ecosystem"],
                max_pages=max_pages,
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

    alert_ids = [alert_id for result in results if (alert_id := _record_collector_degraded_alert(result, db_path=db_path))]

    scoring = score_pending_events(limit=score_limit, db_path=db_path)
    retries = retry_dead_letters(limit=50, db_path=db_path, fetcher=fetcher)
    recovery = recover_interrupted_runs(db_path=db_path)
    try:
        deliveries = deliver_pending_operational_alerts(db_path=db_path)
    except Exception as exc:  # alerting must not stop registry surveillance
        capture_exception(exc, context={"component": "research_alert_delivery"})
        deliveries = {"enabled": True, "attempted": 0, "sent": 0, "failed": 1, "error": "operational alert delivery failed"}
    return {
        "collectors_run": len(results),
        "collector_results": results,
        "scoring": scoring,
        "retries": retries,
        "recovery": recovery,
        "operational_alert_ids": alert_ids,
        "alert_delivery": deliveries,
        "storage": storage,
        "completed_at": _utcnow().isoformat().replace("+00:00", "Z"),
    }


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
    try:
        while not stop["requested"]:
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
                raise
            cycles += 1
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
