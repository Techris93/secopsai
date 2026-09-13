"""Durable coordinator for the SecOpsAI daily operating workflow.

The coordinator joins the existing registry worker, candidate promotion,
evidence investigations, model-review queue, and guarded detection-learning
pipeline. It never sends disclosure, submits a sandbox artifact, publishes a
post, or activates an unverified detector change. Each step is persisted so a
partial run is visible and the next scheduled run can continue safely.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import socket
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

import soc_store
from secopsai.sqlite_writer_lock import sqlite_writer_lock


SCHEMA_VERSION = "secopsai.daily-automation.v1"
RUN_STATUSES = {"running", "succeeded", "degraded", "failed", "skipped"}
STEP_STATUSES = {"running", "succeeded", "failed", "skipped"}
DEFAULTS = {
    "enabled": True,
    "interval_seconds": 86400,
    "max_alert_reviews": 25,
    "max_investigations": 5,
    "max_candidate_cases": 25,
    "auto_promote_candidates": True,
    "run_learning": True,
}
STALE_RUN_SECONDS = 6 * 60 * 60


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _decode(value: Any, default: Any) -> Any:
    try:
        parsed = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed


def _clean(value: Any, limit: int = 2000) -> str:
    return str(value or "").strip()[:limit]


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def _owner_id() -> str:
    """Identify this local scheduler process for run fencing."""
    return _clean(f"{socket.gethostname()}:{os.getpid()}", 160) or "daily-automation"


def _lease_until(seconds: int = STALE_RUN_SECONDS) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=max(60, int(seconds)))
    ).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)


def _is_due(value: Any, *, now: Optional[datetime] = None) -> bool:
    parsed = _parse_time(value)
    return parsed is None or parsed <= (now or datetime.now(timezone.utc))


def _settings_payload(row: Any | None) -> Dict[str, Any]:
    """Normalize a settings row without requiring a write-capable connection."""
    if row is None:
        result: Dict[str, Any] = {
            "settings_id": 1,
            **DEFAULTS,
            "last_run_at": None,
            "next_run_at": None,
            "updated_at": None,
            "updated_by": "secopsai-default",
        }
    else:
        result = dict(row)
    for key in ("enabled", "auto_promote_candidates", "run_learning"):
        result[key] = bool(result.get(key))
    result["schema_version"] = SCHEMA_VERSION
    return result


def get_settings(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            row = connection.execute(
                "SELECT * FROM daily_automation_settings WHERE settings_id = 1"
            ).fetchone()
            if row is None:
                now = soc_store.utc_now()
                connection.execute(
                    """INSERT INTO daily_automation_settings
                    (settings_id, enabled, interval_seconds, max_alert_reviews,
                     max_investigations, max_candidate_cases, auto_promote_candidates,
                     run_learning, last_run_at, next_run_at, updated_at, updated_by)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
                    (
                        int(DEFAULTS["enabled"]),
                        DEFAULTS["interval_seconds"],
                        DEFAULTS["max_alert_reviews"],
                        DEFAULTS["max_investigations"],
                        DEFAULTS["max_candidate_cases"],
                        int(DEFAULTS["auto_promote_candidates"]),
                        int(DEFAULTS["run_learning"]),
                        now,
                        "secopsai-default",
                    ),
                )
                connection.commit()
                row = connection.execute(
                    "SELECT * FROM daily_automation_settings WHERE settings_id = 1"
                ).fetchone()
    return _settings_payload(row)


def read_settings(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Read automation settings without creating schema or default rows.

    Status and health endpoints call this function so a browser refresh cannot
    acquire the SQLite writer lock or mutate a missing database.  Mutation and
    scheduler paths continue to use :func:`get_settings`, which deliberately
    initializes the operational schema and defaults.
    """
    resolved_path = db_path or soc_store.default_db_path()
    if not os.path.exists(resolved_path):
        return _settings_payload(None)
    try:
        with closing(soc_store.read_connect(resolved_path)) as connection:
            row = connection.execute(
                "SELECT * FROM daily_automation_settings WHERE settings_id = 1"
            ).fetchone()
    except sqlite3.Error:
        # Preserve a bounded, explicit status payload for a file that exists
        # but has not reached the operational schema yet.  Do not attempt a
        # repair from a read request; the next scheduler/mutation path can
        # initialize it under its normal writer lock.
        result = _settings_payload(None)
        result["status"] = "degraded"
        result["error"] = "daily automation settings are unavailable"
        return result
    return _settings_payload(row)


def update_settings(
    *,
    enabled: Optional[bool] = None,
    interval_seconds: Optional[int] = None,
    max_alert_reviews: Optional[int] = None,
    max_investigations: Optional[int] = None,
    max_candidate_cases: Optional[int] = None,
    auto_promote_candidates: Optional[bool] = None,
    run_learning: Optional[bool] = None,
    actor: str = "operator",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    with sqlite_writer_lock(db_path):
        current = get_settings(db_path=db_path)
        interval = int(interval_seconds if interval_seconds is not None else current["interval_seconds"])
        alert_limit = int(max_alert_reviews if max_alert_reviews is not None else current["max_alert_reviews"])
        investigation_limit = int(max_investigations if max_investigations is not None else current["max_investigations"])
        candidate_limit = int(max_candidate_cases if max_candidate_cases is not None else current["max_candidate_cases"])
        if not 900 <= interval <= 604800:
            raise ValueError("automation interval must be between 900 seconds and 7 days")
        if not 1 <= alert_limit <= 500:
            raise ValueError("maximum alert reviews must be between 1 and 500")
        if not 1 <= investigation_limit <= 100:
            raise ValueError("maximum investigations must be between 1 and 100")
        if not 1 <= candidate_limit <= 500:
            raise ValueError("maximum candidate cases must be between 1 and 500")
        values = (
            int(bool(enabled if enabled is not None else current["enabled"])),
            interval,
            alert_limit,
            investigation_limit,
            candidate_limit,
            int(bool(auto_promote_candidates if auto_promote_candidates is not None else current["auto_promote_candidates"])),
            int(bool(run_learning if run_learning is not None else current["run_learning"])),
            soc_store.utc_now(),
            _clean(actor, 160) or "operator",
        )
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute(
                """UPDATE daily_automation_settings SET enabled=?, interval_seconds=?,
                   max_alert_reviews=?, max_investigations=?, max_candidate_cases=?,
                   auto_promote_candidates=?, run_learning=?, updated_at=?, updated_by=?
                   WHERE settings_id=1""",
                values,
            )
            connection.commit()
    return get_settings(db_path=db_path)


def _row_to_run(row: Any, *, db_path: Optional[str]) -> Dict[str, Any]:
    result = dict(row)
    result["summary"] = _decode(result.pop("summary_json", "{}"), {})
    result["steps"] = []
    with closing(soc_store.read_connect(db_path)) as connection:
        steps = connection.execute(
            """SELECT * FROM daily_automation_steps
               WHERE run_id=? ORDER BY step_id""",
            (result["run_id"],),
        ).fetchall()
    for item in steps:
        step = dict(item)
        step["result"] = _decode(step.pop("result_json", "{}"), {})
        result["steps"].append(step)
    result["schema_version"] = SCHEMA_VERSION
    return result


def get_run(run_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    # A status/read endpoint must not take the schema writer lock on every
    # request.  The scheduler and mutation paths initialize the database; a
    # missing file simply has no run to return.
    resolved_path = db_path or soc_store.default_db_path()
    if not os.path.exists(resolved_path):
        raise ValueError(f"daily automation run not found: {run_id}")
    with closing(soc_store.read_connect(resolved_path)) as connection:
        row = connection.execute(
            "SELECT * FROM daily_automation_runs WHERE run_id=?", (_clean(run_id, 64).upper(),)
        ).fetchone()
    if row is None:
        raise ValueError(f"daily automation run not found: {run_id}")
    return _row_to_run(row, db_path=resolved_path)


def list_runs(*, status: str = "", limit: int = 20, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    # Keep reads query-only.  ``status`` calls ``get_settings`` first, which
    # creates/initializes a new database when necessary; direct callers on a
    # missing path should receive an empty list without creating a file.
    resolved_path = db_path or soc_store.default_db_path()
    if not os.path.exists(resolved_path):
        return []
    params: list[Any] = []
    where = ""
    if status:
        where = " WHERE status=?"
        params.append(_clean(status, 32).lower())
    params.append(max(1, min(int(limit), 100)))
    with closing(soc_store.read_connect(resolved_path)) as connection:
        rows = connection.execute(
            f"SELECT * FROM daily_automation_runs{where} ORDER BY started_at DESC, run_id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return [_row_to_run(row, db_path=resolved_path) for row in rows]


def _create_run(
    *,
    trigger: str,
    db_path: Optional[str],
    owner_id: Optional[str] = None,
    lease_seconds: int = STALE_RUN_SECONDS,
) -> Dict[str, Any]:
    owner = _clean(owner_id, 160) or _owner_id()
    now = soc_store.utc_now()
    lease_until = _lease_until(lease_seconds)
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT * FROM daily_automation_runs WHERE status='running' ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
            if active:
                active_lease = _parse_time(active["lease_until"] if "lease_until" in active.keys() else None)
                heartbeat = _parse_time(active["updated_at"]) or _parse_time(active["started_at"])
                stale = active_lease is not None and active_lease <= datetime.now(timezone.utc)
                if active_lease is None:
                    stale = heartbeat is None or (datetime.now(timezone.utc) - heartbeat).total_seconds() >= max(60, int(lease_seconds))
                if not stale:
                    connection.commit()
                    return {"status": "already_running", "run": _row_to_run(active, db_path=db_path)}
                connection.execute(
                    """UPDATE daily_automation_runs SET status='degraded', completed_at=?,
                       updated_at=?, lease_until=NULL, error_message=?
                       WHERE run_id=? AND status='running'""",
                    (now, now, "Marked stale after the automation owner stopped reporting.", active["run_id"]),
                )
            generation = int(
                connection.execute("SELECT COALESCE(MAX(generation), 0) + 1 FROM daily_automation_runs").fetchone()[0]
                or 1
            )
            run_id = _id("DAR")
            connection.execute(
                """INSERT INTO daily_automation_runs
                   (run_id, trigger, status, started_at, completed_at, next_run_at,
                    summary_json, error_message, updated_at, owner_id, generation, lease_until)
                   VALUES (?, ?, 'running', ?, NULL, NULL, '{}', NULL, ?, ?, ?, ?)""",
                (run_id, _clean(trigger, 80) or "worker", now, now, owner, generation, lease_until),
            )
            connection.commit()
    return {
        "status": "created",
        "run_id": run_id,
        "owner_id": owner,
        "generation": generation,
        "lease_until": lease_until,
    }


def _record_step(
    run_id: str,
    name: str,
    callback: Callable[[], Dict[str, Any]],
    *,
    db_path: Optional[str],
    owner_id: Optional[str] = None,
    generation: Optional[int] = None,
    lease_seconds: int = STALE_RUN_SECONDS,
) -> Dict[str, Any]:
    owner = _clean(owner_id, 160) if owner_id is not None else None
    expected_generation = int(generation) if generation is not None else None
    started = soc_store.utc_now()
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            run = connection.execute(
                "SELECT status, owner_id, generation, lease_until FROM daily_automation_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise ValueError(f"daily automation run not found: {run_id}")
            if owner is None:
                owner = _clean(run["owner_id"], 160)
            if expected_generation is None:
                expected_generation = int(run["generation"] or 0)
            lease_expired = _parse_time(run["lease_until"]) if run["lease_until"] else None
            if (
                str(run["status"]) != "running"
                or str(run["owner_id"] or "") != str(owner or "")
                or int(run["generation"] or 0) != int(expected_generation or 0)
                or (lease_expired is not None and lease_expired <= datetime.now(timezone.utc))
            ):
                return {"step_name": name, "status": "skipped", "result": {"reason": "run_fenced"}, "error": "run_fenced", "fenced": True}
            renewed = connection.execute(
                """UPDATE daily_automation_runs SET updated_at=?, lease_until=?
                   WHERE run_id=? AND status='running' AND owner_id=? AND generation=?
                     AND (lease_until IS NULL OR lease_until > ?)""",
                (started, _lease_until(lease_seconds), run_id, owner, int(expected_generation or 0), started),
            )
            if renewed.rowcount != 1:
                return {"step_name": name, "status": "skipped", "result": {"reason": "run_fenced"}, "error": "run_fenced", "fenced": True}
            cursor = connection.execute(
                """INSERT INTO daily_automation_steps
                   (run_id, step_name, status, started_at, completed_at, result_json, error_message)
                   VALUES (?, ?, 'running', ?, NULL, '{}', NULL)""",
                (run_id, _clean(name, 120), started),
            )
            step_id = cursor.lastrowid
            connection.commit()
    result: Dict[str, Any] = {}
    status = "succeeded"
    error = None
    retry_count = 0
    for attempt in range(4):
        try:
            result = callback() or {}
            break
        except sqlite3.OperationalError as exc:
            # A short SQLite writer collision is a recoverable infrastructure
            # condition. Retry only that narrow error; security or validation
            # failures remain visible and still fail the step immediately.
            message = str(exc).lower()
            if "locked" not in message and "busy" not in message or attempt >= 3:
                result = {"status": "degraded", "error": _clean(exc, 1000)}
                status = "failed"
                error = _clean(exc, 2000)
                break
            retry_count += 1
            time.sleep((0.2, 0.5, 1.0)[attempt])
        except Exception as exc:  # one step must not prevent the remaining workflow
            result = {"status": "degraded", "error": _clean(exc, 1000)}
            status = "failed"
            error = _clean(exc, 2000)
            break
    if retry_count and isinstance(result, dict):
        result = dict(result)
        result["sqlite_retries"] = retry_count
    completed = soc_store.utc_now()
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            renewed = connection.execute(
                """UPDATE daily_automation_runs SET updated_at=?, lease_until=?
                   WHERE run_id=? AND status='running' AND owner_id=? AND generation=?
                     AND (lease_until IS NULL OR lease_until > ?)""",
                (completed, _lease_until(lease_seconds), run_id, owner, int(expected_generation or 0), completed),
            )
            if renewed.rowcount != 1:
                connection.rollback()
                return {"step_name": name, "status": "skipped", "result": {"reason": "run_fenced"}, "error": "run_fenced", "fenced": True}
            connection.execute(
                """UPDATE daily_automation_steps SET status=?, completed_at=?, result_json=?, error_message=?
                   WHERE step_id=? AND run_id=?""",
                (status, completed, _json(result), error, step_id, run_id),
            )
            connection.commit()
    return {"step_name": name, "status": status, "result": result, "error": error, "fenced": False}


def _finish_run(
    run_id: str,
    *,
    status: str,
    summary: Dict[str, Any],
    next_run_at: Optional[str],
    db_path: Optional[str],
    owner_id: Optional[str] = None,
    generation: Optional[int] = None,
) -> Dict[str, Any]:
    completed = soc_store.utc_now()
    owner = _clean(owner_id, 160) if owner_id is not None else None
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            row = connection.execute(
                "SELECT owner_id, generation FROM daily_automation_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"daily automation run not found: {run_id}")
            if owner is None:
                owner = _clean(row["owner_id"], 160)
            expected_generation = int(generation) if generation is not None else int(row["generation"] or 0)
            updated = connection.execute(
                """UPDATE daily_automation_runs SET status=?, completed_at=?, next_run_at=?,
                   summary_json=?, error_message=?, updated_at=?, lease_until=NULL
                   WHERE run_id=? AND status='running' AND owner_id=? AND generation=?
                     AND (lease_until IS NULL OR lease_until > ?)""",
                (
                    status,
                    completed,
                    next_run_at,
                    _json(summary),
                    _clean(summary.get("error"), 2000) if summary.get("error") else None,
                    completed,
                    run_id,
                    owner,
                    expected_generation,
                    completed,
                ),
            )
            if updated.rowcount != 1:
                connection.rollback()
                raise ValueError("daily automation run lease fenced or expired")
            connection.execute(
                """UPDATE daily_automation_settings SET last_run_at=?, next_run_at=?, updated_at=?
                   WHERE settings_id=1""",
                (completed, next_run_at, completed),
            )
            connection.commit()
    return get_run(run_id, db_path=db_path)


def run_cycle(
    *,
    db_path: Optional[str] = None,
    trigger: str = "operator",
    force: bool = False,
    fetcher: Any = None,
) -> Dict[str, Any]:
    settings = get_settings(db_path=db_path)
    if not settings["enabled"] and not force:
        return {"schema_version": SCHEMA_VERSION, "status": "skipped", "reason": "automation_disabled", "settings": settings}
    created = _create_run(trigger=trigger, db_path=db_path)
    if created["status"] == "already_running":
        return {"schema_version": SCHEMA_VERSION, **created}
    run_id = created["run_id"]
    from secopsai.agent_triage import enqueue_due_findings
    from secopsai.artifact_fleet import run_cycle as run_artifact_fleet_cycle
    from secopsai.detection_learning import run_cycle as run_learning_cycle
    from secopsai.investigation_autopilot import run_due as run_due_investigations
    from secopsai.intelligence_jobs import recover_transient_jobs
    from secopsai.research import build_preflight_report
    from secopsai.research_delivery import deliver_pending_operational_alerts
    from secopsai.research_discovery import run_promotion_policy
    from secopsai.research_specialist_automation import run_cycle as run_specialist_research_cycle
    from secopsai.research_storage import archive_and_prune_history
    from secopsai.research_worker import run_worker_cycle

    steps = [
        (
            "health_preflight",
            lambda: build_preflight_report(),
        ),
        (
            "intelligence_queue_recovery",
            lambda: recover_transient_jobs(
                limit=max(10, int(settings["max_alert_reviews"])),
                max_attempts=3,
                actor="secopsai-daily-automation",
                db_path=db_path,
            ),
        ),
        (
            "registry_surveillance",
            lambda: run_worker_cycle(
                db_path=db_path,
                fetcher=fetcher,
                include_investigations=False,
                include_alert_delivery=False,
                include_automation=False,
            ),
        ),
        (
            "candidate_promotion",
            lambda: run_promotion_policy(
                ecosystem="all",
                apply=bool(settings["auto_promote_candidates"]),
                actor="secopsai-daily-automation",
                limit=int(settings["max_candidate_cases"]),
                db_path=db_path,
            ),
        ),
        (
            "artifact_fleet_safe_cycle",
            lambda: run_artifact_fleet_cycle(since="24h", limit=100, workers=4, db_path=db_path),
        ),
        (
            "alert_review_queue",
            lambda: enqueue_due_findings(
                db_path=db_path,
                requested_by="secopsai-daily-automation",
                limit_override=int(settings["max_alert_reviews"]),
            ),
        ),
        (
            "evidence_investigations",
            lambda: run_due_investigations(
                db_path=db_path,
                limit=int(settings["max_investigations"]),
            ),
        ),
        (
            "research_specialist_review",
            lambda: run_specialist_research_cycle(
                db_path=db_path,
                limit=int(settings["max_investigations"]),
            ),
        ),
        (
            "detection_learning",
            lambda: run_learning_cycle(db_path=db_path) if settings["run_learning"] else {"status": "skipped", "reason": "learning_disabled"},
        ),
        (
            "storage_retention",
            lambda: archive_and_prune_history(db_path=db_path),
        ),
        (
            "operational_alert_delivery",
            lambda: deliver_pending_operational_alerts(db_path=db_path),
        ),
    ]
    step_results: list[Dict[str, Any]] = []
    for name, callback in steps:
        step = _record_step(
            run_id,
            name,
            callback,
            db_path=db_path,
            owner_id=created.get("owner_id"),
            generation=created.get("generation"),
        )
        step_results.append(step)
        if step.get("fenced"):
            break
    failed = [item for item in step_results if item["status"] == "failed"]
    summary: Dict[str, Any] = {
        "steps": step_results,
        "completed_steps": len(step_results) - len(failed),
        "failed_steps": len(failed),
        "operator_gates": [
            "specialist_result_acceptance",
            "publication_review_approval",
            "sandbox_submission",
            "disclosure_send",
            "publish_approved",
            "deployment",
            "unverified_rule_activation",
        ],
        "agent_boundary": "Models may recommend or apply only evidence-gated reversible actions; external communication and publication remain approved actions.",
    }
    # Persist a bounded semantic health snapshot with every daily run. This
    # keeps the coordinator and Mission Control operating picture aligned with
    # the same ontology quality signals used by bridge intelligence requests.
    try:
        from secopsai.ontology import quality as ontology_quality

        summary["ontology_quality"] = ontology_quality(db_path=db_path)
    except Exception as exc:
        summary["ontology_quality"] = {"status": "degraded", "error": _clean(exc, 500)}
    if failed:
        summary["error"] = "; ".join(item["error"] or item["step_name"] for item in failed)
    status = "degraded" if failed else "succeeded"
    next_run = (
        datetime.now(timezone.utc) + timedelta(seconds=int(settings["interval_seconds"]))
    ).isoformat().replace("+00:00", "Z")
    return _finish_run(
        run_id,
        status=status,
        summary=summary,
        next_run_at=next_run,
        db_path=db_path,
        owner_id=created.get("owner_id"),
        generation=created.get("generation"),
    )


def run_due(*, db_path: Optional[str] = None, trigger: str = "worker", fetcher: Any = None) -> Dict[str, Any]:
    settings = get_settings(db_path=db_path)
    if not settings["enabled"]:
        return {"schema_version": SCHEMA_VERSION, "status": "skipped", "reason": "automation_disabled", "settings": settings}
    if not _is_due(settings.get("next_run_at")):
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "not_due",
            "next_run_at": settings.get("next_run_at"),
            "settings": settings,
        }
    return run_cycle(db_path=db_path, trigger=trigger, force=True, fetcher=fetcher)


def status(*, db_path: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
    settings = read_settings(db_path=db_path)
    runs = list_runs(limit=limit, db_path=db_path)
    active = next((run for run in runs if run["status"] == "running"), None)
    return {
        "schema_version": SCHEMA_VERSION,
        "settings": settings,
        "summary": {
            "runs": len(runs),
            "active": 1 if active else 0,
            "last_status": runs[0]["status"] if runs else "never_run",
            "last_run_at": runs[0]["completed_at"] if runs else None,
            "next_run_at": settings.get("next_run_at"),
            # Keep historical failures visible, but make the headline useful:
            # operators need to know whether the latest cycle is healthy.
            "failed_steps": sum(int(run.get("summary", {}).get("failed_steps", 0)) for run in runs),
            "recent_failed_steps": int((runs[0].get("summary", {}) if runs else {}).get("failed_steps", 0)),
            "historical_failed_steps": sum(int(run.get("summary", {}).get("failed_steps", 0)) for run in runs[1:]),
        },
        "active_run": active,
        "runs": runs,
    }
