"""Durable coordinator for the SecOpsAI daily operating workflow.

The coordinator joins the existing registry worker, candidate promotion,
evidence investigations, model-review queue, and guarded detection-learning
pipeline. It never sends disclosure, submits a sandbox artifact, publishes a
post, or activates an unverified detector change. Each step is persisted so a
partial run is visible and the next scheduled run can continue safely.
"""

from __future__ import annotations

import json
import secrets
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

import soc_store


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


def get_settings(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
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
    result = dict(row or {})
    for key in ("enabled", "auto_promote_candidates", "run_learning"):
        result[key] = bool(result.get(key))
    result["schema_version"] = SCHEMA_VERSION
    return result


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
    with closing(soc_store.connect(db_path)) as connection:
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
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM daily_automation_runs WHERE run_id=?", (_clean(run_id, 64).upper(),)
        ).fetchone()
    if row is None:
        raise ValueError(f"daily automation run not found: {run_id}")
    return _row_to_run(row, db_path=db_path)


def list_runs(*, status: str = "", limit: int = 20, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    soc_store.init_db(db_path)
    params: list[Any] = []
    where = ""
    if status:
        where = " WHERE status=?"
        params.append(_clean(status, 32).lower())
    params.append(max(1, min(int(limit), 100)))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"SELECT * FROM daily_automation_runs{where} ORDER BY started_at DESC, run_id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return [_row_to_run(row, db_path=db_path) for row in rows]


def _create_run(*, trigger: str, db_path: Optional[str]) -> Dict[str, Any]:
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        active = connection.execute(
            "SELECT * FROM daily_automation_runs WHERE status='running' ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        if active:
            age = _parse_time(active["started_at"])
            if age and (datetime.now(timezone.utc) - age).total_seconds() < STALE_RUN_SECONDS:
                connection.commit()
                return {"status": "already_running", "run": _row_to_run(active, db_path=db_path)}
            connection.execute(
                "UPDATE daily_automation_runs SET status='degraded', completed_at=?, updated_at=?, error_message=? WHERE run_id=?",
                (now, now, "Marked stale after the automation owner stopped reporting.", active["run_id"]),
            )
        run_id = _id("DAR")
        connection.execute(
            """INSERT INTO daily_automation_runs
               (run_id, trigger, status, started_at, completed_at, next_run_at,
                summary_json, error_message, updated_at)
               VALUES (?, ?, 'running', ?, NULL, NULL, '{}', NULL, ?)""",
            (run_id, _clean(trigger, 80) or "worker", now, now),
        )
        connection.commit()
    return {"status": "created", "run_id": run_id}


def _record_step(
    run_id: str,
    name: str,
    callback: Callable[[], Dict[str, Any]],
    *,
    db_path: Optional[str],
) -> Dict[str, Any]:
    started = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        cursor = connection.execute(
            """INSERT INTO daily_automation_steps
               (run_id, step_name, status, started_at, completed_at, result_json, error_message)
               VALUES (?, ?, 'running', ?, NULL, '{}', NULL)""",
            (run_id, _clean(name, 120), started),
        )
        step_id = cursor.lastrowid
        connection.commit()
    try:
        result = callback() or {}
        status = "succeeded"
        error = None
    except Exception as exc:  # one step must not prevent the remaining workflow
        result = {"status": "degraded", "error": _clean(exc, 1000)}
        status = "failed"
        error = _clean(exc, 2000)
    completed = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE daily_automation_steps SET status=?, completed_at=?, result_json=?, error_message=?
               WHERE step_id=?""",
            (status, completed, _json(result), error, step_id),
        )
        connection.commit()
    return {"step_name": name, "status": status, "result": result, "error": error}


def _finish_run(
    run_id: str,
    *,
    status: str,
    summary: Dict[str, Any],
    next_run_at: Optional[str],
    db_path: Optional[str],
) -> Dict[str, Any]:
    completed = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE daily_automation_runs SET status=?, completed_at=?, next_run_at=?,
               summary_json=?, error_message=?, updated_at=? WHERE run_id=?""",
            (
                status,
                completed,
                next_run_at,
                _json(summary),
                _clean(summary.get("error"), 2000) if summary.get("error") else None,
                completed,
                run_id,
            ),
        )
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
            lambda: run_artifact_fleet_cycle(since="24h", limit=100, workers=4),
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
    step_results = [_record_step(run_id, name, callback, db_path=db_path) for name, callback in steps]
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
    if failed:
        summary["error"] = "; ".join(item["error"] or item["step_name"] for item in failed)
    status = "degraded" if failed else "succeeded"
    next_run = (
        datetime.now(timezone.utc) + timedelta(seconds=int(settings["interval_seconds"]))
    ).isoformat().replace("+00:00", "Z")
    return _finish_run(run_id, status=status, summary=summary, next_run_at=next_run, db_path=db_path)


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
    settings = get_settings(db_path=db_path)
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
            "failed_steps": sum(int(run.get("summary", {}).get("failed_steps", 0)) for run in runs),
        },
        "active_run": active,
        "runs": runs,
    }
