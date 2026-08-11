from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any

import soc_store


SCHEMA_VERSION = "secopsai.intelligence.job.v1"
ACTIVE_STATUSES = {"queued", "running", "awaiting_provider"}
FINAL_STATUSES = {"succeeded", "failed", "canceled"}
WAITING_PROVIDER_STATUS = "awaiting_provider"
MAX_INPUT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 512 * 1024


def enqueue_job(
    *,
    action: str,
    target_id: str = "",
    inputs: dict[str, Any] | None = None,
    requested_by: str = "operator",
    idempotency_key: str = "",
    initial_status: str = "queued",
    initial_error_code: str | None = None,
    initial_error_message: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    action = _required(action, "action", 80)
    target_id = _clean(target_id, 240)
    requested_by = _required(requested_by, "requested_by", 160)
    initial_status = _required(initial_status, "initial_status", 40)
    if initial_status not in {"queued", WAITING_PROVIDER_STATUS}:
        raise ValueError("initial_status must be queued or awaiting_provider")
    normalized_input = dict(inputs or {})
    input_json = _bounded_json(normalized_input, MAX_INPUT_BYTES, "job input")
    if not idempotency_key:
        seed = f"{action}|{target_id}|{input_json}|{requested_by}"
        idempotency_key = hashlib.sha256(seed.encode()).hexdigest()
    else:
        idempotency_key = _required(idempotency_key, "idempotency_key", 256)

    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    job_id = f"AIJ-{uuid.uuid4().hex[:16].upper()}"
    with closing(soc_store.connect(db_path)) as connection:
        existing = connection.execute(
            "SELECT job_id FROM intelligence_jobs WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if existing:
            return get_job(str(existing["job_id"]), db_path=db_path)
        connection.execute(
            """INSERT INTO intelligence_jobs
            (job_id, action, target_id, status, requested_by, idempotency_key,
             attempt, provider, queued_at, started_at, completed_at, updated_at,
             error_code, error_message, input_json, result_json)
            VALUES (?, ?, ?, ?, ?, ?, 0, '', ?, NULL, NULL, ?, ?, ?, ?, '{}')""",
            (
                job_id,
                action,
                target_id,
                initial_status,
                requested_by,
                idempotency_key,
                now,
                now,
                _clean(initial_error_code, 80) if initial_error_code else None,
                _clean(initial_error_message, 2000) if initial_error_message else None,
                input_json,
            ),
        )
        _event(
            connection,
            job_id,
            "queued" if initial_status == "queued" else "awaiting_provider",
            requested_by,
            "Intelligence job queued." if initial_status == "queued" else "Intelligence job is waiting for a healthy provider.",
            {"action": action, "status": initial_status},
        )
        connection.commit()
    return get_job(job_id, db_path=db_path)


def claim_next_job(
    *,
    provider: str,
    worker_id: str,
    stale_after_seconds: int = 900,
    db_path: str | None = None,
) -> dict[str, Any] | None:
    provider = _required(provider, "provider", 80)
    worker_id = _required(worker_id, "worker_id", 160)
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    stale_cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=max(60, int(stale_after_seconds)))
    ).isoformat().replace("+00:00", "Z")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        stale_rows = connection.execute(
            "SELECT job_id FROM intelligence_jobs WHERE status = 'running' AND updated_at < ?",
            (stale_cutoff,),
        ).fetchall()
        for row in stale_rows:
            connection.execute(
                """UPDATE intelligence_jobs SET status = 'queued', provider = '',
                   started_at = NULL, updated_at = ?, error_code = 'worker_recovered',
                   error_message = 'Recovered after the previous worker stopped reporting.'
                   WHERE job_id = ?""",
                (now, row["job_id"]),
            )
            _event(
                connection,
                str(row["job_id"]),
                "recovered",
                worker_id,
                "Recovered a stale running job.",
                {},
            )

        row = connection.execute(
            """SELECT job_id FROM intelligence_jobs WHERE status = 'queued'
               ORDER BY CASE action
                 WHEN 'analyze_research_case' THEN 0
                 WHEN 'generate_analyst_brief' THEN 0
                 WHEN 'review_publication_safety' THEN 0
                 WHEN 'triage_finding' THEN 2
                 ELSE 1 END,
                 queued_at, job_id LIMIT 1"""
        ).fetchone()
        if row is None:
            connection.commit()
            return None
        job_id = str(row["job_id"])
        updated = connection.execute(
            """UPDATE intelligence_jobs SET status = 'running', provider = ?,
               attempt = attempt + 1, started_at = ?, updated_at = ?,
               error_code = NULL, error_message = NULL
               WHERE job_id = ? AND status = 'queued'""",
            (provider, now, now, job_id),
        )
        if updated.rowcount != 1:
            connection.rollback()
            return None
        _event(connection, job_id, "claimed", worker_id, "Intelligence job claimed by local bridge.", {"provider": provider})
        connection.commit()
    return get_job(job_id, db_path=db_path)


def complete_job(
    job_id: str,
    *,
    result: dict[str, Any],
    actor: str,
    provider: str = "",
    db_path: str | None = None,
) -> dict[str, Any]:
    result_json = _bounded_json(result, MAX_RESULT_BYTES, "job result")
    return _finish(
        job_id,
        "succeeded",
        actor=actor,
        result_json=result_json,
        provider=provider,
        db_path=db_path,
    )


def requeue_job(
    job_id: str,
    *,
    actor: str = "operator",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Requeue a failed/canceled job so another bridge model can process it."""
    job_id = _required(job_id, "job_id", 80)
    actor = _required(actor, "actor", 160)
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT status FROM intelligence_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise ValueError(f"intelligence job not found: {job_id}")
        status = str(row["status"])
        if status == "running":
            raise ValueError("a running intelligence job cannot be requeued; stop the bridge or wait for recovery")
        if status == "queued":
            return get_job(job_id, db_path=db_path)
        if status not in {"failed", "canceled"}:
            raise ValueError(f"only failed or canceled intelligence jobs can be requeued (status={status})")
        connection.execute(
            """UPDATE intelligence_jobs
               SET status = 'queued', provider = '', started_at = NULL, completed_at = NULL,
                   updated_at = ?, error_code = NULL, error_message = NULL, result_json = '{}'
               WHERE job_id = ?""",
            (now, job_id),
        )
        _event(connection, job_id, "requeued", actor, "Intelligence job requeued for another bridge model.", {})
        connection.commit()
    return get_job(job_id, db_path=db_path)


def fail_job(
    job_id: str,
    *,
    error_code: str,
    error_message: str,
    actor: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    return _finish(
        job_id,
        "failed",
        actor=actor,
        error_code=_required(error_code, "error_code", 80),
        error_message=_required(error_message, "error_message", 2000),
        db_path=db_path,
    )


def cancel_job(job_id: str, *, actor: str = "operator", db_path: str | None = None) -> dict[str, Any]:
    job_id = _required(job_id, "job_id", 80)
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT status FROM intelligence_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise ValueError(f"intelligence job not found: {job_id}")
        if str(row["status"]) in FINAL_STATUSES:
            return get_job(job_id, db_path=db_path)
        if str(row["status"]) == "running":
            raise ValueError("a running intelligence job cannot be canceled safely; stop the bridge and allow stale-job recovery")
        connection.execute(
            "UPDATE intelligence_jobs SET status = 'canceled', completed_at = ?, updated_at = ? WHERE job_id = ?",
            (now, now, job_id),
        )
        _event(connection, job_id, "canceled", actor, "Intelligence job canceled.", {})
        connection.commit()
    return get_job(job_id, db_path=db_path)


def get_job(job_id: str, *, db_path: str | None = None) -> dict[str, Any]:
    job_id = _required(job_id, "job_id", 80)
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM intelligence_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise ValueError(f"intelligence job not found: {job_id}")
        events = connection.execute(
            "SELECT event_id, event_type, actor, message, data_json, created_at FROM intelligence_job_events WHERE job_id = ? ORDER BY event_id",
            (job_id,),
        ).fetchall()
    result = _row(row)
    result["events"] = [
        {**dict(event), "data": _decode(str(event["data_json"]))}
        for event in events
    ]
    for event in result["events"]:
        event.pop("data_json", None)
    return result


def list_jobs(
    *,
    status: str = "",
    limit: int = 100,
    include_result: bool = True,
    db_path: str | None = None,
) -> list[dict[str, Any]]:
    soc_store.init_db(db_path)
    limit = max(1, min(int(limit), 500))
    params: list[Any] = []
    where = ""
    if status:
        status = _required(status, "status", 32)
        where = " WHERE status = ?"
        params.append(status)
    params.append(limit)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"SELECT * FROM intelligence_jobs{where} ORDER BY updated_at DESC, job_id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return [_row(row, include_result=include_result) for row in rows]


def job_counts(*, db_path: str | None = None) -> dict[str, int]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT status, COUNT(*) AS count FROM intelligence_jobs GROUP BY status").fetchall()
    return {str(row["status"]): int(row["count"]) for row in rows}


def mark_queued_jobs_awaiting_provider(
    *,
    reason: str,
    actor: str = "bridge-health",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Move only unclaimed triage jobs to an explicit provider-wait state."""
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    message = _clean(reason, 2000) or "All configured providers failed their live health probe."
    moved: list[str] = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT job_id FROM intelligence_jobs WHERE status='queued' AND action='triage_finding' ORDER BY queued_at, job_id"
        ).fetchall()
        for row in rows:
            job_id = str(row["job_id"])
            updated = connection.execute(
                """UPDATE intelligence_jobs SET status=?, updated_at=?, error_code='provider_unavailable',
                   error_message=? WHERE job_id=? AND status='queued'""",
                (WAITING_PROVIDER_STATUS, now, message, job_id),
            )
            if updated.rowcount == 1:
                _event(connection, job_id, "awaiting_provider", actor, "Moved to awaiting-provider queue after live provider health failure.", {"error_code": "provider_unavailable"})
                moved.append(job_id)
        connection.commit()
    return {"status": WAITING_PROVIDER_STATUS, "count": len(moved), "job_ids": moved}


def release_waiting_provider_jobs(
    *,
    provider: str,
    actor: str = "bridge-health",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Return provider-waiting triage jobs to the normal queue after recovery."""
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    released: list[str] = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT job_id FROM intelligence_jobs WHERE status=? AND action='triage_finding' ORDER BY queued_at, job_id",
            (WAITING_PROVIDER_STATUS,),
        ).fetchall()
        for row in rows:
            job_id = str(row["job_id"])
            updated = connection.execute(
                """UPDATE intelligence_jobs SET status='queued', provider='', updated_at=?,
                   error_code=NULL, error_message=NULL
                   WHERE job_id=? AND status=?""",
                (now, job_id, WAITING_PROVIDER_STATUS),
            )
            if updated.rowcount == 1:
                _event(connection, job_id, "provider_recovered", actor, "Provider health recovered; job returned to the normal queue.", {"provider": _clean(provider, 80)})
                released.append(job_id)
        connection.commit()
    return {"status": "released", "provider": _clean(provider, 80), "count": len(released), "job_ids": released}


def recover_running_jobs(
    *,
    actor: str = "bridge-service-recovery",
    reason: str = "The local bridge service stopped before completion.",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Requeue local running jobs after the owning bridge has stopped."""
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    recovered: list[str] = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT job_id FROM intelligence_jobs WHERE status = 'running' ORDER BY queued_at, job_id"
        ).fetchall()
        for row in rows:
            job_id = str(row["job_id"])
            connection.execute(
                """UPDATE intelligence_jobs SET status = 'queued', provider = '', started_at = NULL,
                   updated_at = ?, error_code = 'service_recovered', error_message = ?
                   WHERE job_id = ? AND status = 'running'""",
                (now, _clean(reason, 500), job_id),
            )
            _event(connection, job_id, "service_recovered", actor, "Requeued after the local bridge service stopped.", {})
            recovered.append(job_id)
        connection.commit()
    return {"status": "recovered", "count": len(recovered), "job_ids": recovered}


def _finish(
    job_id: str,
    status: str,
    *,
    actor: str,
    result_json: str = "{}",
    error_code: str | None = None,
    error_message: str | None = None,
    provider: str = "",
    db_path: str | None = None,
) -> dict[str, Any]:
    job_id = _required(job_id, "job_id", 80)
    now = soc_store.utc_now()
    provider_name = _clean(provider, 80) if provider else ""
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT status FROM intelligence_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise ValueError(f"intelligence job not found: {job_id}")
        if str(row["status"]) != "running":
            raise ValueError("only a running intelligence job can be completed or failed")
        if provider_name:
            connection.execute(
                """UPDATE intelligence_jobs SET status = ?, result_json = ?, completed_at = ?,
                   updated_at = ?, error_code = ?, error_message = ?, provider = ? WHERE job_id = ?""",
                (status, result_json, now, now, error_code, error_message, provider_name, job_id),
            )
        else:
            connection.execute(
                """UPDATE intelligence_jobs SET status = ?, result_json = ?, completed_at = ?,
                   updated_at = ?, error_code = ?, error_message = ? WHERE job_id = ?""",
                (status, result_json, now, now, error_code, error_message, job_id),
            )
        _event(
            connection,
            job_id,
            status,
            actor,
            "Intelligence job completed." if status == "succeeded" else "Intelligence job failed.",
            {"error_code": error_code} if error_code else {},
        )
        connection.commit()
    completed = get_job(job_id, db_path=db_path)
    _notify_research_pipeline(completed, db_path=db_path)
    _notify_agent_triage(completed, db_path=db_path)
    return get_job(job_id, db_path=db_path)


def _notify_research_pipeline(job: dict[str, Any], *, db_path: str | None) -> None:
    inputs = job.get("input") if isinstance(job.get("input"), dict) else {}
    if not inputs.get("pipeline_id"):
        return
    try:
        from secopsai.research_pipeline import reconcile_intelligence_job

        pipeline = reconcile_intelligence_job(job, db_path=db_path)
        if pipeline:
            from secopsai.investigation_autopilot import reconcile_pipeline

            reconcile_pipeline(pipeline["pipeline_id"], db_path=db_path)
    except Exception as exc:  # The completed AI result remains durable and retryable.
        with closing(soc_store.connect(db_path)) as connection:
            _event(
                connection,
                job["job_id"],
                "pipeline_reconcile_failed",
                "research-pipeline",
                "The Intelligence result was saved, but pipeline reconciliation needs a retry.",
                {"error": str(exc)[:500]},
            )
            connection.commit()


def _notify_agent_triage(job: dict[str, Any], *, db_path: str | None) -> None:
    inputs = job.get("input") if isinstance(job.get("input"), dict) else {}
    if not inputs.get("agent_triage_run_id"):
        return
    try:
        from secopsai.agent_triage import reconcile_intelligence_job

        reconcile_intelligence_job(job, db_path=db_path)
    except Exception as exc:  # Preserve the model result and expose reconciliation failure.
        with closing(soc_store.connect(db_path)) as connection:
            _event(
                connection,
                job["job_id"],
                "agent_triage_reconcile_failed",
                "agent-triage",
                "The Intelligence result was saved, but agent triage reconciliation needs a retry.",
                {"error": str(exc)[:500]},
            )
            connection.commit()


def _event(
    connection: sqlite3.Connection,
    job_id: str,
    event_type: str,
    actor: str,
    message: str,
    data: dict[str, Any],
) -> None:
    connection.execute(
        "INSERT INTO intelligence_job_events (job_id, event_type, actor, message, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (job_id, event_type, _clean(actor, 160), message, json.dumps(data, sort_keys=True), soc_store.utc_now()),
    )


def _row(row: sqlite3.Row, *, include_result: bool = True) -> dict[str, Any]:
    result = dict(row)
    result["schema_version"] = SCHEMA_VERSION
    raw_input = str(result.pop("input_json", "{}"))
    decoded_input = _decode(raw_input)
    if include_result:
        result["input"] = decoded_input
    else:
        # Status polling only needs the routing identity. Evidence, prompts,
        # and deterministic assessments stay behind the explicit job-show
        # endpoint just like the model result does.
        result["input"] = {
            key: decoded_input.get(key)
            for key in ("target_id", "selected_model", "pipeline_id", "agent_triage_run_id")
            if isinstance(decoded_input, dict) and decoded_input.get(key) is not None
        }
        result["input_available"] = raw_input not in {"", "{}"}
        result["input_bytes"] = len(raw_input.encode("utf-8"))
    raw_result = str(result.pop("result_json", "{}"))
    if include_result:
        result["result"] = _decode(raw_result)
    else:
        # Status/list views only need to know whether a result exists. Keep
        # the full normalized result behind the explicit job-show action so a
        # dashboard refresh cannot transfer megabytes of model output.
        result["result"] = {}
        result["result_available"] = raw_result not in {"", "{}"}
        result["result_bytes"] = len(raw_result.encode("utf-8"))
    result.pop("idempotency_key", None)
    return result


def _decode(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _bounded_json(value: dict[str, Any], limit: int, label: str) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return encoded


def _required(value: Any, label: str, limit: int) -> str:
    result = _clean(value, limit)
    if not result:
        raise ValueError(f"{label} is required")
    return result


def _clean(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]
