from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

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
                 WHEN 'execute_specialist_work' THEN 0
                 WHEN 'review_specialist_work' THEN 0
                 WHEN 'analyze_research_case' THEN 1
                 WHEN 'generate_analyst_brief' THEN 1
                 WHEN 'review_publication_safety' THEN 1
                 WHEN 'triage_finding' THEN 3
                 ELSE 2 END,
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


def peek_next_job(
    *,
    include_awaiting_provider: bool = False,
    db_path: str | None = None,
) -> dict[str, Any] | None:
    """Return the next durable job without changing queue state."""
    soc_store.init_db(db_path)
    statuses = "('queued','awaiting_provider')" if include_awaiting_provider else "('queued')"
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute(
            f"""SELECT job_id FROM intelligence_jobs WHERE status IN {statuses}
               ORDER BY CASE action
                 WHEN 'execute_specialist_work' THEN 0
                 WHEN 'review_specialist_work' THEN 0
                 WHEN 'analyze_research_case' THEN 1
                 WHEN 'generate_analyst_brief' THEN 1
                 WHEN 'review_publication_safety' THEN 1
                 WHEN 'triage_finding' THEN 3
                 ELSE 2 END,
                 CASE status WHEN 'queued' THEN 0 ELSE 1 END,
                 queued_at, job_id LIMIT 1"""
        ).fetchone()
    return get_job(str(row["job_id"]), db_path=db_path) if row else None


def heartbeat_job(
    job_id: str,
    *,
    actor: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Refresh a running job lease without changing its status or result."""
    job_id = _required(job_id, "job_id", 80)
    actor = _required(actor, "actor", 160)
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        updated = connection.execute(
            "UPDATE intelligence_jobs SET updated_at=? WHERE job_id=? AND status='running'",
            (now, job_id),
        )
        if updated.rowcount == 1:
            _event(connection, job_id, "heartbeat", actor, "Bridge renewed the running job lease.", {})
        connection.commit()
    return get_job(job_id, db_path=db_path)


def mark_job_awaiting_provider(
    job_id: str,
    *,
    reason: str,
    actor: str = "bridge-health",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Pause one queued job when its captured model is unavailable."""
    job_id = _required(job_id, "job_id", 80)
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE intelligence_jobs SET status=?, provider='', updated_at=?,
               error_code='provider_unavailable', error_message=?
               WHERE job_id=? AND status='queued'""",
            (WAITING_PROVIDER_STATUS, now, _clean(reason, 2000), job_id),
        )
        _event(connection, job_id, "provider_wait", actor, "Captured model is unavailable; job remains durable and was not rerouted.", {"reason": _clean(reason, 500)})
        connection.commit()
    return get_job(job_id, db_path=db_path)


def release_job_from_provider_wait(
    job_id: str,
    *,
    provider: str,
    actor: str = "bridge-health",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Release exactly one job after its captured model becomes healthy."""
    job_id = _required(job_id, "job_id", 80)
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        updated = connection.execute(
            """UPDATE intelligence_jobs SET status='queued', provider='', updated_at=?,
               error_code=NULL, error_message=NULL
               WHERE job_id=? AND status=?""",
            (now, job_id, WAITING_PROVIDER_STATUS),
        )
        if updated.rowcount == 1:
            _event(
                connection,
                job_id,
                "provider_recovered",
                actor,
                "The captured model recovered; this job returned to the normal queue.",
                {"provider": _clean(provider, 80)},
            )
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
    selected_model: str | None = None,
    fallback_models: Sequence[str] | None = None,
    fallback_mode: str | None = None,
    limit: int = 100,
    actor: str = "bridge-health",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Return compatible provider-waiting jobs to the normal queue.

    Older jobs may not have captured a model in their bounded input. Bind those
    legacy rows to the currently selected model before releasing them. Jobs
    captured for a different model stay parked so an operator selection is
    never silently replaced by a provider fallback.
    """
    provider = _clean(provider, 80)
    selected_model = _clean(selected_model, 200) if selected_model else ""
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    released: list[str] = []
    skipped: list[str] = []
    legacy_model_bound: list[str] = []
    bounded_limit = max(1, min(int(limit), 500))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT job_id, input_json FROM intelligence_jobs WHERE status=? ORDER BY queued_at, job_id LIMIT ?",
            (WAITING_PROVIDER_STATUS, bounded_limit),
        ).fetchall()
        for row in rows:
            job_id = str(row["job_id"])
            inputs = _decode(str(row["input_json"] or "{}"))
            captured_model = _clean(inputs.get("selected_model"), 200)
            if captured_model and selected_model and captured_model != selected_model:
                skipped.append(job_id)
                continue
            if not captured_model and selected_model:
                inputs["selected_model"] = selected_model
                if fallback_models is not None or fallback_mode is not None:
                    inputs["fallback_models"] = [
                        str(item).strip()[:200]
                        for item in (fallback_models or ())
                        if str(item).strip() and str(item).strip() != selected_model
                    ][:8]
                    inputs["fallback_mode"] = str(fallback_mode or "disabled").strip()[:40]
                input_json = _bounded_json(inputs, MAX_INPUT_BYTES, "job input")
                connection.execute(
                    "UPDATE intelligence_jobs SET input_json=? WHERE job_id=? AND status=?",
                    (input_json, job_id, WAITING_PROVIDER_STATUS),
                )
                legacy_model_bound.append(job_id)
            updated = connection.execute(
                """UPDATE intelligence_jobs SET status='queued', provider='', updated_at=?,
                   error_code=NULL, error_message=NULL
                   WHERE job_id=? AND status=?""",
                (now, job_id, WAITING_PROVIDER_STATUS),
            )
            if updated.rowcount == 1:
                _event(
                    connection,
                    job_id,
                    "provider_recovered",
                    actor,
                    "The captured model is healthy; job returned to the normal queue.",
                    {"provider": provider, "selected_model": selected_model or captured_model},
                )
                released.append(job_id)
        connection.commit()
    return {
        "status": "released",
        "provider": provider,
        "count": len(released),
        "job_ids": released,
        "skipped": skipped,
        "legacy_model_bound": legacy_model_bound,
    }


def bind_legacy_queued_job_models(
    *,
    selected_model: str,
    fallback_models: Sequence[str] | None = None,
    fallback_mode: str | None = None,
    limit: int = 100,
    actor: str = "bridge-routing",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Pin legacy queued jobs that predate persisted model routing.

    Jobs created before model snapshots were introduced have no selected model
    in their bounded input. Bind those rows before claim so a later operator
    selection cannot change an already queued job implicitly. With no captured
    fallback policy, the safe default is selected-model-only execution.
    """
    selected_model = _required(selected_model, "selected_model", 200)
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    bounded_limit = max(1, min(int(limit), 500))
    bound: list[str] = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT job_id, input_json FROM intelligence_jobs
               WHERE status='queued'
               ORDER BY CASE action
                 WHEN 'execute_specialist_work' THEN 0
                 WHEN 'review_specialist_work' THEN 0
                 WHEN 'analyze_research_case' THEN 1
                 WHEN 'generate_analyst_brief' THEN 1
                 WHEN 'review_publication_safety' THEN 1
                 WHEN 'triage_finding' THEN 3
                 ELSE 2 END,
                 queued_at, job_id LIMIT ?""",
            (bounded_limit,),
        ).fetchall()
        for row in rows:
            job_id = str(row["job_id"])
            inputs = _decode(str(row["input_json"] or "{}"))
            if _clean(inputs.get("selected_model"), 200):
                continue
            inputs["selected_model"] = selected_model
            if fallback_models is not None or fallback_mode is not None:
                inputs["fallback_models"] = [
                    str(item).strip()[:200]
                    for item in (fallback_models or ())
                    if str(item).strip() and str(item).strip() != selected_model
                ][:8]
                inputs["fallback_mode"] = str(fallback_mode or "disabled").strip()[:40]
            elif not isinstance(inputs.get("fallback_models"), list) and not inputs.get("fallback_mode"):
                inputs["fallback_models"] = []
                inputs["fallback_mode"] = "disabled"
            input_json = _bounded_json(inputs, MAX_INPUT_BYTES, "job input")
            updated = connection.execute(
                "UPDATE intelligence_jobs SET input_json=?, updated_at=? WHERE job_id=? AND status='queued'",
                (input_json, now, job_id),
            )
            if updated.rowcount == 1:
                _event(
                    connection,
                    job_id,
                    "model_bound",
                    actor,
                    "Pinned a legacy queued job to the persisted selected model before claim.",
                    {"selected_model": selected_model},
                )
                bound.append(job_id)
        connection.commit()
    return {"status": "bound", "count": len(bound), "job_ids": bound, "selected_model": selected_model}


TRANSIENT_BRIDGE_ERROR_MARKERS = (
    "timeout",
    "timed out",
    "timeoutexpired",
    "429",
    "426",
    "adapter_eof",
    "reconnecting",
    "upstream",
    "loopback 500",
    "connection reset",
    "temporarily unavailable",
)


def recover_transient_jobs(
    *,
    limit: int = 10,
    max_attempts: int = 3,
    min_age_seconds: int = 300,
    actor: str = "bridge-recovery",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Requeue a bounded set of transient bridge failures.

    Only failures explicitly classified as ``bridge_failed`` and carrying a
    transport/quota marker are eligible. Invalid model output and other
    permanent failures remain visible for an operator decision.
    """
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(0, int(min_age_seconds)))
    cutoff_text = cutoff.isoformat().replace("+00:00", "Z")
    bounded_limit = max(1, min(int(limit), 100))
    attempts_limit = max(1, min(int(max_attempts), 10))
    recovered: list[str] = []
    skipped: list[dict[str, Any]] = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT job_id, attempt, error_code, error_message, updated_at
               FROM intelligence_jobs
               WHERE status='failed' AND error_code='bridge_failed'
                 AND attempt < ? AND updated_at <= ?
               ORDER BY updated_at ASC, job_id ASC LIMIT ?""",
            (attempts_limit, cutoff_text, bounded_limit),
        ).fetchall()
        for row in rows:
            job_id = str(row["job_id"])
            message = _clean(row["error_message"], 2000)
            normalized = message.lower()
            if not any(marker in normalized for marker in TRANSIENT_BRIDGE_ERROR_MARKERS):
                skipped.append({"job_id": job_id, "reason": "no_transient_transport_marker"})
                continue
            updated = connection.execute(
                """UPDATE intelligence_jobs
                   SET status='queued', provider='', started_at=NULL, completed_at=NULL,
                       updated_at=?, error_code='transient_recovered',
                       error_message=?
                   WHERE job_id=? AND status='failed' AND error_code='bridge_failed'""",
                (
                    now,
                    "Recovered a transient bridge failure; retry remains bound to the captured model.",
                    job_id,
                ),
            )
            if updated.rowcount != 1:
                continue
            _event(
                connection,
                job_id,
                "transient_recovered",
                actor,
                "A bounded recovery returned a transient bridge failure to the queue.",
                {"previous_error_code": "bridge_failed", "attempt": int(row["attempt"] or 0)},
            )
            recovered.append(job_id)
        connection.commit()
    return {
        "status": "recovered",
        "count": len(recovered),
        "job_ids": recovered,
        "skipped": skipped,
        "limit": bounded_limit,
        "max_attempts": attempts_limit,
    }


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
