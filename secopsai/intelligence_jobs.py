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
ACTIVE_STATUSES = {"queued", "running"}
FINAL_STATUSES = {"succeeded", "failed", "canceled"}
MAX_INPUT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 512 * 1024


def enqueue_job(
    *,
    action: str,
    target_id: str = "",
    inputs: dict[str, Any] | None = None,
    requested_by: str = "operator",
    idempotency_key: str = "",
    db_path: str | None = None,
) -> dict[str, Any]:
    action = _required(action, "action", 80)
    target_id = _clean(target_id, 240)
    requested_by = _required(requested_by, "requested_by", 160)
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
            VALUES (?, ?, ?, 'queued', ?, ?, 0, '', ?, NULL, NULL, ?, NULL, NULL, ?, '{}')""",
            (job_id, action, target_id, requested_by, idempotency_key, now, now, input_json),
        )
        _event(connection, job_id, "queued", requested_by, "Intelligence job queued.", {"action": action})
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
            "SELECT job_id FROM intelligence_jobs WHERE status = 'queued' ORDER BY queued_at, job_id LIMIT 1"
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
    db_path: str | None = None,
) -> dict[str, Any]:
    result_json = _bounded_json(result, MAX_RESULT_BYTES, "job result")
    return _finish(job_id, "succeeded", actor=actor, result_json=result_json, db_path=db_path)


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
    return [_row(row) for row in rows]


def job_counts(*, db_path: str | None = None) -> dict[str, int]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT status, COUNT(*) AS count FROM intelligence_jobs GROUP BY status").fetchall()
    return {str(row["status"]): int(row["count"]) for row in rows}


def _finish(
    job_id: str,
    status: str,
    *,
    actor: str,
    result_json: str = "{}",
    error_code: str | None = None,
    error_message: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    job_id = _required(job_id, "job_id", 80)
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT status FROM intelligence_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise ValueError(f"intelligence job not found: {job_id}")
        if str(row["status"]) != "running":
            raise ValueError("only a running intelligence job can be completed or failed")
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
    return get_job(job_id, db_path=db_path)


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


def _row(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["schema_version"] = SCHEMA_VERSION
    result["input"] = _decode(str(result.pop("input_json", "{}")))
    result["result"] = _decode(str(result.pop("result_json", "{}")))
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
