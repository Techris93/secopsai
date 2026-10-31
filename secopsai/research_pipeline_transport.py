"""Deliver investigation model jobs to Core; the ledger keeps the results.

A pipeline queues its analyses in the worker's own ledger, which the operator's
bridge cannot reach: it claims work from Core. Only runs holding an investigation
slot are delivered, so abandoned jobs in the ledger never spend model quota.
"""
from __future__ import annotations

import json
import re

import soc_store
from secopsai.research_operation_store import append, canonical, digest, read_connection, records, transaction
from secopsai.sqlite_writer_lock import sqlite_writer_lock

ACTOR = "hosted-pipeline-transport"
MAX_JOBS = 10  # Core's results call takes ten job ids
MAX_ROWS = 60  # enough for every slot's three jobs in one pass, with room for retries
MAX_PAYLOAD_BYTES = 60000
PERMANENT_HTTP = {409, 413, 422}
ROUTING_FIELDS = ("selected_model", "fallback_models", "fallback_mode")
# (longest list, longest string) tried in turn until the request fits.
CONTEXT_LIMITS = ((100, 4000), (50, 2000), (25, 1000), (10, 500), (5, 250))


def sync_hosted(client, *, db_path=None) -> dict:
    if not getattr(client, "enabled", False):
        return {"status": "disabled"}
    from secopsai.core_edge_client import CoreEdgeHTTPError
    from secopsai.research_pipeline import AI_STEPS

    marks = ",".join("?" for _ in AI_STEPS)
    with read_connection(db_path) as conn:
        rows = [dict(row) for row in conn.execute(f"""SELECT j.job_id,j.action,j.target_id,j.status,j.input_json
          FROM intelligence_jobs j
          WHERE j.action IN ({marks}) AND (
            (j.status='canceled' AND EXISTS (SELECT 1 FROM research_operation_records r WHERE r.kind='investigation_job_delivery' AND r.case_id=j.job_id)
             AND NOT EXISTS (SELECT 1 FROM research_operation_records r WHERE r.kind='investigation_job_canceled' AND r.case_id=j.job_id))
            OR ((j.status='queued' OR (j.status='running' AND j.provider='hosted_core_bridge')) AND EXISTS (
              SELECT 1 FROM investigation_autopilot_runs a WHERE a.pipeline_id=json_extract(j.input_json,'$.pipeline_id')
                AND a.status IN ('collecting','analyzing','awaiting_model','running'))))
          ORDER BY j.queued_at,j.job_id LIMIT {MAX_ROWS}""", AI_STEPS)]
    delivered, applied, failed, canceled = 0, 0, 0, 0
    reasons: dict[str, int] = {}
    pending = {}
    for job in rows:
        receipt = records("investigation_job_delivery", case_id=job["job_id"], db_path=db_path, limit=1)
        if job["status"] == "canceled":
            remote_id = receipt[0]["payload"]["remote_job_id"]
            if remote_id in client.cancel_assistant_jobs([remote_id]).get("canceled", []):
                append("investigation_job_canceled", {"remote_job_id": remote_id}, actor=ACTOR, case_id=job["job_id"], db_path=db_path)
                canceled += 1
            continue
        if not receipt:
            outbox = records("investigation_job_outbox", case_id=job["job_id"], db_path=db_path, limit=1)
            if not outbox:
                payload = _payload(job, db_path=db_path)
                if len(canonical(payload).encode()) > MAX_PAYLOAD_BYTES:
                    _fail(job, "investigation_context_exceeds_budget", db_path=db_path)
                    failed += 1
                    reasons["context_exceeds_budget"] = reasons.get("context_exceeds_budget", 0) + 1
                    continue
                # Persist before sending: a lost response must retry the same request.
                outbox = [append("investigation_job_outbox", payload, actor=ACTOR, case_id=job["job_id"], db_path=db_path)]
            try:
                response = client.queue_assistant_job(outbox[0]["payload"])
            except CoreEdgeHTTPError as error:
                if error.status not in PERMANENT_HTTP:
                    raise
                _fail(job, "investigation_delivery_rejected", db_path=db_path)
                failed += 1
                reason = f"http_{error.status}_{error.error_code}"
                reasons[reason] = reasons.get(reason, 0) + 1
                continue
            remote_id = (response.get("job") or {}).get("job_id")
            if not isinstance(remote_id, str) or not re.fullmatch(r"AIJ-[A-F0-9]{16}", remote_id):
                raise ValueError("hosted queue did not return a job identity")
            receipt = [append("investigation_job_delivery", {"remote_job_id": remote_id, "payload_hash": digest(outbox[0]["payload"])},
                              actor=ACTOR, case_id=job["job_id"], db_path=db_path)]
            delivered += 1
        pending[receipt[0]["payload"]["remote_job_id"]] = job
    remote_ids = list(pending)
    for start in range(0, len(remote_ids), MAX_JOBS):
        for item in client.assistant_results(remote_ids[start:start + MAX_JOBS]).get("results", []):
            job = pending.get(item.get("job_id")) if isinstance(item, dict) else None
            if job is None or item.get("status") not in {"succeeded", "failed", "canceled"}:
                continue
            pending.pop(item["job_id"])
            if item["status"] == "succeeded" and _complete(job, item, db_path=db_path):
                applied += 1
            else:
                if item["status"] != "succeeded":
                    _fail(job, "hosted_bridge_failed", db_path=db_path)
                failed += 1
                reason = "invalid_answer" if item["status"] == "succeeded" else "bridge_" + item["status"]
                reasons[reason] = reasons.get(reason, 0) + 1
    return {"status": "ok", "delivered": delivered, "applied": applied, "failed": failed, "canceled": canceled, "waiting": len(pending), "reasons": reasons}


def _bounded(value, longest_list: int, longest_string: int):
    if isinstance(value, dict):
        return {key: _bounded(item, longest_list, longest_string) for key, item in value.items()}
    if isinstance(value, list):
        return [_bounded(item, longest_list, longest_string) for item in value[:longest_list]]
    return value[:longest_string] if isinstance(value, str) else value


def _fit(payload: dict) -> dict:
    """Shrink a request's evidence until it fits Core's limit, and say that it did."""
    request = payload["inputs"]["assistant_request"]
    full = request["context"]
    for longest_list, longest_string in CONTEXT_LIMITS:
        if len(canonical(payload).encode()) <= MAX_PAYLOAD_BYTES:
            break
        request["context"] = {**_bounded(full, longest_list, longest_string), "evidence_coverage": {
            "complete": False, "reason": "transport limits shortened the supplied context; name what is missing rather than assuming it"}}
    return payload


def _payload(job: dict, *, db_path=None) -> dict:
    from secopsai.intelligence import prepare_bridge_request

    inputs = json.loads(job["input_json"])
    inputs["target_id"] = job["target_id"]
    request = prepare_bridge_request(job["action"], inputs, db_path=db_path)
    request["instructions"] += " Return no more than 48 KB of structured output."
    if not inputs.get("selected_model"):
        # Unbound: the bridge applies the operator's current routing at claim.
        inputs = {key: value for key, value in inputs.items() if key not in ROUTING_FIELDS}
    return _fit({"action": job["action"], "target_id": job["target_id"], "idempotency_key": "assistant:pipeline:" + job["job_id"],
                 "inputs": {**inputs, "assistant_request": request}})


def _mark_running(job_id: str, *, db_path=None) -> None:
    now = soc_store.utc_now()
    with sqlite_writer_lock(db_path):
        with transaction(db_path) as conn:
            conn.execute("""UPDATE intelligence_jobs SET status='running',provider='hosted_core_bridge',started_at=COALESCE(started_at,?),updated_at=?
              WHERE job_id=? AND status='queued'""", (now, now, job_id))


def _complete(job: dict, item: dict, *, db_path=None) -> bool:
    from secopsai.decision_contracts import DecisionError
    from secopsai.intelligence import validate_bridge_result
    from secopsai.intelligence_jobs import complete_job

    provider = item.get("provider") or "hosted_core_bridge"
    _mark_running(job["job_id"], db_path=db_path)
    try:
        # complete_job re-checks the cited evidence against the ledger, so a
        # result that no longer matches the case fails closed.
        complete_job(job["job_id"], result=validate_bridge_result(job["action"], item.get("result"), provider=provider),
                     actor=ACTOR, provider=provider, db_path=db_path)
    except (ValueError, TypeError, KeyError, DecisionError):
        _fail(job, "invalid_hosted_result", db_path=db_path)
        return False
    return True


def _fail(job: dict, code: str, *, db_path=None) -> None:
    from secopsai.intelligence_jobs import fail_job

    _mark_running(job["job_id"], db_path=db_path)
    fail_job(job["job_id"], error_code=code, error_message=code.replace("_", " "), actor=ACTOR, db_path=db_path)
