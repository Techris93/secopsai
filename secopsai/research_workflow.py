"""Durable research workflow actions and human approval gates."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import urllib.parse
from datetime import datetime, timezone
from contextlib import closing
from typing import Any, Dict, List, Optional, Sequence

import soc_store
from secopsai.research_cases import add_case_note, get_case
from secopsai.research_intake import attach_intake_result, preview_package, run_package_intake


JOB_STATUSES = {"queued", "running", "awaiting_review", "awaiting_approval", "succeeded", "failed", "canceled", "expired"}
VERDICTS = {"credible", "likely", "inconclusive", "not_substantiated", "benign", "retracted"}
DISCLOSURE_STATUSES = {"draft", "approved", "sent", "acknowledged", "coordinating", "closed", "canceled"}
SANDBOX_STATUSES = {"pending_approval", "approved", "submitted", "completed", "rejected", "failed"}
SANDBOX_RESULT_TERMINAL_STATUSES = {"completed", "reported", "finished", "done", "success", "succeeded"}
SANDBOX_REPORT_HOSTS = {"tria.ge", "www.tria.ge", "api.tria.ge"}


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6).upper()}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, default: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _event(connection: Any, case_id: str, event_type: str, message: str, actor: str, data: Dict[str, Any]) -> None:
    connection.execute(
        "INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, event_type[:80], actor[:160], message[:4096], _json(data), soc_store.utc_now()),
    )


def _sandbox_text(value: Any, *, limit: int = 6000) -> str:
    """Bound and redact analyst-facing sandbox text before durable storage."""
    text = str(value or "").replace("\x00", " ").replace("\r", " ").strip()
    text = re.sub(
        r"(?i)\b(?:bearer\s+)?(?:api[_ -]?key|token|password|secret|authorization)\s*[:=]\s*[^\s,;]+",
        "[redacted credential]",
        text,
    )
    return text[:limit]


def _sandbox_report_url(value: Any) -> str:
    """Return a canonical public Tria.ge URL, never an arbitrary locator."""
    raw = str(value or "").strip()[:2000]
    if not raw:
        return ""
    parsed = urllib.parse.urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() != "https" or host not in SANDBOX_REPORT_HOSTS or not parsed.path.strip("/"):
        return ""
    # Query strings and fragments are not needed to identify a report and may
    # contain accidental credentials copied from a browser session.
    return urllib.parse.urlunsplit(("https", host, parsed.path.rstrip("/"), "", ""))


def _sandbox_records(value: Any, fields: Sequence[str], *, limit: int = 100) -> list[dict[str, Any]]:
    """Keep only the small, sanitized fields useful for evidence review."""
    if not isinstance(value, list):
        return []
    records: list[dict[str, Any]] = []
    for item in value[:limit]:
        if not isinstance(item, dict):
            continue
        record: dict[str, Any] = {}
        for field in fields:
            if field not in item or item[field] is None:
                continue
            if field in {"port", "score"}:
                try:
                    record[field] = float(item[field]) if "." in str(item[field]) else int(item[field])
                except (TypeError, ValueError):
                    continue
            else:
                record[field] = _sandbox_text(item[field], limit=500)
        if record:
            records.append(record)
    return records


def _sandbox_evidence_payload(request: Dict[str, Any], result: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Build one safe evidence payload or explain why it cannot be linked."""
    if not isinstance(result, dict):
        return None, "sandbox result is not an object"
    artifact_sha256 = str(request.get("artifact_sha256") or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256):
        return None, "sandbox request does not contain a valid artifact SHA-256"
    status = str(result.get("status") or "").strip().lower().replace("-", "_")
    if status not in SANDBOX_RESULT_TERMINAL_STATUSES:
        return None, "sandbox result is not in a terminal success state"
    submission_id = str(result.get("submission_id") or result.get("id") or "").strip()[:240]
    if not submission_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{3,239}", submission_id):
        return None, "sandbox result is missing a valid submission ID"
    report_url = _sandbox_report_url(result.get("report_url"))
    if not report_url:
        return None, "sandbox result is missing an approved Tria.ge report URL"
    behavior = _sandbox_text(result.get("behavior") or result.get("summary") or "")
    signatures = _sandbox_records(result.get("signatures"), ("name", "score"), limit=100)
    network = _sandbox_records(result.get("network"), ("domain", "ip", "port"), limit=100)
    files = _sandbox_records(result.get("files"), ("path", "sha256"), limit=100)
    if not behavior and not (signatures or network or files):
        return None, "sandbox result is missing a sanitized behavior summary"
    try:
        score = float(result["score"]) if result.get("score") is not None else None
        if score is not None and not 0 <= score <= 10:
            score = None
    except (TypeError, ValueError):
        score = None
    metadata = {
        "analysis_tool": "tria.ge",
        "analysis_tool_version": "api-v0",
        "sandbox_request_id": str(request["request_id"])[:40],
        "submission_id": submission_id,
        "report_url": report_url,
        "result_status": status,
        "score": score,
        "behavior": behavior,
        "signatures": signatures,
        "network": network,
        "files": files,
        "artifact_sha256": artifact_sha256,
        "execution_performed": True,
        "raw_result_retained": False,
    }
    summary = behavior or "External sandbox completed without a behavior summary."
    notes = (
        f"Provider=Tria.ge; submission={submission_id}; result_status={status}; "
        "execution=external_sandbox; raw_result_retained=false. "
        f"Observed summary: {summary}"
    )
    return {
        "evidence_type": "sandbox_analysis",
        "title": f"Tria.ge dynamic analysis {submission_id}",
        "locator": report_url,
        "sha256": artifact_sha256,
        "provenance": f"Tria.ge public analysis (sandbox request {request['request_id']})",
        "notes": _sandbox_text(notes, limit=12000),
        "metadata": metadata,
    }, None


def _update_sandbox_subjects(connection: Any, request: Dict[str, Any], evidence_id: str, actor: str) -> list[str]:
    """Mark only subjects that unambiguously match the analyzed artifact."""
    artifact_sha256 = str(request.get("artifact_sha256") or "").lower()
    artifact_rows = connection.execute(
        """SELECT lower(a.ecosystem) AS ecosystem, a.package_name, a.version
           FROM research_case_artifacts ca
           JOIN research_artifacts a ON a.artifact_id = ca.artifact_id
           WHERE ca.case_id = ? AND lower(a.sha256) = ?""",
        (request["case_id"], artifact_sha256),
    ).fetchall()
    identities = {
        (str(row["ecosystem"] or "").lower(), str(row["package_name"] or ""), str(row["version"] or ""))
        for row in artifact_rows
    }
    subjects = connection.execute(
        """SELECT subject_id, ecosystem, name, version, validation_state, metadata_json
           FROM research_subjects WHERE case_id = ? AND status = 'active'""",
        (request["case_id"],),
    ).fetchall()
    changed: list[str] = []
    reason = f"Confirmed by sandbox evidence {evidence_id} for artifact SHA-256 {artifact_sha256}."
    for subject in subjects:
        metadata = _decode(subject["metadata_json"], {})
        metadata_hash = str(metadata.get("artifact_sha256") or "").lower() if isinstance(metadata, dict) else ""
        identity = (str(subject["ecosystem"] or "").lower(), str(subject["name"] or ""), str(subject["version"] or ""))
        if metadata_hash != artifact_sha256 and identity not in identities:
            continue
        if str(subject["validation_state"] or "unverified") == "sandbox_confirmed":
            continue
        connection.execute(
            """UPDATE research_subjects
               SET validation_state = 'sandbox_confirmed', state_reason = ?, state_checked_at = ?
               WHERE subject_id = ?""",
            (reason, soc_store.utc_now(), subject["subject_id"]),
        )
        changed.append(str(subject["subject_id"]))
    if changed:
        _event(
            connection,
            request["case_id"],
            "sandbox_subjects_confirmed",
            f"Sandbox evidence confirmed {len(changed)} matching research subject(s).",
            actor,
            {"request_id": request["request_id"], "evidence_id": evidence_id, "subject_ids": changed},
        )
    return changed


def _materialize_sandbox_evidence(connection: Any, request: Dict[str, Any], result: Any, actor: str) -> Dict[str, Any]:
    """Idempotently link one completed sandbox result to case evidence."""
    payload, reason = _sandbox_evidence_payload(request, result)
    if payload is None:
        return {"attached": False, "changed": False, "reason": reason or "sandbox result could not be linked"}
    now = soc_store.utc_now()
    logical_key = f"{request['case_id']}|sandbox_analysis|{payload['locator']}|{payload['sha256']}"
    stable_id = f"EVD-{hashlib.sha256(logical_key.encode()).hexdigest()[:12].upper()}"
    fingerprint = hashlib.sha256(
        _json({"logical_key": logical_key, "request_id": request["request_id"], "submission_id": payload["metadata"]["submission_id"]}).encode()
    ).hexdigest()
    source_key = hashlib.sha256(f"tria.ge|{payload['locator']}".encode()).hexdigest()[:24]
    existing = connection.execute(
        """SELECT evidence_id, metadata_json, notes, title, provenance, occurrence_count, status
           FROM research_evidence
           WHERE case_id = ? AND evidence_type = 'sandbox_analysis'
             AND locator = ? AND sha256 = ? AND status = 'active'
           ORDER BY created_at LIMIT 1""",
        (request["case_id"], payload["locator"], payload["sha256"]),
    ).fetchone()
    evidence_id = str(existing["evidence_id"]) if existing else stable_id
    if existing is None:
        prior_id = connection.execute("SELECT status FROM research_evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if prior_id is not None:
            evidence_id = _id("EVD")
    existing_metadata = _decode(existing["metadata_json"], {}) if existing else {}
    merged_metadata = dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
    request_ids = merged_metadata.get("sandbox_request_ids") if isinstance(merged_metadata.get("sandbox_request_ids"), list) else []
    request_ids = [str(item)[:40] for item in request_ids if str(item)[:40]]
    request_ids = list(dict.fromkeys([*request_ids, str(request["request_id"])[:40]]))[-20:]
    merged_metadata.update(payload["metadata"])
    merged_metadata["sandbox_request_ids"] = request_ids
    changed = existing is None or any(
        [
            existing_metadata != merged_metadata,
            str(existing["notes"] if existing else "") != payload["notes"],
            str(existing["title"] if existing else "") != payload["title"],
            str(existing["provenance"] if existing else "") != payload["provenance"],
        ]
    )
    if existing is None:
        connection.execute(
            """INSERT OR IGNORE INTO research_evidence (
                evidence_id, case_id, evidence_type, title, locator, sha256,
                provenance, notes, status, collected_at, created_at, metadata_json,
                fingerprint, occurrence_count, first_observed_at, last_observed_at,
                independent_source_key
            ) VALUES (?, ?, 'sandbox_analysis', ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, 1, ?, ?, ?)""",
            (
                evidence_id,
                request["case_id"],
                payload["title"],
                payload["locator"],
                payload["sha256"],
                payload["provenance"],
                payload["notes"],
                now,
                now,
                _json(merged_metadata),
                fingerprint,
                now,
                now,
                source_key,
            ),
        )
        existing = connection.execute(
            "SELECT evidence_id, metadata_json, notes, title, provenance, occurrence_count, status FROM research_evidence WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()
    if existing is not None and str(existing["status"] or "") == "active" and changed:
        connection.execute(
            """UPDATE research_evidence
               SET title = ?, provenance = ?, notes = ?, metadata_json = ?,
                   fingerprint = ?, last_observed_at = ?, independent_source_key = ?
               WHERE evidence_id = ? AND status = 'active'""",
            (payload["title"], payload["provenance"], payload["notes"], _json(merged_metadata), fingerprint, now, source_key, evidence_id),
        )
    subject_ids = _update_sandbox_subjects(connection, request, evidence_id, actor)
    connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, request["case_id"]))
    return {"attached": True, "changed": changed, "evidence_id": evidence_id, "subject_ids": subject_ids, "reason": None}


def get_research_job(job_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_jobs WHERE job_id = ?", (str(job_id).strip().upper(),)).fetchone()
    if row is None:
        raise ValueError(f"research job not found: {job_id}")
    result = dict(row)
    result["config"] = _decode(result.pop("config_json"), {})
    result["result"] = _decode(result.pop("result_json"), {})
    return result


def list_research_jobs(*, case_id: Optional[str] = None, status: Optional[str] = None, limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    clauses: List[str] = []
    params: List[Any] = []
    if case_id:
        clauses.append("case_id = ?")
        params.append(case_id)
    if status:
        if status not in JOB_STATUSES:
            raise ValueError(f"invalid job status: {status}")
        clauses.append("status = ?")
        params.append(status)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(int(limit), 500)))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(f"SELECT * FROM research_jobs{where} ORDER BY updated_at DESC LIMIT ?", tuple(params)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["config"] = _decode(item.pop("config_json"), {})
        item["result"] = _decode(item.pop("result_json"), {})
        output.append(item)
    return output


def recover_stale_jobs(*, max_age_seconds: int = 3600, db_path: Optional[str] = None, actor: str = "research-worker") -> Dict[str, Any]:
    """Expire abandoned running jobs so a worker restart cannot leave them misleadingly active."""
    now = datetime.now(timezone.utc)
    cutoff = now.timestamp() - max(60, min(int(max_age_seconds), 7 * 24 * 3600))
    soc_store.init_db(db_path)
    expired: List[str] = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT job_id, case_id, updated_at FROM research_jobs WHERE status = 'running'").fetchall()
        for row in rows:
            raw = str(row["updated_at"] or "").replace("Z", "+00:00")
            try:
                timestamp = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc if "+" not in raw else datetime.fromisoformat(raw).tzinfo).timestamp()
            except ValueError:
                timestamp = 0
            if timestamp < cutoff:
                connection.execute("UPDATE research_jobs SET status = 'expired', completed_at = ?, updated_at = ?, error_code = 'stale_job', error_message = 'Job expired after worker inactivity.' WHERE job_id = ?", (soc_store.utc_now(), soc_store.utc_now(), row["job_id"]))
                _event(connection, str(row["case_id"]), "research_job_expired", f"Expired stale research job {row['job_id']}.", actor, {"job_id": row["job_id"]})
                expired.append(str(row["job_id"]))
        connection.commit()
    return {"expired": expired, "count": len(expired)}


def retry_research_job(job_id: str, *, actor: str = "operator", db_path: Optional[str] = None, fetcher: Any = None) -> Dict[str, Any]:
    job = get_research_job(job_id, db_path=db_path)
    if job["status"] not in {"failed", "expired", "canceled"}:
        raise ValueError("only failed, expired, or canceled jobs can be retried")
    config = job.get("config") or {}
    if job.get("action") not in {"package_intake", "package_intake_attach"}:
        raise ValueError("this job type is not retryable")
    return run_intake_job(case_id=job["case_id"], ecosystem=config.get("ecosystem", ""), package=config.get("package", ""), version=config.get("version", ""), attach=bool(config.get("attach")), requested_by=actor, db_path=db_path, fetcher=fetcher)


def cancel_research_job(job_id: str, *, actor: str = "operator", db_path: Optional[str] = None) -> Dict[str, Any]:
    job = get_research_job(job_id, db_path=db_path)
    if job["status"] in {"succeeded", "canceled", "expired"}:
        return job
    _set_job(job_id, status="canceled", error_code="operator_canceled", error_message="Canceled by operator.", db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        _event(connection, job["case_id"], "research_job_canceled", f"Canceled research job {job_id}.", actor, {"job_id": job_id})
        connection.commit()
    return get_research_job(job_id, db_path=db_path)


def create_research_job(*, case_id: str, action: str, config: Dict[str, Any], requested_by: str = "operator", db_path: Optional[str] = None) -> Dict[str, Any]:
    get_case(case_id, db_path=db_path)
    action = str(action or "").strip().lower()
    requested_by = str(requested_by or "operator").strip()[:160]
    stable = _json({"case_id": case_id, "action": action, "config": config})
    idempotency_key = hashlib.sha256(stable.encode()).hexdigest()
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        existing = connection.execute("SELECT job_id FROM research_jobs WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
        if existing:
            connection.commit()
            return get_research_job(str(existing["job_id"]), db_path=db_path)
        job_id = _id("JOB")
        connection.execute(
            """INSERT INTO research_jobs (job_id, case_id, action, status, idempotency_key, requested_by, attempt,
               queued_at, started_at, completed_at, updated_at, error_code, error_message, config_json, result_json)
               VALUES (?, ?, ?, 'queued', ?, ?, 0, ?, NULL, NULL, ?, NULL, NULL, ?, '{}')""",
            (job_id, case_id, action, idempotency_key, requested_by, now, now, _json(config)),
        )
        _event(connection, case_id, "research_job_queued", f"Queued research job {job_id}: {action}.", requested_by, {"job_id": job_id, "action": action})
        connection.commit()
    return get_research_job(job_id, db_path=db_path)


def _set_job(job_id: str, *, status: str, result: Optional[Dict[str, Any]] = None, error_code: Optional[str] = None, error_message: Optional[str] = None, db_path: Optional[str] = None) -> None:
    if status not in JOB_STATUSES:
        raise ValueError(f"invalid job status: {status}")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "UPDATE research_jobs SET status = ?, attempt = attempt + 1, started_at = COALESCE(started_at, ?), completed_at = ?, updated_at = ?, error_code = ?, error_message = ?, result_json = COALESCE(?, result_json) WHERE job_id = ?",
            (status, now, now if status in {"succeeded", "failed", "canceled", "expired", "awaiting_review", "awaiting_approval"} else None, now, error_code, (error_message or "")[:1000] if error_message else None, _json(result) if result is not None else None, job_id),
        )
        connection.commit()


def run_intake_job(*, case_id: str, ecosystem: str, package: str, version: str = "", attach: bool = False, requested_by: str = "operator", db_path: Optional[str] = None, fetcher: Any = None) -> Dict[str, Any]:
    action = "package_intake_attach" if attach else "package_intake"
    config = {"ecosystem": ecosystem, "package": package, "version": version, "attach": bool(attach)}
    job = create_research_job(case_id=case_id, action=action, config=config, requested_by=requested_by, db_path=db_path)
    if job["status"] in {"succeeded", "awaiting_review", "awaiting_approval"} and job.get("result"):
        return job
    _set_job(job["job_id"], status="running", db_path=db_path)
    try:
        result = run_package_intake(case_id=case_id, ecosystem=ecosystem, package=package, version=version, attach=attach, actor=requested_by, db_path=db_path, fetcher=fetcher)
        _set_job(job["job_id"], status="succeeded" if attach else "awaiting_review", result=result, db_path=db_path)
    except Exception as exc:
        _set_job(job["job_id"], status="failed", error_code="intake_failed", error_message=str(exc), db_path=db_path)
    return get_research_job(job["job_id"], db_path=db_path)


def attach_intake_job(job_id: str, *, actor: str = "operator", db_path: Optional[str] = None) -> Dict[str, Any]:
    job = get_research_job(job_id, db_path=db_path)
    if job["status"] == "succeeded" and job.get("result", {}).get("attached"):
        return job
    if job["status"] != "awaiting_review":
        raise ValueError("only an intake job awaiting review can be attached")
    try:
        result = dict(job.get("result") or {})
        result.update(attach_intake_result(result, db_path=db_path, actor=actor))
        _set_job(job_id, status="succeeded", result=result, db_path=db_path)
    except Exception as exc:
        _set_job(job_id, status="failed", error_code="attach_failed", error_message=str(exc), db_path=db_path)
    return get_research_job(job_id, db_path=db_path)


def build_evidence_matrix(case_id: str, *, persist: bool = True, actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    case = get_case(case_id, db_path=db_path)
    from secopsai.research_signal_analysis import collect_observations, deduplicate_observations
    evidence = [item for item in case.get("evidence", []) if item.get("status") == "active"]
    subjects = [item for item in case.get("subjects", []) if item.get("status") == "active"]
    claims = []
    subject_text = ", ".join(f"{item.get('ecosystem')}:{item.get('name')}@{item.get('version') or 'unknown'}" for item in subjects) or "the selected research subject"
    claims.append({"claim_id": "", "statement": f"The investigation concerns {subject_text}.", "confidence": 90 if subjects else 20, "status": "supported" if subjects else "missing", "supporting_evidence": [item["evidence_id"] for item in evidence if item.get("evidence_type") in {"registry_metadata", "source"}], "contradicting_evidence": [], "missing_evidence": [] if subjects else ["structured subject identity"], "limitations": []})
    artifact_evidence = [item for item in evidence if item.get("evidence_type") == "package_artifact"]
    claims.append({"claim_id": "", "statement": "The collected artifact is hash-identified and was not executed by SecOpsAI.", "confidence": 100 if artifact_evidence else 0, "status": "supported" if artifact_evidence else "missing", "supporting_evidence": [item["evidence_id"] for item in artifact_evidence], "contradicting_evidence": [], "missing_evidence": [] if artifact_evidence else ["quarantined package artifact"], "limitations": ["Hash identity does not prove intent or maliciousness."]})
    sandbox_evidence = [item for item in evidence if item.get("evidence_type") == "sandbox_analysis"]
    if sandbox_evidence:
        claims.append({
            "claim_id": "",
            "statement": "A sanitized external sandbox report is linked to the exact artifact hash; runtime observations remain provider-scoped evidence.",
            "confidence": 90,
            "status": "supported",
            "supporting_evidence": [item["evidence_id"] for item in sandbox_evidence],
            "contradicting_evidence": [],
            "missing_evidence": [],
            "limitations": ["The external sandbox result is sanitized and does not by itself establish victim impact or attribution."],
        })
    analysis_evidence = [item for item in evidence if item.get("evidence_type") == "static_analysis"]
    observations = []
    repeat_observations = 0
    for item in analysis_evidence:
        metadata = item.get("metadata") or {}
        if isinstance(metadata, dict):
            observations.extend(collect_observations(metadata))
        repeat_observations += max(0, int(item.get("occurrence_count") or 1) - 1)
    deduped_observations = deduplicate_observations(observations)
    indicator_count = deduped_observations["unique_observations"]
    total_observations = indicator_count + deduped_observations["repeat_observations"] + repeat_observations
    static_limitations = ["Static inspection cannot establish runtime behavior."]
    if not sandbox_evidence:
        static_limitations.append("Dynamic analysis is not configured by default.")
    claims.append({"claim_id": "", "statement": f"Bounded static inspection identified {indicator_count} unique observation(s) across {total_observations} observation record(s); observations are not proof of maliciousness.", "confidence": 80 if analysis_evidence else 0, "status": "supported" if analysis_evidence else "missing", "supporting_evidence": [item["evidence_id"] for item in analysis_evidence], "contradicting_evidence": [], "missing_evidence": [] if analysis_evidence else ["static intake analysis"], "limitations": static_limitations})
    for claim in claims:
        claim["claim_id"] = "CLM-" + hashlib.sha256(f"{case_id}|{claim['statement']}".encode()).hexdigest()[:12].upper()
    matrix = {"case_id": case_id, "generated_at": soc_store.utc_now(), "claims": claims, "summary": {"claims": len(claims), "supported": sum(item["status"] == "supported" for item in claims), "missing": sum(item["status"] == "missing" for item in claims), "unique_observations": indicator_count, "repeat_observations": deduped_observations["repeat_observations"] + repeat_observations, "sandbox_evidence": len(sandbox_evidence), "independent_sources": len({str(item.get("independent_source_key") or item.get("provenance") or item.get("evidence_id")) for item in evidence})}}
    if persist:
        now = soc_store.utc_now()
        with closing(soc_store.connect(db_path)) as connection:
            for claim in claims:
                connection.execute("""INSERT INTO research_claims (claim_id, case_id, statement, confidence, status, supporting_evidence_json, contradicting_evidence_json, missing_evidence_json, limitations_json, rationale, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(claim_id) DO UPDATE SET confidence=excluded.confidence, status=excluded.status, supporting_evidence_json=excluded.supporting_evidence_json, contradicting_evidence_json=excluded.contradicting_evidence_json, missing_evidence_json=excluded.missing_evidence_json, limitations_json=excluded.limitations_json, updated_at=excluded.updated_at""",
                    (claim["claim_id"], case_id, claim["statement"], claim["confidence"], claim["status"], _json(claim["supporting_evidence"]), _json(claim["contradicting_evidence"]), _json(claim["missing_evidence"]), _json(claim["limitations"]), "Generated from normalized evidence; analyst review required.", now, now))
            _event(connection, case_id, "evidence_matrix_generated", "Generated an evidence matrix for analyst review.", actor, {"claim_count": len(claims)})
            connection.commit()
    return matrix


def generate_analyst_brief(case_id: str, *, actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    """Generate a deterministic, minimized brief when no live AI provider is configured."""
    case = get_case(case_id, db_path=db_path)
    matrix = build_evidence_matrix(case_id, persist=True, actor=actor, db_path=db_path)
    indicators = []
    for item in case.get("evidence", []):
        if item.get("evidence_type") == "static_analysis":
            indicators.extend((item.get("metadata") or {}).get("indicators") or [])
    severity_counts: Dict[str, int] = {}
    for item in indicators:
        severity = str(item.get("severity") or "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    subject = (case.get("subjects") or [{}])[0]
    target = f"{subject.get('ecosystem')}:{subject.get('name')}@{subject.get('version') or 'unknown'}" if subject.get("name") else case.get("title")
    sandbox_evidence = [
        item for item in case.get("evidence", [])
        if item.get("evidence_type") == "sandbox_analysis" and item.get("status", "active") == "active"
    ]
    runtime_observation = (
        "A sanitized external sandbox result is linked; its provider-scoped runtime observations require analyst interpretation."
        if sandbox_evidence
        else "The artifact was not executed by SecOpsAI and dynamic behavior remains unverified."
    )
    brief = {
        "case_id": case_id,
        "provider": "deterministic",
        "generation_status": "complete",
        "executive_summary": f"SecOpsAI reviewed {target}. The collected evidence contains {len(indicators)} static indicator(s). This is an analyst brief, not an automatic maliciousness verdict.",
        "key_observations": [
            f"{matrix['summary']['supported']} of {matrix['summary']['claims']} evidence claims currently have supporting evidence.",
            f"Static indicator severity counts: {severity_counts or {'none': 0}}.",
            runtime_observation,
        ],
        "questions_for_analyst": [
            "Does the package behavior match its stated purpose and legitimate comparison package?",
            "Is the publisher, release timing, and distribution path credible?",
            "Is isolated dynamic analysis justified by an unanswered material question?",
        ],
        "limitations": ["The brief uses normalized metadata and static indicators only.", "Final credibility and publication decisions require a human analyst."],
        "raw_telemetry_sent": False,
    }
    with closing(soc_store.connect(db_path)) as connection:
        _event(connection, case_id, "analyst_brief_generated", "Generated a minimized deterministic analyst brief.", actor, {"provider": brief["provider"], "raw_telemetry_sent": False})
        connection.commit()
    return brief


def record_verdict(case_id: str, *, verdict: str, confidence: int, rationale: str, evidence_ids: Sequence[str], actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    if verdict not in VERDICTS:
        raise ValueError(f"invalid verdict: {verdict}")
    rationale = str(rationale or "").strip()
    if not rationale:
        raise ValueError("verdict rationale is required")
    confidence = max(0, min(int(confidence), 100))
    case = get_case(case_id, db_path=db_path)
    known = {item["evidence_id"] for item in case.get("evidence", [])}
    ids = [str(item).strip() for item in evidence_ids if str(item).strip()]
    if not ids or any(item not in known for item in ids):
        raise ValueError("verdict must reference at least one evidence record belonging to the case")
    verdict_id = _id("VRD")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("INSERT INTO research_verdicts (verdict_id, case_id, verdict, confidence, rationale, evidence_ids_json, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (verdict_id, case_id, verdict, confidence, rationale[:12000], _json(ids), actor[:160], now))
        next_status = "validation" if verdict in {"credible", "likely"} else "investigating"
        connection.execute("UPDATE research_cases SET confidence = ?, status = ?, updated_at = ? WHERE case_id = ?", (confidence, next_status, now, case_id))
        _event(connection, case_id, "analyst_verdict_recorded", f"Recorded analyst verdict: {verdict}.", actor, {"verdict_id": verdict_id, "verdict": verdict, "confidence": confidence, "evidence_ids": ids})
        connection.commit()
    return {"case": get_case(case_id, db_path=db_path), "verdict_id": verdict_id, "verdict": verdict, "confidence": confidence}


def publication_safety_check(case_id: str, *, actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    case = get_case(case_id, db_path=db_path)
    blockers: List[str] = []
    warnings: List[str] = []
    checks: Dict[str, str] = {}
    evidence = [item for item in case.get("evidence", []) if item.get("status") == "active"]
    if not evidence:
        blockers.append("at least one active evidence record is required")
        checks["evidence"] = "blocked"
    else:
        checks["evidence"] = "passed"
    if not case.get("subjects"):
        blockers.append("a structured research subject is required")
        checks["subject"] = "blocked"
    else:
        checks["subject"] = "passed"
    combined = " ".join([str(case.get("title") or ""), str(case.get("summary") or "")])
    if re.search(r"(?:^|\s)(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)", combined):
        blockers.append("internal or private network address appears in publication text")
        checks["private_network_data"] = "blocked"
    if re.search(r"(?:api[_ -]?key|password|secret|authorization)\s*[:=]", combined, re.I):
        blockers.append("credential-like text appears in publication text")
        checks["secret_scan"] = "blocked"
    if not any(item.get("evidence_type") == "static_analysis" for item in evidence):
        warnings.append("static analysis evidence has not been attached")
    if not any(item.get("evidence_type") == "sandbox_analysis" for item in evidence):
        warnings.append("no sandbox evidence is present; explain that dynamic analysis was not performed")
    checks.setdefault("private_network_data", "passed")
    checks.setdefault("secret_scan", "passed")
    from secopsai.research_reliability import publication_reliability_gate

    reliability = publication_reliability_gate(case_id, db_path=db_path)
    if reliability["ready"]:
        checks["execution_grounded_reliability"] = "passed"
    else:
        checks["execution_grounded_reliability"] = "blocked"
        blockers.extend(
            f"Reliability: {item}"
            for item in reliability["blockers"]
            if f"Reliability: {item}" not in blockers
        )
    checks["human_verdict"] = "review_required"
    status = "blocked" if blockers else "needs_approval"
    review_id = _id("PUB")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("INSERT INTO research_publication_reviews (review_id, case_id, status, blockers_json, warnings_json, checks_json, waivers_json, approved_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)", (review_id, case_id, status, _json(blockers), _json(warnings), _json(checks), "[]", now, now))
        _event(connection, case_id, "publication_safety_checked", f"Publication safety check completed: {status}.", actor, {"review_id": review_id, "blockers": blockers, "warnings": warnings})
        connection.commit()
    return {"review_id": review_id, "case_id": case_id, "status": status, "blockers": blockers, "warnings": warnings, "checks": checks, "reliability": reliability, "approval_required": True}


def approve_publication_review(case_id: str, *, review_id: str = "", actor: str = "publisher", waivers: Optional[Sequence[str]] = None, db_path: Optional[str] = None) -> Dict[str, Any]:
    case = get_case(case_id, db_path=db_path)
    reviews = case.get("publication_reviews") or []
    review = next((item for item in reviews if not review_id or item.get("review_id") == review_id), None)
    if review is None:
        raise ValueError("a publication safety review is required before approval")
    blockers = list(review.get("blockers") or [])
    waivers = [str(item).strip() for item in (waivers or []) if str(item).strip()]
    from secopsai.research_reliability import publication_reliability_gate

    reliability = publication_reliability_gate(case_id, db_path=db_path)
    if not reliability["ready"]:
        raise ValueError("publication reliability blockers remain: " + "; ".join(reliability["blockers"]))
    # Evidence, execution integrity, blind-review disagreement, originality,
    # completeness, and visual-QA failures are hard gates, not waivable notes.
    unresolved = [
        item for item in blockers
        if item.startswith("Reliability:") or item not in waivers
    ]
    if unresolved:
        raise ValueError("publication blockers remain: " + "; ".join(unresolved))
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("UPDATE research_publication_reviews SET status = 'approved', waivers_json = ?, approved_by = ?, updated_at = ? WHERE review_id = ?", (_json(waivers), actor[:160], now, review["review_id"]))
        connection.execute("UPDATE research_cases SET status = 'ready_to_publish', updated_at = ? WHERE case_id = ?", (now, case_id))
        _event(connection, case_id, "publication_approved", "Human publication approval recorded after safety review.", actor, {"review_id": review["review_id"], "waivers": waivers})
        connection.commit()
    return get_case(case_id, db_path=db_path)


def _package_scope(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    subjects = [
        item for item in (case.get("subjects") or [])
        if item.get("status", "active") == "active" and item.get("subject_type") in {"package", "extension", "publisher"}
    ]
    scope: List[Dict[str, Any]] = []
    for item in subjects:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        scope.append(
            {
                "ecosystem": item.get("ecosystem") or metadata.get("ecosystem") or "",
                "name": item.get("name") or metadata.get("package") or "",
                "version": item.get("version") or metadata.get("version") or "",
                "publisher": item.get("publisher") or metadata.get("publisher") or "",
                "artifact_sha256": metadata.get("artifact_sha256") or "",
                "metadata_url": metadata.get("metadata_url") or "",
                "artifact_url": metadata.get("artifact_url") or "",
                "contacts": metadata.get("contacts") if isinstance(metadata.get("contacts"), dict) else {},
            }
        )
    return scope


def _registry_contact(ecosystem: str) -> str:
    mapping = {
        "npm": "security@npmjs.com",
        "pypi": "security@pypi.org",
        "nuget": "support@nuget.org",
        "maven": "security@central.sonatype.com",
        "rubygems": "security@rubygems.org",
        "packagist": "contact@packagist.org",
        "go": "security@golang.org",
        "open-vsx": "security@eclipse.org",
    }
    return mapping.get(str(ecosystem or "").strip().lower(), "security@secopsai.dev")


def suggest_disclosure_draft(case_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Build a review-only disclosure draft from case subjects and intake metadata."""
    case = get_case(case_id, db_path=db_path)
    scope = _package_scope(case)
    package_lines: List[str] = []
    recipients: List[str] = []
    names: List[str] = []
    urls: List[str] = []
    hashes: List[str] = []
    ecosystems: List[str] = []
    for item in scope:
        label = " / ".join(part for part in [item.get("ecosystem"), item.get("name"), item.get("version")] if part)
        if label:
            package_lines.append(label)
        if item.get("ecosystem"):
            ecosystems.append(str(item["ecosystem"]))
        if item.get("publisher"):
            names.append(str(item["publisher"]))
        if item.get("artifact_sha256"):
            hashes.append(str(item["artifact_sha256"]))
        contacts = item.get("contacts") if isinstance(item.get("contacts"), dict) else {}
        recipients.extend(str(value) for value in contacts.get("emails") or [] if value)
        names.extend(str(value) for value in contacts.get("names") or [] if value)
        urls.extend(str(value) for value in contacts.get("urls") or [] if value)
        if not (contacts.get("emails") or []):
            if item.get("ecosystem"):
                recipients.append(_registry_contact(str(item["ecosystem"])))
    # Prefer maintainer emails, then registry security contacts.
    unique_recipients: List[str] = []
    seen = set()
    for item in recipients:
        key = item.casefold()
        if not item or key in seen or "\n" in item or len(item) > 320:
            continue
        seen.add(key)
        unique_recipients.append(item)
    if not unique_recipients:
        unique_recipients = ["security@secopsai.dev"]
    recipient = unique_recipients[0]
    package_summary = ", ".join(package_lines[:6]) or case.get("title") or "the investigated package"
    subject = f"Responsible disclosure: {package_summary}"[:240]
    hash_lines = "\n".join(f"- {value}" for value in hashes[:8]) or "- Artifact hash available on request through the agreed channel."
    contact_names = ", ".join(dict.fromkeys(names) )[:240] or "the package maintainer"
    body = (
        f"Hello {contact_names},\n\n"
        f"SecOpsAI Research is preparing a responsible disclosure regarding {package_summary}.\n\n"
        "We collected official registry metadata and preserved a hashed, quarantined artifact for defensive analysis. "
        "Package code was not installed or executed on analyst workstations.\n\n"
        f"Relevant artifact hashes:\n{hash_lines}\n\n"
        "We can share reproduction-safe details, affected versions, and recommended mitigations through this channel. "
        "Please confirm the preferred security contact and any embargo expectations.\n\n"
        "Regards,\nSecOpsAI Research\nresearch@secopsai.dev\n"
    )
    return {
        "case_id": case["case_id"],
        "recipient": recipient,
        "recipient_candidates": unique_recipients[:8],
        "subject": subject,
        "body": body[:30000],
        "affected_scope": scope,
        "package_summary": package_summary,
        "artifact_hashes": hashes[:12],
        "contact_names": list(dict.fromkeys(names))[:12],
        "contact_urls": list(dict.fromkeys(urls))[:12],
        "ecosystems": list(dict.fromkeys(ecosystems)),
        "requires_review": True,
        "auto_send": False,
        "notes": [
            "Recipient and message are suggested from registry metadata and case subjects.",
            "Sending remains a separate approval-gated action.",
            "Review names, emails, and package scope before delivery.",
        ],
    }


def prepare_disclosure(case_id: str, *, recipient: str = "", subject: str = "", body: str = "", embargo_until: Optional[str] = None, actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    case = get_case(case_id, db_path=db_path)
    suggestion = suggest_disclosure_draft(case_id, db_path=db_path)
    recipient = str(recipient or suggestion.get("recipient") or "").strip()
    if not recipient or "\n" in recipient or len(recipient) > 320:
        raise ValueError("a valid disclosure recipient is required")
    subject = (subject or suggestion.get("subject") or f"SecOpsAI responsible disclosure: {case['title']}").strip()[:240]
    body = (body or suggestion.get("body") or f"Hello,\n\nSecOpsAI is sharing a responsible disclosure regarding {case['title']}.\n\nWe have preserved evidence and can provide hashes and reproduction-safe details through the agreed channel.\n\nRegards,\nSecOpsAI Research").strip()[:30000]
    disclosure_id = _id("DSC")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "INSERT INTO research_disclosures (disclosure_id, case_id, status, recipient, subject, body, affected_scope_json, attachments_json, embargo_until, approved_by, sent_at, created_at, updated_at) VALUES (?, ?, 'draft', ?, ?, ?, ?, '[]', ?, NULL, NULL, ?, ?)",
            (
                disclosure_id,
                case_id,
                recipient,
                subject,
                body,
                _json({"subjects": suggestion.get("affected_scope") or [{"ecosystem": item.get("ecosystem"), "name": item.get("name"), "version": item.get("version")} for item in case.get("subjects", [])], "suggestion": {"recipient_candidates": suggestion.get("recipient_candidates"), "package_summary": suggestion.get("package_summary")}}),
                embargo_until,
                now,
                now,
            ),
        )
        _event(connection, case_id, "disclosure_prepared", "Prepared a responsible disclosure draft; sending remains approval-gated.", actor, {"disclosure_id": disclosure_id, "recipient": recipient, "auto_suggested": not bool(str(recipient or '').strip() and recipient != suggestion.get('recipient'))})
        connection.commit()
    result = get_disclosure(disclosure_id, db_path=db_path)
    result["suggestion"] = suggestion
    return result


def get_disclosure(disclosure_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_disclosures WHERE disclosure_id = ?", (disclosure_id,)).fetchone()
    if row is None:
        raise ValueError("disclosure not found")
    result = dict(row)
    for key in ("affected_scope_json", "attachments_json"):
        result[key[:-5]] = _decode(result.pop(key), [])
    return result


def set_disclosure_status(disclosure_id: str, status: str, *, actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    if status not in DISCLOSURE_STATUSES:
        raise ValueError("invalid disclosure status")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT case_id FROM research_disclosures WHERE disclosure_id = ?", (disclosure_id,)).fetchone()
        if row is None:
            raise ValueError("disclosure not found")
        approved_by = actor if status == "approved" else None
        sent_at = now if status == "sent" else None
        connection.execute("UPDATE research_disclosures SET status = ?, approved_by = COALESCE(?, approved_by), sent_at = COALESCE(?, sent_at), updated_at = ? WHERE disclosure_id = ?", (status, approved_by, sent_at, now, disclosure_id))
        _event(connection, str(row["case_id"]), "disclosure_status_changed", f"Disclosure moved to {status}.", actor, {"disclosure_id": disclosure_id, "status": status})
        connection.commit()
    return get_disclosure(disclosure_id, db_path=db_path)


def request_sandbox(case_id: str, *, artifact_sha256: str, justification: str, behaviors: Sequence[str], provider: str = "manual-result-import", actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", str(artifact_sha256 or "")):
        raise ValueError("sandbox request requires a valid artifact SHA-256")
    if not str(justification or "").strip():
        raise ValueError("sandbox justification is required")
    if provider not in {"manual-result-import", "disabled", "external-isolated-runner", "tria.ge"}:
        raise ValueError("unsupported sandbox provider")
    request_id = _id("SBX")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("INSERT INTO research_sandbox_requests (request_id, case_id, artifact_sha256, justification, requested_behaviors_json, status, provider, approved_by, result_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'pending_approval', ?, NULL, '{}', ?, ?)", (request_id, case_id, artifact_sha256.lower(), str(justification)[:12000], _json([str(item)[:160] for item in behaviors[:20]]), provider, now, now))
        _event(connection, case_id, "sandbox_requested", "Requested dynamic analysis; execution requires explicit approval and an isolated provider.", actor, {"request_id": request_id, "provider": provider})
        connection.commit()
    return get_sandbox_request(request_id, db_path=db_path)


def get_sandbox_request(request_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_sandbox_requests WHERE request_id = ?", (request_id,)).fetchone()
        linked_evidence_id = None
        if row is not None:
            for evidence_row in connection.execute(
                "SELECT evidence_id, metadata_json FROM research_evidence WHERE case_id = ? AND evidence_type = 'sandbox_analysis' AND status = 'active' ORDER BY created_at DESC",
                (row["case_id"],),
            ).fetchall():
                metadata = _decode(evidence_row["metadata_json"], {})
                request_ids = metadata.get("sandbox_request_ids") if isinstance(metadata, dict) else []
                if (isinstance(metadata, dict) and metadata.get("sandbox_request_id") == request_id) or request_id in (request_ids if isinstance(request_ids, list) else []):
                    linked_evidence_id = str(evidence_row["evidence_id"])
                    break
    if row is None:
        raise ValueError("sandbox request not found")
    result = dict(row)
    result["requested_behaviors"] = _decode(result.pop("requested_behaviors_json"), [])
    result["result"] = _decode(result.pop("result_json"), {})
    result["sandbox_evidence_id"] = linked_evidence_id
    result["sandbox_evidence_attached"] = bool(linked_evidence_id)
    return result


def set_sandbox_status(request_id: str, status: str, *, actor: str = "analyst", result: Optional[Dict[str, Any]] = None, db_path: Optional[str] = None, _approval_acknowledged: bool = False) -> Dict[str, Any]:
    if status not in SANDBOX_STATUSES:
        raise ValueError("invalid sandbox status")
    if status == "approved" and not _approval_acknowledged:
        raise ValueError("sandbox approval requires explicit public-submission acknowledgment")
    current = get_sandbox_request(request_id, db_path=db_path)
    if status in {"submitted", "completed"} and current["status"] != "approved" and status != "completed":
        raise ValueError("sandbox request must be approved before submission")
    now = soc_store.utc_now()
    safe_result = result or {}
    materialization: Dict[str, Any] = {"attached": False, "changed": False, "reason": None}
    effective_result = result if result is not None else current.get("result")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("UPDATE research_sandbox_requests SET status = ?, approved_by = CASE WHEN ? = 'approved' THEN ? ELSE approved_by END, result_json = CASE WHEN ? IS NULL THEN result_json ELSE ? END, updated_at = ? WHERE request_id = ?", (status, status, actor, _json(safe_result) if result is not None else None, _json(safe_result) if result is not None else None, now, request_id))
        if status == "completed":
            materialization = _materialize_sandbox_evidence(connection, current, effective_result, actor)
        status_event = {"request_id": request_id, "status": status}
        if materialization.get("evidence_id"):
            status_event.update({"sandbox_evidence_id": materialization["evidence_id"], "sandbox_evidence_attached": True})
        _event(connection, current["case_id"], "sandbox_status_changed", f"Sandbox request moved to {status}.", actor, status_event)
        if status == "completed":
            if materialization.get("attached"):
                if materialization.get("changed"):
                    _event(
                        connection,
                        current["case_id"],
                        "sandbox_evidence_materialized",
                        "Completed sandbox result was linked to case evidence automatically.",
                        actor,
                        {
                            "request_id": request_id,
                            "evidence_id": materialization.get("evidence_id"),
                            "subject_ids": materialization.get("subject_ids", []),
                        },
                    )
            else:
                _event(
                    connection,
                    current["case_id"],
                    "sandbox_evidence_pending",
                    "Sandbox result was marked completed but could not be linked to evidence yet.",
                    actor,
                    {"request_id": request_id, "reason": materialization.get("reason")},
                )
        connection.commit()
    updated = get_sandbox_request(request_id, db_path=db_path)
    updated["sandbox_evidence"] = materialization
    return updated


def materialize_completed_sandbox_evidence(
    *,
    case_id: Optional[str] = None,
    limit: int = 500,
    actor: str = "sandbox-evidence-reconciler",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Backfill evidence for completed sandbox rows created before auto-linking.

    This is an explicit, bounded repair action rather than a read-side
    mutation. It uses the same idempotent materializer as future completions.
    """
    soc_store.init_db(db_path)
    bounded_limit = max(1, min(int(limit), 5000))
    clauses = ["status = 'completed'"]
    params: list[Any] = []
    if case_id:
        clauses.append("case_id = ?")
        params.append(str(case_id).strip().upper())
    params.append(bounded_limit)
    outcomes: list[Dict[str, Any]] = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"SELECT * FROM research_sandbox_requests WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        for row in rows:
            request = dict(row)
            request["result"] = _decode(request.pop("result_json"), {})
            materialization = _materialize_sandbox_evidence(connection, request, request.get("result"), actor)
            if materialization.get("attached") and materialization.get("changed"):
                _event(
                    connection,
                    request["case_id"],
                    "sandbox_evidence_materialized",
                    "Completed sandbox result was linked to case evidence during reconciliation.",
                    actor,
                    {
                        "request_id": request["request_id"],
                        "evidence_id": materialization.get("evidence_id"),
                        "subject_ids": materialization.get("subject_ids", []),
                    },
                )
            outcomes.append(
                {
                    "request_id": request["request_id"],
                    "case_id": request["case_id"],
                    **materialization,
                }
            )
        connection.commit()
    return {
        "processed": len(outcomes),
        "attached": sum(1 for item in outcomes if item.get("attached") and item.get("changed")),
        "already_linked": sum(1 for item in outcomes if item.get("attached") and not item.get("changed")),
        "unlinked": sum(1 for item in outcomes if not item.get("attached")),
        "results": outcomes,
    }


def approve_sandbox_submission(request_id: str, *, actor: str = "reviewer", public_submission_acknowledged: bool = False, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Approve a sandbox request only after the public-data warning is accepted."""
    if not public_submission_acknowledged:
        raise ValueError("public sandbox submission acknowledgment is required")
    current = get_sandbox_request(request_id, db_path=db_path)
    if current["status"] != "pending_approval":
        raise ValueError("only pending sandbox requests can be approved")
    return set_sandbox_status(request_id, "approved", actor=actor, db_path=db_path, _approval_acknowledged=True)


def record_manual_sandbox_export(
    request_id: str,
    *,
    filename: str,
    size_bytes: int,
    actor: str = "analyst",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Record that an approved sample was prepared for manual submission.

    Local paths are deliberately excluded from the durable record. The event
    proves which approved hash was handed off, when, and by whom without
    disclosing the quarantine layout to browser or model consumers.
    """
    current = get_sandbox_request(request_id, db_path=db_path)
    if current["status"] != "approved":
        raise ValueError("manual sandbox export requires an approved request")
    now = soc_store.utc_now()
    safe_export = {
        "prepared_at": now,
        "filename": str(filename or "sample.bin")[:240],
        "size_bytes": max(0, int(size_bytes)),
        "sha256": current["artifact_sha256"],
        "public_submission": True,
    }
    result = current.get("result") if isinstance(current.get("result"), dict) else {}
    exports = result.get("manual_exports") if isinstance(result.get("manual_exports"), list) else []
    result = {**result, "manual_exports": [*exports[-9:], safe_export]}
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "UPDATE research_sandbox_requests SET result_json = ?, updated_at = ? WHERE request_id = ?",
            (_json(result), now, request_id),
        )
        _event(
            connection,
            current["case_id"],
            "sandbox_manual_export_prepared",
            "Prepared the approved, hash-verified artifact for manual public sandbox submission.",
            actor,
            {"request_id": request_id, **safe_export},
        )
        connection.commit()
    return get_sandbox_request(request_id, db_path=db_path)
