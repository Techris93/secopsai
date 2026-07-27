"""Resumable, approval-gated package research investigation pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from contextlib import closing
from typing import Any, Dict, Iterable, Optional

import soc_store
from secopsai.intelligence_jobs import cancel_job, enqueue_job, get_job
from secopsai.research_analysis import compare_intakes
from secopsai.research_cases import add_evidence, get_case
from secopsai.research_intake import (
    IntakeError,
    attach_intake_result,
    collect_package_intake,
    validate_quarantined_intake,
)
from secopsai.research_workflow import (
    build_evidence_matrix,
    publication_safety_check,
    record_verdict,
)


SCHEMA_VERSION = "secopsai.research.investigation-pipeline.v1"
PIPELINE_STATUSES = {
    "running",
    "awaiting_ai",
    "awaiting_input",
    "awaiting_review",
    "succeeded",
    "failed",
    "canceled",
}
STEP_STATUSES = {
    "pending",
    "running",
    "queued",
    "awaiting_input",
    "succeeded",
    "failed",
    "skipped",
}
REVIEW_STATUSES = {"pending", "applying", "accepted", "rejected", "superseded"}
ACTIVE_PIPELINE_STATUSES = {"running", "awaiting_ai", "awaiting_input", "awaiting_review"}
STEP_ORDER = {
    "validate_subject": 10,
    "collect_subject": 20,
    "collect_reference": 30,
    "compare_packages": 40,
    "evidence_matrix": 50,
    "analyze_research_case": 60,
    "generate_analyst_brief": 70,
    "review_publication_safety": 80,
    "human_review": 90,
}
AI_STEPS = ("analyze_research_case", "generate_analyst_brief", "review_publication_safety")


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, default: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _clean(value: Any, limit: int = 4000) -> str:
    return str(value or "").strip()[:limit]


def _event(connection: Any, case_id: str, event_type: str, message: str, actor: str, data: Dict[str, Any]) -> None:
    connection.execute(
        "INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, event_type[:80], actor[:160], message[:4096], _json(data), soc_store.utc_now()),
    )


def _step_id(pipeline_id: str, step_key: str) -> str:
    digest = hashlib.sha256(f"{pipeline_id}|{step_key}".encode()).hexdigest()[:16].upper()
    return f"PST-{digest}"


def _review_id(pipeline_id: str, source_key: str) -> str:
    digest = hashlib.sha256(f"{pipeline_id}|{source_key}".encode()).hexdigest()[:16].upper()
    return f"RVI-{digest}"


def _ensure_steps(connection: Any, pipeline_id: str) -> None:
    now = soc_store.utc_now()
    for step_key, order in STEP_ORDER.items():
        connection.execute(
            """INSERT OR IGNORE INTO research_pipeline_steps
            (step_id, pipeline_id, step_key, step_order, status, intelligence_job_id,
             result_json, error_code, error_message, started_at, completed_at, updated_at)
            VALUES (?, ?, ?, ?, 'pending', NULL, '{}', NULL, NULL, NULL, NULL, ?)""",
            (_step_id(pipeline_id, step_key), pipeline_id, step_key, order, now),
        )


def _set_step(
    pipeline_id: str,
    step_key: str,
    status: str,
    *,
    result: Optional[Dict[str, Any]] = None,
    intelligence_job_id: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    if status not in STEP_STATUSES:
        raise ValueError(f"invalid pipeline step status: {status}")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE research_pipeline_steps SET status = ?,
               intelligence_job_id = COALESCE(?, intelligence_job_id),
               result_json = COALESCE(?, result_json), error_code = ?, error_message = ?,
               started_at = CASE WHEN ? IN ('running', 'queued') THEN COALESCE(started_at, ?) ELSE started_at END,
               completed_at = CASE WHEN ? IN ('succeeded', 'failed', 'skipped', 'awaiting_input') THEN ? ELSE NULL END,
               updated_at = ? WHERE pipeline_id = ? AND step_key = ?""",
            (
                status,
                intelligence_job_id,
                _json(result) if result is not None else None,
                error_code,
                _clean(error_message, 2000) or None,
                status,
                now,
                status,
                now,
                now,
                pipeline_id,
                step_key,
            ),
        )
        connection.commit()


def _set_pipeline(
    pipeline_id: str,
    status: str,
    *,
    current_step: str,
    summary: Optional[Dict[str, Any]] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    if status not in PIPELINE_STATUSES:
        raise ValueError(f"invalid pipeline status: {status}")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE research_pipeline_runs SET status = ?, current_step = ?,
               summary_json = COALESCE(?, summary_json), error_code = ?, error_message = ?,
               started_at = COALESCE(started_at, ?),
               completed_at = CASE WHEN ? IN ('succeeded', 'failed', 'canceled') THEN ? ELSE NULL END,
               updated_at = ? WHERE pipeline_id = ?""",
            (
                status,
                current_step,
                _json(summary) if summary is not None else None,
                error_code,
                _clean(error_message, 2000) or None,
                now,
                status,
                now,
                now,
                pipeline_id,
            ),
        )
        connection.commit()


def _step_result(pipeline: Dict[str, Any], step_key: str) -> Dict[str, Any]:
    for step in pipeline.get("steps", []):
        if step.get("step_key") == step_key:
            return dict(step.get("result") or {})
    return {}


def get_pipeline(pipeline_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    pipeline_id = _clean(pipeline_id, 40).upper()
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_pipeline_runs WHERE pipeline_id = ?", (pipeline_id,)).fetchone()
        if row is None:
            raise ValueError(f"research pipeline not found: {pipeline_id}")
        steps = connection.execute(
            "SELECT * FROM research_pipeline_steps WHERE pipeline_id = ? ORDER BY step_order", (pipeline_id,)
        ).fetchall()
        review_items = connection.execute(
            "SELECT * FROM research_review_items WHERE pipeline_id = ? ORDER BY created_at, item_id", (pipeline_id,)
        ).fetchall()
    result = dict(row)
    result["config"] = _decode(result.pop("config_json"), {})
    result["summary"] = _decode(result.pop("summary_json"), {})
    result["steps"] = []
    for raw in steps:
        item = dict(raw)
        item["result"] = _decode(item.pop("result_json"), {})
        if item.get("intelligence_job_id"):
            try:
                item["intelligence_job"] = get_job(item["intelligence_job_id"], db_path=db_path)
            except ValueError:
                item["intelligence_job"] = None
        result["steps"].append(item)
    result["review_items"] = []
    for raw in review_items:
        item = dict(raw)
        item["evidence_refs"] = _decode(item.pop("evidence_refs_json"), [])
        item["metadata"] = _decode(item.pop("metadata_json"), {})
        result["review_items"].append(item)
    result["review_summary"] = {
        status: sum(item["status"] == status for item in result["review_items"])
        for status in REVIEW_STATUSES
    }
    return result


def list_pipelines(*, case_id: str = "", limit: int = 50, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    soc_store.init_db(db_path)
    params: list[Any] = []
    where = ""
    if case_id:
        where = " WHERE case_id = ?"
        params.append(_clean(case_id, 32).upper())
    params.append(max(1, min(int(limit), 200)))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"SELECT pipeline_id FROM research_pipeline_runs{where} ORDER BY updated_at DESC LIMIT ?", tuple(params)
        ).fetchall()
    return [get_pipeline(str(row["pipeline_id"]), db_path=db_path) for row in rows]


def _target_from_case(
    case: Dict[str, Any],
    *,
    reference_ecosystem: str = "",
    reference_package: str = "",
    reference_version: str = "",
) -> Dict[str, Any]:
    subjects = [
        item for item in case.get("subjects", [])
        if item.get("status") == "active" and item.get("subject_type") in {"package", "extension"}
    ]
    if not subjects:
        raise ValueError("the case needs an active package or extension subject before the pipeline can run")
    suspect = subjects[0]
    config_reference = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    subject_metadata = suspect.get("metadata") if isinstance(suspect.get("metadata"), dict) else {}
    package = _clean(
        reference_package
        or subject_metadata.get("reference_identifier")
        or subject_metadata.get("legitimate_package")
        or config_reference.get("reference_identifier")
        or config_reference.get("legitimate_package"),
        512,
    )
    ecosystem = _clean(reference_ecosystem or suspect.get("ecosystem"), 80).lower()
    version = _clean(reference_version, 160)
    if not package:
        for candidate in subjects[1:]:
            metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
            if str(metadata.get("comparison_role") or metadata.get("role") or "").lower() in {"reference", "legitimate"}:
                package = _clean(candidate.get("name"), 512)
                ecosystem = _clean(candidate.get("ecosystem"), 80).lower()
                version = _clean(candidate.get("version"), 160)
                break
    suspect_target = {
        "ecosystem": _clean(suspect.get("ecosystem"), 80).lower(),
        "package": _clean(suspect.get("name"), 512),
        "version": _clean(suspect.get("version"), 160),
    }
    reference = {"ecosystem": ecosystem, "package": package, "version": version} if package else None
    if reference and all(reference.get(key) == suspect_target.get(key) for key in ("ecosystem", "package", "version")):
        reference = None
    return {"suspect": suspect_target, "reference": reference}


def start_investigation_pipeline(
    case_id: str,
    *,
    reference_ecosystem: str = "",
    reference_package: str = "",
    reference_version: str = "",
    actor: str = "dashboard-operator",
    db_path: Optional[str] = None,
    fetcher: Any = None,
) -> Dict[str, Any]:
    case = get_case(case_id, db_path=db_path)
    existing = list_pipelines(case_id=case_id, limit=1, db_path=db_path)
    if existing and existing[0]["status"] in ACTIVE_PIPELINE_STATUSES:
        return existing[0]
    targets = _target_from_case(
        case,
        reference_ecosystem=reference_ecosystem,
        reference_package=reference_package,
        reference_version=reference_version,
    )
    pipeline_id = _id("RPL")
    now = soc_store.utc_now()
    config = {**targets, "safety": {"execution_performed": False, "raw_artifact_sent_to_ai": False}}
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_pipeline_runs
            (pipeline_id, schema_version, case_id, status, requested_by, current_step,
             revision, config_json, summary_json, error_code, error_message,
             created_at, started_at, completed_at, updated_at)
            VALUES (?, ?, ?, 'running', ?, 'validate_subject', 1, ?, '{}', NULL, NULL, ?, ?, NULL, ?)""",
            (pipeline_id, SCHEMA_VERSION, case_id, actor[:160], _json(config), now, now, now),
        )
        _ensure_steps(connection, pipeline_id)
        connection.execute(
            "UPDATE research_cases SET status = CASE WHEN status = 'draft' THEN 'investigating' ELSE status END, updated_at = ? WHERE case_id = ?",
            (now, case_id),
        )
        _event(
            connection,
            case_id,
            "investigation_pipeline_started",
            f"Started research investigation pipeline {pipeline_id}.",
            actor,
            {"pipeline_id": pipeline_id, "reference_configured": bool(targets["reference"])},
        )
        connection.commit()
    return _run_pipeline(pipeline_id, actor=actor, db_path=db_path, fetcher=fetcher)


def resume_investigation_pipeline(
    pipeline_id: str,
    *,
    reference_ecosystem: str = "",
    reference_package: str = "",
    reference_version: str = "",
    actor: str = "dashboard-operator",
    db_path: Optional[str] = None,
    fetcher: Any = None,
) -> Dict[str, Any]:
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    if pipeline["status"] == "succeeded":
        return pipeline
    if pipeline["status"] == "running":
        return pipeline
    if pipeline["status"] in {"awaiting_ai", "awaiting_input", "awaiting_review"} and not reference_package:
        return pipeline
    active_ai = [
        step for step in pipeline["steps"]
        if step["step_key"] in AI_STEPS and step.get("intelligence_job", {}).get("status") in {"queued", "running"}
    ]
    if pipeline["status"] == "awaiting_ai" and active_ai:
        running = [step for step in active_ai if step.get("intelligence_job", {}).get("status") == "running"]
        if running:
            raise ValueError("wait for the currently running Local Codex analysis to finish before adding a comparison package")
        for step in active_ai:
            cancel_job(step["intelligence_job_id"], actor=actor, db_path=db_path)
    config = dict(pipeline["config"])
    if reference_package:
        config["reference"] = {
            "ecosystem": _clean(reference_ecosystem or config.get("suspect", {}).get("ecosystem"), 80).lower(),
            "package": _clean(reference_package, 512),
            "version": _clean(reference_version, 160),
        }
    revision = int(pipeline.get("revision") or 1) + 1
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "UPDATE research_pipeline_runs SET status = 'running', current_step = 'resume', revision = ?, config_json = ?, error_code = NULL, error_message = NULL, completed_at = NULL, updated_at = ? WHERE pipeline_id = ?",
            (revision, _json(config), now, pipeline_id),
        )
        connection.execute(
            "UPDATE research_review_items SET status = 'superseded', updated_at = ? WHERE pipeline_id = ? AND status IN ('pending', 'applying')",
            (now, pipeline_id),
        )
        for step_key in ("collect_reference", "compare_packages", "evidence_matrix", *AI_STEPS, "human_review"):
            connection.execute(
                "UPDATE research_pipeline_steps SET status = 'pending', intelligence_job_id = NULL, result_json = '{}', error_code = NULL, error_message = NULL, started_at = NULL, completed_at = NULL, updated_at = ? WHERE pipeline_id = ? AND step_key = ?",
                (now, pipeline_id, step_key),
            )
        connection.commit()
    return _run_pipeline(pipeline_id, actor=actor, db_path=db_path, fetcher=fetcher)


def _run_pipeline(pipeline_id: str, *, actor: str, db_path: Optional[str], fetcher: Any) -> Dict[str, Any]:
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    config = pipeline["config"]
    case_id = pipeline["case_id"]
    revision = int(pipeline.get("revision") or 1)
    try:
        _set_step(pipeline_id, "validate_subject", "succeeded", result={"targets": config, "assumptions_made": False}, db_path=db_path)
        pipeline = get_pipeline(pipeline_id, db_path=db_path)

        suspect_result = _step_result(pipeline, "collect_subject")
        if not suspect_result:
            _set_step(pipeline_id, "collect_subject", "running", db_path=db_path)
            suspect_result = _collect_or_reuse_intake(
                case_id,
                config["suspect"],
                fetcher=fetcher,
                db_path=db_path,
            )
            _set_step(pipeline_id, "collect_subject", "succeeded", result=suspect_result, db_path=db_path)
        _put_review_item(
            pipeline_id,
            case_id,
            source_key=f"r{revision}:static:subject-intake",
            item_type="intake_evidence",
            content=f"Attach reviewed static intake evidence for {_target_label(config['suspect'])}.",
            confidence=100,
            evidence_refs=["collect_subject"],
            metadata={"step_key": "collect_subject", "comparison_role": "suspect"},
            db_path=db_path,
        )

        reference_result: Dict[str, Any] = {}
        if config.get("reference"):
            _set_step(pipeline_id, "collect_reference", "running", db_path=db_path)
            reference_result = _collect_or_reuse_intake(
                case_id,
                config["reference"],
                fetcher=fetcher,
                db_path=db_path,
            )
            _set_step(pipeline_id, "collect_reference", "succeeded", result=reference_result, db_path=db_path)
            _put_review_item(
                pipeline_id,
                case_id,
                source_key=f"r{revision}:static:reference-intake",
                item_type="intake_evidence",
                content=f"Attach reviewed reference-package evidence for {_target_label(config['reference'])}.",
                confidence=100,
                evidence_refs=["collect_reference"],
                metadata={"step_key": "collect_reference", "comparison_role": "reference"},
                db_path=db_path,
            )
            _set_step(pipeline_id, "compare_packages", "running", db_path=db_path)
            comparison = compare_intakes(suspect_result, reference_result, db_path=db_path)
            _set_step(pipeline_id, "compare_packages", "succeeded", result=comparison, db_path=db_path)
            _put_review_item(
                pipeline_id,
                case_id,
                source_key=f"r{revision}:static:package-comparison",
                item_type="comparison_evidence",
                content=f"Attach the static comparison between {_target_label(config['suspect'])} and {_target_label(config['reference'])}.",
                confidence=100,
                evidence_refs=["collect_subject", "collect_reference", "compare_packages"],
                metadata={"step_key": "compare_packages"},
                db_path=db_path,
            )
        else:
            missing = {
                "required_input": "reference_package",
                "message": "No verified legitimate comparison package is recorded. Add one and resume; SecOpsAI will not guess it.",
            }
            _set_step(pipeline_id, "collect_reference", "awaiting_input", result=missing, db_path=db_path)
            _set_step(pipeline_id, "compare_packages", "awaiting_input", result=missing, db_path=db_path)

        matrix = _preliminary_matrix(case_id, suspect_result, reference_result)
        _set_step(pipeline_id, "evidence_matrix", "succeeded", result=matrix, db_path=db_path)
        for index, claim in enumerate(matrix["claims"]):
            _put_review_item(
                pipeline_id,
                case_id,
                source_key=f"r{revision}:static:claim:{index}",
                item_type="evidence_statement",
                content=claim["statement"],
                confidence=claim["confidence"],
                evidence_refs=claim["evidence_refs"],
                metadata={"claim_status": claim["status"], "limitations": claim["limitations"]},
                db_path=db_path,
            )

        for action in AI_STEPS:
            job = enqueue_job(
                action=action,
                target_id=case_id,
                inputs={"case_id": case_id, "pipeline_id": pipeline_id, "pipeline_revision": revision},
                requested_by=actor,
                idempotency_key=f"{pipeline_id}:{revision}:{action}",
                db_path=db_path,
            )
            _set_step(
                pipeline_id,
                action,
                "queued",
                result={"message": "Queued for the local Codex Bridge; no export or upload is required."},
                intelligence_job_id=job["job_id"],
                db_path=db_path,
            )
        summary = {
            "static_collection_complete": True,
            "comparison_complete": bool(reference_result),
            "comparison_input_required": not bool(reference_result),
            "quarantine_reuse_count": sum(
                bool(item.get("reuse")) for item in (suspect_result, reference_result) if item
            ),
            "registry_collection_degraded": bool(suspect_result.get("reuse") or reference_result.get("reuse")),
            "ai_jobs_queued": len(AI_STEPS),
            "human_review_required": True,
            "raw_artifact_sent_to_ai": False,
        }
        _set_pipeline(pipeline_id, "awaiting_ai", current_step="local_codex_bridge", summary=summary, db_path=db_path)
        return get_pipeline(pipeline_id, db_path=db_path)
    except Exception as exc:
        current = get_pipeline(pipeline_id, db_path=db_path)
        failed = next((step for step in current["steps"] if step["status"] == "running"), None)
        if failed:
            _set_step(
                pipeline_id,
                failed["step_key"],
                "failed",
                error_code="pipeline_step_failed",
                error_message=str(exc),
                db_path=db_path,
            )
        _set_pipeline(
            pipeline_id,
            "failed",
            current_step=failed["step_key"] if failed else "pipeline",
            error_code="pipeline_failed",
            error_message=str(exc),
            db_path=db_path,
        )
        with closing(soc_store.connect(db_path)) as connection:
            _event(connection, case_id, "investigation_pipeline_failed", f"Research pipeline {pipeline_id} failed safely.", actor, {"pipeline_id": pipeline_id, "step": failed["step_key"] if failed else "pipeline"})
            connection.commit()
        return get_pipeline(pipeline_id, db_path=db_path)


def _target_label(target: Dict[str, Any]) -> str:
    return f"{target.get('ecosystem')}:{target.get('package')}@{target.get('version') or 'latest'}"


def _preliminary_matrix(case_id: str, suspect: Dict[str, Any], reference: Dict[str, Any]) -> Dict[str, Any]:
    suspect_meta = suspect.get("metadata") or {}
    suspect_analysis = suspect.get("analysis") or {}
    indicators = suspect_analysis.get("indicators") or []
    collection_statement = (
        f"SecOpsAI verified a previously quarantined {_target_label(suspect_meta)} artifact, originally collected from its allowlisted registry source, and "
        if suspect.get("reuse")
        else f"SecOpsAI collected {_target_label(suspect_meta)} from its allowlisted registry source and "
    )
    claims = [
        {
            "statement": f"{collection_statement}recorded SHA-256 {suspect_meta.get('artifact_sha256', 'unavailable')}.",
            "confidence": 100,
            "status": "supported",
            "evidence_refs": ["collect_subject"],
            "limitations": ["Artifact identity does not establish intent or runtime behavior."],
        },
        {
            "statement": f"Bounded static inspection reported {len(indicators)} indicator(s) and did not execute package code.",
            "confidence": 100,
            "status": "supported",
            "evidence_refs": ["collect_subject"],
            "limitations": ["Static indicators require analyst interpretation."],
        },
    ]
    if reference:
        claims.append(
            {
                "statement": f"A separate reference package, {_target_label(reference.get('metadata') or {})}, was collected for deterministic comparison.",
                "confidence": 100,
                "status": "supported",
                "evidence_refs": ["collect_reference", "compare_packages"],
                "limitations": ["The operator must confirm that the reference package is legitimate and relevant."],
            }
        )
    else:
        claims.append(
            {
                "statement": "No legitimate comparison package has been verified.",
                "confidence": 100,
                "status": "missing",
                "evidence_refs": [],
                "limitations": ["SecOpsAI does not guess brand ownership or package legitimacy."],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "generated_at": soc_store.utc_now(),
        "claims": claims,
        "summary": {
            "claims": len(claims),
            "supported": sum(item["status"] == "supported" for item in claims),
            "missing": sum(item["status"] == "missing" for item in claims),
        },
    }


def _put_review_item(
    pipeline_id: str,
    case_id: str,
    *,
    source_key: str,
    item_type: str,
    content: str,
    confidence: int,
    evidence_refs: Iterable[str],
    metadata: Optional[Dict[str, Any]],
    db_path: Optional[str],
) -> None:
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_review_items
            (item_id, pipeline_id, case_id, source_key, item_type, content, confidence,
             evidence_refs_json, metadata_json, status, reviewer, review_note,
             edited_content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, '', '', ?, ?)
            ON CONFLICT(pipeline_id, source_key) DO UPDATE SET
              item_type=excluded.item_type, content=excluded.content,
              confidence=excluded.confidence, evidence_refs_json=excluded.evidence_refs_json,
              metadata_json=excluded.metadata_json, updated_at=excluded.updated_at""",
            (
                _review_id(pipeline_id, source_key),
                pipeline_id,
                case_id,
                source_key[:180],
                item_type[:80],
                _clean(content, 12000),
                max(0, min(int(confidence), 100)),
                _json(list(evidence_refs)[:50]),
                _json(metadata or {}),
                now,
                now,
            ),
        )
        connection.commit()


def reconcile_intelligence_job(job: Dict[str, Any], *, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    inputs = job.get("input") if isinstance(job.get("input"), dict) else {}
    pipeline_id = _clean(inputs.get("pipeline_id"), 40).upper()
    if not pipeline_id:
        return None
    try:
        pipeline = get_pipeline(pipeline_id, db_path=db_path)
    except ValueError:
        return None
    action = str(job.get("action") or "")
    if action not in AI_STEPS:
        return pipeline
    if int(inputs.get("pipeline_revision") or 0) != int(pipeline.get("revision") or 0):
        return pipeline
    status = str(job.get("status") or "")
    if status == "succeeded":
        _set_step(pipeline_id, action, "succeeded", result=job.get("result") or {}, intelligence_job_id=job.get("job_id"), db_path=db_path)
    elif status in {"failed", "canceled"}:
        _set_step(
            pipeline_id,
            action,
            "failed",
            result=job.get("result") or {},
            intelligence_job_id=job.get("job_id"),
            error_code=str(job.get("error_code") or "intelligence_failed"),
            error_message=str(job.get("error_message") or "Local Codex Bridge analysis failed."),
            db_path=db_path,
        )
    else:
        return get_pipeline(pipeline_id, db_path=db_path)
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    ai_steps = [step for step in pipeline["steps"] if step["step_key"] in AI_STEPS]
    if any(step["status"] in {"pending", "queued", "running"} for step in ai_steps):
        return pipeline
    if any(step["status"] == "failed" for step in ai_steps):
        _set_pipeline(
            pipeline_id,
            "failed",
            current_step="local_codex_bridge",
            summary={**pipeline.get("summary", {}), "retry_available": True},
            error_code="intelligence_pipeline_failed",
            error_message="One or more Local Codex Bridge analyses failed. Resume the pipeline to retry.",
            db_path=db_path,
        )
        return get_pipeline(pipeline_id, db_path=db_path)
    _materialize_ai_review_items(pipeline_id, db_path=db_path)
    _set_step(
        pipeline_id,
        "human_review",
        "queued",
        result={"message": "Review every proposed item. No verdict, disclosure, sandbox, or publication action was taken."},
        db_path=db_path,
    )
    current = get_pipeline(pipeline_id, db_path=db_path)
    summary = {
        **current.get("summary", {}),
        "ai_analysis_complete": True,
        "pending_review_items": current["review_summary"].get("pending", 0),
        "human_review_required": True,
    }
    _set_pipeline(pipeline_id, "awaiting_review", current_step="human_review", summary=summary, db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        _event(
            connection,
            current["case_id"],
            "investigation_pipeline_review_ready",
            f"Research pipeline {pipeline_id} is ready for structured human review.",
            "local-codex-bridge",
            {"pipeline_id": pipeline_id, "pending_review_items": summary["pending_review_items"]},
        )
        connection.commit()
    if str(os.environ.get("SECOPSAI_RESEARCH_AUTONOMY_MODE") or "").strip().lower() == "agent_review":
        return agent_complete_pipeline(
            pipeline_id,
            actor="secopsai-agent-autonomy",
            db_path=db_path,
        )
    return get_pipeline(pipeline_id, db_path=db_path)


def _collect_or_reuse_intake(
    case_id: str,
    target: Dict[str, Any],
    *,
    fetcher: Any,
    db_path: Optional[str],
) -> Dict[str, Any]:
    """Prefer fresh registry collection, then reuse exact hash-verified local evidence."""
    try:
        return collect_package_intake(fetcher=fetcher, **target)
    except IntakeError as registry_error:
        cached = _find_verified_cached_intake(case_id, target, db_path=db_path)
        if cached is None:
            raise
        result = json.loads(json.dumps(cached))
        result["reuse"] = {
            "mode": "verified_quarantine",
            "reason": "official registry collection was unavailable",
            "registry_error": _clean(registry_error, 500),
            "hash_verified": True,
            "execution_performed": False,
        }
        return result


def _find_verified_cached_intake(
    case_id: str,
    target: Dict[str, Any],
    *,
    db_path: Optional[str],
) -> Optional[Dict[str, Any]]:
    ecosystem = _clean(target.get("ecosystem"), 80).lower()
    package = _clean(target.get("package"), 512).lower()
    version = _clean(target.get("version"), 160)
    if not ecosystem or not package or not version:
        return None
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT s.result_json
            FROM research_pipeline_steps s
            JOIN research_pipeline_runs p ON p.pipeline_id = s.pipeline_id
            WHERE p.case_id = ? AND s.step_key IN ('collect_subject', 'collect_reference')
              AND s.status = 'succeeded'
            ORDER BY s.completed_at DESC
            LIMIT 50""",
            (case_id,),
        ).fetchall()
    for row in rows:
        result = _decode(row["result_json"], {})
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        if (
            _clean(metadata.get("ecosystem"), 80).lower() != ecosystem
            or _clean(metadata.get("package"), 512).lower() != package
            or _clean(metadata.get("version"), 160) != version
        ):
            continue
        try:
            validate_quarantined_intake(result)
        except IntakeError:
            continue
        return result
    return None


def _materialize_ai_review_items(pipeline_id: str, *, db_path: Optional[str]) -> None:
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    revision = int(pipeline.get("revision") or 1)
    action_fields = {
        "analyze_research_case": (
            ("confirmed_facts", "proposed_fact", 80, 6),
            ("inferences", "inference", 60, 4),
            ("unsupported_claims", "unsupported_claim", 90, 4),
            ("contradictions", "contradiction", 70, 4),
            ("missing_evidence", "missing_evidence", 80, 6),
            ("recommended_actions", "recommended_action", 60, 5),
            ("limitations", "limitation", 90, 5),
        ),
        "generate_analyst_brief": (("article_outline", "article_section", 60, 10),),
        "review_publication_safety": (
            ("publication_risks", "publication_risk", 80, 10),
            ("limitations", "limitation", 90, 5),
        ),
    }
    action_scalars = {
        "analyze_research_case": (
            ("summary", "analyst_summary", 60),
            ("risk_assessment", "risk_assessment", 60),
        ),
        "generate_analyst_brief": (("summary", "analyst_summary", 60),),
        "review_publication_safety": (
            ("summary", "analyst_summary", 60),
            ("disclosure_draft", "disclosure_draft", 50),
        ),
    }
    for step in pipeline["steps"]:
        if step["step_key"] not in AI_STEPS or step["status"] != "succeeded":
            continue
        envelope = step.get("result") or {}
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else envelope
        for key, item_type, confidence, limit in action_fields.get(step["step_key"], ()):
            values = data.get(key) if isinstance(data, dict) else None
            if not isinstance(values, list):
                continue
            normalized: list[str] = []
            seen: set[str] = set()
            for value in values:
                content = _clean(value if isinstance(value, str) else _json(value), 2000)
                fingerprint = " ".join(content.lower().split())
                if not content or fingerprint in seen:
                    continue
                normalized.append(content)
                seen.add(fingerprint)
                if len(normalized) == limit:
                    break
            if not normalized:
                continue
            _put_review_item(
                pipeline_id,
                pipeline["case_id"],
                source_key=f"r{revision}:ai:{step['step_key']}:{key}",
                item_type=item_type,
                content="\n".join(f"- {value}" for value in normalized),
                confidence=confidence,
                evidence_refs=[step.get("intelligence_job_id") or step["step_key"]],
                metadata={
                    "intelligence_action": step["step_key"],
                    "field": key,
                    "grouped_items": len(normalized),
                    "model_output_is_advisory": True,
                },
                db_path=db_path,
            )
        for key, item_type, confidence in action_scalars.get(step["step_key"], ()):
            content = data.get(key) if isinstance(data, dict) else None
            if isinstance(content, str) and content.strip():
                _put_review_item(
                    pipeline_id,
                    pipeline["case_id"],
                    source_key=f"r{revision}:ai:{step['step_key']}:{key}",
                    item_type=item_type,
                    content=content,
                    confidence=confidence,
                    evidence_refs=[step.get("intelligence_job_id") or step["step_key"]],
                    metadata={"intelligence_action": step["step_key"], "field": key, "model_output_is_advisory": True},
                    db_path=db_path,
                )


def auto_review_pipeline(
    pipeline_id: str,
    *,
    actor: str = "analyst",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    if pipeline["status"] != "awaiting_review":
        raise ValueError("pipeline proposals can be reviewed only after all analysis is ready")
    pending = [item for item in pipeline["review_items"] if item["status"] == "pending"]
    if not pending:
        return pipeline
    for item in pending:
        review_pipeline_item(
            pipeline_id,
            item["item_id"],
            decision="accepted",
            actor=actor,
            db_path=db_path,
        )
    return get_pipeline(pipeline_id, db_path=db_path)


def agent_complete_pipeline(
    pipeline_id: str,
    *,
    actor: str = "secopsai-agent-autonomy",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Complete safe review work and record a bounded, evidence-linked agent verdict."""
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    if pipeline["status"] == "awaiting_review":
        pipeline = auto_review_pipeline(pipeline_id, actor=actor, db_path=db_path)
    elif pipeline["status"] != "succeeded":
        raise ValueError("agent completion requires a pipeline awaiting review or already succeeded")

    case = get_case(pipeline["case_id"], db_path=db_path)
    actor_id = f"{actor}:{pipeline_id}"[:160]
    existing = next(
        (item for item in case.get("verdicts") or [] if str(item.get("actor") or "") == actor_id),
        None,
    )
    verdict_recorded = bool(existing)
    verdict = str(existing.get("verdict") or "") if existing else ""
    confidence = int(existing.get("confidence") or 0) if existing else 0

    if not existing:
        analyze = next(
            (step for step in pipeline["steps"] if step["step_key"] == "analyze_research_case"),
            {},
        )
        envelope = analyze.get("result") or {}
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else envelope
        requested = str(data.get("verdict_recommendation") or "inconclusive").strip().lower()
        if requested not in {"credible", "likely", "inconclusive", "not_substantiated", "benign"}:
            requested = "inconclusive"
        try:
            confidence = max(0, min(int(data.get("verdict_confidence") or 0), 100))
        except (TypeError, ValueError):
            confidence = 0
        rationale = _clean(data.get("verdict_rationale"), 8000)
        contradictions = data.get("contradictions") if isinstance(data.get("contradictions"), list) else []
        unsupported = data.get("unsupported_claims") if isinstance(data.get("unsupported_claims"), list) else []
        decision_context = " ".join(
            _clean(value, 2000)
            for value in (
                rationale,
                data.get("summary"),
                data.get("risk_assessment"),
                *(data.get("confirmed_facts") if isinstance(data.get("confirmed_facts"), list) else []),
                *(data.get("limitations") if isinstance(data.get("limitations"), list) else []),
            )
        ).lower()
        local_absence_only = any(
            marker in decision_context
            for marker in (
                "not installed locally",
                "not referenced locally",
                "not present locally",
                "absent from the local",
                "no local dependency",
                "no matching dependency",
                "not found in the local repository",
            )
        )
        active_evidence = [
            item
            for item in case.get("evidence") or []
            if str(item.get("status") or "active") == "active"
            and item.get("evidence_id")
            and str((item.get("metadata") or {}).get("pipeline_id") or "") == pipeline_id
        ]
        evidence_ids = [str(item["evidence_id"]) for item in active_evidence[:50]]
        strong_proof = any(
            str(item.get("evidence_type") or "") == "sandbox_analysis"
            or bool((item.get("metadata") or {}).get("advisory_backed"))
            for item in active_evidence
        )

        verdict = requested
        guardrail_notes: list[str] = []
        if not evidence_ids or confidence < 60:
            verdict = "inconclusive"
            guardrail_notes.append("insufficient linked evidence or confidence")
        if requested == "credible" and not strong_proof:
            verdict = "likely" if evidence_ids and confidence >= 70 else "inconclusive"
            guardrail_notes.append("credible requires advisory-backed or sandbox evidence")
        if contradictions and verdict == "credible":
            verdict = "likely"
            guardrail_notes.append("unresolved contradictions prevent a credible verdict")
        if requested in {"benign", "not_substantiated"} and local_absence_only:
            verdict = "inconclusive"
            guardrail_notes.append("local absence cannot establish package benignness")
        if requested in {"benign", "not_substantiated"} and not strong_proof:
            verdict = "inconclusive"
            guardrail_notes.append("an exonerating verdict requires advisory-backed or sandbox evidence")
        if unsupported and verdict == "credible":
            verdict = "likely"
            guardrail_notes.append("unsupported claims prevent a credible verdict")

        if evidence_ids:
            rationale_text = rationale or "Agent completed bounded review of normalized research evidence."
            if guardrail_notes:
                rationale_text += " Guardrails: " + "; ".join(guardrail_notes) + "."
            record_verdict(
                pipeline["case_id"],
                verdict=verdict,
                confidence=confidence,
                rationale=f"[pipeline {pipeline_id}] {rationale_text}",
                evidence_ids=evidence_ids,
                actor=actor_id,
                db_path=db_path,
            )
            verdict_recorded = True

    safety = publication_safety_check(pipeline["case_id"], actor=actor_id, db_path=db_path)
    current = get_pipeline(pipeline_id, db_path=db_path)
    _set_pipeline(
        pipeline_id,
        "succeeded",
        current_step="agent_review_complete",
        summary={
            **current.get("summary", {}),
            "autonomy_mode": "agent_review",
            "human_review_required": False,
            "verdict_recorded": verdict_recorded,
            "agent_verdict": verdict or None,
            "agent_verdict_confidence": confidence,
            "publication_preflight": safety["status"],
            "disclosure_sent": False,
            "sandbox_submitted": False,
            "published": False,
            "human_gates_remaining": [
                "external sandbox submission",
                "external disclosure delivery",
                "final publication approval",
            ],
        },
        db_path=db_path,
    )
    return get_pipeline(pipeline_id, db_path=db_path)


def review_pipeline_item(
    pipeline_id: str,
    item_id: str,
    *,
    decision: str,
    edited_content: str = "",
    review_note: str = "",
    actor: str = "analyst",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    decision = _clean(decision, 20).lower()
    if decision not in {"accepted", "rejected"}:
        raise ValueError("review decision must be accepted or rejected")
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    if pipeline["status"] != "awaiting_review":
        raise ValueError("pipeline proposals can be reviewed only after all analysis is ready")
    item = next((value for value in pipeline["review_items"] if value["item_id"] == item_id), None)
    if item is None:
        raise ValueError("review item does not belong to this pipeline")
    if item["status"] in {"accepted", "rejected"}:
        return get_pipeline(pipeline_id, db_path=db_path)
    if item["status"] == "superseded":
        raise ValueError("superseded review items cannot be reviewed")
    if item["status"] == "applying":
        raise ValueError("this review item is already being applied")
    content = _clean(edited_content, 12000) or item["content"]
    now = soc_store.utc_now()
    if decision == "rejected":
        with closing(soc_store.connect(db_path)) as connection:
            updated = connection.execute(
                "UPDATE research_review_items SET status = 'rejected', reviewer = ?, review_note = ?, edited_content = ?, updated_at = ? WHERE item_id = ? AND status = 'pending'",
                (actor[:160], _clean(review_note, 2000), content if content != item["content"] else "", now, item_id),
            )
            if updated.rowcount != 1:
                raise ValueError("the review item changed before this decision was saved; refresh and try again")
            _event(connection, pipeline["case_id"], "pipeline_review_item_rejected", f"Rejected pipeline proposal {item_id}.", actor, {"pipeline_id": pipeline_id, "item_id": item_id, "item_type": item["item_type"]})
            connection.commit()
    else:
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE research_review_items SET status = 'applying', reviewer = ?, review_note = ?, edited_content = ?, updated_at = ? WHERE item_id = ? AND status = 'pending'",
                (actor[:160], _clean(review_note, 2000), content if content != item["content"] else "", soc_store.utc_now(), item_id),
            )
            if updated.rowcount != 1:
                connection.rollback()
                raise ValueError("the review item changed before this decision was saved; refresh and try again")
            connection.commit()
        try:
            _apply_accepted_item(pipeline, item, content=content, actor=actor, db_path=db_path)
        except Exception as exc:
            with closing(soc_store.connect(db_path)) as connection:
                connection.execute(
                    "UPDATE research_review_items SET status = 'pending', updated_at = ? WHERE item_id = ? AND status = 'applying'",
                    (soc_store.utc_now(), item_id),
                )
                _event(
                    connection,
                    pipeline["case_id"],
                    "pipeline_review_item_apply_failed",
                    f"Could not apply pipeline proposal {item_id}; it remains pending.",
                    actor,
                    {"pipeline_id": pipeline_id, "item_id": item_id, "item_type": item["item_type"], "error": _clean(exc, 500)},
                )
                connection.commit()
            raise
        with closing(soc_store.connect(db_path)) as connection:
            updated = connection.execute(
                "UPDATE research_review_items SET status = 'accepted', updated_at = ? WHERE item_id = ? AND status = 'applying'",
                (soc_store.utc_now(), item_id),
            )
            if updated.rowcount != 1:
                raise ValueError("the review item was applied but its accepted state could not be recorded")
            _event(connection, pipeline["case_id"], "pipeline_review_item_accepted", f"Accepted pipeline proposal {item_id}.", actor, {"pipeline_id": pipeline_id, "item_id": item_id, "item_type": item["item_type"]})
            connection.commit()
    return _finalize_review_if_complete(pipeline_id, actor=actor, db_path=db_path)


def _apply_accepted_item(pipeline: Dict[str, Any], item: Dict[str, Any], *, content: str, actor: str, db_path: Optional[str]) -> None:
    pipeline_id = pipeline["pipeline_id"]
    case_id = pipeline["case_id"]
    metadata = item.get("metadata") or {}
    marker = {"pipeline_id": pipeline_id, "review_item_id": item["item_id"], "review_state": "accepted"}
    if item["item_type"] == "intake_evidence":
        existing = [
            value for value in get_case(case_id, db_path=db_path).get("evidence", [])
            if (value.get("metadata") or {}).get("review_item_id") == item["item_id"]
        ]
        if len(existing) < 3:
            result = _step_result(pipeline, str(metadata.get("step_key") or ""))
            if not result:
                raise ValueError("the intake result is unavailable; resume the pipeline before accepting it")
            attach_intake_result(
                {**result, "case_id": case_id},
                db_path=db_path,
                actor=actor,
                metadata_extra={**marker, "comparison_role": metadata.get("comparison_role") or "suspect"},
            )
        return
    if item["item_type"] == "comparison_evidence":
        existing = [
            value for value in get_case(case_id, db_path=db_path).get("evidence", [])
            if (value.get("metadata") or {}).get("review_item_id") == item["item_id"]
        ]
        if not existing:
            result = _step_result(pipeline, "compare_packages")
            encoded = _json(result).encode()
            add_evidence(
                case_id,
                evidence_type="static_analysis",
                title="Reviewed static package comparison",
                locator=f"research-pipeline://{pipeline_id}/compare_packages",
                sha256=hashlib.sha256(encoded).hexdigest(),
                provenance="SecOpsAI deterministic package comparison accepted by an analyst",
                notes="Static comparison only. Package code was not executed.",
                metadata={**result, **marker},
                actor=actor,
                db_path=db_path,
            )
        return
    data_json = _json({"pipeline_id": pipeline_id, "item_id": item["item_id"], "item_type": item["item_type"]})
    with closing(soc_store.connect(db_path)) as connection:
        exists = connection.execute(
            "SELECT 1 FROM research_case_events WHERE case_id = ? AND event_type = 'pipeline_review_note' AND data_json = ?",
            (case_id, data_json),
        ).fetchone()
        if not exists:
            connection.execute(
                "INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, 'pipeline_review_note', ?, ?, ?, ?)",
                (case_id, actor[:160], f"[{item['item_type']}] {content}"[:12000], data_json, soc_store.utc_now()),
            )
            connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (soc_store.utc_now(), case_id))
            connection.commit()


def _finalize_review_if_complete(pipeline_id: str, *, actor: str, db_path: Optional[str]) -> Dict[str, Any]:
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    unresolved = [item for item in pipeline["review_items"] if item["status"] in {"pending", "applying"}]
    if unresolved:
        _set_pipeline(
            pipeline_id,
            "awaiting_review",
            current_step="human_review",
            summary={**pipeline.get("summary", {}), "pending_review_items": len(unresolved)},
            db_path=db_path,
        )
        return get_pipeline(pipeline_id, db_path=db_path)
    matrix = build_evidence_matrix(pipeline["case_id"], persist=True, actor=actor, db_path=db_path)
    safety = publication_safety_check(pipeline["case_id"], actor=actor, db_path=db_path)
    _set_step(
        pipeline_id,
        "human_review",
        "succeeded",
        result={"reviewed_items": len(pipeline["review_items"]), "evidence_matrix": matrix["summary"], "publication_preflight": safety["status"]},
        db_path=db_path,
    )
    _set_pipeline(
        pipeline_id,
        "succeeded",
        current_step="human_review_complete",
        summary={
            **pipeline.get("summary", {}),
            "pending_review_items": 0,
            "accepted_review_items": pipeline["review_summary"].get("accepted", 0),
            "rejected_review_items": pipeline["review_summary"].get("rejected", 0),
            "publication_preflight": safety["status"],
            "verdict_recorded": False,
            "disclosure_sent": False,
            "published": False,
        },
        db_path=db_path,
    )
    return get_pipeline(pipeline_id, db_path=db_path)


def pipeline_intelligence_context(pipeline_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return only normalized static results that are safe for model context."""
    pipeline = get_pipeline(pipeline_id, db_path=db_path)

    def intake_summary(step_key: str) -> Dict[str, Any]:
        result = _step_result(pipeline, step_key)
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        analysis = result.get("analysis") if isinstance(result.get("analysis"), dict) else {}
        return {
            "metadata": {key: metadata.get(key) for key in ("ecosystem", "package", "version", "publisher", "published_at", "dependencies", "integrity", "artifact_sha256", "artifact_bytes")},
            "analysis": {
                "member_count": analysis.get("member_count"),
                "expanded_bytes": analysis.get("expanded_bytes"),
                "lifecycle_scripts": analysis.get("lifecycle_scripts") or {},
                "manifest_summary": analysis.get("manifest_summary") or {},
                "indicators": (analysis.get("indicators") or [])[:100],
                "members": (analysis.get("members") or [])[:100],
                "execution_performed": False,
            },
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "pipeline_id": pipeline_id,
        "case_id": pipeline["case_id"],
        "status": pipeline["status"],
        "suspect": intake_summary("collect_subject"),
        "reference": intake_summary("collect_reference") if _step_result(pipeline, "collect_reference").get("metadata") else None,
        "comparison": _step_result(pipeline, "compare_packages"),
        "preliminary_evidence_matrix": _step_result(pipeline, "evidence_matrix"),
        "safety": {
            "execution_performed": False,
            "raw_artifact_included": False,
            "quarantine_locator_included": False,
            "human_review_required": True,
        },
    }
