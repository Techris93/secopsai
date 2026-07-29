"""Durable evidence-collection autopilot for high-priority findings.

This coordinator joins existing Core capabilities. It never executes package
code, approves a sandbox submission, sends disclosure, or publishes content.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from contextlib import closing
from typing import Any, Dict, Optional

import soc_store
from secopsai.intelligence import minimize
from secopsai.research_cases import add_evidence, add_subject, create_case, get_case, link_finding
from secopsai.research_pipeline import get_pipeline, start_investigation_pipeline


SCHEMA_VERSION = "secopsai.investigation-autopilot.v1"
MODES = {"off", "advisory", "guarded"}
ACTIVE = {"queued", "collecting", "analyzing", "awaiting_model", "awaiting_input", "awaiting_sandbox", "ready_for_decision"}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULTS = {
    "mode": "guarded",
    "minimum_severity": "high",
    "max_active_runs": 3,
    "max_attempts": 3,
    "auto_start_pipeline": True,
    "auto_extract_iocs": True,
    "auto_correlate": True,
}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, default: Any) -> Any:
    try:
        return json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _clean(value: Any, limit: int = 4000) -> str:
    return str(value or "").strip()[:limit]


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def get_settings(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM investigation_autopilot_settings WHERE settings_id = 1").fetchone()
        if row is None:
            now = soc_store.utc_now()
            connection.execute(
                """INSERT INTO investigation_autopilot_settings
                (settings_id, mode, minimum_severity, max_active_runs, max_attempts,
                 auto_start_pipeline, auto_extract_iocs, auto_correlate, updated_at, updated_by)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 'secopsai-default')""",
                (
                    DEFAULTS["mode"], DEFAULTS["minimum_severity"], DEFAULTS["max_active_runs"],
                    DEFAULTS["max_attempts"], int(DEFAULTS["auto_start_pipeline"]),
                    int(DEFAULTS["auto_extract_iocs"]), int(DEFAULTS["auto_correlate"]), now,
                ),
            )
            connection.commit()
            row = connection.execute("SELECT * FROM investigation_autopilot_settings WHERE settings_id = 1").fetchone()
    result = dict(row or {})
    for key in ("auto_start_pipeline", "auto_extract_iocs", "auto_correlate"):
        result[key] = bool(result.get(key))
    result["schema_version"] = SCHEMA_VERSION
    return result


def update_settings(
    *, mode: Optional[str] = None, minimum_severity: Optional[str] = None,
    max_active_runs: Optional[int] = None, max_attempts: Optional[int] = None,
    auto_start_pipeline: Optional[bool] = None, auto_extract_iocs: Optional[bool] = None,
    auto_correlate: Optional[bool] = None, actor: str = "operator",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    current = get_settings(db_path=db_path)
    next_mode = _clean(mode if mode is not None else current["mode"], 20).lower()
    severity = _clean(minimum_severity if minimum_severity is not None else current["minimum_severity"], 20).lower()
    active = int(max_active_runs if max_active_runs is not None else current["max_active_runs"])
    attempts = int(max_attempts if max_attempts is not None else current["max_attempts"])
    if next_mode not in MODES:
        raise ValueError("investigation autopilot mode must be off, advisory, or guarded")
    if severity not in SEVERITY_ORDER:
        raise ValueError("minimum severity must be info, low, medium, high, or critical")
    if not 1 <= active <= 20 or not 1 <= attempts <= 10:
        raise ValueError("active runs must be 1-20 and attempts must be 1-10")
    values = (
        next_mode, severity, active, attempts,
        int(auto_start_pipeline if auto_start_pipeline is not None else current["auto_start_pipeline"]),
        int(auto_extract_iocs if auto_extract_iocs is not None else current["auto_extract_iocs"]),
        int(auto_correlate if auto_correlate is not None else current["auto_correlate"]),
        soc_store.utc_now(), _clean(actor, 160) or "operator",
    )
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE investigation_autopilot_settings SET mode=?, minimum_severity=?,
            max_active_runs=?, max_attempts=?, auto_start_pipeline=?, auto_extract_iocs=?,
            auto_correlate=?, updated_at=?, updated_by=? WHERE settings_id=1""", values,
        )
        connection.commit()
    return get_settings(db_path=db_path)


def _fingerprint(finding: Dict[str, Any]) -> str:
    payload = {
        "finding_id": finding.get("finding_id"), "title": finding.get("title"),
        "summary": finding.get("summary"), "severity": finding.get("severity"),
        "source": finding.get("source"), "ecosystem": finding.get("ecosystem"),
        "package": finding.get("package"),
        "version": finding.get("new_version") or finding.get("version"),
        "rules": finding.get("rule_ids") or [], "evidence": minimize(finding.get("evidence") or {}),
    }
    return hashlib.sha256(_json(payload).encode()).hexdigest()


def eligible(finding: Dict[str, Any], *, settings: Dict[str, Any]) -> tuple[bool, str]:
    if settings["mode"] == "off":
        return False, "autopilot_disabled"
    severity = _clean(finding.get("severity"), 20).lower() or "info"
    if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER[settings["minimum_severity"]]:
        return False, "below_severity_threshold"
    ecosystem = _clean(finding.get("ecosystem"), 80).lower()
    package = _clean(finding.get("package"), 512)
    version = _clean(finding.get("new_version") or finding.get("version"), 160)
    if not ecosystem or not package or not version:
        return False, "package_identity_incomplete"
    return True, "eligible"


def enqueue_finding(finding_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    finding = soc_store.get_finding(finding_id, db_path)
    if finding is None:
        raise ValueError(f"finding not found: {finding_id}")
    settings = get_settings(db_path=db_path)
    allowed, reason = eligible(finding, settings=settings)
    if not allowed:
        return {"status": "skipped", "finding_id": finding_id, "reason": reason}
    fingerprint = _fingerprint(finding)
    with closing(soc_store.connect(db_path)) as connection:
        existing = connection.execute(
            "SELECT run_id FROM investigation_autopilot_runs WHERE finding_id=? AND finding_fingerprint=?",
            (finding_id, fingerprint),
        ).fetchone()
        if existing:
            return get_run(str(existing["run_id"]), db_path=db_path)
        run_id, now = _id("IAR"), soc_store.utc_now()
        connection.execute(
            """INSERT INTO investigation_autopilot_runs
            (run_id, finding_id, finding_fingerprint, case_id, pipeline_id, status,
             current_stage, last_successful_stage, attempt, evidence_summary_json,
             decision_json, blocker_code, blocker_message, retryable, created_at,
             started_at, completed_at, updated_at)
            VALUES (?, ?, ?, NULL, NULL, 'queued', 'queued', '', 0, '{}', '{}',
                    NULL, NULL, 1, ?, NULL, NULL, ?)""",
            (run_id, finding_id, fingerprint, now, now),
        )
        connection.commit()
    soc_store.add_note(finding_id, "secopsai-investigation-autopilot", f"Queued evidence investigation {run_id}.", db_path)
    return get_run(run_id, db_path=db_path)


def enqueue_due_findings(*, db_path: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    """Backfill eligible existing findings as well as newly triaged records."""
    settings = get_settings(db_path=db_path)
    findings = soc_store.list_findings(db_path, limit=None, include_payload=True)
    candidates = sorted(
        (
            item for item in findings
            if _clean(item.get("status"), 32).lower() in {"open", "in_review"}
            and _clean(item.get("disposition"), 32).lower() in {"", "unreviewed", "needs_review", "true_positive"}
        ),
        key=lambda item: (-SEVERITY_ORDER.get(_clean(item.get("severity"), 20).lower(), 0), _clean(item.get("first_seen"), 80)),
    )
    queued, skipped = [], 0
    for finding in candidates:
        if len(queued) >= max(1, min(int(limit), 500)):
            break
        result = enqueue_finding(str(finding.get("finding_id") or ""), db_path=db_path)
        if result.get("status") == "queued":
            queued.append(result)
        else:
            skipped += 1
    return {"queued": queued, "skipped": skipped, "eligible_scanned": len(candidates)}


def _existing_case(finding_id: str, *, db_path: Optional[str]) -> Optional[str]:
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute(
            "SELECT case_id FROM research_case_findings WHERE finding_id=? ORDER BY created_at LIMIT 1", (finding_id,),
        ).fetchone()
    return str(row["case_id"]) if row else None


def _ensure_case(finding: Dict[str, Any], *, db_path: Optional[str]) -> Dict[str, Any]:
    existing = _existing_case(str(finding["finding_id"]), db_path=db_path)
    if existing:
        return get_case(existing, db_path=db_path)
    package = _clean(finding.get("package"), 512)
    ecosystem = _clean(finding.get("ecosystem"), 80).lower()
    version = _clean(finding.get("new_version") or finding.get("version"), 160)
    case = create_case(
        title=f"Investigate {ecosystem}:{package}@{version}",
        summary=_clean(finding.get("summary") or finding.get("title"), 8000),
        case_type="malicious_package", severity=_clean(finding.get("severity"), 20).lower() or "high",
        confidence=0, owner="SecOpsAI investigation autopilot", db_path=db_path,
        metadata={"origin": "canonical_finding", "finding_id": finding["finding_id"], "automation": True},
    )
    case = add_subject(
        case["case_id"], subject_type="package", name=package, ecosystem=ecosystem,
        version=version, publisher=_clean(finding.get("publisher"), 240),
        metadata={
            "origin_finding_id": finding["finding_id"],
            "reference_identifier": _clean(finding.get("reference_package"), 512),
            "reference_version": _clean(finding.get("old_version") or finding.get("previous_version"), 160),
        }, actor="secopsai-investigation-autopilot", db_path=db_path,
    )
    evidence_payload = minimize({
        "finding_id": finding.get("finding_id"), "title": finding.get("title"),
        "summary": finding.get("summary"), "rule_ids": finding.get("rule_ids") or [],
        "event_ids": finding.get("event_ids") or [], "evidence": finding.get("evidence") or {},
    })
    case = add_evidence(
        case["case_id"], evidence_type="source", title=f"Originating finding {finding['finding_id']}",
        locator=f"secopsai-finding:{finding['finding_id']}", provenance="SecOpsAI canonical finding",
        notes="Normalized lead evidence; this record is not proof of package behavior.",
        sha256=hashlib.sha256(_json(evidence_payload).encode()).hexdigest(),
        metadata=evidence_payload, actor="secopsai-investigation-autopilot", db_path=db_path,
    )
    return link_finding(case["case_id"], str(finding["finding_id"]), relationship="derived_from", actor="secopsai-investigation-autopilot", db_path=db_path)


def _set_run(run_id: str, *, status: str, stage: str, db_path: Optional[str],
             case_id: Optional[str] = None, pipeline_id: Optional[str] = None,
             blocker_code: Optional[str] = None, blocker_message: Optional[str] = None,
             retryable: bool = True, evidence: Optional[Dict[str, Any]] = None,
             decision: Optional[Dict[str, Any]] = None, completed: bool = False) -> None:
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE investigation_autopilot_runs SET status=?, current_stage=?,
            last_successful_stage=CASE WHEN ? IN ('failed','blocked') THEN last_successful_stage ELSE ? END,
            case_id=COALESCE(?, case_id), pipeline_id=COALESCE(?, pipeline_id),
            blocker_code=?, blocker_message=?, retryable=?,
            evidence_summary_json=COALESCE(?, evidence_summary_json),
            decision_json=COALESCE(?, decision_json), started_at=COALESCE(started_at, ?),
            completed_at=CASE WHEN ? THEN ? ELSE completed_at END, updated_at=? WHERE run_id=?""",
            (
                status, stage, status, stage, case_id, pipeline_id, blocker_code,
                blocker_message, int(retryable), _json(evidence) if evidence is not None else None,
                _json(decision) if decision is not None else None, now, int(completed), now, now, run_id,
            ),
        )
        connection.commit()


def run_due(*, db_path: Optional[str] = None, limit: int = 1) -> Dict[str, Any]:
    settings = get_settings(db_path=db_path)
    if settings["mode"] == "off":
        return {"status": "off", "processed": 0, "runs": []}
    backfill = enqueue_due_findings(db_path=db_path, limit=max(10, int(settings["max_active_runs"])))
    with closing(soc_store.connect(db_path)) as connection:
        active_count = int(connection.execute(
            "SELECT COUNT(*) FROM investigation_autopilot_runs WHERE status IN ('collecting','analyzing','awaiting_model')"
        ).fetchone()[0])
        capacity = max(0, int(settings["max_active_runs"]) - active_count)
        rows = connection.execute(
            "SELECT run_id FROM investigation_autopilot_runs WHERE status='queued' ORDER BY created_at LIMIT ?",
            (min(max(1, int(limit)), capacity) if capacity else 0,),
        ).fetchall()
    results = []
    for row in rows:
        results.append(_run(str(row["run_id"]), db_path=db_path))
    return {"status": "completed", "processed": len(results), "runs": results, "backfill": backfill}


def _run(run_id: str, *, db_path: Optional[str]) -> Dict[str, Any]:
    run = get_run(run_id, db_path=db_path)
    finding = soc_store.get_finding(run["finding_id"], db_path)
    if finding is None:
        _set_run(run_id, status="failed", stage="finding", blocker_code="finding_missing",
                 blocker_message="The canonical finding no longer exists.", retryable=False, completed=True, db_path=db_path)
        return get_run(run_id, db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("UPDATE investigation_autopilot_runs SET attempt=attempt+1 WHERE run_id=?", (run_id,))
        connection.commit()
    try:
        _set_run(run_id, status="collecting", stage="case_promotion", db_path=db_path)
        case = _ensure_case(finding, db_path=db_path)
        reference_version = _clean(finding.get("old_version") or finding.get("previous_version"), 160)
        reference_package = _clean(finding.get("reference_package"), 512)
        if reference_version and not reference_package:
            reference_package = _clean(finding.get("package"), 512)
        _set_run(run_id, status="analyzing", stage="safe_intake", case_id=case["case_id"], db_path=db_path)
        pipeline = start_investigation_pipeline(
            case["case_id"], reference_ecosystem=_clean(finding.get("ecosystem"), 80),
            reference_package=reference_package, reference_version=reference_version,
            actor="secopsai-investigation-autopilot", db_path=db_path, auto_enrich=True,
        )
        next_status = "awaiting_model" if pipeline["status"] == "awaiting_ai" else pipeline["status"]
        blocker = None
        blocker_code = None
        if pipeline.get("summary", {}).get("comparison_input_required"):
            blocker = "No verified comparison package/version is available; SecOpsAI did not guess one."
            blocker_code = "comparison_reference_missing"
        if pipeline["status"] == "failed":
            blocker = _clean(pipeline.get("error_message") or "The evidence pipeline failed safely.", 2000)
            if "HTTP 404" in blocker:
                next_status = "evidence_gap"
                blocker_code = "artifact_unavailable"
            else:
                blocker_code = _clean(pipeline.get("error_code") or "pipeline_failed", 120)
        _set_run(
            run_id, status=next_status, stage=pipeline.get("current_step") or "pipeline",
            case_id=case["case_id"], pipeline_id=pipeline["pipeline_id"],
            blocker_code=blocker_code,
            blocker_message=blocker, retryable=True,
            evidence={"pipeline": pipeline.get("summary") or {}, "case_id": case["case_id"]},
            db_path=db_path,
        )
    except Exception as exc:
        current = get_run(run_id, db_path=db_path)
        maxed = int(current.get("attempt") or 0) >= int(get_settings(db_path=db_path)["max_attempts"])
        _set_run(
            run_id, status="failed", stage=current.get("current_stage") or "pipeline",
            blocker_code="investigation_failed", blocker_message=_clean(exc, 2000),
            retryable=not maxed, completed=maxed, db_path=db_path,
        )
    return get_run(run_id, db_path=db_path)


def reconcile_pipeline(pipeline_id: str, *, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT run_id FROM investigation_autopilot_runs WHERE pipeline_id=?", (pipeline_id,)).fetchone()
    if not row:
        return None
    run_id = str(row["run_id"])
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    summary = pipeline.get("summary") or {}
    resolution = summary.get("agent_resolution") if isinstance(summary.get("agent_resolution"), dict) else {}
    verdict = _clean(summary.get("agent_verdict"), 40)
    status = "awaiting_model"
    completed = False
    blocker_code = None
    blocker_message = None
    if pipeline["status"] == "failed":
        status = "failed"
        blocker_code = _clean(pipeline.get("error_code") or "pipeline_failed", 120)
        blocker_message = _clean(pipeline.get("error_message") or "The evidence pipeline failed safely.", 2000)
        if "HTTP 404" in blocker_message:
            status = "evidence_gap"
            blocker_code = "artifact_unavailable"
    elif pipeline["status"] == "succeeded":
        if verdict in {"credible", "likely"}:
            status = "escalated"
        elif resolution.get("status") == "applied":
            status = "resolved"
        else:
            status = "evidence_gap"
        completed = status in {"resolved", "escalated"}
    _set_run(
        run_id, status=status, stage=pipeline.get("current_step") or "pipeline",
        evidence={"pipeline": summary, "review_summary": pipeline.get("review_summary") or {}},
        decision={"verdict": verdict, "confidence": summary.get("agent_verdict_confidence"), "resolution": resolution},
        blocker_code=blocker_code or ("evidence_incomplete" if status == "evidence_gap" else None),
        blocker_message=blocker_message or ("The available evidence does not support a final automatic resolution." if status == "evidence_gap" else None),
        retryable=status in {"failed", "evidence_gap"}, completed=completed, db_path=db_path,
    )
    return get_run(run_id, db_path=db_path)


def retry(run_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    run = get_run(run_id, db_path=db_path)
    if not run.get("retryable"):
        raise ValueError("this investigation is not retryable")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "UPDATE investigation_autopilot_runs SET status='queued', current_stage='queued', blocker_code=NULL, blocker_message=NULL, completed_at=NULL, updated_at=? WHERE run_id=?",
            (soc_store.utc_now(), run_id),
        )
        connection.commit()
    return get_run(run_id, db_path=db_path)


def cancel(run_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    run = get_run(run_id, db_path=db_path)
    if run["status"] not in ACTIVE and run["status"] != "failed":
        return run
    _set_run(run_id, status="canceled", stage="canceled", blocker_code="operator_canceled",
             blocker_message="Canceled by operator.", retryable=True, completed=True, db_path=db_path)
    return get_run(run_id, db_path=db_path)


def get_run(run_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM investigation_autopilot_runs WHERE run_id=?", (_clean(run_id, 40).upper(),)).fetchone()
    if row is None:
        raise ValueError(f"investigation autopilot run not found: {run_id}")
    result = dict(row)
    result["schema_version"] = SCHEMA_VERSION
    result["evidence_summary"] = _decode(result.pop("evidence_summary_json"), {})
    result["decision"] = _decode(result.pop("decision_json"), {})
    result["retryable"] = bool(result.get("retryable"))
    return result


def list_runs(*, status: str = "", limit: int = 100, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    soc_store.init_db(db_path)
    where, params = (" WHERE status=?", [_clean(status, 40)]) if status else ("", [])
    params.append(max(1, min(int(limit), 500)))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(f"SELECT run_id FROM investigation_autopilot_runs{where} ORDER BY updated_at DESC LIMIT ?", tuple(params)).fetchall()
    return [get_run(str(row["run_id"]), db_path=db_path) for row in rows]


def status(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    runs = list_runs(limit=200, db_path=db_path)
    states = {name: sum(run["status"] == name for run in runs) for name in {
        "queued", "collecting", "analyzing", "awaiting_model", "awaiting_input",
        "awaiting_sandbox", "evidence_gap", "resolved", "escalated", "failed", "canceled",
    }}
    return {"schema_version": SCHEMA_VERSION, "settings": get_settings(db_path=db_path), "summary": states, "runs": runs}
