"""Guarded, reversible agent resolution for completed research pipelines."""

from __future__ import annotations

import hashlib
import json
import secrets
from contextlib import closing
from typing import Any, Dict, Optional

import soc_store
from secopsai.research_cases import get_case, retract_item, update_case
from secopsai.research_pipeline import get_pipeline


SCHEMA_VERSION = "secopsai.research.agent-resolution.v1"
MODES = {"off", "advisory", "guarded"}
ELIGIBLE_VERDICTS = {"not_substantiated", "benign"}
DEFAULTS = {
    "mode": "advisory",
    "min_confidence": 90,
    "min_evidence_refs": 4,
    "max_cases_per_cycle": 10,
    "auto_retract_rules": True,
}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, default: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def _clean(value: Any, limit: int = 4000) -> str:
    return str(value or "").strip()[:limit]


def get_settings(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_resolution_settings WHERE settings_id = 1").fetchone()
        if row is None:
            now = soc_store.utc_now()
            connection.execute(
                """INSERT INTO research_resolution_settings
                   (settings_id, mode, min_confidence, min_evidence_refs,
                    max_cases_per_cycle, auto_retract_rules, updated_at, updated_by)
                   VALUES (1, ?, ?, ?, ?, ?, ?, 'secopsai-default')""",
                (
                    DEFAULTS["mode"], DEFAULTS["min_confidence"], DEFAULTS["min_evidence_refs"],
                    DEFAULTS["max_cases_per_cycle"], int(DEFAULTS["auto_retract_rules"]), now,
                ),
            )
            connection.commit()
            row = connection.execute("SELECT * FROM research_resolution_settings WHERE settings_id = 1").fetchone()
    result = dict(row or {})
    result["schema_version"] = SCHEMA_VERSION
    result["auto_retract_rules"] = bool(result.get("auto_retract_rules"))
    return result


def update_settings(
    *,
    mode: Optional[str] = None,
    min_confidence: Optional[int] = None,
    min_evidence_refs: Optional[int] = None,
    max_cases_per_cycle: Optional[int] = None,
    auto_retract_rules: Optional[bool] = None,
    actor: str = "operator",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    current = get_settings(db_path=db_path)
    next_mode = _clean(mode if mode is not None else current["mode"], 20).lower()
    confidence = int(min_confidence if min_confidence is not None else current["min_confidence"])
    refs = int(min_evidence_refs if min_evidence_refs is not None else current["min_evidence_refs"])
    limit = int(max_cases_per_cycle if max_cases_per_cycle is not None else current["max_cases_per_cycle"])
    retract = bool(auto_retract_rules if auto_retract_rules is not None else current["auto_retract_rules"])
    if next_mode not in MODES:
        raise ValueError("research resolution mode must be off, advisory, or guarded")
    if not 85 <= confidence <= 100:
        raise ValueError("research resolution confidence must be between 85 and 100")
    if not 2 <= refs <= 20:
        raise ValueError("research resolution evidence references must be between 2 and 20")
    if not 1 <= limit <= 100:
        raise ValueError("research resolution cycle limit must be between 1 and 100")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE research_resolution_settings SET mode = ?, min_confidence = ?,
               min_evidence_refs = ?, max_cases_per_cycle = ?, auto_retract_rules = ?,
               updated_at = ?, updated_by = ? WHERE settings_id = 1""",
            (next_mode, confidence, refs, limit, int(retract), soc_store.utc_now(), _clean(actor, 160) or "operator"),
        )
        connection.commit()
    return get_settings(db_path=db_path)


def _fingerprint(case: Dict[str, Any], pipeline: Dict[str, Any], verdict: Dict[str, Any]) -> str:
    payload = {
        "case_id": case["case_id"],
        "case_updated_at": case.get("updated_at"),
        "pipeline_id": pipeline["pipeline_id"],
        "pipeline_revision": pipeline.get("revision"),
        "verdict_id": verdict.get("verdict_id"),
        "verdict": verdict.get("verdict"),
        "confidence": verdict.get("confidence"),
        "evidence_ids": verdict.get("evidence_ids") or [],
    }
    return hashlib.sha256(_json(payload).encode()).hexdigest()


def _decision(case: Dict[str, Any], pipeline: Dict[str, Any], verdict: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    reasons: list[str] = []
    evidence = [item for item in case.get("evidence") or [] if item.get("status") == "active"]
    evidence_by_id = {str(item.get("evidence_id")): item for item in evidence if item.get("evidence_id")}
    cited = [value for value in verdict.get("evidence_ids") or [] if value in evidence_by_id]
    evidence_types = {str(evidence_by_id[value].get("evidence_type") or "") for value in cited}
    active_iocs = [item for item in case.get("iocs") or [] if item.get("status") == "active" and int(item.get("confidence") or 0) >= 80]
    pending = [item for item in pipeline.get("review_items") or [] if item.get("status") in {"pending", "applying"}]
    accepted_unsupported = [
        item for item in pipeline.get("review_items") or []
        if item.get("item_type") == "unsupported_claim" and item.get("status") == "accepted"
    ]
    sandbox_threat = any(
        item.get("status") in {"completed", "succeeded"}
        and any(token in _json(item.get("result") or {}).lower() for token in ("malicious", "credential theft", "exfiltration"))
        for item in case.get("sandbox_requests") or []
    )
    linked_findings = case.get("findings") or []
    if pipeline.get("status") != "succeeded":
        reasons.append("the investigation pipeline is not complete")
    if verdict.get("verdict") not in ELIGIBLE_VERDICTS:
        reasons.append("the agent verdict is not eligible for automatic closure")
    if int(verdict.get("confidence") or 0) < int(settings["min_confidence"]):
        reasons.append("agent confidence is below the configured closure threshold")
    if len(cited) < int(settings["min_evidence_refs"]):
        reasons.append("the verdict does not cite enough active case evidence")
    if not {"package_artifact", "static_analysis"}.issubset(evidence_types):
        reasons.append("cited evidence must include both package artifact and static analysis records")
    if pending:
        reasons.append("pipeline review items remain unresolved")
    if verdict.get("verdict") == "not_substantiated" and not accepted_unsupported:
        reasons.append("not-substantiated closure requires an accepted unsupported-claim assessment")
    if verdict.get("verdict") == "benign" and not any(item.get("evidence_type") == "sandbox_analysis" for item in evidence):
        reasons.append("a benign verdict requires independently reviewed sandbox evidence")
    if active_iocs:
        reasons.append("high-confidence active IOCs require analyst review")
    if sandbox_threat:
        reasons.append("sandbox evidence contains a potential malicious-behavior signal")
    # Linked findings are reconciled in the same guarded resolution workflow;
    # their existence no longer creates a permanent manual-only dead end.
    if case.get("disclosure_status") not in {"not_started", "not_required"}:
        reasons.append("an active disclosure workflow prevents automatic closure")
    return {
        "eligible": not reasons,
        "guardrail_reasons": reasons,
        "validated_evidence_refs": cited,
        "evidence_types": sorted(evidence_types),
        "active_high_confidence_iocs": len(active_iocs),
        "pending_review_items": len(pending),
        "publication_approved": False,
        "disclosure_sent": False,
    }


def adjudicate_pipeline(
    pipeline_id: str,
    *,
    actor: str = "secopsai-agent-resolution",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    settings = get_settings(db_path=db_path)
    pipeline = get_pipeline(pipeline_id, db_path=db_path)
    case = get_case(pipeline["case_id"], db_path=db_path)
    verdicts = case.get("verdicts") or []
    if not verdicts:
        raise ValueError("agent resolution requires an evidence-linked verdict")
    verdict = verdicts[0]
    fingerprint = _fingerprint(case, pipeline, verdict)
    with closing(soc_store.connect(db_path)) as connection:
        existing = connection.execute(
            "SELECT run_id FROM research_resolution_runs WHERE case_id = ? AND case_fingerprint = ?",
            (case["case_id"], fingerprint),
        ).fetchone()
    if existing:
        return get_run(str(existing["run_id"]), db_path=db_path)
    decision = _decision(case, pipeline, verdict, settings)
    status = "blocked"
    if settings["mode"] == "off":
        decision["guardrail_reasons"].append("agent research resolution is disabled")
        decision["eligible"] = False
    elif decision["eligible"]:
        status = "recommended" if settings["mode"] != "guarded" else "applied"
    rollback = {
        "status": case.get("status"),
        "severity": case.get("severity"),
        "confidence": case.get("confidence"),
        "disclosure_status": case.get("disclosure_status"),
        "summary": case.get("summary"),
        "rule_ids": [],
        "findings": [],
    }
    run_id = _id("ARR")
    now = soc_store.utc_now()
    if status == "applied":
        rationale = _clean(verdict.get("rationale"), 2400)
        summary = (
            f"Agent resolution: {str(verdict['verdict']).replace('_', ' ')} at {int(verdict.get('confidence') or 0)}% confidence. "
            f"{rationale} No disclosure or publication action was taken. Reopen this case if material new evidence appears."
        )[:8000]
        if settings["auto_retract_rules"]:
            for rule in case.get("rules") or []:
                if rule.get("status") != "active":
                    continue
                rollback["rule_ids"].append(rule["rule_id"])
                retract_item(
                    case["case_id"], item_type="rule", item_id=rule["rule_id"],
                    reason=f"Automatically retracted by {run_id}: the case was closed as {verdict['verdict']}; active detection would risk unsupported alerts.",
                    actor=actor, db_path=db_path,
                )
        update_case(
            case["case_id"], status="closed", severity="info", confidence=int(verdict.get("confidence") or 0),
            disclosure_status="not_required", summary=summary, actor=actor, db_path=db_path,
        )
        for linked in case.get("findings") or []:
            finding_id = str(linked.get("finding_id") or "")
            finding = soc_store.get_finding(finding_id, db_path)
            if finding is None:
                continue
            rollback["findings"].append({
                "finding_id": finding_id,
                "status": finding.get("status"),
                "disposition": finding.get("disposition"),
            })
            soc_store.set_finding_disposition(finding_id, "false_positive", db_path)
            soc_store.set_finding_status(finding_id, "closed", db_path)
            soc_store.add_note(
                finding_id, actor,
                f"Closed reversibly by research resolution {run_id}: {verdict['verdict']} with evidence-gated confidence {int(verdict.get('confidence') or 0)}%.",
                db_path,
            )
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_resolution_runs
               (run_id, case_id, pipeline_id, case_fingerprint, status, verdict, confidence,
                decision_json, rollback_json, actor, created_at, updated_at, reviewed_at, reviewed_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
            (
                run_id, case["case_id"], pipeline_id, fingerprint, status, verdict["verdict"],
                int(verdict.get("confidence") or 0), _json(decision), _json(rollback), _clean(actor, 160), now, now,
            ),
        )
        connection.execute(
            "INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                case["case_id"], "agent_case_resolution", _clean(actor, 160),
                f"Agent resolution {run_id}: {status} ({verdict['verdict']}).",
                _json({"run_id": run_id, "status": status, "decision": decision}), now,
            ),
        )
        connection.commit()
    return get_run(run_id, db_path=db_path)


def get_run(run_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_resolution_runs WHERE run_id = ?", (_clean(run_id, 40).upper(),)).fetchone()
    if row is None:
        raise ValueError(f"research resolution run not found: {run_id}")
    result = dict(row)
    result["schema_version"] = SCHEMA_VERSION
    result["decision"] = _decode(result.pop("decision_json"), {})
    result["rollback"] = _decode(result.pop("rollback_json"), {})
    return result


def list_runs(*, status: str = "", limit: int = 100, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    soc_store.init_db(db_path)
    where = " WHERE status = ?" if status else ""
    params: list[Any] = [_clean(status, 40)] if status else []
    params.append(max(1, min(int(limit), 500)))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"SELECT run_id FROM research_resolution_runs{where} ORDER BY updated_at DESC LIMIT ?", tuple(params),
        ).fetchall()
    return [get_run(str(row["run_id"]), db_path=db_path) for row in rows]


def review_run(
    run_id: str,
    *,
    decision: str,
    actor: str = "operator",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    run = get_run(run_id, db_path=db_path)
    decision = _clean(decision, 20).lower()
    if decision not in {"accept", "reopen"}:
        raise ValueError("resolution review decision must be accept or reopen")
    if run["status"] not in {"applied", "recommended"}:
        raise ValueError("only an applied or recommended resolution can be reviewed")
    now = soc_store.utc_now()
    next_status = "reviewed"
    if decision == "reopen":
        rollback = run.get("rollback") or {}
        update_case(
            run["case_id"], status=rollback.get("status") or "validation",
            severity=rollback.get("severity") or "medium", confidence=int(rollback.get("confidence") or 0),
            disclosure_status=rollback.get("disclosure_status") or "not_started",
            summary=rollback.get("summary") or "Reopened for analyst review.", actor=actor, db_path=db_path,
        )
        with closing(soc_store.connect(db_path)) as connection:
            for rule_id in rollback.get("rule_ids") or []:
                connection.execute(
                    "UPDATE research_rules SET status = 'active' WHERE rule_id = ? AND case_id = ? AND validation_status = 'passed'",
                    (rule_id, run["case_id"]),
                )
            connection.commit()
        for finding in rollback.get("findings") or []:
            finding_id = str(finding.get("finding_id") or "")
            if finding_id and soc_store.get_finding(finding_id, db_path):
                soc_store.set_finding_disposition(finding_id, str(finding.get("disposition") or "unreviewed"), db_path)
                soc_store.set_finding_status(finding_id, str(finding.get("status") or "open"), db_path)
        next_status = "rolled_back"
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "UPDATE research_resolution_runs SET status = ?, reviewed_at = ?, reviewed_by = ?, updated_at = ? WHERE run_id = ?",
            (next_status, now, _clean(actor, 160) or "operator", now, run["run_id"]),
        )
        connection.execute(
            "INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (run["case_id"], "agent_resolution_reviewed", _clean(actor, 160), f"Agent resolution {run_id} review: {decision}.", _json({"run_id": run_id, "decision": decision}), now),
        )
        connection.commit()
    return get_run(run_id, db_path=db_path)


def status(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    runs = list_runs(limit=100, db_path=db_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "settings": get_settings(db_path=db_path),
        "summary": {
            "awaiting_review": sum(item["status"] in {"applied", "recommended"} for item in runs),
            "applied": sum(item["status"] == "applied" for item in runs),
            "blocked": sum(item["status"] == "blocked" for item in runs),
            "reviewed": sum(item["status"] == "reviewed" for item in runs),
            "rolled_back": sum(item["status"] == "rolled_back" for item in runs),
        },
        "runs": runs,
    }
