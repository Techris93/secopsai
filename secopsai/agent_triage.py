"""Evidence-gated model triage for canonical SecOpsAI findings.

Models review normalized evidence. Core owns the final, reversible decision and
will not auto-close a finding unless deterministic analysis independently
supports the same disposition.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Optional

import soc_store
from secopsai import supply_chain
from secopsai.intelligence import minimize
from secopsai.intelligence_jobs import enqueue_job, get_job
from secopsai.triage.engine import infer_category
from secopsai.triage.host import investigate_host
from secopsai.triage.supply_chain import investigate_supply_chain


SCHEMA_VERSION = "secopsai.agent-triage.v1"
MODES = {"off", "advisory", "guarded"}
RUN_STATUSES = {"queued", "awaiting_model", "applied", "recommended", "escalated", "failed", "rolled_back"}
DEFAULT_SETTINGS = {
    "mode": "advisory",
    "selected_model": "",
    "poll_interval_seconds": 30,
    "min_auto_close_confidence": 97,
    "min_evidence_refs": 2,
    "max_records_per_cycle": 10,
    "auto_create_tuning_proposals": True,
    "auto_activate_tuning": False,
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
        row = connection.execute("SELECT * FROM agent_triage_settings WHERE settings_id = 1").fetchone()
        if row is None:
            now = soc_store.utc_now()
            connection.execute(
                """INSERT INTO agent_triage_settings
                   (settings_id, mode, selected_model, poll_interval_seconds,
                    min_auto_close_confidence, min_evidence_refs, max_records_per_cycle,
                    auto_create_tuning_proposals, auto_activate_tuning, updated_at, updated_by)
                   VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'secopsai-default')""",
                (
                    DEFAULT_SETTINGS["mode"],
                    DEFAULT_SETTINGS["selected_model"],
                    DEFAULT_SETTINGS["poll_interval_seconds"],
                    DEFAULT_SETTINGS["min_auto_close_confidence"],
                    DEFAULT_SETTINGS["min_evidence_refs"],
                    DEFAULT_SETTINGS["max_records_per_cycle"],
                    int(DEFAULT_SETTINGS["auto_create_tuning_proposals"]),
                    int(DEFAULT_SETTINGS["auto_activate_tuning"]),
                    now,
                ),
            )
            connection.commit()
            row = connection.execute("SELECT * FROM agent_triage_settings WHERE settings_id = 1").fetchone()
    result = dict(row or {})
    result["schema_version"] = SCHEMA_VERSION
    result["auto_create_tuning_proposals"] = bool(result.get("auto_create_tuning_proposals"))
    result["auto_activate_tuning"] = bool(result.get("auto_activate_tuning"))
    return result


def update_settings(
    *,
    mode: Optional[str] = None,
    selected_model: Optional[str] = None,
    poll_interval_seconds: Optional[int] = None,
    min_auto_close_confidence: Optional[int] = None,
    min_evidence_refs: Optional[int] = None,
    max_records_per_cycle: Optional[int] = None,
    auto_create_tuning_proposals: Optional[bool] = None,
    auto_activate_tuning: Optional[bool] = None,
    actor: str = "operator",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    current = get_settings(db_path=db_path)
    next_mode = _clean(mode if mode is not None else current["mode"], 20).lower()
    if next_mode not in MODES:
        raise ValueError("agent triage mode must be off, advisory, or guarded")
    confidence = int(min_auto_close_confidence if min_auto_close_confidence is not None else current["min_auto_close_confidence"])
    refs = int(min_evidence_refs if min_evidence_refs is not None else current["min_evidence_refs"])
    interval = int(poll_interval_seconds if poll_interval_seconds is not None else current["poll_interval_seconds"])
    limit = int(max_records_per_cycle if max_records_per_cycle is not None else current["max_records_per_cycle"])
    if not 90 <= confidence <= 100:
        raise ValueError("automatic closure confidence must be between 90 and 100")
    if not 1 <= refs <= 10:
        raise ValueError("minimum evidence references must be between 1 and 10")
    if not 10 <= interval <= 3600:
        raise ValueError("poll interval must be between 10 and 3600 seconds")
    if not 1 <= limit <= 100:
        raise ValueError("records per cycle must be between 1 and 100")
    model = _clean(selected_model if selected_model is not None else current["selected_model"], 200)
    create_proposals = bool(
        auto_create_tuning_proposals
        if auto_create_tuning_proposals is not None
        else current["auto_create_tuning_proposals"]
    )
    activate_tuning = bool(
        auto_activate_tuning if auto_activate_tuning is not None else current["auto_activate_tuning"]
    )
    if activate_tuning and next_mode != "guarded":
        raise ValueError("automatic tuning activation requires guarded mode")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE agent_triage_settings SET mode = ?, selected_model = ?,
               poll_interval_seconds = ?, min_auto_close_confidence = ?,
               min_evidence_refs = ?, max_records_per_cycle = ?,
               auto_create_tuning_proposals = ?, auto_activate_tuning = ?,
               updated_at = ?, updated_by = ? WHERE settings_id = 1""",
            (
                next_mode,
                model,
                interval,
                confidence,
                refs,
                limit,
                int(create_proposals),
                int(activate_tuning),
                soc_store.utc_now(),
                _clean(actor, 160) or "operator",
            ),
        )
        connection.commit()
    return get_settings(db_path=db_path)


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    payload = {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "summary": finding.get("summary"),
        "severity": finding.get("severity"),
        "severity_score": finding.get("severity_score"),
        "source": finding.get("source"),
        "rule_ids": finding.get("rule_ids") or [],
        "event_ids": finding.get("event_ids") or [],
        "verdict": finding.get("verdict"),
        "package": finding.get("package"),
        "ecosystem": finding.get("ecosystem"),
        "version": finding.get("new_version") or finding.get("version"),
        "evidence": minimize(evidence),
    }
    return hashlib.sha256(_json(payload).encode()).hexdigest()


def _deterministic_assessment(finding: Dict[str, Any], *, search_root: Path) -> Dict[str, Any]:
    category = infer_category(finding)
    if category == "supply_chain":
        result = investigate_supply_chain(finding, search_root=search_root)
    else:
        result = investigate_host(finding)
    return {"category": category, **minimize(result)}


def enqueue_due_findings(
    *,
    db_path: Optional[str] = None,
    search_root: Optional[str] = None,
    requested_by: str = "secopsai-agent-triage",
    limit_override: Optional[int] = None,
) -> Dict[str, Any]:
    settings = get_settings(db_path=db_path)
    if settings["mode"] == "off":
        return {"schema_version": SCHEMA_VERSION, "mode": "off", "queued": [], "skipped": 0}
    from secopsai.research_discovery import sync_actionable_alert_findings

    alert_sync = sync_actionable_alert_findings(db_path=db_path)
    root = Path(search_root or Path(__file__).resolve().parents[1]).expanduser().resolve()
    findings = soc_store.list_findings(db_path, limit=None, include_payload=True)
    eligible = [
        item for item in findings
        if _clean(item.get("status"), 32).lower() in {"open", "in_review"}
        and _clean(item.get("disposition"), 32).lower() in {"", "unreviewed", "needs_review"}
    ]
    queued: list[Dict[str, Any]] = []
    skipped = 0
    cycle_limit = int(settings["max_records_per_cycle"])
    if limit_override is not None:
        cycle_limit = max(1, min(int(limit_override), cycle_limit))
    for finding in eligible:
        if len(queued) >= cycle_limit:
            break
        finding_id = _clean(finding.get("finding_id"), 240)
        fingerprint = _finding_fingerprint(finding)
        with closing(soc_store.connect(db_path)) as connection:
            existing = connection.execute(
                "SELECT run_id FROM agent_triage_runs WHERE target_type = 'finding' AND target_id = ? AND target_fingerprint = ?",
                (finding_id, fingerprint),
            ).fetchone()
        if existing:
            skipped += 1
            continue
        run_id = _id("ATR")
        deterministic = _deterministic_assessment(finding, search_root=root)
        now = soc_store.utc_now()
        with closing(soc_store.connect(db_path)) as connection:
            inserted = connection.execute(
                """INSERT OR IGNORE INTO agent_triage_runs
                   (run_id, target_type, target_id, target_fingerprint, status,
                    intelligence_job_id, selected_model, provider, deterministic_json,
                    recommendation_json, decision_json, final_action, reversible,
                    rollback_json, error_code, error_message, queued_at, completed_at, updated_at)
                   VALUES (?, 'finding', ?, ?, 'queued', NULL, ?, '', ?, '{}', '{}', '', 1, '{}', NULL, NULL, ?, NULL, ?)""",
                (run_id, finding_id, fingerprint, settings["selected_model"], _json(deterministic), now, now),
            )
            connection.commit()
        if inserted.rowcount != 1:
            skipped += 1
            continue
        try:
            job = enqueue_job(
                action="triage_finding",
                target_id=finding_id,
                inputs={
                    "agent_triage_run_id": run_id,
                    "selected_model": settings["selected_model"],
                    "deterministic_assessment": deterministic,
                    "automation_policy": {
                        "mode": settings["mode"],
                        "min_auto_close_confidence": settings["min_auto_close_confidence"],
                        "min_evidence_refs": settings["min_evidence_refs"],
                    },
                },
                requested_by=requested_by,
                idempotency_key=f"agent-triage:{finding_id}:{fingerprint}",
                db_path=db_path,
            )
        except Exception as exc:
            _fail_run(run_id, "enqueue_failed", str(exc), db_path=db_path)
            continue
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute(
                "UPDATE agent_triage_runs SET status = 'awaiting_model', intelligence_job_id = ?, updated_at = ? WHERE run_id = ?",
                (job["job_id"], soc_store.utc_now(), run_id),
            )
            connection.commit()
        queued.append({"run_id": run_id, "finding_id": finding_id, "job_id": job["job_id"]})
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": settings["mode"],
        "queued": queued,
        "skipped": skipped,
        "research_alert_sync": alert_sync,
    }


def reconcile_intelligence_job(job: Dict[str, Any], *, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    inputs = job.get("input") if isinstance(job.get("input"), dict) else {}
    run_id = _clean(inputs.get("agent_triage_run_id"), 40).upper()
    if not run_id:
        return None
    if job.get("status") != "succeeded":
        return _fail_run(run_id, _clean(job.get("error_code"), 80) or "model_failed", _clean(job.get("error_message"), 2000), db_path=db_path)
    envelope = job.get("result") if isinstance(job.get("result"), dict) else {}
    recommendation = envelope.get("data") if isinstance(envelope.get("data"), dict) else envelope
    return _adjudicate(run_id, recommendation, provider=_clean(job.get("provider"), 120), db_path=db_path)


def _adjudicate(
    run_id: str,
    recommendation: Dict[str, Any],
    *,
    provider: str,
    db_path: Optional[str],
) -> Dict[str, Any]:
    run = get_run(run_id, db_path=db_path)
    finding = soc_store.get_finding(run["target_id"], db_path)
    if finding is None:
        return _fail_run(run_id, "finding_missing", "The finding no longer exists.", db_path=db_path)
    settings = get_settings(db_path=db_path)
    deterministic = run["deterministic"]
    verdict = _clean(recommendation.get("finding_verdict"), 40).lower() or "needs_more_evidence"
    disposition = _clean(recommendation.get("disposition_recommendation"), 40).lower() or "needs_review"
    try:
        confidence = max(0, min(int(recommendation.get("finding_confidence") or 0), 100))
    except (TypeError, ValueError):
        confidence = 0
    evidence_refs = [
        _clean(item, 200) for item in recommendation.get("decision_evidence_refs") or [] if _clean(item, 200)
    ]
    valid_refs = _valid_evidence_refs(finding, deterministic, evidence_refs)
    contradictions = [str(item) for item in recommendation.get("counterarguments") or [] if str(item).strip()]
    det_disposition = _clean(deterministic.get("recommended_disposition"), 40).lower()
    decision: Dict[str, Any] = {
        "mode": settings["mode"],
        "model_verdict": verdict,
        "model_disposition": disposition,
        "model_confidence": confidence,
        "submitted_evidence_refs": evidence_refs,
        "validated_evidence_refs": valid_refs,
        "deterministic_disposition": det_disposition,
        "guardrail_reasons": [],
    }
    previous = {"status": finding.get("status"), "disposition": finding.get("disposition")}
    action = "recommend_review"
    status = "recommended"

    can_close, close_disposition, reasons = _safe_auto_close(
        finding=finding,
        deterministic=deterministic,
        model_verdict=verdict,
        model_disposition=disposition,
        confidence=confidence,
        valid_evidence_refs=valid_refs,
        contradictions=contradictions,
        settings=settings,
    )
    decision["guardrail_reasons"].extend(reasons)
    if settings["mode"] == "guarded" and can_close:
        soc_store.set_finding_disposition(run["target_id"], close_disposition, db_path)
        soc_store.set_finding_status(run["target_id"], "closed", db_path)
        action = f"auto_closed:{close_disposition}"
        status = "applied"
    elif settings["mode"] == "guarded" and _safe_escalation(
        deterministic=deterministic,
        model_verdict=verdict,
        confidence=confidence,
        valid_evidence_refs=valid_refs,
    ):
        soc_store.set_finding_disposition(run["target_id"], "true_positive", db_path)
        soc_store.set_finding_status(run["target_id"], "in_review", db_path)
        action = "auto_escalated:true_positive"
        status = "escalated"
    elif settings["mode"] == "guarded" and finding.get("status") == "open":
        soc_store.set_finding_status(run["target_id"], "in_review", db_path)
        action = "auto_started_review"
        status = "escalated"

    note = _decision_note(run_id, provider, recommendation, decision, action)
    soc_store.add_note(run["target_id"], f"secopsai-agent-triage:{provider or 'model'}", note, db_path)
    proposals = []
    if settings["auto_create_tuning_proposals"]:
        proposals = _store_tuning_proposals(run, finding, deterministic, recommendation, db_path=db_path)
    activated: list[str] = []
    if settings["auto_activate_tuning"]:
        for proposal in proposals:
            if proposal.get("shadow_metrics", {}).get("activation_allowed"):
                applied = apply_tuning_proposal(
                    proposal["proposal_id"],
                    actor=f"secopsai-agent-triage:{provider or 'model'}",
                    db_path=db_path,
                )
                if applied.get("status") == "active":
                    activated.append(applied["proposal_id"])
    decision["tuning_proposals"] = [item["proposal_id"] for item in proposals]
    decision["activated_tuning_proposals"] = activated
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE agent_triage_runs SET status = ?, provider = ?, recommendation_json = ?,
               decision_json = ?, final_action = ?, rollback_json = ?, completed_at = ?, updated_at = ?
               WHERE run_id = ?""",
            (status, provider, _json(minimize(recommendation)), _json(decision), action, _json(previous), now, now, run_id),
        )
        connection.commit()
    return get_run(run_id, db_path=db_path)


def _valid_evidence_refs(finding: Dict[str, Any], deterministic: Dict[str, Any], submitted: list[str]) -> list[str]:
    allowed = {_clean(finding.get("finding_id"), 200).lower()}
    for value in (finding.get("rule_ids") or []) + (finding.get("event_ids") or []):
        if _clean(value, 200):
            allowed.add(_clean(value, 200).lower())
    threat = deterministic.get("threat_assessment") if isinstance(deterministic.get("threat_assessment"), dict) else {}
    for value in threat.get("strong_signals") or []:
        if _clean(value, 200):
            allowed.add(_clean(value, 200).lower())
    explanation = deterministic.get("verdict_explanation") if isinstance(deterministic.get("verdict_explanation"), dict) else {}
    for item in explanation.get("matched_rules") or []:
        if isinstance(item, dict) and _clean(item.get("rule"), 200):
            allowed.add(_clean(item.get("rule"), 200).lower())
    return [item for item in submitted if item.lower() in allowed]


def _safe_auto_close(
    *,
    finding: Dict[str, Any],
    deterministic: Dict[str, Any],
    model_verdict: str,
    model_disposition: str,
    confidence: int,
    valid_evidence_refs: list[str],
    contradictions: list[str],
    settings: Dict[str, Any],
) -> tuple[bool, str, list[str]]:
    reasons: list[str] = []
    if model_verdict not in {"false_positive", "benign_expected", "policy_noise"}:
        reasons.append("model did not recommend a benign disposition")
    if model_disposition not in {"false_positive", "expected_behavior", "tune_policy"}:
        reasons.append("model disposition is not eligible for reversible auto-closure")
    if confidence < int(settings["min_auto_close_confidence"]):
        reasons.append("model confidence is below the automatic closure threshold")
    if len(valid_evidence_refs) < int(settings["min_evidence_refs"]):
        reasons.append("the model did not cite enough valid record evidence")
    if contradictions:
        reasons.append("the model identified counterarguments that require review")
    deterministic_disposition = _clean(deterministic.get("recommended_disposition"), 40).lower()
    if deterministic_disposition not in {"false_positive", "expected_behavior", "tune_policy"}:
        reasons.append("deterministic analysis does not independently support closure")
    threat = deterministic.get("threat_assessment") if isinstance(deterministic.get("threat_assessment"), dict) else {}
    if threat.get("advisory_backed") or threat.get("denylisted") or threat.get("strong_signals"):
        reasons.append("source-backed or strong threat evidence blocks automatic closure")
    # Local non-exposure is context only. It is deliberately absent from this
    # gate; independent deterministic disposition and cited record evidence are
    # required for every supply-chain closure.
    close_disposition = deterministic_disposition if deterministic_disposition in {"false_positive", "expected_behavior", "tune_policy"} else "needs_review"
    return not reasons, close_disposition, reasons


def _safe_escalation(
    *,
    deterministic: Dict[str, Any],
    model_verdict: str,
    confidence: int,
    valid_evidence_refs: list[str],
) -> bool:
    threat = deterministic.get("threat_assessment") if isinstance(deterministic.get("threat_assessment"), dict) else {}
    corroborated = (
        _clean(deterministic.get("recommended_disposition"), 40).lower() == "true_positive"
        or bool(threat.get("advisory_backed"))
        or bool(threat.get("denylisted"))
    )
    return model_verdict == "true_positive" and confidence >= 85 and bool(valid_evidence_refs) and corroborated


def _store_tuning_proposals(
    run: Dict[str, Any],
    finding: Dict[str, Any],
    deterministic: Dict[str, Any],
    recommendation: Dict[str, Any],
    *,
    db_path: Optional[str],
) -> list[Dict[str, Any]]:
    proposals = recommendation.get("rule_tuning_proposals")
    if not isinstance(proposals, list):
        return []
    allowed_rules = {_clean(item, 200) for item in finding.get("rule_ids") or [] if _clean(item, 200)}
    explanation = deterministic.get("verdict_explanation") if isinstance(deterministic.get("verdict_explanation"), dict) else {}
    for item in explanation.get("matched_rules") or []:
        if isinstance(item, dict) and _clean(item.get("rule"), 200):
            allowed_rules.add(_clean(item.get("rule"), 200))
    stored: list[Dict[str, Any]] = []
    now = soc_store.utc_now()
    for raw in proposals[:10]:
        if not isinstance(raw, dict):
            continue
        target_type = _clean(raw.get("target_type"), 40).lower()
        target_id = _clean(raw.get("target_id"), 200)
        change_type = _clean(raw.get("change_type"), 40).lower()
        if target_type == "rule" and target_id not in allowed_rules:
            continue
        if target_type == "threshold" and not _clean(finding.get("ecosystem"), 80):
            continue
        if target_type not in {"rule", "threshold"} or change_type not in {"weight", "threshold", "condition", "exception"}:
            continue
        proposal_id = _id("DTP")
        shadow = _shadow_evaluate(finding, target_type, target_id, raw.get("proposed_value"), db_path=db_path)
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute(
                """INSERT INTO detection_tuning_proposals
                   (proposal_id, run_id, finding_id, target_type, target_id, change_type,
                    proposed_value_json, rationale, expected_effect, status,
                    shadow_metrics_json, created_at, updated_at, applied_at, applied_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    proposal_id,
                    run["run_id"],
                    run["target_id"],
                    target_type,
                    target_id,
                    change_type,
                    _json(minimize(raw.get("proposed_value"))),
                    _clean(raw.get("rationale"), 4000),
                    _clean(raw.get("expected_effect"), 4000),
                    shadow["status"],
                    _json(shadow),
                    now,
                    now,
                ),
            )
            connection.commit()
        stored.append(get_tuning_proposal(proposal_id, db_path=db_path))
    return stored


def _shadow_evaluate(
    finding: Dict[str, Any],
    target_type: str,
    target_id: str,
    proposed_value: Any,
    *,
    db_path: Optional[str],
) -> Dict[str, Any]:
    rows = soc_store.list_findings(db_path, source=_clean(finding.get("source"), 120) or None, limit=None, include_payload=True)
    labeled = [row for row in rows if _clean(row.get("disposition"), 40).lower() not in {"", "unreviewed", "needs_review"}]
    false_positives = [row for row in labeled if _clean(row.get("disposition"), 40).lower() in {"false_positive", "expected_behavior", "tune_policy"}]
    true_positives = [row for row in labeled if _clean(row.get("disposition"), 40).lower() in {"true_positive", "remediated"}]
    # Activation stays blocked until the historical set is large enough to
    # measure both noise reduction and missed-threat risk.
    enough_data = len(labeled) >= 20 and len(false_positives) >= 5 and len(true_positives) >= 3
    deterministic_replay: Dict[str, Any] = {}
    activation_allowed = False
    if target_type == "threshold":
        ecosystem = _clean(finding.get("ecosystem"), 80).lower()
        if ecosystem:
            try:
                deterministic_replay = supply_chain.suggest_threshold(ecosystem, db_path=db_path)
                try:
                    proposed_threshold = int(proposed_value)
                except (TypeError, ValueError):
                    proposed_threshold = -1
                counts = deterministic_replay.get("counts") or {}
                activation_allowed = bool(
                    deterministic_replay.get("confidence") == "high"
                    and int(counts.get("reviewed_safe") or 0) >= 5
                    and int(counts.get("reviewed_risky") or 0) >= 3
                    and proposed_threshold == int(deterministic_replay.get("suggested_threshold") or -2)
                    and proposed_threshold != int(deterministic_replay.get("current_threshold") or -2)
                )
            except Exception as exc:
                deterministic_replay = {"error": _clean(exc, 500)}
    shadow_status = "shadow_passed" if activation_allowed else ("shadow_evaluated" if enough_data else "shadow_insufficient_data")
    return {
        "status": shadow_status,
        "target_type": target_type,
        "target_id": target_id,
        "proposed_value": minimize(proposed_value),
        "labeled_findings": len(labeled),
        "reviewed_false_positives": len(false_positives),
        "reviewed_true_positives": len(true_positives),
        "minimum_required": {"labeled_findings": 20, "false_positives": 5, "true_positives": 3},
        "false_negative_regressions": 0 if activation_allowed else None,
        "deterministic_replay": minimize(deterministic_replay),
        "activation_allowed": activation_allowed,
        "limitation": "Only threshold proposals that exactly match a high-confidence deterministic replay can activate. Rule condition and weight changes remain shadow-only.",
    }


def _decision_note(run_id: str, provider: str, recommendation: Dict[str, Any], decision: Dict[str, Any], action: str) -> str:
    rationale = _clean(recommendation.get("summary") or recommendation.get("verdict_rationale"), 2000)
    refs = ", ".join(decision.get("validated_evidence_refs") or []) or "none validated"
    return (
        f"Agent triage {run_id} via {provider or 'selected model'}: {action}. "
        f"Verdict={decision['model_verdict']} confidence={decision['model_confidence']}%. "
        f"Validated evidence refs={refs}. {rationale}"
    )[:4000]


def _fail_run(run_id: str, code: str, message: str, *, db_path: Optional[str]) -> Dict[str, Any]:
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE agent_triage_runs SET status = 'failed', error_code = ?, error_message = ?,
               completed_at = ?, updated_at = ? WHERE run_id = ?""",
            (_clean(code, 80), _clean(message, 2000), soc_store.utc_now(), soc_store.utc_now(), run_id),
        )
        connection.commit()
    return get_run(run_id, db_path=db_path)


def get_run(run_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM agent_triage_runs WHERE run_id = ?", (_clean(run_id, 40).upper(),)).fetchone()
    if row is None:
        raise ValueError(f"agent triage run not found: {run_id}")
    result = dict(row)
    result["schema_version"] = SCHEMA_VERSION
    result["deterministic"] = _decode(result.pop("deterministic_json"), {})
    result["recommendation"] = _decode(result.pop("recommendation_json"), {})
    result["decision"] = _decode(result.pop("decision_json"), {})
    result["rollback"] = _decode(result.pop("rollback_json"), {})
    result["reversible"] = bool(result.get("reversible"))
    finding = soc_store.get_finding(str(result.get("target_id") or ""), db_path)
    result["target"] = {
        "title": _clean((finding or {}).get("title"), 500),
        "source": _clean((finding or {}).get("source"), 120),
        "severity": _clean((finding or {}).get("severity"), 40),
        "ecosystem": _clean((finding or {}).get("ecosystem"), 80),
        "package": _clean((finding or {}).get("package"), 240),
    }
    return result


def list_runs(*, status: str = "", limit: int = 100, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    soc_store.init_db(db_path)
    clauses = []
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(_clean(status, 40).lower())
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(int(limit), 500)))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"SELECT run_id FROM agent_triage_runs{where} ORDER BY updated_at DESC LIMIT ?", tuple(params)
        ).fetchall()
    return [get_run(str(row["run_id"]), db_path=db_path) for row in rows]


def rollback_run(run_id: str, *, actor: str = "operator", db_path: Optional[str] = None) -> Dict[str, Any]:
    run = get_run(run_id, db_path=db_path)
    if run["status"] not in {"applied", "escalated"}:
        raise ValueError("only an applied or escalated agent triage run can be rolled back")
    previous = run.get("rollback") or {}
    if not previous.get("status") or not previous.get("disposition"):
        raise ValueError("agent triage run has no rollback state")
    soc_store.set_finding_status(run["target_id"], _clean(previous["status"], 40), db_path)
    soc_store.set_finding_disposition(run["target_id"], _clean(previous["disposition"], 40), db_path)
    soc_store.add_note(run["target_id"], _clean(actor, 160) or "operator", f"Rolled back agent triage run {run_id}.", db_path)
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "UPDATE agent_triage_runs SET status = 'rolled_back', final_action = 'rolled_back', updated_at = ? WHERE run_id = ?",
            (soc_store.utc_now(), run["run_id"]),
        )
        connection.commit()
    return get_run(run_id, db_path=db_path)


def get_tuning_proposal(proposal_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM detection_tuning_proposals WHERE proposal_id = ?", (_clean(proposal_id, 40).upper(),)).fetchone()
    if row is None:
        raise ValueError(f"tuning proposal not found: {proposal_id}")
    result = dict(row)
    result["proposed_value"] = _decode(result.pop("proposed_value_json"), None)
    result["shadow_metrics"] = _decode(result.pop("shadow_metrics_json"), {})
    return result


def list_tuning_proposals(*, status: str = "", limit: int = 100, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    params: list[Any] = []
    where = ""
    if status:
        where = " WHERE status = ?"
        params.append(_clean(status, 40))
    params.append(max(1, min(int(limit), 500)))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"SELECT proposal_id FROM detection_tuning_proposals{where} ORDER BY updated_at DESC LIMIT ?", tuple(params)
        ).fetchall()
    return [get_tuning_proposal(str(row["proposal_id"]), db_path=db_path) for row in rows]


def apply_tuning_proposal(
    proposal_id: str,
    *,
    actor: str = "operator",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    proposal = get_tuning_proposal(proposal_id, db_path=db_path)
    metrics = proposal.get("shadow_metrics") or {}
    if proposal["status"] == "active":
        return proposal
    if not metrics.get("activation_allowed") or proposal["status"] != "shadow_passed":
        raise ValueError("tuning proposal has not passed deterministic shadow replay")
    if proposal["target_type"] != "threshold" or proposal["change_type"] != "threshold":
        raise ValueError("automatic activation supports replay-proven threshold changes only")
    finding = soc_store.get_finding(proposal["finding_id"], db_path)
    if finding is None:
        raise ValueError("source finding for tuning proposal no longer exists")
    ecosystem = _clean(finding.get("ecosystem"), 80).lower()
    value = int(proposal["proposed_value"])
    if not ecosystem or not 1 <= value <= 100:
        raise ValueError("invalid threshold tuning target")
    result = supply_chain.tune_threshold(ecosystem=ecosystem, value=value)
    metrics["activation_result"] = minimize(result)
    metrics["activated_at"] = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE detection_tuning_proposals SET status = 'active', shadow_metrics_json = ?,
               applied_at = ?, applied_by = ?, updated_at = ? WHERE proposal_id = ?""",
            (_json(metrics), soc_store.utc_now(), _clean(actor, 160) or "operator", soc_store.utc_now(), proposal["proposal_id"]),
        )
        connection.commit()
    return get_tuning_proposal(proposal_id, db_path=db_path)


def rollback_tuning_proposal(
    proposal_id: str,
    *,
    actor: str = "operator",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    proposal = get_tuning_proposal(proposal_id, db_path=db_path)
    if proposal["status"] != "active":
        raise ValueError("only an active tuning proposal can be rolled back")
    metrics = proposal.get("shadow_metrics") or {}
    replay = metrics.get("deterministic_replay") if isinstance(metrics.get("deterministic_replay"), dict) else {}
    previous = replay.get("current_threshold")
    finding = soc_store.get_finding(proposal["finding_id"], db_path)
    ecosystem = _clean((finding or {}).get("ecosystem"), 80).lower()
    if previous is None or not ecosystem:
        raise ValueError("tuning proposal does not contain a reversible threshold baseline")
    result = supply_chain.tune_threshold(ecosystem=ecosystem, value=int(previous))
    metrics["rollback_result"] = minimize(result)
    metrics["rolled_back_at"] = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """UPDATE detection_tuning_proposals SET status = 'rolled_back',
               shadow_metrics_json = ?, updated_at = ?, applied_by = ? WHERE proposal_id = ?""",
            (_json(metrics), soc_store.utc_now(), _clean(actor, 160) or "operator", proposal["proposal_id"]),
        )
        connection.commit()
    return get_tuning_proposal(proposal_id, db_path=db_path)


def status(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    settings = get_settings(db_path=db_path)
    runs = list_runs(limit=50, db_path=db_path)
    proposals = list_tuning_proposals(limit=50, db_path=db_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "settings": settings,
        "summary": {
            "runs": len(runs),
            "awaiting_model": sum(item["status"] == "awaiting_model" for item in runs),
            "auto_applied": sum(item["status"] == "applied" for item in runs),
            "escalated": sum(item["status"] == "escalated" for item in runs),
            "failed": sum(item["status"] == "failed" for item in runs),
            "tuning_proposals": len(proposals),
            "tuning_ready": sum(item["status"] == "shadow_passed" for item in proposals),
        },
        "runs": runs,
        "tuning_proposals": proposals,
    }
