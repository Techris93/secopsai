from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from secopsai.adaptive_response import evaluate_adaptive_response
from secopsai import supply_chain as supply_chain_mod

from .engine import close_finding, investigate_finding, list_triage_findings, start_finding
from .policy import load_policy
from .queue import enqueue_action, get_action, list_actions, queue_path, update_action


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SUMMARY_DIR = ROOT / "reports" / "triage" / "orchestrator"


@dataclass
class OrchestrateResult:
    processed: int
    auto_applied: int
    queued: int
    findings: List[Dict[str, Any]]
    queue_path: str
    summary_json: str
    summary_markdown: str


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _report_paths(summary_dir: Optional[str] = None) -> tuple[Path, Path]:
    target = Path(summary_dir).expanduser().resolve() if summary_dir else DEFAULT_SUMMARY_DIR
    target.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return target / f"triage-orchestrator-{stamp}.json", target / f"triage-orchestrator-{stamp}.md"


def _safe_close_note(investigation: Dict[str, Any], finding: Dict[str, Any], disposition: str) -> str:
    package = finding.get("package")
    if disposition == "expected_behavior":
        if package:
            return f"Package {package} is not referenced in local dependency manifests; treating as ecosystem intelligence outside current risk boundary."
        return "Finding appears outside the current risk boundary based on native triage evidence."
    if disposition == "false_positive":
        if package:
            return f"Package {package} matches the local allowlist; closing as false_positive."
        return "Finding matches local allowlist or trusted policy state; closing as false_positive."
    return str(investigation.get("summary") or "Closed by triage orchestrator.")


def _queue_action(
    *,
    finding: Dict[str, Any],
    category: str,
    action_type: str,
    summary: str,
    payload: Dict[str, Any],
    investigation: Dict[str, Any],
    queue_file: Optional[str] = None,
) -> Dict[str, Any]:
    return enqueue_action(
        {
            "finding_id": finding.get("finding_id"),
            "category": category,
            "action_type": action_type,
            "summary": summary,
            "payload": payload,
            "recommended_disposition": investigation.get("recommended_disposition"),
            "confidence": investigation.get("confidence"),
            "requires_confirmation": True,
        },
        path=queue_file,
    )


def _planned_action_for(
    *,
    finding: Dict[str, Any],
    category: str,
    investigation: Dict[str, Any],
    queue_file: Optional[str] = None,
) -> Dict[str, Any]:
    recommended = str(investigation.get("recommended_disposition") or "needs_review")
    dependency_present = bool(investigation.get("dependency_presence", {}).get("present"))
    policy = investigation.get("policy") or {}
    explanation = investigation.get("verdict_explanation") or {}
    score = explanation.get("score")
    threshold = explanation.get("effective_threshold")
    matched_rules = explanation.get("matched_rules") or []

    if category == "supply_chain":
        if recommended == "expected_behavior":
            return {"kind": "auto_close", "disposition": "expected_behavior"}
        if recommended == "false_positive" and policy.get("allow_matches"):
            return {"kind": "auto_close", "disposition": "false_positive"}
        if recommended == "false_positive":
            summary = "Package appears low-risk but is not allowlisted yet; analyst should confirm whether to add it to allowlist."
            queued = _queue_action(
                finding=finding,
                category=category,
                action_type="allowlist_package",
                summary=summary,
                payload={
                    "ecosystem": finding.get("ecosystem"),
                    "package": finding.get("package"),
                    "finding_id": finding.get("finding_id"),
                },
                investigation=investigation,
                queue_file=queue_file,
            )
            return {"kind": "queued", "action": queued}
        if recommended == "needs_review" and dependency_present:
            queued = _queue_action(
                finding=finding,
                category=category,
                action_type="close_finding",
                summary="Package is present locally and needs explicit analyst review before closure.",
                payload={
                    "finding_id": finding.get("finding_id"),
                    "disposition": "needs_review",
                    "status": "triaged",
                    "note": "Strong rule hits require manual package/report review before downgrade or closure.",
                },
                investigation=investigation,
                queue_file=queue_file,
            )
            return {"kind": "queued", "action": queued}
        weak_rule_names = [
            str(rule.get("rule") or "")
            for rule in matched_rules
            if str(rule.get("rule") or "").strip()
        ]
        if recommended in {"false_positive", "expected_behavior"} and score is not None and threshold is not None and score <= threshold + 1:
            queued = _queue_action(
                finding=finding,
                category=category,
                action_type="tune_threshold",
                summary="Borderline score suggests ecosystem threshold tuning may reduce noise without muting stronger malicious packages.",
                payload={
                    "ecosystem": finding.get("ecosystem"),
                    "value": int(threshold) + 1,
                },
                investigation=investigation,
                queue_file=queue_file,
            )
            return {"kind": "queued", "action": queued}
        if weak_rule_names and recommended in {"false_positive", "expected_behavior"}:
            queued = _queue_action(
                finding=finding,
                category=category,
                action_type="tune_rule",
                summary="Weak heuristic noise suggests a rule-weight adjustment should be reviewed by an analyst.",
                payload={
                    "rule_name": weak_rule_names[0],
                    "weight": 1,
                },
                investigation=investigation,
                queue_file=queue_file,
            )
            return {"kind": "queued", "action": queued}

    if recommended == "tune_policy":
        queued = _queue_action(
            finding=finding,
            category=category,
            action_type="close_finding",
            summary="Finding pattern suggests policy tuning rather than incident escalation.",
            payload={
                "finding_id": finding.get("finding_id"),
                "disposition": "tune_policy",
                "status": "triaged",
                "note": investigation.get("summary") or "Repeated benign pattern; review policy or exception path.",
            },
            investigation=investigation,
            queue_file=queue_file,
        )
        return {"kind": "queued", "action": queued}

    queued = _queue_action(
        finding=finding,
        category=category,
        action_type="close_finding",
        summary="Finding requires explicit analyst decision before closure.",
        payload={
            "finding_id": finding.get("finding_id"),
            "disposition": recommended,
            "status": "triaged",
            "note": investigation.get("summary") or "Escalated by triage orchestrator for manual review.",
        },
        investigation=investigation,
        queue_file=queue_file,
    )
    return {"kind": "queued", "action": queued}


def apply_action(
    action_id: str,
    *,
    queue_file: Optional[str] = None,
    db_path: Optional[str] = None,
    author: Optional[str] = None,
    yes: bool = False,
) -> Dict[str, Any]:
    action = get_action(action_id, queue_file)
    if not action:
        raise ValueError(f"action not found: {action_id}")
    if str(action.get("status") or "").lower() == "applied":
        return action
    if not yes:
        raise ValueError("apply-action requires --yes for execution")

    payload = action.get("payload") or {}
    action_type = str(action.get("action_type") or "")
    result: Dict[str, Any]
    if action_type == "close_finding":
        result = close_finding(
            str(payload.get("finding_id") or action.get("finding_id")),
            disposition=str(payload.get("disposition") or action.get("recommended_disposition") or "needs_review"),
            note=str(payload.get("note") or action.get("summary") or "Applied queued triage action."),
            status=str(payload.get("status") or "triaged"),
            author=author,
            db_path=db_path,
        )
    elif action_type == "allowlist_package":
        result = supply_chain_mod.allowlist_add(
            ecosystem=str(payload.get("ecosystem") or ""),
            package=str(payload.get("package") or ""),
        )
        if payload.get("finding_id"):
            close_finding(
                str(payload["finding_id"]),
                disposition="false_positive",
                note=f"Verified trusted package {payload.get('package')}; added to allowlist.",
                author=author,
                status="closed",
                db_path=db_path,
            )
        if action.get("requires_confirmation"):
            supply_chain_mod.reconcile_history()
    elif action_type == "tune_rule":
        result = supply_chain_mod.tune_rule(
            str(payload.get("rule_name") or ""),
            weight=payload.get("weight"),
            enabled=payload.get("enabled"),
        )
        if load_policy().get("safety", {}).get("reconcile_on_policy_change", True):
            supply_chain_mod.reconcile_history()
    elif action_type == "tune_threshold":
        result = supply_chain_mod.tune_threshold(
            ecosystem=payload.get("ecosystem"),
            package=payload.get("package"),
            global_threshold=payload.get("global_threshold"),
            value=int(payload.get("value")),
        )
        if load_policy().get("safety", {}).get("reconcile_on_policy_change", True):
            supply_chain_mod.reconcile_history()
    else:
        raise ValueError(f"Unsupported action type: {action_type}")

    updated = update_action(
        action_id,
        {
            "status": "applied",
            "applied_at": _utc_now(),
            "applied_by": author or os.environ.get("USER", "analyst"),
            "result": result,
        },
        path=queue_file,
    )
    return updated


def _write_summary(payload: Dict[str, Any], summary_dir: Optional[str] = None) -> Dict[str, str]:
    json_path, md_path = _report_paths(summary_dir)
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        "# SecOpsAI Triage Orchestrator Summary",
        "",
        f"- Generated At: {payload.get('generated_at')}",
        f"- Processed: {payload.get('processed')}",
        f"- Auto Applied: {payload.get('auto_applied')}",
        f"- Queued: {payload.get('queued')}",
        f"- Queue Path: {payload.get('queue_path')}",
        "",
        "## Adaptive Response",
        "",
        f"- Response Posture: {(payload.get('adaptive_response') or {}).get('response_posture', {}).get('mode')}",
        f"- Sensitivity Multiplier: {(payload.get('adaptive_response') or {}).get('response_posture', {}).get('sensitivity_multiplier')}",
        f"- Loop: {' -> '.join((payload.get('adaptive_response') or {}).get('loop', []))}",
        "",
        "## Findings",
        "",
    ]
    for item in payload.get("findings", []):
        lines.extend(
            [
                f"### {item.get('finding_id')}",
                "",
                f"- Category: {item.get('category')}",
                f"- Recommended Disposition: {item.get('recommended_disposition')}",
                f"- Outcome: {item.get('outcome')}",
                f"- Confidence: {item.get('confidence')}",
                f"- Summary: {item.get('summary')}",
                "",
            ]
        )
    md_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return {"summary_json": str(json_path), "summary_markdown": str(md_path)}


def generate_summary(
    *,
    db_path: Optional[str] = None,
    queue_file: Optional[str] = None,
    summary_dir: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    findings = list_triage_findings(db_path=db_path, limit=1_000_000)
    queued = list_actions(path=queue_file, status="pending", limit=1000)
    applied = list_actions(path=queue_file, status="applied", limit=1000)
    severity_counts: Dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    response_layer = evaluate_adaptive_response(findings)
    payload = {
        "generated_at": _utc_now(),
        "open_findings": len([f for f in findings if str(f.get("status") or "").lower() == "open"]),
        "in_review_findings": len([f for f in findings if str(f.get("status") or "").lower() == "in_review"]),
        "severity_counts": severity_counts,
        "pending_actions": len(queued),
        "applied_actions": len(applied),
        "queue_path": str(queue_path(queue_file)),
        "adaptive_response": {
            "design_principle": response_layer["design_principle"],
            "loop": response_layer["loop"],
            "response_posture": response_layer["response_posture"],
            "priority_routing": response_layer["priority_routing"],
            "validation_probes": response_layer["validation_probes"],
            "deception_controls": response_layer["deception_controls"],
        },
        "findings": findings[:limit],
    }
    payload.update(_write_summary(payload, summary_dir))
    return payload


def orchestrate_findings(
    *,
    finding_ids: Optional[List[str]] = None,
    db_path: Optional[str] = None,
    search_root: Optional[str] = None,
    report_dir: Optional[str] = None,
    summary_dir: Optional[str] = None,
    queue_file: Optional[str] = None,
    author: Optional[str] = None,
    limit: Optional[int] = None,
    auto_apply_safe: bool = True,
) -> OrchestrateResult:
    policy = load_policy()
    limit = int(limit or policy.get("limits", {}).get("max_findings_per_run", 20))
    if finding_ids:
        selected: List[Dict[str, Any]] = []
        for finding_id in finding_ids:
            matches = list_triage_findings(db_path=db_path, limit=1000)
            selected.extend([row for row in matches if str(row.get("finding_id")) == finding_id])
        findings = selected
    else:
        findings = list_triage_findings(db_path=db_path, status="open", limit=limit)

    processed: List[Dict[str, Any]] = []
    auto_applied = 0
    queued = 0
    for finding in findings[:limit]:
        finding_id = str(finding.get("finding_id"))
        if policy.get("safety", {}).get("auto_start_in_review", True) and str(finding.get("status") or "").lower() == "open":
            finding = start_finding(
                finding_id,
                author=author,
                note="Orchestrator started triage review.",
                db_path=db_path,
            )

        investigation_payload = investigate_finding(
            finding_id,
            db_path=db_path,
            search_root=search_root,
            report_dir=report_dir,
            author=author,
        )
        category = investigation_payload["category"]
        investigation = investigation_payload["investigation"]
        plan = _planned_action_for(
            finding=investigation_payload["finding"],
            category=category,
            investigation=investigation,
            queue_file=queue_file,
        )
        outcome = "queued"
        action_id = None
        if auto_apply_safe and plan.get("kind") == "auto_close":
            disposition = str(plan["disposition"])
            closed = close_finding(
                finding_id,
                disposition=disposition,
                note=_safe_close_note(investigation, investigation_payload["finding"], disposition),
                author=author,
                status="closed",
                db_path=db_path,
            )
            auto_applied += 1
            outcome = "auto_closed"
            processed.append(
                {
                    "finding_id": finding_id,
                    "category": category,
                    "recommended_disposition": investigation.get("recommended_disposition"),
                    "confidence": investigation.get("confidence"),
                    "summary": investigation.get("summary"),
                    "outcome": outcome,
                    "finding": closed,
                }
            )
            continue

        if plan.get("kind") == "queued":
            queued += 1
            action_id = str(plan["action"].get("action_id"))
            outcome = "queued"

        processed.append(
            {
                "finding_id": finding_id,
                "category": category,
                "recommended_disposition": investigation.get("recommended_disposition"),
                "confidence": investigation.get("confidence"),
                "summary": investigation.get("summary"),
                "outcome": outcome,
                "action_id": action_id,
                "json_report": investigation_payload.get("json_report"),
                "markdown_report": investigation_payload.get("markdown_report"),
            }
        )

    payload = {
        "generated_at": _utc_now(),
        "processed": len(processed),
        "auto_applied": auto_applied,
        "queued": queued,
        "findings": processed,
        "queue_path": str(queue_path(queue_file)),
    }
    payload["adaptive_response"] = evaluate_adaptive_response(
        [item.get("finding", item) for item in processed]
    )
    payload.update(_write_summary(payload, summary_dir))
    return OrchestrateResult(
        processed=len(processed),
        auto_applied=auto_applied,
        queued=queued,
        findings=processed,
        queue_path=str(queue_path(queue_file)),
        summary_json=payload["summary_json"],
        summary_markdown=payload["summary_markdown"],
    )
