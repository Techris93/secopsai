"""Guarded Research Case handoff to the reviewed specialist orchestrator.

This coordinator is intentionally read-only from the model's perspective. It
may build evidence matrices, queue reviewed specialists, attach their bounded
results as analyst-note evidence, and create a review-only draft after a human
has approved publication readiness. It never approves, publishes, deploys,
discloses, submits artifacts, or changes the selected model/fallback policy.
"""

from __future__ import annotations

import json
from contextlib import closing
from typing import Any, Optional

import soc_store
from secopsai.research_cases import add_evidence, draft_case_blog, get_case, list_cases
from secopsai.research_reliability import run_guarded_reliability_batch
from secopsai.research_workflow import build_evidence_matrix, publication_safety_check
from secopsai.specialist_orchestrator import auto_route_task, get_policy


SCHEMA_VERSION = "secopsai.research-specialist-automation.v1"
ELIGIBLE_CASE_STATUSES = {"validation", "ready_to_publish"}
FINAL_REVIEW_STATUS = "needs_review"


def _case_runs(case_id: str, *, db_path: Optional[str]) -> list[dict[str, Any]]:
    # get_policy initializes the specialist tables in the same durable store.
    get_policy(db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT run_id, task_id, status, automation_tier, primary_profile_id,
                      reviewer_profile_id, selected_model, fallback_mode,
                      result_json, review_json, created_at, updated_at, completed_at
               FROM specialist_runs WHERE task_id = ?
               ORDER BY updated_at DESC, run_id DESC""",
            (case_id,),
        ).fetchall()
    runs: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for source, target in (("result_json", "result"), ("review_json", "review")):
            try:
                item[target] = json.loads(str(item.pop(source) or "{}"))
            except (TypeError, ValueError):
                item[target] = {}
        runs.append(item)
    return runs


def _active_case_evidence(case: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in (case.get("evidence") or []) if item.get("status", "active") == "active"]


def _domain_for_case(case: dict[str, Any]) -> str:
    if case.get("case_type") == "vulnerability_research":
        return "security"
    return "research"


def _profile_for_case(case: dict[str, Any]) -> str:
    case_type = str(case.get("case_type") or "")
    if case_type == "vulnerability_research":
        return "security/appsec-engineer"
    if case_type in {
        "malicious_package", "typosquatting", "dependency_confusion",
        "supply_chain_campaign", "credential_theft", "malware",
        "infrastructure_cluster",
    }:
        return "security/threat-intelligence-analyst"
    return "security/senior-secops"


def _task_for_case(case: dict[str, Any]) -> dict[str, Any]:
    evidence = _active_case_evidence(case)
    return {
        "task_id": case["case_id"],
        "title": f"Independent evidence review for {case['case_id']}: {case['title']}",
        "description": (
            f"Review this normalized SecOpsAI Research Case as {case.get('case_type')}. "
            f"Separate confirmed evidence, source claims, analyst inference, contradictions, "
            f"missing evidence, and publication risk. Case summary: {case.get('summary') or 'No summary supplied.'}"
        )[:8000],
        "domain": _domain_for_case(case),
        "priority": "high" if case.get("severity") in {"high", "critical"} else "normal",
        "status": str(case.get("status") or "investigating"),
        "repo_alias": "secopsai",
        "evidence_refs": [str(item.get("evidence_id")) for item in evidence if item.get("evidence_id")][:25],
        "external_facing": case.get("status") == "ready_to_publish",
        "requires_security_review": True,
        # Trusted Core-only marker. The browser task normalizer does not accept
        # it, so a user request cannot use it to bypass high-risk safeguards.
        "analysis_only": True,
    }


def route_cases(*, limit: int = 5, db_path: Optional[str] = None) -> dict[str, Any]:
    """Queue at most ``limit`` eligible cases under the persisted guarded policy."""
    policy = get_policy(db_path=db_path)
    if policy.get("mode") != "guarded" or policy.get("maximum_automatic_tier") != "read_only":
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "skipped",
            "reason": "guarded_read_only_policy_not_enabled",
            "routed": [],
            "skipped": [],
        }

    routed: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    bounded = max(1, min(int(limit), 25))
    for summary in list_cases(db_path=db_path, limit=1000):
        if len(routed) >= bounded:
            break
        case_id = str(summary.get("case_id") or "")
        if summary.get("status") not in ELIGIBLE_CASE_STATUSES:
            continue
        case = get_case(case_id, db_path=db_path)
        evidence = _active_case_evidence(case)
        active_subjects = [
            item for item in (case.get("subjects") or [])
            if item.get("status", "active") == "active"
        ]
        if not active_subjects or not evidence:
            skipped.append({"case_id": case_id, "reason": "subject_and_evidence_required"})
            continue
        prior = [
            run for run in _case_runs(case_id, db_path=db_path)
            if run.get("automation_tier") == "read_only" and run.get("status") != "canceled"
        ]
        if prior:
            skipped.append({"case_id": case_id, "reason": f"existing_read_only_run:{prior[0]['status']}"})
            continue
        result = auto_route_task(
            _task_for_case(case),
            profile_id=_profile_for_case(case),
            requested_by="secopsai-research-specialist-automation",
            db_path=db_path,
        )
        run = result.get("run") or {}
        routed.append(
            {
                "case_id": case_id,
                "run_id": run.get("run_id"),
                "status": run.get("status"),
                "primary_profile_id": run.get("primary_profile_id"),
                "reviewer_profile_id": run.get("reviewer_profile_id"),
                "selected_model": run.get("selected_model"),
                "fallback_mode": run.get("fallback_mode"),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "routed": routed,
        "skipped": skipped,
        "protected_actions_performed": [],
    }


def _summary(value: Any, *, fallback: str) -> str:
    payload = value if isinstance(value, dict) else {}
    output = payload.get("output") if isinstance(payload.get("output"), dict) else payload
    return str(output.get("summary") or fallback).strip()[:5000]


def sync_completed_reviews(*, limit: int = 10, db_path: Optional[str] = None) -> dict[str, Any]:
    """Attach completed primary+independent reviews once, then rerun safe checks."""
    get_policy(db_path=db_path)
    bounded = max(1, min(int(limit), 50))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT run_id, task_id FROM specialist_runs
               WHERE automation_tier='read_only' AND status=? AND task_id GLOB 'RSC-*'
               ORDER BY completed_at, run_id LIMIT ?""",
            (FINAL_REVIEW_STATUS, bounded),
        ).fetchall()
    attached: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for row in rows:
        case_id = str(row["task_id"] or "")
        run_id = str(row["run_id"] or "")
        try:
            case = get_case(case_id, db_path=db_path)
        except ValueError:
            skipped.append({"run_id": run_id, "reason": "research_case_not_found"})
            continue
        locator = f"specialist-review:{run_id}"
        if any(item.get("locator") == locator for item in case.get("evidence") or []):
            skipped.append({"run_id": run_id, "case_id": case_id, "reason": "already_attached"})
            continue
        run = next(item for item in _case_runs(case_id, db_path=db_path) if item["run_id"] == run_id)
        primary = _summary(run.get("result"), fallback="Primary specialist returned no summary.")
        review = _summary(run.get("review"), fallback="Independent reviewer returned no summary.")
        updated = add_evidence(
            case_id,
            evidence_type="analyst_note",
            title=f"Guarded specialist and independent review {run_id}",
            locator=locator,
            provenance="SecOpsAI reviewed specialist catalog and persisted OpenCodex model routing",
            notes=f"Primary specialist: {primary}\n\nIndependent reviewer: {review}",
            metadata={
                "specialist_run_id": run_id,
                "primary_profile_id": run.get("primary_profile_id"),
                "reviewer_profile_id": run.get("reviewer_profile_id"),
                "selected_model": run.get("selected_model"),
                "fallback_mode": run.get("fallback_mode"),
                "read_only": True,
                "operator_acceptance_required": True,
            },
            actor="secopsai-research-specialist-automation",
            db_path=db_path,
        )
        matrix = build_evidence_matrix(
            case_id,
            persist=True,
            actor="secopsai-research-specialist-automation",
            db_path=db_path,
        )
        safety = publication_safety_check(
            case_id,
            actor="secopsai-research-specialist-automation",
            db_path=db_path,
        )
        attached.append(
            {
                "case_id": case_id,
                "run_id": run_id,
                "evidence_id": next(
                    (
                        item.get("evidence_id")
                        for item in updated.get("evidence") or []
                        if item.get("locator") == locator
                    ),
                    None,
                ),
                "evidence_matrix": matrix.get("summary"),
                "publication_safety": safety.get("status"),
                "publication_approved": False,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "attached": attached,
        "skipped": skipped,
        "protected_actions_performed": [],
    }


def create_approved_review_drafts(*, limit: int = 3, db_path: Optional[str] = None) -> dict[str, Any]:
    """Create editorial drafts only after the human publication gate is approved."""
    created: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    bounded = max(1, min(int(limit), 10))
    for summary in list_cases(status="ready_to_publish", db_path=db_path, limit=100):
        if len(created) >= bounded:
            break
        case = get_case(str(summary["case_id"]), db_path=db_path)
        if any(item.get("event_type") == "blog_draft_created" for item in case.get("timeline") or []):
            skipped.append({"case_id": case["case_id"], "reason": "review_draft_already_created"})
            continue
        reviews = case.get("publication_reviews") or []
        if not reviews or reviews[0].get("status") != "approved":
            skipped.append({"case_id": case["case_id"], "reason": "human_publication_approval_required"})
            continue
        result = draft_case_blog(case["case_id"], db_path=db_path)
        created.append(
            {
                "case_id": case["case_id"],
                "draft_id": result.get("draft_id"),
                "review_only": True,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "created": created,
        "skipped": skipped,
        "publication_performed": False,
        "deployment_performed": False,
    }


def run_cycle(*, limit: int = 5, db_path: Optional[str] = None) -> dict[str, Any]:
    """Synchronize reviews, advance safe gates, and prepare approved drafts."""
    review_sync = sync_completed_reviews(limit=max(limit * 2, 10), db_path=db_path)
    reliability_progress = run_guarded_reliability_batch(limit=limit, db_path=db_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "review_sync": review_sync,
        "reliability_progress": reliability_progress,
        "case_routing": {
            "status": "integrated",
            "reason": "Specialist routing now occurs only after the guarded full-bundle and claim-ledger gates.",
            "routed": [
                item
                for item in reliability_progress.get("processed", [])
                if item.get("stopped_at") == "awaiting_model_review"
                and not item.get("reused")
            ],
        },
        "review_drafts": create_approved_review_drafts(limit=min(limit, 3), db_path=db_path),
        "operator_gates": [
            "specialist_result_acceptance",
            "publication_review_approval",
            "sandbox_submission",
            "disclosure_send",
            "publish_approved",
            "deployment",
        ],
    }
