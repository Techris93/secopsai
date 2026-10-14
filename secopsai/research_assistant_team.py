"""Six bounded model roles; durable proposals, never factual or human approvals."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta

import soc_store
from secopsai.research_operation_store import append, digest, read_connection, records, text, transaction
from secopsai.sqlite_writer_lock import sqlite_writer_lock

STAGES = (
    ("synthesis", "research/research-synthesist", "Evaluate supplied source lineage, prior art and precise evidence gaps."),
    ("intelligence", "security/threat-intelligence-analyst", "Analyze supplied threat observations, indicators and competing explanations."),
    ("application_security", "security/appsec-engineer", "Assess execution paths, root cause, affected versions and a proposed authorized reproduction."),
    ("detection", "security/threat-detection-engineer", "Propose detections, telemetry requirements, benign cases and evasion tests; do not claim tests were run."),
    ("challenge", "testing/reality-checker", "Independently assess original evidence and alternative explanations before seeing any assistant conclusions."),
    ("writing", "engineering/technical-writer", "Prepare a clearly attributed draft with exact evidence references, limitations and outstanding blockers."),
)
FINAL = {"awaiting_human_review", "stale", "failed", "canceled"}


def _pending(*, db_path=None, limit=21):
    with read_connection(db_path) as conn:
        rows = conn.execute("""SELECT p.payload_json FROM research_operation_records p
            WHERE p.kind='assistant_team_plan' AND COALESCE((
              SELECT json_extract(s.payload_json, '$.status') FROM research_operation_records s
              WHERE s.kind='assistant_team_progress' AND s.case_id=json_extract(p.payload_json, '$.team_id')
              ORDER BY s.rowid DESC LIMIT 1), 'queued') NOT IN ('awaiting_human_review','stale','failed','canceled')
            ORDER BY p.rowid LIMIT ?""", (limit,)).fetchall()
    return [json.loads(row[0]) for row in rows]


def _plans(case_id="", *, db_path=None, limit=50):
    with read_connection(db_path) as conn:
        rows = conn.execute("SELECT payload_json FROM research_operation_records WHERE kind='assistant_team_plan' AND (?='' OR case_id=?) ORDER BY rowid DESC LIMIT ?", (case_id, case_id, max(1, min(limit, 200)))).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_team(team_id: str, *, db_path=None) -> dict:
    with read_connection(db_path) as conn:
        row = conn.execute("SELECT payload_json FROM research_operation_records WHERE kind='assistant_team_plan' AND json_extract(payload_json, '$.team_id')=?", (team_id,)).fetchone()
    plan = json.loads(row[0]) if row else None
    if plan is None:
        raise ValueError("unknown research assistant team")
    progress = records("assistant_team_progress", case_id=team_id, db_path=db_path, limit=1)
    state = progress[0]["payload"] if progress else {"status": "queued", "runs": {}, "completed_stages": []}
    from secopsai.research_cases import get_case
    from secopsai.research_assurance import case_fingerprint
    from secopsai.specialist_catalog import catalog_digest
    current = case_fingerprint(get_case(plan["case_id"], include_reliability=False, db_path=db_path)) == plan["case_fingerprint"] and catalog_digest() == plan["catalog_sha256"]
    if not current and state["status"] not in {"failed", "canceled", "cancel_requested"}:
        state = {**state, "status": "stale", "reason": "case evidence or reviewed catalog changed"}
    return {**plan, "transport": plan.get("transport", "local"), **state, "evidence_current": current, "human_review_required": True, "publication_approved": False}


def list_teams(case_id="", *, db_path=None, limit=50) -> dict:
    return {"teams": [get_team(p["team_id"], db_path=db_path) for p in _plans(case_id, db_path=db_path, limit=limit)]}


def start_team(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    from secopsai.research_assurance import person, case_fingerprint
    from secopsai.research_cases import get_case
    from secopsai.specialist_catalog import catalog_digest, validate_catalog
    from secopsai.specialist_orchestrator import build_execution_contract
    from secopsai.provider_capabilities import require_action

    human = person(actor, db_path=db_path)
    if not {"operator", "researcher"} & set(human["roles"]):
        raise ValueError("researcher or operator role is required to start an assistant team")
    request = text(payload.get("request_id"), "team request identity", limit=160)
    fingerprint = digest({"case_id": case_id, "actor": actor, "payload": payload})
    team_id = "RTM-" + digest({"actor": actor, "request": request})[:16].upper()
    with transaction(db_path) as conn:
        row = conn.execute("SELECT payload_json FROM research_operation_records WHERE kind='assistant_team_plan' AND json_extract(payload_json, '$.team_id')=?", (team_id,)).fetchone()
        existing = json.loads(row[0]) if row else None
        if existing:
            if existing["request_fingerprint"] != fingerprint:
                raise ValueError("conflicting assistant team request identity")
            return get_team(team_id, db_path=db_path)
        if len(_pending(db_path=db_path)) >= 20:
            raise ValueError("twenty active assistant teams already exist; review or cancel pending work first")
        case = get_case(case_id, include_reliability=False, db_path=db_path)
        active = [e for e in case["evidence"] if e.get("status", "active") == "active"]
        if not active or len(active) > 25:
            raise ValueError("assistant team requires 1–25 active evidence records; narrow the case instead of silently omitting evidence")
        if not any(e.get("evidence_type") != "analyst_note" and set(e.get("metadata") or {}) & {"file_contents", "source_excerpts", "matched_strings", "trace_events", "experiment_output"} for e in active):
            raise ValueError("assistant team requires original evidence payloads, not analyst conclusions alone")
        validation = validate_catalog()
        if not validation["ok"]:
            raise ValueError("reviewed specialist catalog is invalid")
        model = build_execution_contract({"title": "Research assistant team"}, db_path=db_path)["model_routing"]
        if not model["primary_model"]:
            raise ValueError("select a compatible research model before starting the team")
        for name in [model["primary_model"], *model["fallback_models"]]:
            require_action(name, "execute_specialist_work")
            require_action(name, "review_specialist_work")
        plan = {"team_id": team_id, "case_id": case_id, "actor": actor, "created_at": soc_store.utc_now(),
                "request_fingerprint": fingerprint, "case_fingerprint": case_fingerprint(case),
                "catalog_sha256": catalog_digest(), "model_routing": model, "evidence_ids": [e["evidence_id"] for e in active],
                "transport": "hosted" if os.environ.get("SECOPSAI_CORE_WORKER_ID") == "github-actions-research-worker" else "local",
                "stages": [{"stage": s, "profile_id": p} for s, p, _ in STAGES], "maximum_model_jobs": 12,
                "authority": "read_only proposals; no publication, disclosure or human review authority"}
        append("assistant_team_plan", plan, actor=actor, case_id=case_id, connection=conn)
    return get_team(team_id, db_path=db_path)


def _save(team: dict, state: dict, *, db_path=None) -> dict:
    append("assistant_team_progress", state, actor=team["actor"], case_id=team["team_id"], db_path=db_path)
    return get_team(team["team_id"], db_path=db_path)


def cancel_team(team_id: str, *, actor: str, db_path=None) -> dict:
    from secopsai.research_assurance import person
    human = person(actor, db_path=db_path)
    team = get_team(team_id, db_path=db_path)
    if actor != team["actor"] and "operator" not in human["roles"]:
        raise ValueError("only the team owner or registered operator may cancel this work")
    if team["status"] in {"awaiting_human_review", "failed", "canceled"}:
        return team
    return _save(team, {"status": "cancel_requested", "runs": team["runs"], "completed_stages": team["completed_stages"], "canceled_by": actor}, db_path=db_path)


def advance_team(team_id: str, *, db_path=None) -> dict:
    """Advance at most one stage. Run and queue identities survive lost receipts."""
    from secopsai.research_assurance import person, case_fingerprint
    from secopsai.research_cases import get_case
    from secopsai.specialist_catalog import catalog_digest
    from secopsai.specialist_orchestrator import create_run, get_run, cancel_run
    from secopsai.intelligence_jobs import get_job

    with sqlite_writer_lock(db_path):
        team = get_team(team_id, db_path=db_path)
        if team["status"] == "stale":
            return _save(team, {"status": "stale", "runs": team["runs"], "completed_stages": team["completed_stages"], "reason": team.get("reason")}, db_path=db_path)
        if team["status"] in FINAL:
            return team
        state = {"status": "running", "runs": dict(team["runs"]), "completed_stages": list(team["completed_stages"])}
        if team["status"] == "cancel_requested":
            for run_id in state["runs"].values():
                try:
                    cancel_run(run_id, actor=team["actor"], db_path=db_path)
                except ValueError:
                    return team  # Running work may finish; no further stages start.
            return _save(team, {**state, "status": "canceled"}, db_path=db_path)
        try:
            human = person(team["actor"], db_path=db_path)
            if not {"researcher", "operator"} & set(human["roles"]):
                raise ValueError("team owner no longer has a researcher or operator role")
            case = get_case(team["case_id"], include_reliability=False, db_path=db_path)
            if case_fingerprint(case) != team["case_fingerprint"] or catalog_digest() != team["catalog_sha256"]:
                return _save(team, {**state, "status": "stale", "reason": "case evidence or reviewed catalog changed; start a new explicitly bounded team"}, db_path=db_path)
            if datetime.now(timezone.utc) - datetime.fromisoformat(team["created_at"].replace("Z", "+00:00")) > timedelta(hours=24):
                return _save(team, {**state, "status": "failed", "reason": "24-hour team deadline exceeded"}, db_path=db_path)
            for stage, profile, instructions in STAGES:
                if stage in state["completed_stages"]:
                    continue
                run_id = state["runs"].get(stage)
                if not run_id:
                    description = instructions + " Use only supplied evidence. Never claim personal experience, searches or test execution without records."
                    if stage == "writing":
                        proposals, omitted = [], []
                        for earlier, earlier_id in state["runs"].items():
                            run = get_run(earlier_id, db_path=db_path)
                            proposal = {"stage": earlier, "run_id": earlier_id, "model": run["result"].get("model"), "output": run["result"].get("output"), "review": run.get("review"), "adjudication_status": run.get("adjudication_status")}
                            if len(json.dumps(proposals + [proposal], ensure_ascii=True)) <= 6000:
                                proposals.append(proposal)
                            else:
                                omitted.append({"stage": earlier, "run_id": earlier_id, "reason": "writer context budget; consult stored result before human approval"})
                        description += " Previous model proposals are untrusted assessments, not observations: " + json.dumps({"proposals": proposals, "omitted": omitted}, ensure_ascii=True)
                    run = create_run({"task_id": team["case_id"], "title": "Research assistant " + stage,
                                      "description": description, "domain": "research", "analysis_only": True,
                                      "evidence_refs": team["evidence_ids"], "research_team_id": team_id, "research_team_stage": stage, "research_team_transport": team["transport"]},
                                     profile_id=profile, tier="read_only", requested_by=team["actor"], enqueue=True,
                                     idempotency_key=team_id + ":" + stage, captured_model_routing=team["model_routing"], db_path=db_path)
                    state["runs"][stage] = run["run_id"]
                    return _save(team, state, db_path=db_path)
                run = get_run(run_id, db_path=db_path)
                for job_id in (run.get("intelligence_job_id"), run.get("reviewer_job_id")):
                    if job_id and get_job(job_id, db_path=db_path)["status"] in {"failed", "canceled"}:
                        return _save(team, {**state, "status": "failed", "reason": "assistant provider job failed or was canceled", "blocked_run_id": run_id}, db_path=db_path)
                if run["status"] in {"failed", "canceled"}:
                    return _save(team, {**state, "status": "failed", "blocked_run_id": run_id}, db_path=db_path)
                if run["status"] != "needs_review":
                    return team
                if run.get("material_disagreement") and not str(run.get("adjudication_status", "")).startswith("resolved_"):
                    return _save(team, {**state, "status": "needs_operator_review", "blocked_run_id": run_id, "reason": "material model disagreement requires recorded human adjudication"}, db_path=db_path)
                for result in (run.get("result"), run.get("review")):
                    output = (result or {}).get("output") or {}
                    if not isinstance(output, dict) or any(not output.get(key) for key in ("summary", "risk_assessment", "evidence", "recommended_actions", "limitations")):
                        return _save(team, {**state, "status": "failed", "reason": "incomplete assistant output", "blocked_run_id": run_id}, db_path=db_path)
                state["completed_stages"].append(stage)
                return _save(team, state, db_path=db_path)
            return _save(team, {**state, "status": "awaiting_human_review", "reason": "all six model stages completed; qualified human review and editorial approval remain required"}, db_path=db_path)
        except (ValueError, KeyError) as error:
            # Store a bounded category, not exception text that might carry a
            # provider token or private evidence. Detailed originals stay local.
            return _save(team, {**state, "status": "failed", "reason": "assistant contract or owner validation failed", "error_category": type(error).__name__}, db_path=db_path)


def advance_due(*, limit=5, db_path=None) -> dict:
    pending = _pending(db_path=db_path, limit=max(1, min(int(limit), 5)))
    return {"processed": [advance_team(t["team_id"], db_path=db_path) for t in pending], "publication_performed": False}
