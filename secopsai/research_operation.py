"""Public interface for the research-company operating workflow."""
from __future__ import annotations

import json
from contextlib import closing

import soc_store
from secopsai.research_operation_store import read_connection
from secopsai.research_operation_store import records

READ_ACTIONS = {"status", "coverage", "people", "events", "editions", "queue", "audit", "metrics", "storage-assessment"}
READ_ACTIONS.add("assistant-teams")
WRITE_ACTIONS = {"person-register", "claim-assess", "prior-art", "experiment", "behavior", "case-review", "case-disposition", "source-configure", "source-collect", "event-verify", "roster", "board", "brief-create", "brief-edit", "brief-approve", "brief-publish", "brief-correct", "submission", "disclosure-milestone", "requirement", "queue-claim", "queue-heartbeat", "queue-complete", "queue-fail", "outcome"}
# Remote operator commands never accept local file paths or publish files from
# an ephemeral worker. Publication uses the reviewed export and release path.
WRITE_ACTIONS.add("recovery-drill")
WRITE_ACTIONS.add("compare-releases")
WRITE_ACTIONS.add("assistant-team-start")
WRITE_ACTIONS.add("assistant-team-cancel")
WRITE_ACTIONS.update({"artifact-backup", "artifact-restore"})
HOSTED_WRITE_ACTIONS = WRITE_ACTIONS - {"submission", "brief-publish", "source-collect", "queue-claim", "queue-heartbeat", "queue-complete", "queue-fail", "recovery-drill", "artifact-backup", "artifact-restore"}


def execute(action: str, payload: dict | None = None, *, actor: str = "", case_id: str = "", identity: str = "", db_path=None) -> dict:
    from secopsai import research_assurance as assurance, research_editorial as editorial, research_primary_intel as intel, research_governance as governance
    from secopsai.research_coverage import coverage_report, readiness_report

    soc_store.init_db(db_path)
    payload = payload or {}
    if not isinstance(payload, dict):
        raise ValueError("operation input must be an object")
    if action not in READ_ACTIONS | WRITE_ACTIONS:
        raise ValueError("unsupported research operation action")
    if action == "status":
        return readiness_report(db_path=db_path)
    if action == "coverage":
        return coverage_report(db_path=db_path)
    if action == "metrics":
        from secopsai.research_metrics import metrics_report

        return metrics_report(db_path=db_path)
    if action == "storage-assessment":
        from secopsai.research_recovery import storage_assessment

        return storage_assessment(db_path=db_path)
    if action in {"assistant-teams", "assistant-team-start", "assistant-team-cancel"}:
        from secopsai.research_assistant_team import list_teams, start_team, cancel_team
        if action == "assistant-teams":
            return list_teams(case_id, db_path=db_path)
        if action == "assistant-team-cancel":
            return cancel_team(identity, actor=actor, db_path=db_path)
        return start_team(case_id, payload, actor=actor, db_path=db_path)
    if action in {"people", "events", "editions", "queue"}:
        query = {"people": "SELECT person_id,display_name,roles_json,qualification,active FROM research_people",
                 "events": "SELECT event_id,source_id,payload_json,published_at,collected_at,first_observed_at FROM research_intel_events ORDER BY collected_at DESC LIMIT 100",
                 "editions": "SELECT * FROM research_editorial_editions ORDER BY edition_date DESC LIMIT 90",
                 "queue": "SELECT job_id,kind,event_id,state,attempt,error_category,lease_until,created_at,updated_at FROM research_operation_queue ORDER BY created_at DESC LIMIT 200"}[action]
        with read_connection(db_path) as conn:
            rows = [dict(r) for r in conn.execute(query)]
        for row in rows:
            for key in list(row):
                if key.endswith("_json"):
                    row[key[:-5]] = json.loads(row.pop(key))
        return {action: rows}
    if action == "audit":
        kinds = ("claim_assessment", "prior_art", "experiment", "human_review", "partner_submission", "disclosure_milestone") if case_id else ("edition_approval", "edition_correction", "person_registration", "legal_signoff", "research_quality_evaluation")
        return {kind: records(kind, case_id=case_id, db_path=db_path) for kind in kinds}
    if not actor:
        raise ValueError("an explicit human operator identity is required for mutations")
    if action == "person-register":
        # Registration records operator assertions of identity/qualification;
        # it never invents staff or represents authentication of a legal ID.
        return assurance.register_person(payload, actor=actor, db_path=db_path)
    assurance.person(actor, db_path=db_path)
    if action in {"artifact-backup", "artifact-restore"}:
        from secopsai.research_artifact_vault import backup_artifact, restore_artifact
        assurance.person(actor, role="operator", db_path=db_path)
        options = {"actor": actor, "db_path": db_path}
        if action == "artifact-backup":
            if type(payload.get("cloud_storage_authorized", False)) is not bool:
                raise ValueError("cloud_storage_authorized must be a boolean")
            options["cloud_storage_authorized"] = payload.get("cloud_storage_authorized", False)
        return (backup_artifact if action == "artifact-backup" else restore_artifact)(payload.get("artifact_id", ""), **options)
    if action == "compare-releases":
        from secopsai.research_methods import compare_releases

        return compare_releases(payload, actor=actor, case_id=case_id, db_path=db_path)
    if action == "recovery-drill":
        from secopsai.research_recovery import recovery_drill

        return recovery_drill(output_dir=payload.get("output_dir", ""), actor=actor, db_path=db_path)
    functions = {"claim-assess": assurance.assess_claim, "prior-art": assurance.record_prior_art, "experiment": assurance.record_experiment,
                 "behavior": assurance.record_behavior, "case-review": assurance.review_case, "board": editorial.update_board,
                 "submission": governance.submit_sample, "disclosure-milestone": governance.disclosure_milestone}
    if action in functions:
        return functions[action](case_id, payload, actor=actor, db_path=db_path)
    if action == "case-disposition":
        from secopsai.research_routing import record_case_disposition

        return record_case_disposition(case_id, payload, actor=actor, db_path=db_path)
    if action == "source-configure":
        return intel.configure_source(payload, actor=actor, db_path=db_path)
    if action == "source-collect":
        return intel.collect_due(db_path=db_path)
    if action == "event-verify":
        return intel.verify_event(identity, payload, actor=actor, db_path=db_path)
    if action == "roster":
        return editorial.configure_roster(payload, actor=actor, db_path=db_path)
    if action == "brief-create":
        return editorial.create_daily_brief(date=payload.get("date"), db_path=db_path)
    if action == "brief-edit":
        return editorial.edit_edition(identity, payload, actor=actor, db_path=db_path)
    if action == "brief-approve":
        return editorial.approve_edition(identity, payload, actor=actor, db_path=db_path)
    if action == "brief-publish":
        return editorial.publish_edition(identity, actor=actor, db_path=db_path)
    if action == "brief-correct":
        return editorial.correct_edition(identity, payload, actor=actor, db_path=db_path)
    if action == "requirement":
        return governance.operational_requirement(payload, actor=actor, db_path=db_path)
    if action == "outcome":
        from secopsai.research_metrics import record_outcome

        return record_outcome(case_id, payload, actor=actor, db_path=db_path)
    if action == "queue-claim":
        return {"job": intel.claim_job(worker_id=actor, db_path=db_path)}
    if action == "queue-heartbeat":
        intel.heartbeat(identity, payload.get("lease_token", ""), db_path=db_path)
        return {"heartbeat": "accepted"}
    if action == "queue-complete":
        return intel.complete_job(identity, payload.get("lease_token", ""), payload.get("result", {}), db_path=db_path)
    return intel.fail_job(identity, payload.get("lease_token", ""), category=payload.get("category", "unknown"), retryable=payload.get("retryable") is True, db_path=db_path)


def _daily_automation_view(*, db_path=None) -> dict:
    """Latest scheduled daily-workflow state.

    Core records daily runs only when the dashboard starts one, so the
    worker's own six-hourly runs reach the hosted console through this
    snapshot instead.
    """
    try:
        from secopsai.daily_automation import status as daily_status
        value = daily_status(db_path=db_path, limit=1)
    except Exception as exc:  # status must never block the operation snapshot
        return {"error_category": type(exc).__name__}
    latest = (value.get("runs") or [None])[0]
    settings = {key: value["settings"].get(key) for key in ("enabled", "interval_seconds", "last_run_at", "next_run_at",
                                                             "max_alert_reviews", "max_investigations", "max_candidate_cases",
                                                             "auto_promote_candidates", "run_learning")}
    return {"settings": settings, "summary": value.get("summary") or {},
            "latest_run": {key: latest.get(key) for key in ("run_id", "trigger", "status", "started_at", "completed_at")}
            | {"steps": [{"step_name": step.get("step_name"), "status": step.get("status")} for step in (latest.get("steps") or [])[:16]]}
            if latest else None}


def hosted_projection(*, db_path=None) -> dict:
    import os
    from secopsai.intelligence import minimize
    from secopsai.research_editorial import pending_edition_update
    from secopsai.research_operation_store import records
    from secopsai.research_primary_intel import pending_public_reviews

    status = execute("status", db_path=db_path)
    from secopsai.research_assistant_team import list_teams
    teams = [{key: team.get(key) for key in ("team_id", "case_id", "status", "completed_stages", "runs", "reason", "human_review_required", "publication_approved")}
             for team in list_teams(db_path=db_path, limit=20)["teams"]]
    # The research desk decides what the reviewer sees first: primary sources
    # of the highest-ranked advisories, then the newest remaining items.
    from secopsai import research_desk
    try:
        desk = research_desk.projection(db_path=db_path, limit=12)
    except Exception as exc:  # the desk must never block the operation snapshot
        desk = {"schema_version": "secopsai.research.desk.v1", "items": [], "error_category": type(exc).__name__}
    desk["solo_operation"] = status.get("solo_operation") or {"active": False}
    # Who is registered and what happened to recent dashboard actions; no
    # qualifications or other personal detail beyond the public display name.
    desk["people"] = registered_people(db_path=db_path)
    from secopsai.research_auto_verify import policy as verification_policy
    delegation = verification_policy(db_path=db_path)
    automated = [r for r in records("intel_verification", db_path=db_path, limit=500) if r["payload"].get("automation")]
    desk["automated_verification"] = {"active": bool(delegation), "operator_id": (delegation or {}).get("operator_id", ""),
                                      "decisions": [{"event_id": r["payload"]["event_id"], "decision": r["payload"]["decision"],
                                                     "reason": r["payload"]["automation"].get("rule", ""), "at": r["created_at"]}
                                                    for r in automated[:20]]}
    desk["recent_actions"] = recent_actions(db_path=db_path)
    desk_event_ids = [event_id for item in desk["items"] for event_id in (item.get("primary_event_ids") or item.get("event_ids") or [])[:2]]
    pending_reviews = pending_public_reviews(db_path=db_path, limit=10, event_ids=desk_event_ids)
    dispatches = records("assistant_team_automation_dispatch", db_path=db_path, limit=1)
    auto_cycles = records("assistant_team_automation_cycle", db_path=db_path, limit=1)
    editions = []
    for index, item in enumerate(execute("editions", db_path=db_path)["editions"]):
        value = {key: item.get(key) for key in ("edition_id", "edition_date", "product", "author_id", "state", "published_url", "updated_at", "fingerprint")}
        update = pending_edition_update(item["edition_id"], db_path=db_path)
        if update:
            value["pending_update"] = {"fingerprint": update["draft_fingerprint"],
                                       "edition_state": update["edition_state"],
                                       "new_items": [{key: str(source_item.get(key) or "")[:500]
                                                      for key in ("event_id", "title", "source", "url", "summary", "defensive_action", "limitations")}
                                                     for source_item in update.get("new_items", [])],
                                       "replace_event_ids": update.get("replace_event_ids", []),
                                       "remove_event_ids": update.get("remove_event_ids", []),
                                       "removed_items": [{key: str(source_item.get(key) or "")[:500]
                                                          for key in ("event_id", "title", "source", "url")}
                                                         for source_item in update.get("removed_items", [])],
                                       "coverage_summary": str(update.get("coverage_summary") or "")[:1000]}
        if index < 3 and len(item["draft"]["body_markdown"].encode()) <= 30000:
            value["draft"] = {key: item["draft"].get(key) for key in ("title", "summary", "body_markdown", "author", "references")}
        else:
            value["draft_omitted"] = "Full draft remains in the ledger; it cannot be approved from this projection"
        editions.append(value)
    # Raw samples, restricted source material, private submissions, legal
    # agreements and confidential review notes are never sent to the hosted
    # read surface. Pending review contains only capped excerpts from sources
    # explicitly configured for public sharing, with archive hashes attached.
    raw_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    runtime = {"worker_run_id": os.environ.get("GITHUB_RUN_ID") or os.environ.get("SECOPSAI_GITHUB_RUN_ID"),
               "worker_run_attempt": int(raw_attempt) if raw_attempt.isdigit() else None,
               "worker_revision": (os.environ.get("GITHUB_SHA") or os.environ.get("SECOPSAI_BUILD_REVISION") or "")[:80]}
    projection = minimize({"schema_version": "secopsai.research.operation.v1", "coverage": status["coverage"], "editions": editions, "assistant_teams": teams,
                     "runtime": runtime,
                     "pending_source_reviews": pending_reviews,
                     "research_desk": desk,
                     "automation": {"assistant_team_autostart_enabled": os.environ.get("SECOPSAI_RESEARCH_ASSISTANT_AUTOSTART") == "1",
                                    "daily_brief_assembly_enabled": os.environ.get("SECOPSAI_PRIMARY_INTEL") == "1",
                                    "team_dispatch": dispatches[0]["payload"] if dispatches else None,
                                    "team_cycle": auto_cycles[0]["payload"] if auto_cycles else None,
                                    "daily": _daily_automation_view(db_path=db_path)},
                     "requirements": status["requirements"], "missing_requirements": status["missing_requirements"],
                     "reviewed_daily_brief_streak": status["reviewed_daily_brief_streak"], "fourteen_day_gate_met": status["fourteen_day_gate_met"],
                     "rpo_target_seconds": status["rpo_target_seconds"], "rto_target_seconds": status["rto_target_seconds"],
                     "recovery_targets_proven": status["recovery_targets_proven"], "decision_mode": status["decision_mode"], "clef_enabled": status["clef_enabled"]}, string_limit=30000)
    for original, projected in zip(editions, projection["editions"]):
        if "draft" in original and projected.get("draft") != original["draft"]:
            projected.pop("draft", None)
            projected["draft_omitted"] = "Complete draft cannot be shown after privacy minimization; review it in the ledger"
    # Remove whole oldest previews before transport, never silently cut text.
    for projected in reversed(projection["editions"]):
        if len(json.dumps(projection).encode()) <= 125000:
            break
        if "draft" in projected:
            projected.pop("draft")
            projected["draft_omitted"] = "Complete draft exceeds hosted transport budget; review it in the ledger"
    if len(json.dumps(projection).encode()) > 125000:
        raise ValueError("research operation projection exceeds budget; hosted data was not silently truncated")
    return projection


def execute_hosted(command_id: str, payload: dict, *, db_path=None) -> dict:
    from secopsai.research_operation_store import append, digest, text, transaction

    text(command_id, "command identity", limit=160)
    action = payload.get("action")
    if action not in HOSTED_WRITE_ACTIONS:
        raise ValueError("unsupported hosted research action")
    fingerprint = digest(payload)
    # Apply and receipt commit together. A lost hosted acknowledgement can
    # redeliver the command without duplicating a correction or an approval.
    try:
        with transaction(db_path) as conn:
            receipt = conn.execute("SELECT fingerprint,payload_json FROM research_operation_records WHERE record_id=?", ("CMD-" + command_id,)).fetchone()
            if receipt:
                if receipt["fingerprint"] != fingerprint:
                    raise ValueError("conflicting research command delivery")
                return json.loads(receipt["payload_json"])["result"]
            result = execute(action, payload.get("data", {}), actor=payload.get("actor", ""), case_id=payload.get("case_id", ""), identity=payload.get("id", ""), db_path=db_path)
            receipt = append("hosted_command", {"action": action, "result": result}, actor=payload["actor"], fingerprint=fingerprint, connection=conn)
            conn.execute("UPDATE research_operation_records SET record_id=? WHERE record_id=?", ("CMD-" + command_id, receipt["record_id"]))
    except Exception as exc:
        # The dashboard only sees the ledger: record why an operator's action
        # was refused so it is not silently lost.
        append("hosted_command_failed", {"action": action, "command_id": command_id, "error": str(exc)[:500]},
               actor=str(payload.get("actor") or "unknown")[:160], db_path=db_path)
        raise
    return result


def recent_actions(*, db_path=None, limit: int = 10) -> list[dict]:
    """Latest hosted operator actions and their outcome, for the dashboard."""
    rows = [{"action": r["payload"].get("action") or "", "actor": r["actor"], "status": "recorded", "error": "", "at": r["created_at"]}
            for r in records("hosted_command", db_path=db_path, limit=limit)]
    rows += [{"action": r["payload"].get("action") or "", "actor": r["actor"], "status": "refused", "error": r["payload"].get("error", ""), "at": r["created_at"]}
             for r in records("hosted_command_failed", db_path=db_path, limit=limit)]
    return sorted(rows, key=lambda row: row["at"], reverse=True)[:limit]


def registered_people(*, db_path=None) -> list[dict]:
    import soc_store
    from secopsai.research_operation_store import read_connection

    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        rows = conn.execute("SELECT person_id,display_name,roles_json,active FROM research_people ORDER BY person_id LIMIT 50").fetchall()
    return [{"person_id": r["person_id"], "display_name": r["display_name"], "roles": json.loads(r["roles_json"]), "active": bool(r["active"])} for r in rows]


