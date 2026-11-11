"""Publish a bounded, redacted projection of research cases to Core Edge.

The hosted Mission Control has no access to the research ledger, so its
Research page was empty.  Each worker cycle pushes changed cases to
``/api/v1/research/cases/sync``.  The projection keeps what an operator needs
to review a case (status, verdicts, evidence titles and hashes, IOCs, claims,
recent timeline, publication reviews) and drops raw artifact metadata, local
filesystem locators, and disclosure message bodies.
"""

from __future__ import annotations

import json
import re
from contextlib import closing
from typing import Any, Dict, List, Optional

import soc_store

SUMMARY_LIMIT = 15_000
DETAIL_LIMIT = 90_000
BATCH_SIZE = 25
CURSOR_KEY = "core_research_case_sync"
LOCAL_LOCATOR_RE = re.compile(r"^(?:local-artifact|file|quarantine)://|^/|^[A-Za-z]:\\\\")


def _text(value: Any, limit: int) -> str:
    return str(value if value is not None else "")[:limit]


def _locator(value: Any) -> str:
    text = _text(value, 500)
    # Local paths and quarantine locators reveal the analyst workstation layout.
    return "local evidence (not published)" if LOCAL_LOCATOR_RE.search(text) else text


def _pick(item: Dict[str, Any], keys: List[str], limit: int = 500) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key in keys:
        value = item.get(key)
        if isinstance(value, (int, float, bool)) or value is None:
            result[key] = value
        elif isinstance(value, (list, tuple)):
            result[key] = [_text(entry, 200) for entry in list(value)[:20]]
        else:
            result[key] = _text(value, limit)
    return result


TEAM_TEXT_FIELDS = ("summary", "risk_assessment", "verdict_recommendation", "verdict_rationale")
TEAM_LIST_FIELDS = ("evidence", "recommended_actions", "limitations")
# Each step halves what a stage may show until the case fits Core's bounds.
TEAM_SHRINK_STEPS = ((1500, 8, 500), (800, 6, 300), (400, 4, 200), (200, 3, 120))


def _team_output(output: Any, text_limit: int, items: int, item_limit: int) -> Dict[str, Any]:
    if not isinstance(output, dict):
        return {}
    shown: Dict[str, Any] = {}
    for key in TEAM_TEXT_FIELDS:
        value = _text(output.get(key), text_limit)
        if value:
            shown[key] = value
    for key in TEAM_LIST_FIELDS:
        values = [_text(item, item_limit) for item in (output.get(key) or []) if isinstance(item, str) and item.strip()]
        if values:
            shown[key] = values[:items]
            if len(values) > items:
                shown[key + "_omitted"] = len(values) - items
    return shown


def case_teams(case_id: str, *, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Each assistant team's stage outputs and blind reviews, newest team first.

    These are model proposals for a human reviewer to read; the dashboard
    shows them on the case so review does not need the worker's ledger.
    """
    from secopsai.research_assistant_team import STAGES, _plans
    from secopsai.research_operation_store import records
    from secopsai.specialist_orchestrator import get_run

    teams = []
    for plan in _plans(case_id, db_path=db_path, limit=3):
        progress = records("assistant_team_progress", case_id=plan["team_id"], db_path=db_path, limit=1)
        state = progress[0]["payload"] if progress else {}
        stages = []
        for stage, profile, _ in STAGES:
            run_id = (state.get("runs") or {}).get(stage)
            if not run_id:
                continue
            try:
                run = get_run(run_id, db_path=db_path)
            except Exception:  # a missing run must not stop the case from syncing
                continue
            review = run.get("review") or {}
            stages.append({
                "stage": stage, "profile": profile, "run_id": run_id, "status": run.get("status"),
                "completed": stage in (state.get("completed_stages") or []),
                "model": _text((run.get("result") or {}).get("model"), 160),
                "material_disagreement": bool(run.get("material_disagreement")),
                "output": (run.get("result") or {}).get("output") or {},
                "review": review.get("output") or {},
            })
        teams.append({"team_id": plan["team_id"], "created_at": plan.get("created_at"), "status": state.get("status", "queued"),
                      "reason": _text(state.get("reason"), 500), "updated_at": progress[0]["created_at"] if progress else plan.get("created_at"),
                      "stages": stages})
    return teams


def _shown_teams(teams: List[Dict[str, Any]], step: tuple) -> List[Dict[str, Any]]:
    text_limit, items, item_limit = step
    return [{**{key: value for key, value in team.items() if key != "stages"},
             "stages": [{**{key: value for key, value in stage.items() if key not in {"output", "review"}},
                         "output": _team_output(stage["output"], text_limit, items, item_limit),
                         "review": _team_output(stage["review"], text_limit, items, item_limit)}
                        for stage in team["stages"]]}
            for team in teams]


def project_case(case: Dict[str, Any], summary: Dict[str, Any], teams: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Return {summary, detail} within the Core size bounds."""
    summary_projection = {key: value for key, value in summary.items() if isinstance(value, (str, int, float, bool)) or value is None}
    detail: Dict[str, Any] = _pick(case, [
        "case_id", "title", "summary", "case_type", "severity", "confidence", "status", "owner",
        "disclosure_status", "embargo_until", "created_at", "updated_at", "closed_at", "published_at",
        "investigation_priority", "detection_confidence", "assessment", "potential_impact",
        "local_exposure", "evidence_quality",
    ], limit=4000)
    detail["publication_readiness"] = case.get("publication_readiness") if isinstance(case.get("publication_readiness"), dict) else {}
    assurance = case.get("research_assurance") or {}
    detail["research_assurance"] = {key: assurance.get(key) for key in ("policy_version", "ready", "blockers", "technical_review_current", "editorial_review_current", "prior_art_current", "confirmed_observation")}
    detail["subjects"] = [_pick(item, ["subject_id", "subject_type", "ecosystem", "name", "version", "publisher", "status", "registry_state", "artifact_state", "validation_state"]) for item in (case.get("subjects") or [])[:50]]
    detail["evidence"] = [
        {**_pick(item, ["evidence_id", "evidence_type", "title", "sha256", "provenance", "notes", "status", "collected_at", "created_at"], limit=1000), "locator": _locator(item.get("locator"))}
        for item in (case.get("evidence") or [])[:100]
    ]
    detail["iocs"] = [_pick(item, ["ioc_id", "ioc_type", "value", "confidence", "status", "source_evidence_id", "first_seen", "last_seen"]) for item in (case.get("iocs") or [])[:200]]
    detail["claims"] = [_pick(item, ["claim_id", "statement", "status", "confidence", "supporting_evidence", "missing_evidence", "limitations"], limit=1000) for item in (case.get("claims") or [])[:100]]
    detail["verdicts"] = [_pick(item, ["verdict_id", "verdict", "confidence", "rationale", "actor", "evidence_ids", "created_at"], limit=2000) for item in (case.get("verdicts") or [])[:50]]
    detail["publication_reviews"] = [_pick(item, ["review_id", "status", "blockers", "warnings", "approved_by", "created_at"]) for item in (case.get("publication_reviews") or [])[:10]]
    # Disclosure bodies and attachments stay local; status is enough to operate.
    detail["disclosures"] = [_pick(item, ["disclosure_id", "status", "recipient", "subject", "created_at", "sent_at"]) for item in (case.get("disclosures") or [])[:20]]
    detail["timeline"] = [_pick(item, ["event_id", "event_type", "message", "actor", "created_at"]) for item in (case.get("timeline") or [])[:50]]
    detail["findings"] = [_pick(item, ["finding_id", "title", "severity", "status", "relationship"]) for item in (case.get("findings") or [])[:50]]
    teams = teams or []
    for step in TEAM_SHRINK_STEPS:
        detail["assistant_teams"] = _shown_teams(teams, step)
        if len(json.dumps(detail, default=str)) <= DETAIL_LIMIT:
            break
    while len(json.dumps(detail, default=str)) > DETAIL_LIMIT and detail["assistant_teams"]:
        detail["assistant_teams"].pop()  # oldest team first
        detail["projection_truncated"] = True
    for key in ("timeline", "claims", "iocs", "evidence"):
        while len(json.dumps(detail, default=str)) > DETAIL_LIMIT and detail[key]:
            detail[key] = detail[key][: len(detail[key]) // 2]
            detail["projection_truncated"] = True
    while len(json.dumps(summary_projection, default=str)) > SUMMARY_LIMIT and summary_projection.get("summary"):
        summary_projection["summary"] = str(summary_projection["summary"])[: len(str(summary_projection["summary"])) // 2]
    from secopsai.intelligence import minimize

    # Same redaction as every other Core payload: secret-named keys and
    # absolute local paths are removed.
    return {"summary": minimize(summary_projection), "detail": minimize(json.loads(json.dumps(detail, default=str)))}


def _cursor(db_path: Optional[str]) -> str:
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS core_sync_cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
        row = connection.execute("SELECT value FROM core_sync_cursors WHERE name=?", (CURSOR_KEY,)).fetchone()
        connection.commit()
    return str(row["value"]) if row else ""


def _save_cursor(db_path: Optional[str], value: str) -> None:
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "INSERT INTO core_sync_cursors (name, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (CURSOR_KEY, value, soc_store.utc_now()),
        )
        connection.commit()


def _team_changes(db_path: Optional[str]) -> Dict[str, str]:
    """case_id -> when any of its assistant teams last changed."""
    with closing(soc_store.connect(db_path)) as connection:
        try:
            rows = connection.execute(
                """SELECT p.case_id, MAX(COALESCE(s.created_at, p.created_at)) AS changed
                   FROM research_operation_records p
                   LEFT JOIN research_operation_records s
                     ON s.kind = 'assistant_team_progress' AND s.case_id = json_extract(p.payload_json, '$.team_id')
                   WHERE p.kind = 'assistant_team_plan'
                   GROUP BY p.case_id"""
            ).fetchall()
        except Exception:  # no operation store yet
            return {}
    return {str(row["case_id"]): str(row["changed"] or "") for row in rows}


def sync_research_cases(client: Any, *, db_path: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    """Push cases changed since the last successful sync.  Resumable."""
    from secopsai.research_cases import get_case, list_cases

    if not getattr(client, "enabled", False):
        return {"status": "disabled"}
    since = _cursor(db_path)
    listed = list_cases(limit=500, db_path=db_path)
    listed = listed.get("cases", []) if isinstance(listed, dict) else listed
    # A team's progress does not change the case's own updated_at, so the case
    # is resent when either moves; Core keeps the newer of the two.
    team_changes = _team_changes(db_path)
    for item in listed:
        item["_synced_at"] = max(str(item.get("updated_at") or ""), team_changes.get(item.get("case_id"), ""))
    changed = sorted((item for item in listed if item["_synced_at"] > since), key=lambda item: item["_synced_at"])[:limit]
    accepted = 0
    rejected: List[Dict[str, Any]] = []
    for start in range(0, len(changed), BATCH_SIZE):
        batch = changed[start:start + BATCH_SIZE]
        payload = []
        for item in batch:
            summary = {key: value for key, value in item.items() if key != "_synced_at"}
            teams = case_teams(item["case_id"], db_path=db_path) if item["case_id"] in team_changes else []
            projection = project_case(get_case(item["case_id"], db_path=db_path), summary, teams)
            payload.append({"case_id": item["case_id"], "updated_at": item["_synced_at"], **projection})
        result = client.sync_research_cases(payload)
        accepted += int(result.get("accepted") or 0)
        rejected.extend(result.get("rejected") or [])
        # Advance only past batches Core accepted, so a failure resumes here.
        _save_cursor(db_path, str(batch[-1]["_synced_at"] or since))
    return {"status": "accepted", "considered": len(changed), "accepted": accepted, "rejected": rejected[:20]}
