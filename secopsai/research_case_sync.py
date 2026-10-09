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


def project_case(case: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, Any]:
    """Return {summary, detail} within the Core size bounds."""
    summary_projection = {key: value for key, value in summary.items() if isinstance(value, (str, int, float, bool)) or value is None}
    detail: Dict[str, Any] = _pick(case, [
        "case_id", "title", "summary", "case_type", "severity", "confidence", "status", "owner",
        "disclosure_status", "embargo_until", "created_at", "updated_at", "closed_at", "published_at",
        "investigation_priority", "detection_confidence", "assessment", "potential_impact",
        "local_exposure", "evidence_quality",
    ], limit=4000)
    detail["publication_readiness"] = case.get("publication_readiness") if isinstance(case.get("publication_readiness"), dict) else {}
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


def sync_research_cases(client: Any, *, db_path: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    """Push cases changed since the last successful sync.  Resumable."""
    from secopsai.research_cases import get_case, list_cases

    if not getattr(client, "enabled", False):
        return {"status": "disabled"}
    since = _cursor(db_path)
    listed = list_cases(limit=500, db_path=db_path)
    listed = listed.get("cases", []) if isinstance(listed, dict) else listed
    changed = sorted((item for item in listed if str(item.get("updated_at") or "") > since), key=lambda item: str(item.get("updated_at") or ""))[:limit]
    accepted = 0
    rejected: List[Dict[str, Any]] = []
    for start in range(0, len(changed), BATCH_SIZE):
        batch = changed[start:start + BATCH_SIZE]
        payload = []
        for item in batch:
            projection = project_case(get_case(item["case_id"], db_path=db_path), item)
            payload.append({"case_id": item["case_id"], "updated_at": item.get("updated_at"), **projection})
        result = client.sync_research_cases(payload)
        accepted += int(result.get("accepted") or 0)
        rejected.extend(result.get("rejected") or [])
        # Advance only past batches Core accepted, so a failure resumes here.
        _save_cursor(db_path, str(batch[-1].get("updated_at") or since))
    return {"status": "accepted", "considered": len(changed), "accepted": accepted, "rejected": rejected[:20]}
