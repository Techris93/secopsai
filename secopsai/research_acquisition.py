"""Auditable requests for artifacts that are no longer available from a registry."""
from __future__ import annotations

from contextlib import closing
from typing import Any, Dict, Optional

import soc_store


def create_partner_request(case_id: str, *, recipient: str, reason: str, subject_id: Optional[str] = None, artifact_sha256: str = "", actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    if not recipient.strip() or not reason.strip():
        raise ValueError("recipient and reason are required")
    soc_store.init_db(db_path)
    request_id = "PRQ-" + __import__("secrets").token_hex(6).upper()
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        if subject_id and connection.execute("SELECT 1 FROM research_subjects WHERE subject_id = ? AND case_id = ?", (subject_id, case_id)).fetchone() is None:
            raise ValueError("subject does not belong to case")
        connection.execute("""INSERT INTO research_partner_requests
            (request_id, case_id, subject_id, requested_by, recipient, reason, status, artifact_sha256, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)""", (request_id, case_id, subject_id, actor, recipient.strip(), reason.strip(), artifact_sha256.strip().lower(), now, now))
        connection.commit()
    return {"request_id": request_id, "case_id": case_id, "status": "draft", "recipient": recipient.strip(), "artifact_sha256": artifact_sha256.strip().lower()}


def update_partner_request(request_id: str, *, status: str, actor: str = "analyst", db_path: Optional[str] = None) -> Dict[str, Any]:
    if status not in {"approved", "sent", "received", "closed", "canceled"}:
        raise ValueError("invalid partner request status")
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_partner_requests WHERE request_id = ?", (request_id,)).fetchone()
        if row is None:
            raise ValueError(f"partner request not found: {request_id}")
        connection.execute("UPDATE research_partner_requests SET status = ?, updated_at = ? WHERE request_id = ?", (status, soc_store.utc_now(), request_id))
        connection.commit()
    return {"request_id": request_id, "case_id": row["case_id"], "status": status, "actor": actor}


def list_partner_requests(case_id: Optional[str] = None, *, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        if case_id:
            rows = connection.execute("SELECT * FROM research_partner_requests WHERE case_id = ? ORDER BY updated_at DESC", (case_id,)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM research_partner_requests ORDER BY updated_at DESC").fetchall()
    return [dict(row) for row in rows]
