from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SESSION_DIR = ROOT / "data" / "sessions"
VALID_SESSION_STATUS = {"open", "closed"}
VALID_STEP_STATUS = {"pending", "in_progress", "completed", "blocked"}
VALID_APPROVAL_DECISIONS = {"approved", "rejected"}


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def session_dir(path: Optional[str] = None) -> Path:
    configured = path or os.environ.get("SECOPSAI_SESSION_DIR")
    return Path(configured).expanduser().resolve() if configured else DEFAULT_SESSION_DIR


def session_path(session_id: str, path: Optional[str] = None) -> Path:
    return session_dir(path) / f"{session_id}.json"


def _write_session(payload: Dict[str, Any], path: Optional[str] = None) -> Path:
    target = session_path(str(payload["session_id"]), path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload["updated_at"] = _utc_now()
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return target


def load_session(session_id: str, path: Optional[str] = None) -> Dict[str, Any]:
    target = session_path(session_id, path)
    if not target.exists():
        raise ValueError(f"session not found: {session_id}")
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid session payload: {session_id}")
    return payload


def list_sessions(
    *,
    kind: Optional[str] = None,
    status: Optional[str] = None,
    finding_id: Optional[str] = None,
    limit: int = 50,
    path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    target = session_dir(path)
    if not target.exists():
        return []

    rows: List[Dict[str, Any]] = []
    for candidate in target.glob("*.json"):
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        if kind and str(payload.get("kind") or "") != kind:
            continue
        if status and str(payload.get("status") or "") != status:
            continue
        subject = payload.get("subject") or {}
        if finding_id and str(subject.get("finding_id") or "") != finding_id:
            continue
        rows.append(payload)

    rows.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
    return rows[:limit]


def _normalize_step(item: Dict[str, Any], now: str) -> Dict[str, Any]:
    status = str(item.get("status") or "pending")
    if status not in VALID_STEP_STATUS:
        raise ValueError(f"invalid plan status: {status}")
    title = str(item.get("title") or item.get("step") or "").strip()
    if not title:
        raise ValueError("plan step requires a title")
    normalized = {
        "step_id": str(item.get("step_id") or _new_id("STEP")),
        "title": title,
        "status": status,
        "updated_at": str(item.get("updated_at") or now),
    }
    note = str(item.get("note") or "").strip()
    if note:
        normalized["note"] = note
    return normalized


def _append_event(
    session: Dict[str, Any],
    *,
    event_type: str,
    message: str,
    data: Optional[Dict[str, Any]] = None,
    author: Optional[str] = None,
) -> Dict[str, Any]:
    event = {
        "event_id": _new_id("EVT"),
        "ts": _utc_now(),
        "type": str(event_type),
        "message": str(message),
    }
    if data:
        event["data"] = data
    if author:
        event["author"] = author
    session.setdefault("events", []).append(event)
    return event


def create_session(
    *,
    kind: str = "general",
    title: str,
    subject: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    initial_plan: Optional[List[Dict[str, Any]]] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    now = _utc_now()
    payload: Dict[str, Any] = {
        "session_id": _new_id("SES"),
        "kind": str(kind),
        "title": str(title).strip(),
        "status": "open",
        "created_at": now,
        "updated_at": now,
        "subject": dict(subject or {}),
        "metadata": dict(metadata or {}),
        "plan": [_normalize_step(item, now) for item in (initial_plan or [])],
        "artifacts": [],
        "approvals": [],
        "events": [],
    }
    _append_event(
        payload,
        event_type="session_created",
        message=f"Created {payload['kind']} session.",
        data={"subject": payload["subject"]},
    )
    _write_session(payload, path)
    return payload


def add_note(
    session_id: str,
    *,
    message: str,
    author: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    session = load_session(session_id, path)
    _append_event(session, event_type="note", message=message, author=author)
    _write_session(session, path)
    return session


def add_event(
    session_id: str,
    *,
    event_type: str,
    message: str,
    data: Optional[Dict[str, Any]] = None,
    author: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    session = load_session(session_id, path)
    _append_event(session, event_type=event_type, message=message, data=data, author=author)
    _write_session(session, path)
    return session


def update_step(
    session_id: str,
    *,
    step: str,
    status: str,
    note: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    if status not in VALID_STEP_STATUS:
        raise ValueError(f"invalid plan status: {status}")
    session = load_session(session_id, path)
    now = _utc_now()
    matched = None
    for item in session.get("plan", []):
        if str(item.get("step_id") or "") == step or str(item.get("title") or "") == step:
            matched = item
            break
    if matched is None:
        matched = _normalize_step({"title": step, "status": status, "note": note or ""}, now)
        session.setdefault("plan", []).append(matched)
    else:
        matched["status"] = status
        matched["updated_at"] = now
        if note:
            matched["note"] = str(note).strip()
    _append_event(
        session,
        event_type="plan_step_updated",
        message=f"{matched['title']} -> {status}",
        data={"step_id": matched["step_id"], "status": status},
    )
    _write_session(session, path)
    return session


def add_artifact(
    session_id: str,
    *,
    kind: str,
    artifact_path: str,
    label: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    session = load_session(session_id, path)
    normalized_path = str(Path(artifact_path).expanduser().resolve())
    for item in session.get("artifacts", []):
        if str(item.get("path") or "") == normalized_path and str(item.get("kind") or "") == kind:
            return session
    artifact = {
        "artifact_id": _new_id("ART"),
        "kind": str(kind),
        "path": normalized_path,
        "created_at": _utc_now(),
    }
    if label:
        artifact["label"] = str(label)
    if metadata:
        artifact["metadata"] = dict(metadata)
    session.setdefault("artifacts", []).append(artifact)
    _append_event(
        session,
        event_type="artifact_added",
        message=f"Attached {kind} artifact.",
        data={"artifact_id": artifact["artifact_id"], "path": normalized_path},
    )
    _write_session(session, path)
    return session


def request_approval(
    session_id: str,
    *,
    approval_type: str,
    summary: str,
    payload: Dict[str, Any],
    requested_by: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    session = load_session(session_id, path)
    approval = {
        "approval_id": _new_id("APR"),
        "type": str(approval_type),
        "summary": str(summary),
        "payload": dict(payload),
        "state": "pending",
        "requested_at": _utc_now(),
    }
    if requested_by:
        approval["requested_by"] = requested_by
    session.setdefault("approvals", []).append(approval)
    _append_event(
        session,
        event_type="approval_requested",
        message=approval["summary"],
        data={"approval_id": approval["approval_id"], "type": approval["type"]},
        author=requested_by,
    )
    _write_session(session, path)
    return approval


def resolve_approval(
    session_id: str,
    approval_id: str,
    *,
    decision: str,
    note: Optional[str] = None,
    decided_by: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    if decision not in VALID_APPROVAL_DECISIONS:
        raise ValueError(f"invalid approval decision: {decision}")
    session = load_session(session_id, path)
    approval = None
    for item in session.get("approvals", []):
        if str(item.get("approval_id") or "") == approval_id:
            approval = item
            break
    if approval is None:
        raise ValueError(f"approval not found: {approval_id}")
    approval["state"] = decision
    approval["decided_at"] = _utc_now()
    if note:
        approval["note"] = str(note).strip()
    if decided_by:
        approval["decided_by"] = decided_by
    _append_event(
        session,
        event_type="approval_resolved",
        message=f"{approval['summary']} -> {decision}",
        data={"approval_id": approval_id, "decision": decision},
        author=decided_by,
    )
    _write_session(session, path)
    return approval


def set_session_status(
    session_id: str,
    *,
    status: str,
    message: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    if status not in VALID_SESSION_STATUS:
        raise ValueError(f"invalid session status: {status}")
    session = load_session(session_id, path)
    session["status"] = status
    _append_event(
        session,
        event_type="session_status_changed",
        message=message or f"Session marked {status}.",
        data={"status": status},
    )
    _write_session(session, path)
    return session
