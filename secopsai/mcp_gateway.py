from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import soc_store


SAFE_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,240}$")
SAFE_DIGEST = re.compile(r"^[a-f0-9]{64}$")
ALLOWED_EVENTS = {"authenticated_request", "stdio_started", "tool_call"}
ALLOWED_TRANSPORTS = {"streamable-http", "stdio"}
ALLOWED_DETAIL_KEYS = {"error_type", "method", "process_id", "request_id", "result"}
ACTIVE_WINDOW_MINUTES = 15


def record_activity(payload: dict[str, Any], *, request_id: str, db_path: str | None = None) -> dict[str, Any]:
    normalized = _normalize_activity(payload)
    now = soc_store.utc_now()
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        existing = connection.execute(
            "SELECT status FROM mcp_client_sessions WHERE session_id = ?",
            (normalized["session_id"],),
        ).fetchone()
        status = "revoked" if existing and existing["status"] == "revoked" else "active"
        connection.execute(
            """
            INSERT INTO mcp_client_sessions (
                session_id, client_id, client_name, subject_id, organization_id, workspace_id,
                transport, scopes_json, status, first_seen_at, last_seen_at,
                last_tool, request_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(session_id) DO UPDATE SET
                client_id = excluded.client_id,
                client_name = excluded.client_name,
                subject_id = excluded.subject_id,
                organization_id = excluded.organization_id,
                workspace_id = excluded.workspace_id,
                transport = excluded.transport,
                scopes_json = excluded.scopes_json,
                status = CASE WHEN mcp_client_sessions.status = 'revoked' THEN 'revoked' ELSE 'active' END,
                last_seen_at = excluded.last_seen_at,
                last_tool = CASE WHEN excluded.last_tool != '' THEN excluded.last_tool ELSE mcp_client_sessions.last_tool END,
                request_count = mcp_client_sessions.request_count + 1
            """,
            (
                normalized["session_id"], normalized["client_id"], normalized["client_name"],
                normalized["subject_id"], normalized["organization_id"], normalized["workspace_id"], normalized["transport"],
                json.dumps(normalized["scopes"]), status, now, now, normalized["tool_name"],
            ),
        )
        connection.execute(
            """
            INSERT INTO mcp_client_events (
                session_id, event_type, tool_name, request_id, details_json, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                normalized["session_id"], normalized["event_type"], normalized["tool_name"],
                _safe_text(request_id, 128), json.dumps(_safe_details(payload.get("details"))), now,
            ),
        )
        connection.commit()
    return {"recorded": True, "session": session_status(normalized["session_id"], db_path=db_path)["session"]}


def session_status(session_id: str, *, db_path: str | None = None) -> dict[str, Any]:
    normalized = _digest(session_id, "session_id")
    soc_store.init_db(db_path)
    with soc_store.read_connect(db_path) as connection:
        row = connection.execute(
            "SELECT session_id, status, revoked_at FROM mcp_client_sessions WHERE session_id = ?",
            (normalized,),
        ).fetchone()
    if row is None:
        return {"session": {"session_id": normalized, "status": "unknown", "revoked_at": None}}
    return {"session": dict(row)}


def revoke_session(
    session_id: str,
    *,
    actor: str,
    reason: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    normalized = _digest(session_id, "session_id")
    now = soc_store.utc_now()
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        row = connection.execute("SELECT session_id FROM mcp_client_sessions WHERE session_id = ?", (normalized,)).fetchone()
        if row is None:
            raise ValueError(f"MCP session not found: {normalized}")
        connection.execute(
            "UPDATE mcp_client_sessions SET status = 'revoked', revoked_at = ?, revoked_by = ? WHERE session_id = ?",
            (now, _safe_text(actor, 120), normalized),
        )
        connection.execute(
            "INSERT INTO mcp_client_events (session_id, event_type, tool_name, request_id, details_json, occurred_at) VALUES (?, 'revoked', '', ?, ?, ?)",
            (normalized, f"revoke-{normalized[:12]}", json.dumps({"reason": _safe_text(reason, 500)}), now),
        )
        connection.commit()
    return session_status(normalized, db_path=db_path)


def gateway_status(*, limit: int = 100, db_path: str | None = None) -> dict[str, Any]:
    bounded = max(1, min(int(limit), 500))
    soc_store.init_db(db_path)
    with soc_store.read_connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT session_id, client_id, client_name, subject_id, organization_id, workspace_id,
                   transport, scopes_json, status, first_seen_at, last_seen_at,
                   revoked_at, revoked_by, last_tool, request_count
            FROM mcp_client_sessions
            ORDER BY last_seen_at DESC, session_id DESC
            LIMIT ?
            """,
            (bounded,),
        ).fetchall()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=ACTIVE_WINDOW_MINUTES)
    sessions = []
    for row in rows:
        item = dict(row)
        item["scopes"] = _json_list(item.pop("scopes_json"))
        item["connected"] = item["status"] != "revoked" and _timestamp(item["last_seen_at"]) >= cutoff
        sessions.append(item)
    active = [item for item in sessions if item["connected"]]
    revoked = [item for item in sessions if item["status"] == "revoked"]
    return {
        "schema_version": "secopsai.mcp.gateway.status.v1",
        "generated_at": soc_store.utc_now(),
        "active_window_minutes": ACTIVE_WINDOW_MINUTES,
        "summary": {
            "recent_clients": len({item["client_id"] for item in active}),
            "connected_sessions": len(active),
            "revoked_sessions": len(revoked),
            "tracked_sessions": len(sessions),
        },
        "sessions": sessions,
        "revoked_sessions": revoked,
    }


def _normalize_activity(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("MCP activity must be an object")
    event_type = _safe_text(payload.get("event_type"), 64)
    transport = _safe_text(payload.get("transport"), 32)
    if event_type not in ALLOWED_EVENTS:
        raise ValueError("unsupported MCP activity event")
    if transport not in ALLOWED_TRANSPORTS:
        raise ValueError("unsupported MCP transport")
    scopes = payload.get("scopes") or []
    if not isinstance(scopes, list) or len(scopes) > 32:
        raise ValueError("MCP scopes must be a bounded array")
    return {
        "session_id": _digest(payload.get("session_id"), "session_id"),
        "subject_id": _digest(payload.get("subject_id"), "subject_id"),
        "client_id": _safe_id(payload.get("client_id"), "client_id"),
        "client_name": _safe_text(payload.get("client_name"), 120),
        "organization_id": _safe_id(payload.get("organization_id"), "organization_id"),
        "workspace_id": _safe_id(payload.get("workspace_id"), "workspace_id"),
        "transport": transport,
        "scopes": sorted({_safe_id(value, "scope") for value in scopes}),
        "event_type": event_type,
        "tool_name": _safe_text(payload.get("tool_name"), 120),
    }


def _safe_id(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not SAFE_ID.fullmatch(text):
        raise ValueError(f"invalid MCP {label}")
    return text


def _digest(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not SAFE_DIGEST.fullmatch(text):
        raise ValueError(f"invalid MCP {label}")
    return text


def _safe_text(value: Any, limit: int) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def _safe_details(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        _safe_text(key, 80): _safe_text(item, 500)
        for key, item in list(value.items())[:20]
        if str(key).lower() in ALLOWED_DETAIL_KEYS
    }


def _timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _json_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []
