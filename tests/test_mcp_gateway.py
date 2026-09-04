from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import soc_store
from secopsai.mcp_gateway import gateway_status, record_activity, revoke_session, session_status


SESSION_ID = "a" * 64
SUBJECT_ID = "b" * 64


def activity(**overrides):
    payload = {
        "session_id": SESSION_ID,
        "client_id": "vscode-client",
        "client_name": "Visual Studio Code",
        "subject_id": SUBJECT_ID,
        "organization_id": "org-pilot-1",
        "workspace_id": "workspace-pilot-1",
        "transport": "streamable-http",
        "scopes": ["secopsai.findings.read", "secopsai.workspace.read"],
        "event_type": "authenticated_request",
        "tool_name": "",
        "details": {
            "method": "POST",
            "authorization": "must-not-persist",
            "access_token": "must-not-persist-either",
            "nested": {"client_secret": "must-not-persist-nested"},
        },
    }
    payload.update(overrides)
    return payload


def test_mcp_activity_is_deduplicated_into_one_auditable_session(tmp_path):
    db = str(tmp_path / "core.db")
    first = record_activity(activity(), request_id="request-1", db_path=db)
    assert first["session"]["status"] == "active"
    record_activity(
        activity(event_type="tool_call", tool_name="secopsai_list_findings"),
        request_id="request-2",
        db_path=db,
    )

    status = gateway_status(db_path=db)
    assert status["summary"] == {
        "recent_clients": 1,
        "connected_sessions": 1,
        "revoked_sessions": 0,
        "tracked_sessions": 1,
    }
    session = status["sessions"][0]
    assert session["request_count"] == 2
    assert session["last_tool"] == "secopsai_list_findings"
    assert session["subject_id"] == SUBJECT_ID
    assert session["workspace_id"] == "workspace-pilot-1"
    assert session["scopes"] == ["secopsai.findings.read", "secopsai.workspace.read"]
    with soc_store.read_connect(db) as connection:
        details = connection.execute("SELECT details_json FROM mcp_client_events ORDER BY event_id LIMIT 1").fetchone()[0]
    assert "authorization" not in details
    assert "must-not-persist" not in details


def test_revocation_is_durable_and_activity_cannot_reactivate_session(tmp_path):
    db = str(tmp_path / "core.db")
    record_activity(activity(), request_id="request-1", db_path=db)
    revoked = revoke_session(SESSION_ID, actor="security-operator", reason="device retired", db_path=db)
    assert revoked["session"]["status"] == "revoked"
    record_activity(activity(), request_id="request-2", db_path=db)
    assert session_status(SESSION_ID, db_path=db)["session"]["status"] == "revoked"
    status = gateway_status(db_path=db)
    assert status["summary"]["revoked_sessions"] == 1
    assert status["summary"]["connected_sessions"] == 0


def test_old_activity_is_not_presented_as_connected(tmp_path):
    db = str(tmp_path / "core.db")
    record_activity(activity(), request_id="request-1", db_path=db)
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    with soc_store.connect(db) as connection:
        connection.execute("UPDATE mcp_client_sessions SET last_seen_at = ?", (old,))
        connection.commit()
    status = gateway_status(db_path=db)
    assert status["sessions"][0]["connected"] is False


def test_schema_upgrade_backfills_workspace_for_existing_mcp_sessions(tmp_path):
    db = str(tmp_path / "core.db")
    with sqlite3.connect(db) as connection:
        connection.execute(
            """
            CREATE TABLE mcp_client_sessions (
                session_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, client_name TEXT NOT NULL,
                subject_id TEXT NOT NULL, organization_id TEXT NOT NULL, transport TEXT NOT NULL,
                scopes_json TEXT NOT NULL, status TEXT NOT NULL, first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL, revoked_at TEXT, revoked_by TEXT,
                last_tool TEXT NOT NULL DEFAULT '', request_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute("PRAGMA user_version = 8")
        connection.commit()

    soc_store.init_db(db)

    with soc_store.read_connect(db) as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(mcp_client_sessions)")}
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert "workspace_id" in columns
    assert version == soc_store.SCHEMA_VERSION


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", "not-a-digest"),
        ("subject_id", "not-a-digest"),
        ("client_id", "bad client id"),
        ("organization_id", "bad organization"),
        ("workspace_id", "bad workspace"),
        ("transport", "websocket"),
        ("event_type", "execute_anything"),
    ],
)
def test_mcp_activity_rejects_untrusted_identifiers(tmp_path, field, value):
    db = str(tmp_path / "core.db")
    with pytest.raises(ValueError):
        record_activity(activity(**{field: value}), request_id="request-1", db_path=db)
