from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        hook = str(pick(record, ("hook",), ("event",), ("type",)) or "")
        if "session" not in hook.lower():
            continue

        action = "start" if "start" in hook.lower() else "end"
        default_status = "ok" if action == "start" else "completed"
        context = pick(record, ("context",)) or {}
        if not isinstance(context, dict):
            context = {}

        adapted.append(
            make_envelope(
                ts=str(pick(record, ("ts",), ("timestamp",), ("context", "ts"))),
                surface="session",
                action=action,
                status=str(pick(record, ("status",), ("context", "status")) or default_status),
                origin="session_hook",
                native_type=hook or "session_hook",
                source_path=source_path,
                index=index,
                record=record,
                collected_from=collected_from,
                host=host,
                privacy_profile=privacy_profile,
                openclaw_fields={
                    "session_key": pick(record, ("sessionKey",), ("session_key",), ("context", "sessionKey"), ("context", "session_key")),
                    "session_id": pick(record, ("sessionId",), ("session_id",), ("context", "sessionId"), ("context", "session_id")),
                    "agent_id": pick(record, ("agentId",), ("agent_id",), ("context", "agentId"), ("context", "agent_id")),
                    "channel": pick(record, ("channel",), ("context", "channel")),
                    "account_id": pick(record, ("accountId",), ("account_id",), ("context", "accountId"), ("context", "account_id")),
                    "thread_id": pick(record, ("threadId",), ("thread_id",), ("context", "threadId"), ("context", "thread_id")),
                },
                payload={
                    "resumed_from": pick(record, ("resumedFrom",), ("resumed_from",), ("context", "resumedFrom"), ("context", "resumed_from")),
                    "message_count": pick(record, ("messageCount",), ("message_count",), ("context", "messageCount"), ("context", "message_count")),
                },
            )
        )
    return adapted
