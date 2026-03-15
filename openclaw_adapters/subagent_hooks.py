from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick


def _action_for_hook(hook: str) -> str:
    lowered = hook.lower()
    if "end" in lowered:
        return "end"
    if "delivery" in lowered:
        return "update"
    return "spawn"


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        hook = str(pick(record, ("hook",), ("event",), ("type",)) or "")
        if "subagent" not in hook.lower():
            continue

        action = _action_for_hook(hook)
        default_status = "completed" if action == "end" else "ok"
        adapted.append(
            make_envelope(
                ts=str(pick(record, ("ts",), ("timestamp",))),
                surface="subagent",
                action=action,
                status=str(pick(record, ("status",), ("result", "status")) or default_status),
                origin="subagent_hook",
                native_type=hook or "subagent_hook",
                source_path=source_path,
                index=index,
                record=record,
                collected_from=collected_from,
                host=host,
                privacy_profile=privacy_profile,
                openclaw_fields={
                    "run_id": pick(record, ("runId",), ("run_id",)),
                    "session_key": pick(record, ("sessionKey",), ("session_key",)),
                    "session_id": pick(record, ("sessionId",), ("session_id",)),
                    "agent_id": pick(record, ("agentId",), ("agent_id",)),
                    "channel": pick(record, ("channel",)),
                    "account_id": pick(record, ("accountId",), ("account_id",)),
                    "thread_id": pick(record, ("threadId",), ("thread_id",)),
                    "child_session_key": pick(record, ("childSessionKey",), ("child_session_key",)),
                    "requester_session_key": pick(record, ("requesterSessionKey",), ("requester_session_key",)),
                },
                payload={
                    "delivery_target": pick(record, ("deliveryTarget",), ("delivery_target",), ("target",)),
                    "mode": pick(record, ("mode",)),
                    "thread_requested": pick(record, ("threadRequested",), ("thread_requested",)),
                },
            )
        )
    return adapted
