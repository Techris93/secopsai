from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick


ACTION_MAP = {
    "start": "start",
    "request": "start",
    "approve": "approve",
    "approved": "approve",
    "accept": "approve",
    "deny": "deny",
    "denied": "deny",
}


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        kind = str(pick(record, ("kind",), ("type",), ("event",)) or "")
        if "pairing" not in kind.lower():
            continue

        raw_action = str(pick(record, ("action",), ("status",)) or "start").lower()
        action = ACTION_MAP.get(raw_action, "start")
        default_status = "ok" if action == "start" else "accepted" if action == "approve" else "blocked"

        adapted.append(
            make_envelope(
                ts=str(pick(record, ("ts",), ("timestamp",))),
                surface="pairing",
                action=action,
                status=str(pick(record, ("status",)) or default_status),
                origin="pairing_store",
                native_type=kind or "pairing_event",
                source_path=source_path,
                index=index,
                record=record,
                collected_from=collected_from,
                host=host,
                privacy_profile=privacy_profile,
                openclaw_fields={
                    "session_key": pick(record, ("sessionKey",), ("session_key",)),
                    "session_id": pick(record, ("sessionId",), ("session_id",)),
                    "agent_id": pick(record, ("agentId",), ("agent_id",)),
                    "channel": pick(record, ("channel",)),
                    "account_id": pick(record, ("accountId",), ("account_id",)),
                    "thread_id": pick(record, ("threadId",), ("thread_id",)),
                },
                payload={
                    "approval_state": pick(record, ("approvalState",), ("approval_state",), ("status",)),
                    "delivery_target": pick(record, ("deliveryTarget",), ("delivery_target",)),
                    "label": pick(record, ("label",)),
                    "attack_type": pick(record, ("attack_type",)),
                    "mitre": pick(record, ("mitre",)),
                },
            )
        )
    return adapted
