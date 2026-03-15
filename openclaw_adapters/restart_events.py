from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        kind = str(pick(record, ("kind",), ("type",), ("event",)) or "")
        if "restart" not in kind.lower():
            continue

        delivery_context = pick(record, ("deliveryContext",), ("delivery_context",)) or {}
        if not isinstance(delivery_context, dict):
            delivery_context = {}

        adapted.append(
            make_envelope(
                ts=str(pick(record, ("ts",), ("timestamp",))),
                surface="restart",
                action="restart",
                status=str(pick(record, ("status",)) or "ok"),
                origin="restart_sentinel",
                native_type=kind or "restart_sentinel",
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
                    "channel": pick(record, ("channel",), ("deliveryContext", "channel"), ("delivery_context", "channel")),
                    "account_id": pick(record, ("accountId",), ("account_id",), ("deliveryContext", "accountId"), ("delivery_context", "account_id")),
                    "thread_id": pick(record, ("threadId",), ("thread_id",), ("deliveryContext", "threadId"), ("delivery_context", "thread_id")),
                },
                payload={
                    "delivery_target": pick(record, ("deliveryTarget",), ("delivery_target",), ("deliveryContext", "target"), ("delivery_context", "target")),
                    "message": pick(record, ("message",)),
                    "doctor_hint": pick(record, ("doctorHint",), ("doctor_hint",)),
                    "stats": pick(record, ("stats",)),
                },
            )
        )
    return adapted
