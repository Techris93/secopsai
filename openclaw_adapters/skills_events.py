from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick


ACTION_MAP = {
    "install": "install",
    "enable": "enable",
    "disable": "disable",
    "update": "enable",
}


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        kind = str(pick(record, ("kind",), ("type",), ("event",)) or "")
        if "skill" not in kind.lower():
            continue

        raw_action = str(pick(record, ("action",), ("operation",)) or "install").lower()
        action = ACTION_MAP.get(raw_action, "install")

        adapted.append(
            make_envelope(
                ts=str(pick(record, ("ts",), ("timestamp",))),
                surface="skills",
                action=action,
                status=str(pick(record, ("status",)) or "ok"),
                origin="skills_rpc",
                native_type=kind or "skills_event",
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
                    "skill_key": pick(record, ("skillKey",), ("skill_key",)),
                },
                payload={
                    "skill_source": pick(record, ("skillSource",), ("skill_source",), ("source",)),
                    "source": pick(record, ("skillSource",), ("skill_source",), ("source",)),
                    "mutating": True,
                    "label": pick(record, ("label",)),
                    "attack_type": pick(record, ("attack_type",)),
                    "mitre": pick(record, ("mitre",)),
                },
            )
        )
    return adapted
