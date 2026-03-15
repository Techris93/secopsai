from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        changed_paths = pick(record, ("changedPaths",), ("changed_paths",))
        if changed_paths is None:
            continue
        if not isinstance(changed_paths, list):
            raise ValueError(f"config changedPaths must be a list: {source_path}:{index + 1}")

        action = str(pick(record, ("action",), ("operation",), ("kind",)) or "patch").lower()
        if action not in {"patch", "apply"}:
            action = "patch"

        adapted.append(
            make_envelope(
                ts=str(pick(record, ("ts",), ("timestamp",))),
                surface="config",
                action=action,
                status=str(pick(record, ("status",)) or "ok"),
                origin="config_audit_jsonl",
                native_type=str(pick(record, ("kind",), ("type",), ("event",)) or f"config.{action}"),
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
                    "thread_id": pick(record, ("threadId",), ("thread_id",)),
                    "changed_paths": changed_paths,
                },
                payload={
                    "actor": pick(record, ("actor",)),
                    "note": pick(record, ("note",)),
                    "policy_decision": pick(record, ("policyDecision",), ("policy_decision",)),
                    "restart_delay_ms": pick(record, ("restartDelayMs",), ("restart_delay_ms",)),
                },
            )
        )
    return adapted
