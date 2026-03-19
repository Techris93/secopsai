from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick, redact_text


EXEC_TOOL_NAMES = {"exec", "run_in_terminal", "execute_command", "shell", "bash", "sh"}


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        tool_name = str(pick(record, ("toolName",), ("tool_name",)) or "")
        if tool_name not in EXEC_TOOL_NAMES:
            continue

        phase = str(pick(record, ("phase",), ("action",)) or "end").lower()
        action = "start" if phase in {"start", "running"} else "end"
        default_status = "running" if action == "start" else "completed"

        adapted.append(
            make_envelope(
                ts=str(pick(record, ("ts",), ("timestamp",))),
                surface="exec",
                action=action,
                status=str(pick(record, ("status",)) or default_status),
                origin="process_registry",
                native_type=str(pick(record, ("kind",), ("type",)) or f"exec_{action}"),
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
                    "details": {"cwd": pick(record, ("cwd",))},
                },
                payload={
                    "command": redact_text(str(pick(record, ("command",)) or ""), max_length=512) or None,
                    "duration_ms": pick(record, ("durationMs",), ("duration_ms",)),
                    "exit_code": pick(record, ("exitCode",), ("exit_code",)),
                    "background": pick(record, ("background",)),
                    "mutating": pick(record, ("mutating",)),
                    "approval_state": pick(record, ("approvalState",), ("approval_state",)),
                    "label": pick(record, ("label",)),
                    "attack_type": pick(record, ("attack_type",)),
                    "mitre": pick(record, ("mitre",)),
                },
            )
        )
    return adapted
