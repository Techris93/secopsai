from __future__ import annotations

from typing import Any, Dict, List

from .common import make_envelope, pick


def _action_for_stream(stream: str, phase: str | None) -> str:
    lowered = f"{stream} {phase or ''}".lower()
    if "update" in lowered:
        return "update"
    if "start" in lowered:
        return "start"
    return "end"


def adapt(records: List[Dict[str, Any]], source_path: str, collected_from: str, host: str, privacy_profile: str) -> List[Dict[str, Any]]:
    adapted: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        stream = str(pick(record, ("stream",), ("event",), ("type",)) or "")
        tool_name = pick(record, ("data", "toolName"), ("data", "tool_name"), ("toolName",), ("tool_name",))
        if "tool" not in stream.lower() and tool_name is None:
            continue

        phase = pick(record, ("data", "phase"), ("phase",), ("data", "action"), ("action",))
        action = _action_for_stream(stream, str(phase) if phase is not None else None)
        default_status = "running" if action in {"start", "update"} else "completed"
        timestamp = pick(record, ("ts",), ("timestamp",), ("data", "ts"))
        run_id = pick(record, ("runId",), ("run_id",), ("data", "runId"), ("data", "run_id"))
        tool_call_id = pick(record, ("data", "toolCallId"), ("data", "tool_call_id"), ("toolCallId",), ("tool_call_id",))
        args = pick(record, ("data", "args"), ("args",)) or {}
        result = pick(record, ("data", "result"), ("result",)) or {}

        adapted.append(
            make_envelope(
                ts=str(timestamp),
                surface="tool",
                action=action,
                status=str(pick(record, ("data", "status"), ("status",), ("data", "result", "status")) or default_status),
                origin="agent_event",
                native_type=stream or "tool_execution",
                source_path=source_path,
                index=index,
                record=record,
                collected_from=collected_from,
                host=host,
                privacy_profile=privacy_profile,
                openclaw_fields={
                    "run_id": run_id,
                    "session_key": pick(record, ("sessionKey",), ("session_key",), ("data", "sessionKey"), ("data", "session_key")),
                    "session_id": pick(record, ("data", "sessionId"), ("sessionId",), ("session_id",)),
                    "agent_id": pick(record, ("data", "agentId"), ("agentId",), ("agent_id",)),
                    "channel": pick(record, ("data", "channel"), ("channel",)),
                    "account_id": pick(record, ("data", "accountId"), ("accountId",), ("account_id",)),
                    "thread_id": pick(record, ("data", "threadId"), ("threadId",), ("thread_id",)),
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                },
                payload={
                    "args": args if isinstance(args, dict) else {"raw_args": args},
                    "result": result if isinstance(result, dict) else {"raw_result": result},
                    "command": pick(record, ("data", "command"), ("command",), ("data", "args", "command")),
                    "duration_ms": pick(record, ("data", "durationMs"), ("durationMs",), ("data", "result", "durationMs")),
                    "exit_code": pick(record, ("data", "exitCode"), ("exitCode",), ("data", "result", "exitCode")),
                    "mutating": pick(record, ("data", "mutating"), ("mutating",)),
                    "background": pick(record, ("data", "background"), ("background",)),
                    "approval_state": pick(record, ("data", "approvalState"), ("approvalState",), ("approval_state",)),
                },
            )
        )
    return adapted
