from __future__ import annotations

import glob
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
NATIVE_DIR = REPO_ROOT / "data" / "openclaw" / "native"
SESSION_GLOB = os.path.expanduser("~/.openclaw/agents/main/sessions/*.jsonl")
CONFIG_AUDIT_FILE = Path(os.path.expanduser("~/.openclaw/logs/config-audit.jsonl"))
GATEWAY_LOG_FILES = [
    Path(os.path.expanduser("~/.openclaw/logs/gateway.log")),
    Path("/tmp/openclaw/openclaw-2026-03-16.log"),
]
EXEC_TOOL_NAMES = {"exec", "run_in_terminal", "execute_command", "shell", "bash", "sh"}
MUTATING_TOOL_NAMES = {
    "apply_patch",
    "create_file",
    "edit",
    "exec",
    "install_extension",
    "run_in_terminal",
    "shell",
    "bash",
    "sh",
    "write",
}


def iso(value: Any) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        return value if value.endswith("Z") else value
    try:
        n = float(value)
        if n > 1e12:
            n /= 1000.0
        return datetime.fromtimestamp(n, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows


def dedupe(rows: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(row.get(field) for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def infer_mutating(tool_name: str | None, arguments: dict[str, Any]) -> bool:
    if tool_name in MUTATING_TOOL_NAMES:
        return True

    command = arguments.get("command")
    if isinstance(command, str):
        lowered = command.lower()
        return any(token in lowered for token in ("chmod ", "mv ", "cp ", "rm ", "git checkout", "npm install", "pip install"))
    return False


def infer_background(arguments: dict[str, Any]) -> bool:
    value = arguments.get("isBackground")
    return bool(value) if isinstance(value, bool) else False


def config_changed_paths(row: dict[str, Any]) -> list[str]:
    suspicious = row.get("suspicious")
    if isinstance(suspicious, list) and suspicious:
        return [str(item) for item in suspicious if str(item).strip()]

    inferred: list[str] = []
    if row.get("gatewayModeBefore") != row.get("gatewayModeAfter") and row.get("gatewayModeAfter") is not None:
        inferred.append("gateway.mode")
    if row.get("configPath"):
        inferred.append("openclaw.json")
    return inferred or ["openclaw.json"]


def export_agent_and_session_hooks() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    agent_events: list[dict[str, Any]] = []
    session_hooks: list[dict[str, Any]] = []
    subagent_hooks: list[dict[str, Any]] = []
    exec_events: list[dict[str, Any]] = []
    tool_context_by_id: dict[str, dict[str, Any]] = {}
    pairing_events: list[dict[str, Any]] = []
    skills_events: list[dict[str, Any]] = []

    for file_path in sorted(glob.glob(SESSION_GLOB)):
        path = Path(file_path)
        sid = path.stem
        rows = load_jsonl(path)
        if not rows:
            continue

        first_ts = rows[0].get("timestamp")
        last_ts = rows[-1].get("timestamp")

        session_key = f"agent:main:{sid}"
        session_hooks.append(
            {
                "hook": "session_start",
                "ts": iso(first_ts),
                "sessionKey": session_key,
                "sessionId": sid,
                "agentId": "main",
                "channel": "openclaw.session",
                "status": "ok",
            }
        )
        session_hooks.append(
            {
                "hook": "session_end",
                "ts": iso(last_ts),
                "sessionKey": session_key,
                "sessionId": sid,
                "agentId": "main",
                "channel": "openclaw.session",
                "status": "completed",
            }
        )

        for row in rows:
            if row.get("type") != "message":
                continue
            message = row.get("message")
            if not isinstance(message, dict):
                continue
            role = message.get("role")

            if role == "assistant":
                for content in message.get("content", []):
                    if not isinstance(content, dict) or content.get("type") != "toolCall":
                        continue
                    arguments = content.get("arguments")
                    if not isinstance(arguments, dict):
                        arguments = {"raw": arguments}

                    tool_name = content.get("name")
                    tool_context = {
                        "command": arguments.get("command"),
                        "background": infer_background(arguments),
                        "mutating": infer_mutating(str(tool_name) if tool_name else None, arguments),
                    }
                    if content.get("id"):
                        tool_context_by_id[str(content.get("id"))] = tool_context
                    agent_events.append(
                        {
                            "stream": "toolExecution",
                            "ts": iso(message.get("timestamp") or row.get("timestamp")),
                            "runId": f"session-{sid}",
                            "sessionKey": session_key,
                            "sessionId": sid,
                            "agentId": "main",
                            "channel": "openclaw.session",
                            "toolName": tool_name,
                            "toolCallId": content.get("id"),
                            "phase": "start",
                            "status": "running",
                            "args": arguments,
                            "command": tool_context["command"],
                            "background": tool_context["background"],
                            "mutating": tool_context["mutating"],
                        }
                    )

                    if tool_name in EXEC_TOOL_NAMES:
                        exec_events.append(
                            {
                                "kind": "exec_start",
                                "ts": iso(message.get("timestamp") or row.get("timestamp")),
                                "runId": f"session-{sid}",
                                "sessionKey": session_key,
                                "sessionId": sid,
                                "agentId": "main",
                                "channel": "openclaw.session",
                                "toolName": tool_name,
                                "toolCallId": content.get("id"),
                                "phase": "start",
                                "status": "running",
                                "command": tool_context["command"],
                                "background": tool_context["background"],
                                "mutating": tool_context["mutating"],
                            }
                        )

            if role == "toolResult":
                details = message.get("details") if isinstance(message.get("details"), dict) else {}
                tool_call_id = str(message.get("toolCallId") or "")
                context = tool_context_by_id.get(tool_call_id, {})
                output_parts: list[str] = []
                for content in message.get("content", []):
                    if isinstance(content, dict) and isinstance(content.get("text"), str):
                        output_parts.append(content["text"])

                agent_events.append(
                    {
                        "stream": "toolExecution",
                        "ts": iso(message.get("timestamp") or row.get("timestamp")),
                        "runId": f"session-{sid}",
                        "sessionKey": session_key,
                        "sessionId": sid,
                        "agentId": "main",
                        "channel": "openclaw.session",
                        "toolName": message.get("toolName"),
                        "toolCallId": message.get("toolCallId"),
                        "phase": "end",
                        "status": str(details.get("status") or ("failed" if message.get("isError") else "completed")),
                        "command": context.get("command"),
                        "background": bool(context.get("background")),
                        "mutating": bool(context.get("mutating")),
                        "result": {
                            "output": "\n".join(output_parts)[:4000],
                            "exitCode": details.get("exitCode"),
                            "durationMs": details.get("durationMs"),
                            "cwd": details.get("cwd"),
                        },
                        "approvalState": "denied" if message.get("isError") else "approved",
                    }
                )

                if message.get("toolName") in EXEC_TOOL_NAMES:
                    exec_events.append(
                        {
                            "kind": "exec_end",
                            "ts": iso(message.get("timestamp") or row.get("timestamp")),
                            "runId": f"session-{sid}",
                            "sessionKey": session_key,
                            "sessionId": sid,
                            "agentId": "main",
                            "channel": "openclaw.session",
                            "toolName": message.get("toolName"),
                            "toolCallId": message.get("toolCallId"),
                            "phase": "end",
                            "status": str(details.get("status") or ("failed" if message.get("isError") else "completed")),
                            "command": context.get("command"),
                            "background": bool(context.get("background")),
                            "mutating": bool(context.get("mutating")),
                            "cwd": details.get("cwd"),
                            "durationMs": details.get("durationMs"),
                            "exitCode": details.get("exitCode"),
                            "approvalState": "denied" if message.get("isError") else "approved",
                        }
                    )

    return (
        dedupe(agent_events, ("ts", "toolCallId", "phase", "toolName")),
        dedupe(session_hooks, ("hook", "sessionId", "ts")),
        subagent_hooks,
        dedupe(exec_events, ("ts", "toolCallId", "phase", "toolName")),
        pairing_events,
        skills_events,
    )


def export_config_audit() -> list[dict[str, Any]]:
    config_events: list[dict[str, Any]] = []
    for row in load_jsonl(CONFIG_AUDIT_FILE):
        config_events.append(
            {
                "kind": "config.patch",
                "ts": iso(row.get("ts")),
                "sessionKey": row.get("watchSession") or "openclaw-config",
                "sessionId": "config-audit",
                "agentId": "main",
                "threadId": "config",
                "action": "patch",
                "status": "ok" if row.get("result") == "rename" else "failed",
                "actor": "openclaw",
                "changedPaths": config_changed_paths(row),
                "note": row.get("event"),
                "policyDecision": "allow",
                "mutating": True,
            }
        )
    return dedupe(config_events, ("ts", "note", "status"))


def export_restart_sentinels() -> list[dict[str, Any]]:
    sentinels: list[dict[str, Any]] = []
    for log_file in GATEWAY_LOG_FILES:
        for row in load_jsonl(log_file):
            line_text = json.dumps(row)
            if "handshake timeout" not in line_text and "closed before connect" not in line_text:
                continue
            sentinels.append(
                {
                    "kind": "restart_sentinel",
                    "ts": iso(row.get("time") or (row.get("_meta") or {}).get("date")),
                    "sessionKey": "gateway-runtime",
                    "sessionId": "gateway-runtime",
                    "agentId": "main",
                    "channel": "gateway",
                    "threadId": "gateway",
                    "status": "ok",
                    "message": str(row.get("1") or row.get("0") or "gateway reconnect event"),
                    "doctorHint": "check_gateway_connectivity",
                }
            )
    return dedupe(sentinels, ("ts", "message"))


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True))
            handle.write("\n")


def main() -> None:
    NATIVE_DIR.mkdir(parents=True, exist_ok=True)

    agent_events, session_hooks, subagent_hooks, exec_events, pairing_events, skills_events = export_agent_and_session_hooks()
    config_audit = export_config_audit()
    restart_sentinels = export_restart_sentinels()

    outputs = {
        "agent-events.jsonl": agent_events,
        "session-hooks.jsonl": session_hooks,
        "subagent-hooks.jsonl": subagent_hooks,
        "pairing-events.jsonl": pairing_events,
        "skills-events.jsonl": skills_events,
        "config-audit.jsonl": config_audit,
        "exec-events.jsonl": exec_events,
        "restart-sentinels.jsonl": restart_sentinels,
    }

    for name, rows in outputs.items():
        write_jsonl(NATIVE_DIR / name, rows)
        print(f"{name}: {len(rows)}")


if __name__ == "__main__":
    main()
