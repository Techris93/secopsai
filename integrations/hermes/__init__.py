from __future__ import annotations

import json
from typing import Any

from .runner import SEVERITIES, STATUSES, bounded_limit, identifier, optional_choice, result, run


def _hermes_status(_: dict[str, Any]) -> dict[str, Any]:
    return run(["hermes", "doctor"])


def _hermes_findings(args: dict[str, Any]) -> dict[str, Any]:
    return run(["list", "--platform", "hermes", "--no-refresh", "--limit", str(bounded_limit(args.get("limit")))])


def _list_findings(args: dict[str, Any]) -> dict[str, Any]:
    inputs: dict[str, Any] = {"limit": bounded_limit(args.get("limit"))}
    severity = optional_choice(args.get("severity"), choices=SEVERITIES, label="severity")
    status = optional_choice(args.get("status"), choices=STATUSES, label="status")
    source = str(args.get("source") or "").strip()
    if severity:
        inputs["severity"] = severity
    if status:
        inputs["status"] = status
    if source:
        if len(source) > 80 or not source.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Invalid finding source")
        inputs["source"] = source
    return run(["intelligence", "query", "list_findings", "--inputs-json", json.dumps(inputs, separators=(",", ":"))])


def _show_finding(args: dict[str, Any]) -> dict[str, Any]:
    target = identifier(args.get("finding_id"), kind="finding")
    return run(["intelligence", "query", "get_finding", "--target-id", target])


def _triage_summary(_: dict[str, Any]) -> dict[str, Any]:
    return run(["intelligence", "query", "workspace_summary"])


def _session_list(args: dict[str, Any]) -> dict[str, Any]:
    command = ["session", "list", "--limit", str(bounded_limit(args.get("limit")))]
    status = optional_choice(args.get("status"), choices={"open", "closed"}, label="session status")
    if status:
        command.extend(["--status", status])
    return run(command)


def _session_show(args: dict[str, Any]) -> dict[str, Any]:
    return run(["session", "show", identifier(args.get("session_id"), kind="session")])


def _asset_summary(args: dict[str, Any]) -> dict[str, Any]:
    inputs = json.dumps({"limit": bounded_limit(args.get("limit"))}, separators=(",", ":"))
    return run(["intelligence", "query", "list_assets", "--inputs-json", inputs])


EMPTY_PARAMETERS = {"type": "object", "properties": {}, "additionalProperties": False}
LIMIT_PARAMETERS = {
    "type": "object",
    "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
    "additionalProperties": False,
}

TOOLS = (
    (
        "secopsai_hermes_status",
        "Check the local SecOpsAI Hermes integration, telemetry coverage, plugin state, monitor service, and latest refresh.",
        EMPTY_PARAMETERS,
        result(_hermes_status),
    ),
    (
        "secopsai_hermes_findings",
        "List normalized findings produced from local Hermes Agent telemetry without refreshing or reading raw logs.",
        LIMIT_PARAMETERS,
        result(_hermes_findings),
    ),
    (
        "secopsai_list_findings",
        "List minimized SecOpsAI findings using optional severity, status, source, and limit filters.",
        {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": sorted(SEVERITIES)},
                "status": {"type": "string", "enum": sorted(STATUSES)},
                "source": {"type": "string", "maxLength": 80},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "additionalProperties": False,
        },
        result(_list_findings),
    ),
    (
        "secopsai_show_finding",
        "Show one minimized SecOpsAI finding and its current workflow state.",
        {
            "type": "object",
            "properties": {"finding_id": {"type": "string", "maxLength": 128}},
            "required": ["finding_id"],
            "additionalProperties": False,
        },
        result(_show_finding),
    ),
    (
        "secopsai_triage_summary",
        "Read current finding, severity, asset, research-case, and intelligence-job counts without changing triage state.",
        EMPTY_PARAMETERS,
        result(_triage_summary),
    ),
    (
        "secopsai_session_list",
        "List local SecOpsAI investigation sessions without modifying them.",
        {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["open", "closed"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "additionalProperties": False,
        },
        result(_session_list),
    ),
    (
        "secopsai_session_show",
        "Show one local SecOpsAI investigation session, including its plan and approval state.",
        {
            "type": "object",
            "properties": {"session_id": {"type": "string", "pattern": "^SES-[A-Za-z0-9]{6,64}$"}},
            "required": ["session_id"],
            "additionalProperties": False,
        },
        result(_session_show),
    ),
    (
        "secopsai_asset_summary",
        "List minimized SecOpsAI Edge assets imported into the canonical local Core graph.",
        LIMIT_PARAMETERS,
        result(_asset_summary),
    ),
)


def register(ctx) -> None:
    for name, description, parameters, handler in TOOLS:
        ctx.register_tool(
            name=name,
            toolset="secopsai",
            schema={"name": name, "description": description, "parameters": parameters},
            handler=handler,
        )
