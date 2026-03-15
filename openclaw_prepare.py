"""
OpenClaw adapter-event normalizer.

Reads OpenClaw collector events that follow schemas/openclaw_audit.schema.json
and converts them into the flat event shape consumed by detect.py and evaluate.py.

This script intentionally uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, UTC
from typing import Any, Dict, Iterable, List, Tuple


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT_DIR, "data", "openclaw")
DEFAULT_INPUT = os.path.join(DATA_DIR, "raw", "sample_audit.jsonl")
DEFAULT_LABELED_OUTPUT = os.path.join(DATA_DIR, "replay", "labeled", "sample_events.json")
DEFAULT_UNLABELED_OUTPUT = os.path.join(DATA_DIR, "replay", "unlabeled", "sample_events.json")
AUDIT_SCHEMA_PATH = os.path.join(ROOT_DIR, "schemas", "openclaw_audit.schema.json")
NORMALIZED_SCHEMA_PATH = os.path.join(ROOT_DIR, "schemas", "normalized_event.schema.json")

SENSITIVE_CONFIG_PREFIXES = (
    "gateway.auth",
    "tools.exec",
    "commands",
    "channels.",
    "skills.entries.",
    "agents.defaults.",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize OpenClaw adapter events")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input JSONL or JSON array file")
    parser.add_argument("--output", default=DEFAULT_LABELED_OUTPUT, help="Labeled output JSON file")
    parser.add_argument(
        "--unlabeled-output",
        default=DEFAULT_UNLABELED_OUTPUT,
        help="Unlabeled output JSON file",
    )
    parser.add_argument("--stats", action="store_true", help="Print dataset statistics")
    parser.add_argument("--validate-only", action="store_true", help="Validate input and exit")
    return parser.parse_args()


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_records(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read().strip()

    if not raw:
        return []

    if raw.startswith("["):
        loaded = json.loads(raw)
        if not isinstance(loaded, list):
            raise ValueError("JSON input must be a list of records")
        return [ensure_dict(item, "record") for item in loaded]

    records = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        records.append(ensure_dict(record, f"line {line_number}"))
    return records


def ensure_dict(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def normalize_timestamp(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def validate_enum(value: Any, allowed: Iterable[str], label: str) -> None:
    if value not in allowed:
        raise ValueError(f"{label} must be one of {sorted(allowed)}")


def validate_adapter_record(record: Dict[str, Any], schema: Dict[str, Any]) -> None:
    required = schema.get("required", [])
    for key in required:
        if key not in record:
            raise ValueError(f"adapter record missing required key: {key}")

    validate_enum(record.get("source"), [schema["properties"]["source"]["const"]], "source")
    validate_enum(
        record.get("surface"),
        schema["properties"]["surface"]["enum"],
        "surface",
    )
    validate_enum(
        record.get("action"),
        schema["properties"]["action"]["enum"],
        "action",
    )
    validate_enum(
        record.get("status"),
        schema["properties"]["status"]["enum"],
        "status",
    )
    normalize_timestamp(record["ts"])

    openclaw = ensure_dict(record.get("openclaw"), "openclaw")
    collector = ensure_dict(record.get("collector"), "collector")
    payload = record.get("payload", {})
    if payload is None:
        record["payload"] = {}
    elif not isinstance(payload, dict):
        raise ValueError("payload must be an object when present")

    for key in schema["properties"]["openclaw"]["required"]:
        if key not in openclaw:
            raise ValueError(f"openclaw missing required key: {key}")
    for key in schema["properties"]["collector"]["required"]:
        if key not in collector:
            raise ValueError(f"collector missing required key: {key}")

    validate_enum(
        openclaw.get("origin"),
        schema["properties"]["openclaw"]["properties"]["origin"]["enum"],
        "openclaw.origin",
    )
    validate_enum(
        collector.get("schema_version"),
        [schema["properties"]["collector"]["properties"]["schema_version"]["const"]],
        "collector.schema_version",
    )

    surface = record["surface"]
    conditional_required = {
        "tool": ["run_id", "tool_name", "tool_call_id"],
        "session": ["session_key", "session_id", "agent_id"],
        "subagent": ["child_session_key"],
        "skills": ["skill_key"],
        "config": ["changed_paths"],
    }
    for key in conditional_required.get(surface, []):
        if key not in openclaw:
            raise ValueError(f"openclaw.{key} required for surface={surface}")


def validate_normalized_record(record: Dict[str, Any], schema: Dict[str, Any]) -> None:
    for key in schema.get("required", []):
        if key not in record:
            raise ValueError(f"normalized record missing required key: {key}")

    validate_enum(record.get("dataset"), schema["properties"]["dataset"]["enum"], "dataset")
    validate_enum(record.get("product"), schema["properties"]["product"]["enum"], "product")
    validate_enum(record.get("family"), schema["properties"]["family"]["enum"], "family")
    normalize_timestamp(record["timestamp"])

    entity = ensure_dict(record.get("entity"), "entity")
    context = ensure_dict(record.get("context"), "context")
    features = ensure_dict(record.get("features"), "features")
    raw_ref = ensure_dict(record.get("raw_ref"), "raw_ref")

    if not entity.get("session_key"):
        raise ValueError("entity.session_key is required")
    if raw_ref.get("schema") != schema["properties"]["raw_ref"]["properties"]["schema"]["const"]:
        raise ValueError("raw_ref.schema has unexpected value")
    if not raw_ref.get("record_id"):
        raise ValueError("raw_ref.record_id is required")

    _ = context, features


def make_event_id(record: Dict[str, Any]) -> str:
    collector = ensure_dict(record.get("collector"), "collector")
    record_id = collector.get("record_id")
    if isinstance(record_id, str) and record_id.strip():
        return record_id.strip()

    digest = hashlib.sha1(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"OC-{digest[:12].upper()}"


def build_message(surface: str, action: str, status: str, native: str, details: Dict[str, Any]) -> str:
    summary_bits = [f"OpenClaw {surface}", action, f"status={status}", f"native={native}"]
    tool_name = details.get("tool_name")
    skill_key = details.get("skill_key")
    if tool_name:
        summary_bits.append(f"tool={tool_name}")
    if skill_key:
        summary_bits.append(f"skill={skill_key}")
    return " ".join(summary_bits)


def flatten_command(payload: Dict[str, Any], details: Dict[str, Any]) -> str | None:
    args = payload.get("args") if isinstance(payload.get("args"), dict) else {}
    for candidate in (
        payload.get("command"),
        args.get("command"),
        details.get("command"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def flatten_changed_paths(record: Dict[str, Any]) -> List[str]:
    openclaw = ensure_dict(record.get("openclaw"), "openclaw")
    payload = ensure_dict(record.get("payload", {}), "payload")

    changed_paths = openclaw.get("changed_paths")
    if isinstance(changed_paths, list):
        return [str(path).strip() for path in changed_paths if str(path).strip()]

    payload_changed = payload.get("changed_paths")
    if isinstance(payload_changed, list):
        return [str(path).strip() for path in payload_changed if str(path).strip()]

    return []


def is_sensitive_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SENSITIVE_CONFIG_PREFIXES)


def normalize_record(record: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    openclaw = ensure_dict(record.get("openclaw"), "openclaw")
    collector = ensure_dict(record.get("collector"), "collector")
    payload = ensure_dict(record.get("payload", {}), "payload")
    details = ensure_dict(openclaw.get("details", {}), "openclaw.details") if isinstance(openclaw.get("details", {}), dict) else {}

    timestamp = normalize_timestamp(record["ts"])
    event_id = make_event_id(record)
    surface = str(record["surface"])
    action = str(record["action"])
    status = str(record["status"])
    changed_paths = flatten_changed_paths(record)
    command = flatten_command(payload, details)
    session_key = str(openclaw.get("session_key") or openclaw.get("child_session_key") or "unknown")
    denied = bool(payload.get("denied")) or status in {"blocked", "approval-unavailable"}
    source_text = payload.get("source") or payload.get("skill_source")
    skill_key = openclaw.get("skill_key") or payload.get("skill_key")

    normalized = {
        "event_id": event_id,
        "timestamp": timestamp,
        "dataset": "openclaw",
        "product": "openclaw",
        "family": surface,
        "action": action,
        "status": status,
        "severity_hint": payload.get("severity_hint", "medium" if denied else "info"),
        "entity": {
            "run_id": openclaw.get("run_id"),
            "session_key": session_key,
            "session_id": openclaw.get("session_id"),
            "agent_id": openclaw.get("agent_id"),
            "channel": openclaw.get("channel"),
            "account_id": openclaw.get("account_id"),
            "thread_id": openclaw.get("thread_id"),
            "tool_name": openclaw.get("tool_name"),
            "skill_key": skill_key,
            "child_session_key": openclaw.get("child_session_key"),
            "requester_session_key": openclaw.get("requester_session_key"),
        },
        "context": {
            "origin": openclaw.get("origin"),
            "native_type": openclaw.get("native_type"),
            "changed_paths": changed_paths,
            "policy_decision": payload.get("policy_decision"),
            "approval_state": payload.get("approval_state"),
            "delivery_target": payload.get("delivery_target"),
        },
        "features": {
            "duration_ms": payload.get("duration_ms"),
            "exit_code": payload.get("exit_code"),
            "has_error": status in {"failed", "error"},
            "mutating": bool(payload.get("mutating")),
            "background": bool(payload.get("background")),
            "changed_path_count": len(changed_paths),
            "sensitive_path_touched": any(is_sensitive_path(path) for path in changed_paths),
            "burst_index": payload.get("burst_index", 0),
            "denied": denied,
        },
        "privacy": {
            "profile": collector.get("privacy_profile"),
            "transform_mode": payload.get("transform_mode", "balanced"),
        },
        "raw_ref": {
            "schema": collector.get("schema_version"),
            "record_id": event_id,
        },
        "label": payload.get("label", "benign"),
    }

    flat = {
        "timestamp": timestamp,
        "event_id": event_id,
        "sourcetype": f"openclaw_{surface}",
        "event_type": surface,
        "message": build_message(surface, action, status, str(openclaw.get("native_type")), {
            "tool_name": openclaw.get("tool_name"),
            "skill_key": skill_key,
        }),
        "label": normalized["label"],
        "attack_type": payload.get("attack_type", "none"),
        "mitre": payload.get("mitre"),
        "run_id": openclaw.get("run_id"),
        "session_key": session_key,
        "session_id": openclaw.get("session_id"),
        "agent_id": openclaw.get("agent_id"),
        "channel": openclaw.get("channel"),
        "account_id": openclaw.get("account_id"),
        "thread_id": openclaw.get("thread_id"),
        "tool_name": openclaw.get("tool_name"),
        "tool_call_id": openclaw.get("tool_call_id"),
        "skill_key": skill_key,
        "skill_source": source_text,
        "action": action,
        "status": status,
        "origin": openclaw.get("origin"),
        "native_type": openclaw.get("native_type"),
        "changed_paths": changed_paths,
        "changed_path_count": len(changed_paths),
        "sensitive_path_touched": normalized["features"]["sensitive_path_touched"],
        "command": command,
        "duration_ms": payload.get("duration_ms"),
        "exit_code": payload.get("exit_code"),
        "mutating": bool(payload.get("mutating")),
        "background": bool(payload.get("background")),
        "denied": denied,
        "approval_state": payload.get("approval_state"),
        "child_session_key": openclaw.get("child_session_key"),
        "requester_session_key": openclaw.get("requester_session_key"),
        "delivery_target": payload.get("delivery_target"),
        "severity_hint": normalized["severity_hint"],
    }

    return normalized, flat


def write_json(path: str, payload: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def strip_labels(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unlabeled = []
    for event in events:
        stripped = dict(event)
        stripped.pop("label", None)
        stripped.pop("attack_type", None)
        stripped.pop("mitre", None)
        unlabeled.append(stripped)
    return unlabeled


def print_stats(flat_events: List[Dict[str, Any]]) -> None:
    print(f"records={len(flat_events)}")
    surfaces = Counter(event.get("sourcetype", "unknown") for event in flat_events)
    labels = Counter(event.get("label", "unknown") for event in flat_events)
    attacks = Counter(event.get("attack_type", "none") for event in flat_events)

    print("surfaces:")
    for key, value in sorted(surfaces.items()):
        print(f"  {key}: {value}")

    print("labels:")
    for key, value in sorted(labels.items()):
        print(f"  {key}: {value}")

    print("attack_types:")
    for key, value in sorted(attacks.items()):
        print(f"  {key}: {value}")


def main() -> None:
    args = parse_args()
    audit_schema = load_json(AUDIT_SCHEMA_PATH)
    normalized_schema = load_json(NORMALIZED_SCHEMA_PATH)
    raw_records = load_records(args.input)

    normalized_records = []
    flat_records = []
    for record in raw_records:
        validate_adapter_record(record, audit_schema)
        normalized, flat = normalize_record(record)
        validate_normalized_record(normalized, normalized_schema)
        normalized_records.append(normalized)
        flat_records.append(flat)

    if args.stats:
        print_stats(flat_records)

    if args.validate_only:
        return

    write_json(args.output, flat_records)
    write_json(args.unlabeled_output, strip_labels(flat_records))

    print(f"wrote_labeled={args.output}")
    print(f"wrote_unlabeled={args.unlabeled_output}")


if __name__ == "__main__":
    main()