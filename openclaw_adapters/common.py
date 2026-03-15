from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Dict, Iterable, List, Sequence


ALLOWED_STATUSES = {
    "ok",
    "running",
    "completed",
    "failed",
    "error",
    "blocked",
    "approval-pending",
    "approval-unavailable",
    "accepted",
    "skipped",
}


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} must be a JSON object")
            records.append(value)
    return records


def get_path(mapping: Dict[str, Any], path: Sequence[str]) -> Any:
    current: Any = mapping
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def pick(mapping: Dict[str, Any], *paths: Sequence[str]) -> Any:
    for path in paths:
        value = get_path(mapping, path)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def normalize_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def normalize_status(value: Any, default: str) -> str:
    if value is None:
        return default

    normalized = str(value).strip().lower()
    if normalized in ALLOWED_STATUSES:
        return normalized

    synonyms = {
        "success": "ok",
        "succeeded": "ok",
        "done": "completed",
        "complete": "completed",
        "denied": "blocked",
        "rejected": "blocked",
        "pending": "approval-pending",
        "unavailable": "approval-unavailable",
    }
    return synonyms.get(normalized, default)


def stable_record_id(surface: str, source_path: str, index: int, record: Dict[str, Any]) -> str:
    digest = hashlib.sha1(
        json.dumps(
            {
                "surface": surface,
                "source_path": source_path,
                "index": index,
                "record": record,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:16]
    return f"OCI-{digest.upper()}"


def compact_dict(mapping: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in mapping.items() if value is not None}


def make_envelope(
    *,
    ts: str,
    surface: str,
    action: str,
    status: str,
    origin: str,
    native_type: str,
    source_path: str,
    index: int,
    record: Dict[str, Any],
    collected_from: str,
    host: str,
    privacy_profile: str,
    openclaw_fields: Dict[str, Any],
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "ts": normalize_timestamp(ts),
        "source": "openclaw",
        "surface": surface,
        "action": action,
        "status": normalize_status(status, default="ok"),
        "openclaw": compact_dict(
            {
                "origin": origin,
                "native_type": native_type,
                **openclaw_fields,
            }
        ),
        "collector": compact_dict(
            {
                "schema_version": "openclaw-audit-v1",
                "privacy_profile": privacy_profile,
                "collected_from": collected_from,
                "record_id": stable_record_id(surface, source_path, index, record),
                "host": host,
            }
        ),
        "payload": compact_dict(payload),
    }


def write_jsonl(path: str, records: Iterable[Dict[str, Any]], append: bool = False) -> None:
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record))
            handle.write("\n")
