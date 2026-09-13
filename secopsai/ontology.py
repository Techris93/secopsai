"""Canonical security ontology and relationship services.

The ontology is a semantic layer over SecOpsAI's existing findings, research,
and Edge graph tables.  It deliberately stores bounded summaries and evidence
references; raw artifacts and full research records remain in their owning
stores.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import unicodedata
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

import soc_store
from secopsai.sqlite_writer_lock import sqlite_writer_lock


SCHEMA_VERSION = "secopsai.ontology.v1"
MAX_PROPERTIES_BYTES = 64 * 1024
MAX_RELATION_PROPERTIES_BYTES = 32 * 1024
MAX_SUMMARY_BYTES = 32 * 1024
MAX_SEARCH_LIMIT = 500
MAX_TRAVERSAL_DEPTH = 4
MAX_TRAVERSAL_NODES = 500

# Read paths must never use ``init_db``: that helper intentionally opens a
# writable connection and may create or migrate a database.  Keep the table
# requirements explicit so a missing or partially-created store degrades to an
# empty bounded response instead of turning a status request into a 500.
_ONTOLOGY_GRAPH_READ_TABLES = frozenset({
    "ontology_entities",
    "ontology_aliases",
    "ontology_relationships",
    "ontology_events",
})
_ONTOLOGY_EXPORT_READ_TABLES = frozenset({
    "ontology_entities",
    "ontology_relationships",
    "ontology_events",
    "ontology_evidence_refs",
})
_ONTOLOGY_QUALITY_READ_TABLES = frozenset({
    "ontology_entities",
    "ontology_relationships",
    "ontology_evidence_refs",
    "ontology_conflicts",
    "ontology_change_log",
    "findings",
    "runner_heartbeats",
    "intelligence_jobs",
    "coordinator_commands",
    "agent_triage_runs",
})
_ONTOLOGY_READ_COLUMNS = {
    "ontology_entities": frozenset({
        "entity_id", "entity_type", "namespace", "canonical_key", "display_name", "source", "source_id",
        "workspace_id", "owner_id", "status", "properties_json", "confidence", "first_seen_at", "last_seen_at",
        "observed_at", "freshness_at", "valid_from", "valid_to", "schema_version", "created_at", "updated_at",
    }),
    "ontology_aliases": frozenset({
        "entity_id", "alias_type", "alias_value", "normalized_value", "source", "confidence",
    }),
    "ontology_relationships": frozenset({
        "relationship_id", "relationship_type", "from_entity_id", "to_entity_id", "source", "source_record_id",
        "workspace_id", "evidence_ref_id", "properties_json", "confidence", "observed_at", "valid_from",
        "valid_to", "freshness_at", "created_at", "updated_at",
    }),
    "ontology_events": frozenset({
        "event_id", "entity_id", "event_type", "source", "source_record_id", "summary_json", "occurred_at",
        "created_at",
    }),
    "ontology_evidence_refs": frozenset({
        "evidence_ref_id", "source", "locator", "content_hash", "content_type", "workspace_id", "summary_json",
        "observed_at", "created_at", "updated_at",
    }),
    "ontology_conflicts": frozenset({"conflict_type", "status"}),
    "ontology_change_log": frozenset(),
    "findings": frozenset({
        "finding_id", "title", "severity", "severity_score", "status", "disposition", "source", "first_seen",
        "last_seen", "updated_at",
    }),
    "runner_heartbeats": frozenset({"last_seen_at"}),
    "intelligence_jobs": frozenset({"status", "queued_at"}),
    "coordinator_commands": frozenset({"status", "queued_at"}),
    "agent_triage_runs": frozenset({"run_id", "target_id", "status", "recommendation_json", "decision_json"}),
}

ENTITY_TYPES = frozenset(
    {
        "package",
        "package_version",
        "artifact",
        "registry",
        "release_event",
        "advisory",
        "vulnerability",
        "repository",
        "manifest",
        "dependency",
        "build",
        "ci_run",
        "deployment",
        "asset",
        "service",
        "sensor",
        "network",
        "workspace",
        "owner",
        "team",
        "finding",
        "alert",
        "candidate",
        "research_case",
        "investigation",
        "evidence",
        "ioc",
        "hypothesis",
        "collector",
        "source",
        "automation_run",
        "intelligence_job",
        "task",
        "command",
        "model",
        "triage_decision",
        "remediation_action",
        "approval",
        "publication",
    }
)

RELATION_TYPES = frozenset(
    {
        "VERSION_AFFECTED_BY_ADVISORY",
        "VERSION_HAS_ARTIFACT",
        "PACKAGE_HAS_VERSION",
        "VERSION_RELEASED_IN",
        "REPOSITORY_DEPENDS_ON_VERSION",
        "MANIFEST_DECLARES_DEPENDENCY",
        "BUILD_PRODUCES_ARTIFACT",
        "ARTIFACT_DEPLOYED_TO_ASSET",
        "ASSET_PROVIDES_SERVICE",
        "ASSET_OWNED_BY_TEAM",
        "FINDING_ON_VERSION",
        "FINDING_ON_ASSET",
        "ALERT_DERIVED_FROM_FINDING",
        "CANDIDATE_PROMOTED_TO_CASE",
        "CASE_GROUPS_FINDING",
        "CASE_GROUPS_ALERT",
        "CASE_SUPPORTED_BY_EVIDENCE",
        "EVIDENCE_FROM_SOURCE",
        "EVIDENCE_SUPPORTS_HYPOTHESIS",
        "ACTION_REMEDIATES_FINDING",
        "RUN_PRODUCED_RESULT",
        "COMMAND_REQUESTS_RUN",
        "ACTOR_APPROVED_ACTION",
        "COLLECTOR_OBSERVED_RELEASE",
        "SOURCE_PROVIDES_ADVISORY",
        "ASSET_DEPENDS_ON_SERVICE",
        "INVESTIGATION_PRODUCES_EVIDENCE",
        "JOB_TARGETS_ENTITY",
        "TASK_ASSIGNED_TO_OWNER",
        "CASE_HAS_SUBJECT",
        "CASE_HAS_ARTIFACT",
        "CASE_HAS_IOC",
        "RELEASE_EVENT_FROM_SOURCE",
        "TRIAGE_DECISION_FOR_ENTITY",
    }
)

ENTITY_PREFIXES = {
    "package": "pkg",
    "package_version": "pkgver",
    "artifact": "artifact",
    "release_event": "release",
    "advisory": "adv",
    "vulnerability": "vuln",
    "repository": "repo",
    "manifest": "manifest",
    "dependency": "dep",
    "build": "build",
    "ci_run": "ci",
    "deployment": "deploy",
    "asset": "asset",
    "service": "service",
    "sensor": "sensor",
    "network": "network",
    "workspace": "workspace",
    "owner": "owner",
    "team": "team",
    "finding": "finding",
    "alert": "alert",
    "candidate": "candidate",
    "research_case": "case",
    "investigation": "investigation",
    "evidence": "evidence",
    "ioc": "ioc",
    "hypothesis": "hypothesis",
    "collector": "collector",
    "source": "source",
    "automation_run": "automation",
    "intelligence_job": "job",
    "task": "task",
    "command": "command",
    "model": "model",
    "triage_decision": "triage",
    "remediation_action": "action",
    "approval": "approval",
    "publication": "publication",
}
ENTITY_TYPES_BY_PREFIX = {prefix: entity_type for entity_type, prefix in ENTITY_PREFIXES.items()}

# Higher-priority sources are allowed to keep their canonical descriptive
# fields when a lower-priority projection arrives later.  Timestamps still
# advance so freshness is never hidden by precedence.
SOURCE_PRIORITY = {
    "secopsai-research": 90,
    "core": 85,
    "registry": 80,
    "edge": 75,
    "github": 70,
    "scanner": 65,
    "legacy": 40,
    "unknown": 0,
}

# Collectors have historically used a few human-readable spellings for the
# same source.  Keep the stored source value backwards-compatible while
# normalising it for precedence and deterministic identifiers.
SOURCE_ALIASES = {
    "secopsai research": "secopsai-research",
    "secopsai_research": "secopsai-research",
    "secopsai-research": "secopsai-research",
    "research": "secopsai-research",
    "secopsai core": "core",
    "secopsai_core": "core",
}

MAX_CANONICAL_KEY_BYTES = 1024
MAX_ENTITY_ID_BYTES = 512
UNKNOWN_OBSERVED_AT = "1970-01-01T00:00:00Z"

FORBIDDEN_KEY_PARTS = {
    "authorization",
    "password",
    "secret",
    "token",
    "credential",
    "private_key",
    "raw_output",
    "raw_scan",
    "raw_artifact",
    "raw_payload",
    "packet_capture",
    "pcap",
    "nmap_xml",
    "artifact_content",
    "artifact_bytes",
}

LEGACY_EDGE_RELATIONS = {
    "site_has_sensor": "ASSET_PROVIDES_SERVICE",
    "sensor_ran_scan": "RUN_PRODUCED_RESULT",
    "scan_observed_asset": "RUN_PRODUCED_RESULT",
    "asset_exposes_service": "ASSET_PROVIDES_SERVICE",
    "sensor_observed_wifi": "COLLECTOR_OBSERVED_RELEASE",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any, limit: int = 512) -> str:
    return str(value or "").strip()[:limit]


def normalize_value(value: Any, *, limit: int = 512) -> str:
    text = unicodedata.normalize("NFKC", _text(value, limit)).strip().lower()
    return re.sub(r"\s+", " ", text)


def normalize_canonical_key(entity_type: str, namespace: str, value: Any) -> str:
    # ``_text`` intentionally bounds ordinary fields, but canonical identity
    # must hash the complete input before applying a storage bound.  Otherwise
    # two long keys sharing their first 1,024 characters silently collide and
    # the prefix can expose sensitive material in the ontology table.
    key = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", str(value or "")).strip().lower())
    if not key:
        raise ValueError("canonical_key is required")
    if namespace in {"pypi", "python"} and entity_type in {"package", "package_version"}:
        key = key.replace("_", "-")
    if entity_type in {"vulnerability", "advisory"}:
        key = key.upper()
    if entity_type in {"artifact", "evidence"}:
        key = re.sub(r"^(?:sha(?:256)?|hash):", "", key)
    if entity_type in {"repository", "registry", "source"}:
        key = key.rstrip("/")
    if entity_type == "package_version" and "@" not in key:
        raise ValueError("package_version canonical_key must include package@version")
    prefix = ENTITY_PREFIXES.get(entity_type, entity_type)
    if len(key.encode("utf-8")) > MAX_CANONICAL_KEY_BYTES or len(f"{prefix}:{namespace}:{key}".encode("utf-8")) > MAX_ENTITY_ID_BYTES:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]
        return f"sha256-{digest}"
    return key


def sanitize_locator(value: Any) -> str:
    """Return a safe evidence locator without credentials, query secrets, or local paths."""
    # Keep the full value for hashing.  Bounding before hashing would let a
    # long secret leak its first 2 KiB through an attacker-controlled digest
    # collision and would make two values with a common prefix indistinguishable.
    raw = str(value or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered.startswith(("file:", "data:", "javascript:", "\\\\", "/")):
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return f"redacted://local/{digest}"
    try:
        parsed = urlsplit(raw)
    except ValueError:
        parsed = None
    if parsed and parsed.scheme.lower() in {"http", "https"}:
        try:
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            host = ""
        if not host:
            parsed = None
    if parsed and parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        private = host in {"localhost", "localhost.localdomain"}
        try:
            private = private or ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
        except ValueError:
            private = private or host.endswith((".internal", ".local", ".lan"))
        if parsed.username or parsed.password or private:
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
            return f"redacted://url/{digest}"
        # Query strings and fragments are commonly used for access tokens. Keep
        # the public host/path as a stable citation and discard both.
        netloc = host
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port:
            netloc = f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path[:1024], "", ""))[:1024]
    # Evidence locators are citation material, so an opaque value (for
    # example ``evidence://...``, ``s3://...``, a local pseudo-URI, or a bare
    # source identifier) must never be echoed into the ontology.  Preserve a
    # stable digest so callers can still correlate repeated observations.
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return f"redacted://opaque/{digest}"


def canonical_entity_id(entity_type: str, namespace: str, canonical_key: Any) -> str:
    entity_type = normalize_value(entity_type, limit=80)
    if entity_type not in ENTITY_TYPES:
        raise ValueError(f"unsupported entity_type: {entity_type}")
    namespace = normalize_value(namespace or "global", limit=120) or "global"
    key = normalize_canonical_key(entity_type, namespace, canonical_key)
    prefix = ENTITY_PREFIXES.get(entity_type, entity_type)
    candidate = f"{prefix}:{namespace}:{key}"
    if len(candidate.encode("utf-8")) <= MAX_ENTITY_ID_BYTES:
        return candidate
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]
    return f"{prefix}:{namespace}:sha256-{digest}"


def _stable_legacy_id(entity_type: str, namespace: str, value: Any) -> str:
    """Return a canonical ID for a legacy source ID while preserving aliases.

    A number of the original SQLite tables use compact IDs such as ``EDGE-*``
    and ``RSC-*`` without a namespace.  Those values remain useful source
    identifiers, but ontology rows must always use a namespaced ID so graph
    joins are deterministic and safe to expose through the bridge.
    """
    raw = _text(value, 1024)
    if not raw:
        raise ValueError("legacy entity ID is required")
    if ":" in raw:
        return raw
    return canonical_entity_id(entity_type, namespace, raw)


def _legacy_alias(value: Any, source: str) -> list[dict[str, str]]:
    raw = _text(value, 512)
    return ([{"type": "source_id", "value": raw, "source": normalize_source(source) or "legacy"}] if raw else [])


def _stable_graph_reference(value: Any) -> str:
    """Canonicalize an asset-graph endpoint when the legacy ID was unscoped."""
    raw = _text(value, 512)
    return raw if ":" in raw else _stable_legacy_id("asset", "edge", raw)


def _safe_key(key: Any) -> bool:
    normalized = normalize_value(key, limit=120).replace("-", "_")
    return not any(part in normalized for part in FORBIDDEN_KEY_PARTS)


def sanitize_summary(value: Any, *, depth: int = 0, max_items: int = 100) -> Any:
    """Redact sensitive keys and bound nested summaries before persistence."""
    if depth > 5:
        return "[depth-limited]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:max_items]:
            if not _safe_key(key):
                continue
            key_text = _text(key, 120)
            result[key_text] = sanitize_locator(item) if re.search(r"(?:^|_)(?:url|uri|locator)$", key_text, flags=re.IGNORECASE) and isinstance(item, str) else sanitize_summary(item, depth=depth + 1, max_items=max_items)
        return result
    if isinstance(value, (list, tuple, set)):
        return [sanitize_summary(item, depth=depth + 1, max_items=max_items) for item in list(value)[:max_items]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            return value[:4000]
        return value
    return _text(value, 1000)


def bounded_json(value: Any, limit: int = MAX_SUMMARY_BYTES) -> str:
    cleaned = sanitize_summary(value if isinstance(value, (dict, list)) else {})
    encoded = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) <= limit:
        return encoded
    # Keep a useful bounded marker rather than truncating invalid JSON.
    marker = {"status": "truncated", "original_bytes": len(encoded.encode("utf-8"))}
    return json.dumps(marker, sort_keys=True, separators=(",", ":"))


def _source_priority(source: str) -> int:
    normalized = normalize_source(source)
    return SOURCE_PRIORITY.get(normalized, 50 if normalized else 0)


def normalize_source(source: Any) -> str:
    """Return the stable source spelling used for precedence decisions."""
    normalized = normalize_value(source, limit=160).replace("_", "-")
    normalized = re.sub(r"\s+", " ", normalized)
    return SOURCE_ALIASES.get(normalized, normalized)


def _record_change_connection(
    connection: Any,
    *,
    object_type: str,
    object_id: str,
    action: str,
    before: Any,
    after: Any,
    source: str,
    actor: str,
    now: str,
    change_id: str | None = None,
) -> None:
    """Persist a bounded, redacted before/after record when state changes."""
    def comparable(value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        return {key: item for key, item in value.items() if key not in {"created_at", "updated_at"}}

    if comparable(before) == comparable(after) and action == "upsert":
        return
    change_id = change_id or "chg:" + hashlib.sha256(f"{object_type}|{object_id}|{action}|{now}|{uuid.uuid4()}".encode()).hexdigest()[:40]
    connection.execute(
        """
        INSERT INTO ontology_change_log
            (change_id, object_type, object_id, action, before_json, after_json, source, actor, occurred_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            change_id,
            _text(object_type, 80),
            _text(object_id, 512),
            _text(action, 80),
            bounded_json(before if isinstance(before, dict) else {}, MAX_RELATION_PROPERTIES_BYTES),
            bounded_json(after if isinstance(after, dict) else {}, MAX_RELATION_PROPERTIES_BYTES),
            _text(source or "unknown", 160) or "unknown",
            _text(actor or "system", 160) or "system",
            now,
        ),
    )


def _loads(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _open_ontology_read_connection(db_path: str | None, required_tables: Iterable[str]) -> sqlite3.Connection | None:
    """Open a query-only ontology connection when its schema is available.

    ``soc_store.read_connect`` deliberately refuses to create a missing file.
    The table check here also handles a zero-byte or partially initialized
    database, which is common while a first writer is starting up.
    """
    required = {str(table) for table in required_tables}
    try:
        connection = soc_store.read_connect(db_path)
    except (FileNotFoundError, sqlite3.Error):
        return None
    try:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
    except sqlite3.Error:
        connection.close()
        return None
    if not required <= tables:
        connection.close()
        return None
    for table in required:
        required_columns = _ONTOLOGY_READ_COLUMNS.get(table, frozenset())
        if not required_columns:
            continue
        try:
            columns = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        except sqlite3.Error:
            connection.close()
            return None
        if not required_columns <= columns:
            connection.close()
            return None
    return connection


@contextmanager
def _ontology_read_connection(db_path: str | None, required_tables: Iterable[str]):
    connection = _open_ontology_read_connection(db_path, required_tables)
    try:
        yield connection
    finally:
        if connection is not None:
            connection.close()


def _confidence(value: Any, default: int = 100) -> int:
    try:
        return max(0, min(int(value), 100))
    except (TypeError, ValueError):
        return default


def _limit(value: Any, default: int = 100) -> int:
    try:
        return max(1, min(int(value), MAX_SEARCH_LIMIT))
    except (TypeError, ValueError):
        return default


def _entity_row(row: Any, *, include_properties: bool = True) -> dict[str, Any]:
    item = {
        "entity_id": str(row["entity_id"]),
        "entity_type": str(row["entity_type"]),
        "namespace": str(row["namespace"]),
        "canonical_key": str(row["canonical_key"]),
        "display_name": str(row["display_name"]),
        "source": str(row["source"]),
        "source_id": str(row["source_id"] or ""),
        "workspace_id": str(row["workspace_id"] or "local"),
        "owner_id": str(row["owner_id"] or ""),
        "status": str(row["status"] or "active"),
        "confidence": int(row["confidence"] or 0),
        "first_seen_at": str(row["first_seen_at"]),
        "last_seen_at": str(row["last_seen_at"]),
        "observed_at": str(row["observed_at"]),
        "freshness_at": str(row["freshness_at"]),
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "schema_version": str(row["schema_version"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }
    if include_properties:
        item["properties"] = _loads(row["properties_json"])
    return item


def _relationship_row(row: Any) -> dict[str, Any]:
    return {
        "relationship_id": str(row["relationship_id"]),
        "relationship_type": str(row["relationship_type"]),
        "from_entity_id": str(row["from_entity_id"]),
        "to_entity_id": str(row["to_entity_id"]),
        "source": str(row["source"]),
        "source_record_id": str(row["source_record_id"] or ""),
        "workspace_id": str(row["workspace_id"] or "local"),
        "evidence_ref_id": row["evidence_ref_id"],
        "properties": _loads(row["properties_json"]),
        "confidence": int(row["confidence"] or 0),
        "observed_at": str(row["observed_at"]),
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "freshness_at": str(row["freshness_at"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def _upsert_entity_connection(
    connection: Any,
    item: dict[str, Any],
    *,
    now: str | None = None,
    return_state: bool = False,
) -> str | tuple[str, bool]:
    entity_type = normalize_value(item.get("entity_type") or item.get("type"), limit=80)
    namespace = normalize_value(item.get("namespace") or item.get("ecosystem") or "global", limit=120) or "global"
    canonical_key = normalize_canonical_key(entity_type, namespace, item.get("canonical_key") or item.get("key") or item.get("source_id") or item.get("entity_id"))
    raw_entity_id = item.get("entity_id")
    explicit_entity_id = _text(raw_entity_id, MAX_ENTITY_ID_BYTES) if len(str(raw_entity_id or "").encode("utf-8")) <= MAX_ENTITY_ID_BYTES else ""
    entity_id = explicit_entity_id or canonical_entity_id(entity_type, namespace, canonical_key)
    if entity_id != canonical_entity_id(entity_type, namespace, canonical_key):
        # Explicit IDs are accepted for legacy records, but must remain stable
        # and namespaced.  This avoids accidentally merging unrelated objects.
        if len(entity_id) > 512 or ":" not in entity_id:
            raise ValueError("entity_id must be a namespaced stable identifier")
    now = now or utc_now()
    first_seen = _text(item.get("first_seen_at") or item.get("first_seen") or item.get("observed_at") or now, 64)
    last_seen = _text(item.get("last_seen_at") or item.get("last_seen") or item.get("observed_at") or now, 64)
    observed = _text(item.get("observed_at") or last_seen or now, 64)
    freshness = _text(item.get("freshness_at") or observed or now, 64)
    properties_json = bounded_json(item.get("properties") or {}, MAX_PROPERTIES_BYTES)
    source = normalize_source(item.get("source") or "unknown") or "unknown"
    display_name = _text(item.get("display_name") or item.get("label") or canonical_key, 512) or canonical_key
    source_id = _text(item.get("source_id"), 512)
    workspace_id = _text(item.get("workspace_id") or "local", 160) or "local"
    owner_id = _text(item.get("owner_id") or item.get("owner"), 256)
    status = _text(item.get("status") or "active", 80) or "active"
    confidence = _confidence(item.get("confidence"), 100)
    existing = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (entity_id,)).fetchone()
    canonical_existing = connection.execute(
        "SELECT entity_id FROM ontology_entities WHERE entity_type = ? AND namespace = ? AND canonical_key = ? LIMIT 1",
        (entity_type, namespace, canonical_key),
    ).fetchone()
    if canonical_existing and str(canonical_existing["entity_id"]) != entity_id:
        raise ValueError(
            f"canonical identity already belongs to {canonical_existing['entity_id']}; resolve or merge the duplicate first"
        )
    if existing is not None and (
        str(existing["entity_type"]) != entity_type
        or str(existing["namespace"]) != namespace
        or str(existing["canonical_key"]) != canonical_key
    ):
        raise ValueError("entity identity is immutable; use a new entity_id for a different type, namespace, or key")
    # Workspace is an ownership boundary.  A legacy ``local`` projection may
    # be upgraded to a hosted workspace, and an incoming local observation may
    # inherit an already-bound hosted workspace, but two concrete tenant
    # workspaces can never overwrite one another through an upsert.
    if existing is not None:
        existing_workspace = _text(existing["workspace_id"], 160) or "local"
        if existing_workspace != "local" and workspace_id != "local" and existing_workspace != workspace_id:
            raise ValueError("entity belongs to a different workspace")
        if existing_workspace != "local" and workspace_id == "local":
            workspace_id = existing_workspace
    if existing is not None and _source_priority(str(existing["source"])) > _source_priority(source):
        # Preserve descriptive state from the authoritative source while still
        # recording the observation and advancing freshness.
        source = str(existing["source"])
        display_name = str(existing["display_name"])
        source_id = str(existing["source_id"] or source_id or "")
        owner_id = owner_id or str(existing["owner_id"] or "")
        status = str(existing["status"] or status)
        properties_json = str(existing["properties_json"] or properties_json)
    connection.execute(
        """
        INSERT INTO ontology_entities (
            entity_id, entity_type, namespace, canonical_key, display_name,
            source, source_id, workspace_id, owner_id, status, properties_json,
            confidence, first_seen_at, last_seen_at, observed_at, freshness_at,
            valid_from, valid_to, schema_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            entity_type=excluded.entity_type,
            namespace=excluded.namespace,
            canonical_key=excluded.canonical_key,
            display_name=excluded.display_name,
            source=excluded.source,
            source_id=CASE WHEN excluded.source_id <> '' THEN excluded.source_id ELSE ontology_entities.source_id END,
            workspace_id=excluded.workspace_id,
            owner_id=CASE WHEN excluded.owner_id <> '' THEN excluded.owner_id ELSE ontology_entities.owner_id END,
            status=excluded.status,
            properties_json=excluded.properties_json,
            confidence=excluded.confidence,
            first_seen_at=CASE WHEN excluded.first_seen_at < ontology_entities.first_seen_at THEN excluded.first_seen_at ELSE ontology_entities.first_seen_at END,
            last_seen_at=CASE WHEN excluded.last_seen_at > ontology_entities.last_seen_at THEN excluded.last_seen_at ELSE ontology_entities.last_seen_at END,
            observed_at=excluded.observed_at,
            freshness_at=excluded.freshness_at,
            valid_from=COALESCE(excluded.valid_from, ontology_entities.valid_from),
            valid_to=COALESCE(excluded.valid_to, ontology_entities.valid_to),
            schema_version=excluded.schema_version,
            updated_at=excluded.updated_at
        """,
        (
            entity_id,
            entity_type,
            namespace,
            canonical_key,
            display_name,
            source,
            source_id,
            workspace_id,
            owner_id,
            status,
            properties_json,
            confidence,
            first_seen,
            last_seen,
            observed,
            freshness,
            _text(item.get("valid_from"), 64) or None,
            _text(item.get("valid_to"), 64) or None,
            SCHEMA_VERSION,
            now,
            now,
        ),
    )
    after = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (entity_id,)).fetchone()
    _record_change_connection(
        connection,
        object_type="entity",
        object_id=entity_id,
        action="upsert",
        before=dict(existing) if existing is not None else {},
        after=dict(after) if after is not None else {},
        source=source,
        actor=_text(item.get("actor") or item.get("source_instance") or "system", 160),
        now=now,
    )
    aliases = item.get("aliases") or []
    if isinstance(aliases, str):
        aliases = [aliases]
    for alias in list(aliases)[:20]:
        alias_value = _text(alias.get("value") if isinstance(alias, dict) else alias, 512)
        if not alias_value:
            continue
        alias_type = _text(alias.get("type") if isinstance(alias, dict) else "source", 80) or "source"
        normalized = normalize_value(alias_value, limit=512)
        alias_source = normalize_source(alias.get("source") if isinstance(alias, dict) else source) or source
        alias_id = "alias:" + hashlib.sha256(f"{alias_type}|{normalized}|{alias_source}".encode()).hexdigest()[:40]
        # ``ontology_aliases`` deliberately has a uniqueness constraint for a
        # normalized source value.  Never let a later record silently steal an
        # alias from the entity that first claimed it; keep the incumbent and
        # leave an auditable reconciliation record instead.
        incumbent = connection.execute(
            "SELECT alias_id, entity_id FROM ontology_aliases WHERE alias_type = ? AND normalized_value = ? AND source = ?",
            (alias_type, normalized, alias_source),
        ).fetchone()
        if incumbent is not None and str(incumbent["entity_id"]) != entity_id:
            conflict_id = "conflict:" + hashlib.sha256(f"alias|{alias_type}|{normalized}|{alias_source}|{incumbent['entity_id']}|{entity_id}".encode()).hexdigest()[:40]
            connection.execute(
                "INSERT OR IGNORE INTO ontology_conflicts (conflict_id, object_type, object_id, conflict_type, details_json, status, source, created_at) VALUES (?, 'alias', ?, 'duplicate_alias', ?, 'open', ?, ?)",
                (conflict_id, alias_id, bounded_json({"alias_type": alias_type, "normalized_value": normalized, "source": alias_source, "incumbent_entity_id": str(incumbent["entity_id"]), "candidate_entity_id": entity_id}, MAX_SUMMARY_BYTES), source, now),
            )
            continue
        connection.execute(
            """
            INSERT INTO ontology_aliases
                (alias_id, entity_id, alias_type, alias_value, normalized_value, source, confidence, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alias_id) DO UPDATE SET
                entity_id=excluded.entity_id, alias_value=excluded.alias_value,
                confidence=excluded.confidence, updated_at=excluded.updated_at
            """,
            (alias_id, entity_id, alias_type, alias_value, normalized, alias_source, _confidence(alias.get("confidence") if isinstance(alias, dict) else 100), now, now),
        )
    return (entity_id, existing is not None) if return_state else entity_id


def upsert_entity(item: dict[str, Any], *, db_path: str | None = None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            entity_id = _upsert_entity_connection(connection, item)
            connection.commit()
            row = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (entity_id,)).fetchone()
    return _entity_row(row)


def upsert_entities(items: Iterable[dict[str, Any]], *, db_path: str | None = None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    now = utc_now()
    ids: list[str] = []
    inserted = 0
    updated = 0
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            # Consume every item in one transaction.  The previous safety
            # slice silently discarded records after the first 1,000, which
            # made large backfills incomplete while reporting success.
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError("each ontology entity must be an object")
                entity_id, existed = _upsert_entity_connection(connection, item, now=now, return_state=True)
                ids.append(entity_id)
                if existed:
                    updated += 1
                else:
                    inserted += 1
            connection.commit()
    return {
        "status": "accepted",
        "count": len(ids),
        "inserted": inserted,
        "updated": updated,
        "entity_ids": ids,
        "schema_version": SCHEMA_VERSION,
    }


def upsert_evidence_ref(item: dict[str, Any], *, db_path: str | None = None) -> str:
    soc_store.init_db(db_path)
    source = normalize_source(item.get("source") or "unknown") or "unknown"
    locator = sanitize_locator(item.get("locator") or item.get("uri") or item.get("source_id"))
    if not locator:
        raise ValueError("evidence locator is required")
    content_hash = _text(item.get("content_hash") or item.get("sha256"), 128)
    evidence_id = _text(item.get("evidence_ref_id"), 512) or "eref:" + hashlib.sha256(f"{source}|{locator}|{content_hash}".encode()).hexdigest()[:40]
    now = utc_now()
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            existing = connection.execute("SELECT workspace_id FROM ontology_evidence_refs WHERE evidence_ref_id = ?", (evidence_id,)).fetchone()
            workspace_id = _text(item.get("workspace_id") or "local", 160) or "local"
            if existing is not None:
                existing_workspace = _text(existing["workspace_id"], 160) or "local"
                if existing_workspace != "local" and workspace_id != "local" and existing_workspace != workspace_id:
                    raise ValueError("evidence reference belongs to a different workspace")
                if existing_workspace != "local" and workspace_id == "local":
                    workspace_id = existing_workspace
            connection.execute(
                """
                INSERT INTO ontology_evidence_refs
                    (evidence_ref_id, source, locator, content_hash, content_type, workspace_id, summary_json, observed_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(evidence_ref_id) DO UPDATE SET
                    source=excluded.source, locator=excluded.locator,
                    content_hash=excluded.content_hash, content_type=excluded.content_type,
                    workspace_id=excluded.workspace_id,
                    summary_json=excluded.summary_json, observed_at=excluded.observed_at,
                    updated_at=excluded.updated_at
                """,
                (evidence_id, source, locator, content_hash, _text(item.get("content_type"), 120), workspace_id, bounded_json(item.get("summary") or {}, MAX_SUMMARY_BYTES), _text(item.get("observed_at") or now, 64), now, now),
            )
            connection.commit()
    return evidence_id


def _semantic_relationship_id(item: dict[str, Any]) -> str:
    """Derive one relationship identity from its semantic source tuple.

    Request and caller-generated IDs are transport metadata.  A replay of the
    same edge under a new request key must address the same row and change
    record, otherwise each worker cycle grows a duplicate graph edge.
    """
    relation = _text(item.get("relationship_type") or item.get("type"), 120).upper()
    from_id = _text(item.get("from_entity_id") or item.get("from"), 512)
    to_id = _text(item.get("to_entity_id") or item.get("to"), 512)
    source = normalize_source(item.get("source") or "unknown") or "unknown"
    source_record_id = _text(item.get("source_record_id") or item.get("source_id"), 512)
    return "rel:" + hashlib.sha256(f"{relation}|{from_id}|{to_id}|{source}|{source_record_id}".encode()).hexdigest()[:40]


def _relationship_change_id(relation_id: str, after: Any) -> str:
    """Return a deterministic change ID for one semantic relationship state."""
    stable = dict(after) if isinstance(after, dict) else {}
    stable.pop("created_at", None)
    stable.pop("updated_at", None)
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)
    return "chg:" + hashlib.sha256(f"relationship|{relation_id}|upsert|{encoded}".encode()).hexdigest()[:40]


def _upsert_relationship_connection(
    connection: Any,
    item: dict[str, Any],
    *,
    now: str | None = None,
    return_state: bool = False,
) -> str | tuple[str, bool]:
    relation = _text(item.get("relationship_type") or item.get("type"), 120).upper()
    if relation not in RELATION_TYPES:
        raise ValueError(f"unsupported relationship_type: {relation}")
    from_id = _text(item.get("from_entity_id") or item.get("from"), 512)
    to_id = _text(item.get("to_entity_id") or item.get("to"), 512)
    if not from_id or not to_id or from_id == to_id:
        raise ValueError("relationships require distinct from_entity_id and to_entity_id")
    from_entity = connection.execute("SELECT entity_id, workspace_id FROM ontology_entities WHERE entity_id = ?", (from_id,)).fetchone()
    if from_entity is None:
        raise ValueError(f"unknown relationship source entity: {from_id}")
    to_entity = connection.execute("SELECT entity_id, workspace_id FROM ontology_entities WHERE entity_id = ?", (to_id,)).fetchone()
    if to_entity is None:
        raise ValueError(f"unknown relationship target entity: {to_id}")
    evidence_ref_id = _text(item.get("evidence_ref_id"), 512)
    evidence_row = None
    if evidence_ref_id:
        evidence_row = connection.execute("SELECT workspace_id FROM ontology_evidence_refs WHERE evidence_ref_id = ?", (evidence_ref_id,)).fetchone()
        if evidence_row is None:
            raise ValueError(f"unknown relationship evidence reference: {evidence_ref_id}")
    source = normalize_source(item.get("source") or "unknown") or "unknown"
    source_record_id = _text(item.get("source_record_id") or item.get("source_id"), 512)
    relation_id = _text(item.get("relationship_id") or item.get("edge_id"), 512)
    if not relation_id:
        relation_id = _semantic_relationship_id(item)
    now = now or utc_now()
    existing = connection.execute("SELECT * FROM ontology_relationships WHERE relationship_id = ?", (relation_id,)).fetchone()
    # A missing relationship workspace inherits the source entity's scope.
    # This keeps older local callers compatible while preventing a default
    # ``local`` value from joining two tenant-scoped entities accidentally.
    workspace_id = _text(item.get("workspace_id") or from_entity["workspace_id"] or "local", 160) or "local"
    if existing is not None:
        existing_workspace = _text(existing["workspace_id"], 160) or "local"
        if existing_workspace != "local" and workspace_id != "local" and existing_workspace != workspace_id:
            raise ValueError("relationship belongs to a different workspace")
        if existing_workspace != "local" and workspace_id == "local":
            workspace_id = existing_workspace
    if evidence_row is not None:
        evidence_workspace = _text(evidence_row["workspace_id"], 160) or "local"
        if evidence_workspace != "local" and workspace_id != "local" and evidence_workspace != workspace_id:
            raise ValueError("relationship evidence reference belongs to a different workspace")
        if evidence_workspace != "local" and workspace_id == "local":
            workspace_id = evidence_workspace
    endpoint_workspaces = {str(from_entity["workspace_id"] or "local"), str(to_entity["workspace_id"] or "local")}
    if workspace_id != "local" and any(scope not in {workspace_id, "local"} for scope in endpoint_workspaces):
        raise ValueError("relationship endpoints belong to a different workspace")
    if existing is not None:
        immutable = {
            "relationship_type": relation,
            "from_entity_id": from_id,
            "to_entity_id": to_id,
            "source": source,
            "source_record_id": source_record_id,
            "workspace_id": workspace_id,
        }
        for field, incoming in immutable.items():
            stored = _text(existing[field], 512)
            if field == "source":
                stored = normalize_source(stored)
            if stored != incoming:
                raise ValueError("relationship identity is immutable; use a new relationship_id for a different relation")
    observed = _text(
        item.get("observed_at")
        or item.get("last_seen_at")
        or item.get("first_seen_at")
        or item.get("created_at")
        or item.get("updated_at")
        or (existing["observed_at"] if existing is not None else UNKNOWN_OBSERVED_AT),
        64,
    ) or UNKNOWN_OBSERVED_AT
    connection.execute(
        """
        INSERT INTO ontology_relationships (
            relationship_id, relationship_type, from_entity_id, to_entity_id,
            source, source_record_id, workspace_id, evidence_ref_id,
            properties_json, confidence, observed_at, valid_from, valid_to,
            freshness_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(relationship_id) DO UPDATE SET
            evidence_ref_id=excluded.evidence_ref_id,
            properties_json=excluded.properties_json, confidence=excluded.confidence,
            observed_at=excluded.observed_at, valid_from=excluded.valid_from,
            valid_to=excluded.valid_to, freshness_at=excluded.freshness_at,
            updated_at=excluded.updated_at
        """,
        (
            relation_id,
            relation,
            from_id,
            to_id,
            source,
            source_record_id,
            workspace_id,
            evidence_ref_id or None,
            bounded_json(item.get("properties") or {}, MAX_RELATION_PROPERTIES_BYTES),
            _confidence(item.get("confidence"), 100),
            observed,
            _text(item.get("valid_from"), 64) or None,
            _text(item.get("valid_to"), 64) or None,
            _text(item.get("freshness_at") or observed, 64),
            now,
            now,
        ),
    )
    after = connection.execute("SELECT * FROM ontology_relationships WHERE relationship_id = ?", (relation_id,)).fetchone()
    _record_change_connection(
        connection,
        object_type="relationship",
        object_id=relation_id,
        action="upsert",
        before=dict(existing) if existing is not None else {},
        after=dict(after) if after is not None else {},
        source=source,
        actor=_text(item.get("actor") or item.get("source_instance") or "system", 160),
        now=now,
        change_id=_relationship_change_id(relation_id, dict(after) if after is not None else {}),
    )
    return (relation_id, existing is not None) if return_state else relation_id


def upsert_relationship(item: dict[str, Any], *, db_path: str | None = None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            relationship_id = _upsert_relationship_connection(connection, item)
            connection.commit()
            row = connection.execute("SELECT * FROM ontology_relationships WHERE relationship_id = ?", (relationship_id,)).fetchone()
    return _relationship_row(row)


def upsert_relationships(items: Iterable[dict[str, Any]], *, db_path: str | None = None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    now = utc_now()
    ids: list[str] = []
    inserted = 0
    updated = 0
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            # As with entities, process the complete iterable so callers can
            # submit a chunk larger than the old response bound without
            # silently losing relations.
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError("each ontology relationship must be an object")
                relationship_id, existed = _upsert_relationship_connection(connection, item, now=now, return_state=True)
                ids.append(relationship_id)
                if existed:
                    updated += 1
                else:
                    inserted += 1
            connection.commit()
    return {
        "status": "accepted",
        "count": len(ids),
        "inserted": inserted,
        "updated": updated,
        "relationship_ids": ids,
        "schema_version": SCHEMA_VERSION,
    }


def resolve_identity(
    entity_type: str,
    namespace: str,
    value: Any,
    *,
    aliases: Iterable[Any] | None = None,
    source: str | None = None,
    workspace_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Resolve a source value to canonical entities without silently merging.

    A single high-confidence candidate is returned as ``selected``.  Multiple
    candidates are surfaced as a conflict for operator review; callers can use
    :func:`merge_entities` once provenance and ownership have been verified.
    """
    normalized_type = normalize_value(entity_type, limit=80)
    normalized_namespace = normalize_value(namespace or "global", limit=120) or "global"
    normalized_value = normalize_canonical_key(normalized_type, normalized_namespace, value)
    search_values = [normalized_value, *[_text(item, 512) for item in (aliases or []) if _text(item, 512)]]
    source_filter = normalize_source(source) if source else ""
    workspace_filter = _text(workspace_id, 160)
    soc_store.init_db(db_path)
    candidates: dict[str, dict[str, Any]] = {}
    with soc_store.read_connect(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM ontology_entities WHERE entity_type = ? AND namespace = ? AND canonical_key = ?",
            (normalized_type, normalized_namespace, normalized_value),
        ).fetchone()
        if row:
            candidates[str(row["entity_id"])] = _entity_row(row)
        for candidate in search_values:
            params: list[Any] = [normalize_value(candidate, limit=512)]
            query = "SELECT e.* FROM ontology_aliases a JOIN ontology_entities e ON e.entity_id = a.entity_id WHERE a.normalized_value = ?"
            if source_filter:
                query += " AND a.source = ?"
                params.append(source_filter)
            if workspace_filter:
                query += " AND e.workspace_id = ?"
                params.append(workspace_filter)
            for alias_row in connection.execute(query, tuple(params)).fetchall():
                candidates[str(alias_row["entity_id"])] = _entity_row(alias_row)
    ranked = sorted(
        candidates.values(),
        key=lambda item: (_source_priority(str(item.get("source") or "")), int(item.get("confidence") or 0), str(item.get("updated_at") or "")),
        reverse=True,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "entity_type": normalized_type,
        "namespace": normalized_namespace,
        "normalized_value": normalized_value,
        "candidates": ranked[:20],
        "selected": ranked[0] if len(ranked) == 1 else None,
        "conflict": len(ranked) > 1,
    }


def merge_entities(
    loser_entity_id: str,
    winner_entity_id: str,
    *,
    reason: str,
    actor: str = "operator",
    source: str = "reconciler",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Merge duplicate identities while preserving an auditable history."""
    loser_id = _text(loser_entity_id, 512)
    winner_id = _text(winner_entity_id, 512)
    if not loser_id or not winner_id or loser_id == winner_id:
        raise ValueError("loser and winner must be distinct entity IDs")
    soc_store.init_db(db_path)
    now = utc_now()
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            loser = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (loser_id,)).fetchone()
            winner = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (winner_id,)).fetchone()
            if loser is None or winner is None:
                raise ValueError("both merge entities must exist")
            if str(loser["entity_type"]) != str(winner["entity_type"]):
                raise ValueError("merge entities must have the same entity_type")
            if str(loser["workspace_id"]) != str(winner["workspace_id"]):
                raise ValueError("merge entities must belong to the same workspace")
            relation_rows = connection.execute(
                "SELECT relationship_id, from_entity_id, to_entity_id FROM ontology_relationships WHERE from_entity_id = ? OR to_entity_id = ?",
                (loser_id, loser_id),
            ).fetchall()
            moved = 0
            removed = 0
            for relation in relation_rows:
                relation_id = str(relation["relationship_id"])
                from_id = winner_id if relation["from_entity_id"] == loser_id else str(relation["from_entity_id"])
                to_id = winner_id if relation["to_entity_id"] == loser_id else str(relation["to_entity_id"])
                if from_id == to_id:
                    connection.execute("DELETE FROM ontology_relationships WHERE relationship_id = ?", (relation_id,))
                    removed += 1
                    continue
                try:
                    connection.execute(
                        "UPDATE ontology_relationships SET from_entity_id = ?, to_entity_id = ?, updated_at = ? WHERE relationship_id = ?",
                        (from_id, to_id, now, relation_id),
                    )
                    moved += 1
                except Exception:
                    # A relationship may already exist for the winner. Keep
                    # the canonical copy and remove the duplicate edge.
                    connection.execute("DELETE FROM ontology_relationships WHERE relationship_id = ?", (relation_id,))
                    removed += 1
            aliases_moved = 0
            for alias in connection.execute("SELECT alias_id, alias_type, normalized_value, source FROM ontology_aliases WHERE entity_id = ?", (loser_id,)).fetchall():
                try:
                    connection.execute("UPDATE ontology_aliases SET entity_id = ?, updated_at = ? WHERE alias_id = ?", (winner_id, now, alias["alias_id"]))
                    aliases_moved += 1
                except Exception:
                    connection.execute("DELETE FROM ontology_aliases WHERE alias_id = ?", (alias["alias_id"],))
            merge_id = "merge:" + hashlib.sha256(f"{loser_id}|{winner_id}|{now}|{uuid.uuid4()}".encode()).hexdigest()[:40]
            connection.execute(
                "INSERT INTO ontology_entity_merges (merge_id, loser_entity_id, winner_entity_id, reason, source, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (merge_id, loser_id, winner_id, _text(reason, 2000) or "operator-confirmed duplicate", _text(source, 160) or "reconciler", _text(actor, 160) or "operator", now),
            )
            loser_before = dict(loser)
            loser_properties = _loads(loser["properties_json"])
            loser_properties["merged_into"] = winner_id
            connection.execute(
                "UPDATE ontology_entities SET status = 'merged', properties_json = ?, updated_at = ? WHERE entity_id = ?",
                (bounded_json(loser_properties, MAX_PROPERTIES_BYTES), now, loser_id),
            )
            loser_after = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (loser_id,)).fetchone()
            _record_change_connection(connection, object_type="entity", object_id=loser_id, action="merge", before=loser_before, after=dict(loser_after), source=source, actor=actor, now=now)
            connection.commit()
    return {"status": "merged", "merge_id": merge_id, "loser_entity_id": loser_id, "winner_entity_id": winner_id, "relationships_moved": moved, "relationships_removed": removed, "aliases_moved": aliases_moved}


def reconcile(*, db_path: str | None = None, limit: int = 500) -> dict[str, Any]:
    """Record duplicate and contradictory observations for later review."""
    soc_store.init_db(db_path)
    bound = _limit(limit, 500)
    now = utc_now()
    conflicts: list[dict[str, Any]] = []
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            for row in connection.execute(
                "SELECT alias_type, normalized_value, COUNT(*) AS count, GROUP_CONCAT(DISTINCT entity_id) AS entity_ids FROM ontology_aliases GROUP BY alias_type, normalized_value HAVING COUNT(DISTINCT entity_id) > 1 LIMIT ?",
                (bound,),
            ).fetchall():
                object_id = f"alias:{row['alias_type']}:{row['normalized_value']}"
                conflicts.append({"object_type": "alias", "object_id": object_id, "conflict_type": "duplicate_identity", "details": {"entity_ids": str(row["entity_ids"] or "").split(",")}})
            for row in connection.execute(
                "SELECT relationship_type, from_entity_id, to_entity_id, COUNT(DISTINCT source) AS sources, GROUP_CONCAT(DISTINCT source) AS source_names FROM ontology_relationships GROUP BY relationship_type, from_entity_id, to_entity_id HAVING COUNT(DISTINCT source) > 1 LIMIT ?",
                (bound,),
            ).fetchall():
                object_id = f"rel:{row['relationship_type']}:{row['from_entity_id']}:{row['to_entity_id']}"
                conflicts.append({"object_type": "relationship", "object_id": object_id, "conflict_type": "source_contradiction", "details": {"sources": str(row["source_names"] or "").split(",")}})
            for conflict in conflicts:
                conflict_id = "conflict:" + hashlib.sha256(f"{conflict['object_type']}|{conflict['object_id']}|{conflict['conflict_type']}".encode()).hexdigest()[:40]
                connection.execute(
                    "INSERT INTO ontology_conflicts (conflict_id, object_type, object_id, conflict_type, details_json, status, source, created_at) VALUES (?, ?, ?, ?, ?, 'open', 'reconciler', ?) ON CONFLICT(conflict_id) DO UPDATE SET details_json=excluded.details_json, status='open'",
                    (conflict_id, conflict["object_type"], conflict["object_id"], conflict["conflict_type"], bounded_json(conflict["details"], MAX_SUMMARY_BYTES), now),
                )
            connection.commit()
    return {"status": "completed", "conflicts": len(conflicts), "items": conflicts[:bound]}


def record_event(item: dict[str, Any], *, db_path: str | None = None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    entity_id = _text(item.get("entity_id"), 512)
    if not entity_id:
        raise ValueError("event entity_id is required")
    event_type = _text(item.get("event_type") or "observed", 120) or "observed"
    source = normalize_source(item.get("source") or "unknown") or "unknown"
    source_record_id = _text(item.get("source_record_id") or item.get("source_id"), 512)
    occurred_at = _text(item.get("occurred_at") or item.get("observed_at") or item.get("created_at") or UNKNOWN_OBSERVED_AT, 64) or UNKNOWN_OBSERVED_AT
    event_id = _text(item.get("event_id"), 512) or "event:" + hashlib.sha256(f"{entity_id}|{event_type}|{source}|{source_record_id}|{occurred_at}".encode()).hexdigest()[:40]
    now = utc_now()
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            if connection.execute("SELECT 1 FROM ontology_entities WHERE entity_id = ?", (entity_id,)).fetchone() is None:
                raise ValueError(f"unknown event entity: {entity_id}")
            connection.execute(
                """
                INSERT INTO ontology_events
                    (event_id, entity_id, event_type, source, source_record_id, summary_json, occurred_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    event_type=excluded.event_type, source=excluded.source,
                    source_record_id=excluded.source_record_id, summary_json=excluded.summary_json,
                    occurred_at=excluded.occurred_at
                """,
                (event_id, entity_id, event_type, source, source_record_id, bounded_json(item.get("summary") or {}, MAX_SUMMARY_BYTES), occurred_at, now),
            )
            connection.commit()
    return {"event_id": event_id, "entity_id": entity_id, "event_type": event_type, "occurred_at": occurred_at}


def sync_payload(payload: dict[str, Any], *, db_path: str | None = None) -> dict[str, Any]:
    """Apply a bounded bridge snapshot atomically and idempotently."""
    if not isinstance(payload, dict):
        raise ValueError("ontology sync payload must be an object")
    entities = payload.get("entities") or []
    relationships = payload.get("relationships") or []
    events = payload.get("events") or []
    evidence_refs = payload.get("evidence_refs") or []
    if not all(isinstance(value, list) for value in (entities, relationships, events, evidence_refs)):
        raise ValueError("entities, relationships, events, and evidence_refs must be arrays")
    if len(entities) > 1000 or len(relationships) > 2000 or len(events) > 2000 or len(evidence_refs) > 1000:
        raise ValueError("ontology sync batch exceeds its bounded limit")
    schema_version = _text(payload.get("schema_version") or SCHEMA_VERSION, 80) or SCHEMA_VERSION
    if schema_version != SCHEMA_VERSION:
        raise ValueError(f"unsupported ontology schema_version: {schema_version}")
    supplied_idempotency = _text(payload.get("idempotency_key"), 200)
    if supplied_idempotency and not re.fullmatch(r"[A-Za-z0-9._:-]{8,200}", supplied_idempotency):
        raise ValueError("idempotency_key must be 8-200 ASCII letters, digits, '.', '_', ':' or '-'")
    request_material = {
        "schema_version": schema_version,
        "source_instance": payload.get("source_instance") or "ontology-bridge",
        "organization_id": payload.get("organization_id") or "",
        "workspace_id": payload.get("workspace_id") or "",
        "entities": entities,
        "relationships": relationships,
        "events": events,
        "evidence_refs": evidence_refs,
    }
    request_hash = hashlib.sha256(json.dumps(request_material, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    idempotency_key = supplied_idempotency or request_hash
    soc_store.init_db(db_path)
    now = utc_now()
    counts = {"entities": 0, "relationships": 0, "events": 0, "evidence_refs": 0}
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            receipt = connection.execute("SELECT response_json, request_hash FROM ontology_ingest_receipts WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
            if receipt is not None:
                if str(receipt["request_hash"] or "") != request_hash:
                    raise ValueError("idempotency_key was already used for a different ontology payload")
                replay = _loads(receipt["response_json"])
                replay["idempotent"] = True
                return replay
            for item in entities:
                if not isinstance(item, dict):
                    raise ValueError("ontology entity must be an object")
                _upsert_entity_connection(connection, item, now=now)
                counts["entities"] += 1
            for item in evidence_refs:
                if not isinstance(item, dict):
                    raise ValueError("ontology evidence_ref must be an object")
                source = normalize_source(item.get("source") or "unknown") or "unknown"
                locator = sanitize_locator(item.get("locator") or item.get("uri") or item.get("source_id"))
                if not locator:
                    raise ValueError("evidence locator is required")
                content_hash = _text(item.get("content_hash") or item.get("sha256"), 128)
                evidence_id = _text(item.get("evidence_ref_id"), 512) or "eref:" + hashlib.sha256(f"{source}|{locator}|{content_hash}".encode()).hexdigest()[:40]
                existing_evidence = connection.execute("SELECT workspace_id FROM ontology_evidence_refs WHERE evidence_ref_id = ?", (evidence_id,)).fetchone()
                evidence_workspace = _text(item.get("workspace_id") or "local", 160) or "local"
                if existing_evidence is not None:
                    existing_workspace = _text(existing_evidence["workspace_id"], 160) or "local"
                    if existing_workspace != "local" and evidence_workspace != "local" and existing_workspace != evidence_workspace:
                        raise ValueError("evidence reference belongs to a different workspace")
                    if existing_workspace != "local" and evidence_workspace == "local":
                        evidence_workspace = existing_workspace
                connection.execute(
                    "INSERT INTO ontology_evidence_refs (evidence_ref_id, source, locator, content_hash, content_type, workspace_id, summary_json, observed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(evidence_ref_id) DO UPDATE SET source=excluded.source, locator=excluded.locator, content_hash=excluded.content_hash, content_type=excluded.content_type, workspace_id=excluded.workspace_id, summary_json=excluded.summary_json, observed_at=excluded.observed_at, updated_at=excluded.updated_at",
                    (evidence_id, source, locator, content_hash, _text(item.get("content_type"), 120), evidence_workspace, bounded_json(item.get("summary") or {}, MAX_SUMMARY_BYTES), _text(item.get("observed_at") or now, 64), now, now),
                )
                counts["evidence_refs"] += 1
            for item in relationships:
                if not isinstance(item, dict):
                    raise ValueError("ontology relationship must be an object")
                semantic_item = dict(item)
                semantic_item["relationship_id"] = _semantic_relationship_id(item)
                _upsert_relationship_connection(connection, semantic_item, now=now)
                counts["relationships"] += 1
            for item in events:
                if not isinstance(item, dict):
                    raise ValueError("ontology event must be an object")
                entity_id = _text(item.get("entity_id"), 512)
                if connection.execute("SELECT 1 FROM ontology_entities WHERE entity_id = ?", (entity_id,)).fetchone() is None:
                    raise ValueError(f"unknown event entity: {entity_id}")
                event_type = _text(item.get("event_type") or "observed", 120) or "observed"
                source = normalize_source(item.get("source") or "unknown") or "unknown"
                source_record_id = _text(item.get("source_record_id") or item.get("source_id"), 512)
                # A transport timestamp would make a replay with omitted
                # occurred_at produce a new event ID on every worker cycle.
                # Prefer the producer's observation/creation time, then a
                # fixed epoch so the semantic fallback is deterministic.
                occurred_at = _text(item.get("occurred_at") or item.get("observed_at") or item.get("created_at") or UNKNOWN_OBSERVED_AT, 64) or UNKNOWN_OBSERVED_AT
                # Caller event IDs are transport metadata for synchronization;
                # derive the durable identity from the semantic event tuple.
                event_id = "event:" + hashlib.sha256(f"{entity_id}|{event_type}|{source}|{source_record_id}|{occurred_at}".encode()).hexdigest()[:40]
                connection.execute(
                    """
                    INSERT INTO ontology_events
                        (event_id, entity_id, event_type, source, source_record_id, summary_json, occurred_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(event_id) DO UPDATE SET
                        event_type=excluded.event_type, source=excluded.source,
                        source_record_id=excluded.source_record_id, summary_json=excluded.summary_json,
                        occurred_at=excluded.occurred_at
                    """,
                    (event_id, entity_id, event_type, source, source_record_id, bounded_json(item.get("summary") or {}, MAX_SUMMARY_BYTES), occurred_at, now),
                )
                counts["events"] += 1
            result = {"status": "accepted", "schema_version": SCHEMA_VERSION, "counts": counts, "idempotency_key": idempotency_key}
            connection.execute(
                "INSERT INTO ontology_ingest_receipts (idempotency_key, request_hash, source_instance, response_json, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(idempotency_key) DO NOTHING",
                (idempotency_key, request_hash, _text(payload.get("source_instance") or "ontology-bridge", 160), bounded_json(result, MAX_SUMMARY_BYTES), now),
            )
            connection.commit()
    return result


def search_entities(query: str = "", *, entity_type: str | None = None, workspace_id: str | None = None, limit: int = 100, db_path: str | None = None) -> list[dict[str, Any]]:
    bounded = _limit(limit)
    clauses: list[str] = []
    params: list[Any] = []
    if entity_type:
        normalized_type = normalize_value(entity_type, limit=80)
        if normalized_type not in ENTITY_TYPES:
            raise ValueError(f"unsupported entity_type: {normalized_type}")
        clauses.append("e.entity_type = ?")
        params.append(normalized_type)
    if workspace_id:
        clauses.append("e.workspace_id = ?")
        params.append(_text(workspace_id, 160))
    text_query = normalize_value(query, limit=256)
    if text_query:
        like = f"%{text_query}%"
        clauses.append("(lower(e.entity_id) LIKE ? OR lower(e.canonical_key) LIKE ? OR lower(e.display_name) LIKE ? OR lower(e.source_id) LIKE ? OR EXISTS (SELECT 1 FROM ontology_aliases a WHERE a.entity_id=e.entity_id AND a.normalized_value LIKE ?))")
        params.extend([like, like, like, like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _ontology_read_connection(db_path, _ONTOLOGY_GRAPH_READ_TABLES) as connection:
        if connection is None:
            return []
        rows = connection.execute(
            f"SELECT e.* FROM ontology_entities e {where} ORDER BY e.updated_at DESC, e.entity_id LIMIT ?",
            (*params, bounded),
        ).fetchall()
    return [_entity_row(row, include_properties=False) for row in rows]


def get_entity(entity_id: str, *, workspace_id: str | None = None, db_path: str | None = None) -> dict[str, Any] | None:
    identifier = _text(entity_id, 512)
    with _ontology_read_connection(db_path, _ONTOLOGY_GRAPH_READ_TABLES) as connection:
        if connection is None:
            return None
        row = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (identifier,)).fetchone()
        if row is None:
            alias = connection.execute("SELECT entity_id FROM ontology_aliases WHERE normalized_value = ? LIMIT 1", (normalize_value(identifier, limit=512),)).fetchone()
            if alias:
                row = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (alias["entity_id"],)).fetchone()
        if row is None:
            return None
        if workspace_id and str(row["workspace_id"] or "") not in {_text(workspace_id, 160), "local"}:
            return None
        entity = _entity_row(row)
        entity["aliases"] = [
            {"type": str(item["alias_type"]), "value": str(item["alias_value"]), "source": str(item["source"]), "confidence": int(item["confidence"] or 0)}
            for item in connection.execute("SELECT alias_type, alias_value, source, confidence FROM ontology_aliases WHERE entity_id = ? ORDER BY alias_type, alias_value", (entity["entity_id"],)).fetchall()
        ]
        if workspace_id:
            scope = _text(workspace_id, 160)
            entity["relationship_counts"] = {
                "outgoing": int(connection.execute("SELECT COUNT(*) FROM ontology_relationships r JOIN ontology_entities t ON t.entity_id = r.to_entity_id WHERE r.from_entity_id = ? AND (r.workspace_id IN (?, 'local')) AND t.workspace_id IN (?, 'local')", (entity["entity_id"], scope, scope)).fetchone()[0]),
                "incoming": int(connection.execute("SELECT COUNT(*) FROM ontology_relationships r JOIN ontology_entities f ON f.entity_id = r.from_entity_id WHERE r.to_entity_id = ? AND (r.workspace_id IN (?, 'local')) AND f.workspace_id IN (?, 'local')", (entity["entity_id"], scope, scope)).fetchone()[0]),
            }
        else:
            entity["relationship_counts"] = {
                "outgoing": int(connection.execute("SELECT COUNT(*) FROM ontology_relationships WHERE from_entity_id = ?", (entity["entity_id"],)).fetchone()[0]),
                "incoming": int(connection.execute("SELECT COUNT(*) FROM ontology_relationships WHERE to_entity_id = ?", (entity["entity_id"],)).fetchone()[0]),
            }
    return entity


def neighbors(entity_id: str, *, depth: int = 1, relationship_type: str | None = None, limit: int = 100, workspace_id: str | None = None, db_path: str | None = None) -> dict[str, Any]:
    root = _text(entity_id, 512)
    depth = max(1, min(int(depth or 1), MAX_TRAVERSAL_DEPTH))
    bounded = _limit(limit)
    relations: dict[str, dict[str, Any]] = {}
    nodes: dict[str, dict[str, Any]] = {}
    frontier = deque([(root, 0)])
    visited = {root}
    with _ontology_read_connection(db_path, _ONTOLOGY_GRAPH_READ_TABLES) as connection:
        if connection is None:
            return {"entity_id": root, "depth": depth, "nodes": [], "relationships": []}
        root_row = connection.execute("SELECT workspace_id FROM ontology_entities WHERE entity_id = ?", (root,)).fetchone()
        if root_row is None or (workspace_id and str(root_row["workspace_id"] or "") not in {_text(workspace_id, 160), "local"}):
            return {"entity_id": root, "depth": depth, "nodes": [], "relationships": []}
        while frontier and len(nodes) < bounded:
            current, distance = frontier.popleft()
            if distance >= depth:
                continue
            clauses = ["(r.from_entity_id = ? OR r.to_entity_id = ?)"]
            params: list[Any] = [current, current]
            if workspace_id:
                clauses.append("(r.workspace_id = ? OR r.workspace_id = 'local')")
                params.append(_text(workspace_id, 160))
            if relationship_type:
                relation = _text(relationship_type, 120).upper()
                if relation not in RELATION_TYPES:
                    raise ValueError(f"unsupported relationship_type: {relation}")
                clauses.append("r.relationship_type = ?")
                params.append(relation)
            if workspace_id:
                scope = _text(workspace_id, 160)
                clauses.extend(["f.workspace_id IN (?, 'local')", "t.workspace_id IN (?, 'local')"])
                params.extend([scope, scope])
            rows = connection.execute(
                f"SELECT r.*, f.entity_id AS from_exists, t.entity_id AS to_exists FROM ontology_relationships r JOIN ontology_entities f ON f.entity_id=r.from_entity_id JOIN ontology_entities t ON t.entity_id=r.to_entity_id WHERE {' AND '.join(clauses)} ORDER BY r.updated_at DESC LIMIT ?",
                (*params, bounded),
            ).fetchall()
            for row in rows:
                relationship = _relationship_row(row)
                relations[relationship["relationship_id"]] = relationship
                other = relationship["to_entity_id"] if relationship["from_entity_id"] == current else relationship["from_entity_id"]
                if other != root and other not in nodes:
                    node_row = connection.execute("SELECT * FROM ontology_entities WHERE entity_id = ?", (other,)).fetchone()
                    if node_row and (not workspace_id or str(node_row["workspace_id"] or "") in {_text(workspace_id, 160), "local"}):
                        nodes[other] = _entity_row(node_row, include_properties=False)
                if other not in visited and len(visited) < bounded:
                    visited.add(other)
                    frontier.append((other, distance + 1))
    return {"entity_id": root, "depth": depth, "nodes": list(nodes.values())[:bounded], "relationships": list(relations.values())[:bounded]}


def timeline(entity_id: str, *, limit: int = 100, workspace_id: str | None = None, db_path: str | None = None) -> list[dict[str, Any]]:
    bounded = _limit(limit)
    identifier = _text(entity_id, 512)
    with _ontology_read_connection(db_path, _ONTOLOGY_GRAPH_READ_TABLES) as connection:
        if connection is None:
            return []
        root_row = connection.execute("SELECT workspace_id FROM ontology_entities WHERE entity_id = ?", (identifier,)).fetchone()
        if root_row is None or (workspace_id and str(root_row["workspace_id"] or "") not in {_text(workspace_id, 160), "local"}):
            return []
        event_rows = connection.execute("SELECT event_id, event_type, source, source_record_id, summary_json, occurred_at FROM ontology_events WHERE entity_id = ? ORDER BY occurred_at DESC, event_id DESC LIMIT ?", (identifier, bounded)).fetchall()
        if workspace_id:
            scope = _text(workspace_id, 160)
            relation_rows = connection.execute("SELECT r.relationship_id, r.relationship_type, r.from_entity_id, r.to_entity_id, r.source, r.source_record_id, r.properties_json, r.confidence, r.observed_at FROM ontology_relationships r JOIN ontology_entities f ON f.entity_id=r.from_entity_id JOIN ontology_entities t ON t.entity_id=r.to_entity_id WHERE (r.from_entity_id = ? OR r.to_entity_id = ?) AND (r.workspace_id = ? OR r.workspace_id = 'local') AND f.workspace_id IN (?, 'local') AND t.workspace_id IN (?, 'local') ORDER BY r.observed_at DESC, r.relationship_id DESC LIMIT ?", (identifier, identifier, scope, scope, scope, bounded)).fetchall()
        else:
            relation_rows = connection.execute("SELECT relationship_id, relationship_type, from_entity_id, to_entity_id, source, source_record_id, properties_json, confidence, observed_at FROM ontology_relationships WHERE from_entity_id = ? OR to_entity_id = ? ORDER BY observed_at DESC, relationship_id DESC LIMIT ?", (identifier, identifier, bounded)).fetchall()
    events = [
        {"event_id": str(row["event_id"]), "event_type": str(row["event_type"]), "source": str(row["source"]), "source_record_id": str(row["source_record_id"] or ""), "summary": _loads(row["summary_json"]), "occurred_at": str(row["occurred_at"]), "kind": "event"}
        for row in event_rows
    ]
    events.extend(
        {"event_id": str(row["relationship_id"]), "event_type": str(row["relationship_type"]), "source": str(row["source"]), "source_record_id": str(row["source_record_id"] or ""), "summary": {"from_entity_id": row["from_entity_id"], "to_entity_id": row["to_entity_id"], "confidence": row["confidence"], **_loads(row["properties_json"])}, "occurred_at": str(row["observed_at"]), "kind": "relationship"}
        for row in relation_rows
    )
    return sorted(events, key=lambda item: (item["occurred_at"], item["event_id"]), reverse=True)[:bounded]


def lineage(entity_id: str, *, depth: int = 2, limit: int = 100, workspace_id: str | None = None, db_path: str | None = None) -> dict[str, Any]:
    graph = neighbors(entity_id, depth=depth, limit=limit, workspace_id=workspace_id, db_path=db_path)
    paths: list[list[str]] = []
    adjacency: dict[str, list[str]] = {}
    for relation in graph["relationships"]:
        adjacency.setdefault(relation["from_entity_id"], []).append(relation["to_entity_id"])
        adjacency.setdefault(relation["to_entity_id"], []).append(relation["from_entity_id"])
    queue = deque([(entity_id, [entity_id])])
    while queue and len(paths) < limit:
        current, path = queue.popleft()
        if len(path) > 1:
            paths.append(path)
        if len(path) - 1 >= max(1, min(int(depth or 2), MAX_TRAVERSAL_DEPTH)):
            continue
        for nxt in adjacency.get(current, []):
            if nxt not in path:
                queue.append((nxt, [*path, nxt]))
    return {"entity_id": entity_id, "depth": depth, "paths": paths, "nodes": graph["nodes"], "relationships": graph["relationships"]}


def risk_context(entity_id: str, *, workspace_id: str | None = None, db_path: str | None = None) -> dict[str, Any]:
    entity = get_entity(entity_id, db_path=db_path)
    if entity is None:
        return {"entity_id": entity_id, "status": "not_found"}
    if workspace_id and entity.get("workspace_id") not in {_text(workspace_id, 160), "local"}:
        return {"entity_id": entity_id, "status": "not_found"}
    graph = neighbors(entity["entity_id"], depth=2, limit=250, workspace_id=workspace_id, db_path=db_path)
    finding_ids = {entity["entity_id"]} if entity["entity_type"] == "finding" else set()
    # Keep the ontology ID and the owning findings-store ID separate.  Core
    # projections commonly use ``finding:secopsai:<source-id>`` as their
    # ontology key, while the durable row is keyed by the source ID itself.
    # Include the root entity's source fields as well as linked graph nodes so
    # a direct risk request cannot lose severity just because the root is not
    # returned in its own neighbor list.
    finding_source_ids: set[str] = set()
    root_properties = entity.get("properties") if isinstance(entity.get("properties"), dict) else {}
    for candidate in (
        entity.get("source_id"),
        entity.get("canonical_key"),
        root_properties.get("finding_id"),
        root_properties.get("source_id"),
    ):
        value = _text(candidate, 512)
        if value:
            finding_source_ids.add(value)
    for node in graph["nodes"]:
        if node["entity_type"] == "finding":
            finding_ids.add(node["entity_id"])
            for candidate in (node.get("source_id"), node.get("canonical_key")):
                value = _text(candidate, 512)
                if value:
                    finding_source_ids.add(value)
    findings: list[dict[str, Any]] = []
    severity_values = {"critical": 95, "high": 80, "medium": 55, "low": 25, "info": 10}
    properties = entity.get("properties") if isinstance(entity.get("properties"), dict) else {}
    severity_score = int(properties.get("severity_score") or severity_values.get(str(properties.get("severity") or "").lower(), 0) or 0)
    # The findings store is an optional legacy dependency of the ontology
    # projection.  If it is not present, retain the graph-derived context and
    # report no linked legacy payload rather than initializing a database.
    with _ontology_read_connection(db_path, {"findings"}) as connection:
        if connection is not None:
            for finding_id in list(finding_ids)[:100]:
                finding_entity = next((node for node in graph["nodes"] if node.get("entity_id") == finding_id), None)
                source_finding_id = _text((finding_entity or {}).get("source_id") if isinstance(finding_entity, dict) else "", 512)
                candidates = [finding_id, source_finding_id]
                if finding_id == entity["entity_id"]:
                    candidates.extend(finding_source_ids)
                row = None
                for candidate in dict.fromkeys(_text(value, 512) for value in candidates if _text(value, 512)):
                    row = connection.execute("SELECT finding_id, title, severity, severity_score, status, disposition, source, first_seen, last_seen, updated_at FROM findings WHERE finding_id = ?", (candidate,)).fetchone()
                    if row is not None:
                        break
                if row:
                    item = dict(row)
                    item["ontology_entity_id"] = finding_id
                    findings.append(item)
                    severity_score = max(severity_score, int(item.get("severity_score") or severity_values.get(str(item.get("severity") or "").lower(), 0) or 0))
    evidence_count = sum(1 for relation in graph["relationships"] if relation.get("evidence_ref_id"))
    freshness = entity.get("freshness_at") or entity.get("last_seen_at")
    # Keep the risk score deterministic and explainable.  Optional context
    # raises attention when it is present, while the severity-only baseline
    # remains stable for legacy findings that do not publish these fields.
    criticality_values = {"critical": 20, "high": 12, "medium": 6, "low": 0, "normal": 0}
    exploitability_values = {"critical": 15, "high": 12, "medium": 7, "low": 2}
    reachability = properties.get("internet_exposed")
    if reachability is None:
        reachability = properties.get("internet_reachable")
    reachability_bonus = 12 if reachability is True or str(reachability).lower() in {"true", "yes", "public", "internet"} else 0
    criticality_label = str(properties.get("asset_criticality") or properties.get("criticality") or "").lower()
    criticality_bonus = criticality_values.get(criticality_label, 0)
    exploitability_raw = properties.get("exploitability_score")
    try:
        exploitability_bonus = max(0, min(15, round(float(exploitability_raw) * 1.5))) if exploitability_raw is not None else exploitability_values.get(str(properties.get("exploitability") or "").lower(), 0)
    except (TypeError, ValueError):
        exploitability_bonus = exploitability_values.get(str(properties.get("exploitability") or "").lower(), 0)
    evidence_bonus = min(10, evidence_count * 2)
    risk_score = max(0, min(100, severity_score + criticality_bonus + exploitability_bonus + reachability_bonus + evidence_bonus))
    stale = False
    try:
        parsed_freshness = datetime.fromisoformat(str(freshness).replace("Z", "+00:00"))
        if parsed_freshness.tzinfo is None:
            parsed_freshness = parsed_freshness.replace(tzinfo=timezone.utc)
        stale = (datetime.now(timezone.utc) - parsed_freshness).total_seconds() > 7 * 24 * 3600
    except (TypeError, ValueError):
        stale = True
    next_step = "Review the evidence and confirm ownership before proposing a reversible remediation." if risk_score >= 55 else "Continue collecting provenance and monitor the linked context before taking action."
    return {
        "entity_id": entity["entity_id"],
        "entity": entity,
        "risk_score": risk_score,
        "severity_score": severity_score,
        "findings": findings,
        "related_entities": graph["nodes"],
        "relationships": graph["relationships"],
        "evidence_references": evidence_count,
        "freshness_at": freshness,
        "freshness_stale": stale,
        "risk_factors": {
            "severity_score": severity_score,
            "asset_criticality_bonus": criticality_bonus,
            "exploitability_bonus": exploitability_bonus,
            "reachability_bonus": reachability_bonus,
            "evidence_quality_bonus": evidence_bonus,
        },
        "confidence": min([entity.get("confidence", 100), *[item.get("confidence", 100) for item in graph["relationships"]]]),
        "explanation": "Deterministic context from linked findings, relationships, evidence references, and freshness metadata.",
        "recommended_next_step": next_step,
        "action_contract": {
            "mode": "proposal",
            "reversible": True,
            "approval_required": True,
            "preconditions": ["evidence references are reviewed", "owner and workspace are confirmed"],
            "rollback": "No change is applied until an operator approves a bounded remediation proposal.",
        },
    }


def quality(*, workspace_id: str | None = None, stale_after_seconds: int = 7 * 24 * 3600, db_path: str | None = None) -> dict[str, Any]:
    try:
        stale_after = max(300, min(int(stale_after_seconds), 365 * 24 * 3600))
    except (TypeError, ValueError):
        stale_after = 7 * 24 * 3600
    now_dt = datetime.now(timezone.utc)
    cutoff_dt = now_dt.timestamp() - stale_after
    workspace = _text(workspace_id, 160) if workspace_id else ""
    resolved_path = os.path.abspath(os.path.expanduser(db_path or soc_store.default_db_path()))

    def empty_quality(database_present: bool) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "workspace_id": workspace or "all",
            "database_present": database_present,
            "entities": 0,
            "relationships": 0,
            "evidence_references": 0,
            "relationships_with_provenance": 0,
            "relationships_with_evidence": 0,
            # An empty denominator is unmeasured, not a perfect score.  Null
            # keeps Mission Control from presenting an empty store as healthy.
            "provenance_coverage_percent": None,
            "evidence_with_valid_locator": 0,
            "orphan_relationships": 0,
            "orphan_entities": 0,
            "stale_entities": 0,
            "stale_after_seconds": stale_after,
            "canonical_id_coverage_percent": None,
            "graph_coverage_percent": None,
            "stale_sources": 0,
            "duplicate_candidates": 0,
            "contradictory_relationships": 0,
            "findings_total": 0,
            "findings_linked_percent": None,
            "open_conflicts": 0,
            "change_history_records": 0,
            "queue_age_seconds": 0,
            "stale_runner_heartbeats": 0,
            "heartbeat_freshness_seconds": None,
            "heartbeat_measurement_status": "unknown",
            "ai_evidence_completeness_percent": None,
            "false_positive_rate": None,
            "recommendation_acceptance_rate": None,
            "action_completion_rate": None,
            "action_rollback_rate": None,
            "quality_alerts": [],
            "entities_by_type": {},
        }

    # Reports must not initialize or otherwise mutate a missing database.  In
    # particular, a read-only health probe should not create a new file merely
    # because a deployment has not completed its first write yet.
    if not os.path.isfile(resolved_path):
        return empty_quality(False)

    def parse_timestamp(value: Any) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None

    with _ontology_read_connection(resolved_path, _ONTOLOGY_QUALITY_READ_TABLES) as connection:
        if connection is None:
            return empty_quality(os.path.isfile(resolved_path))
        entity_clause = "WHERE workspace_id IN (?, 'local')" if workspace else ""
        entity_params: tuple[Any, ...] = (workspace,) if workspace else ()
        entity_rows = connection.execute(f"SELECT * FROM ontology_entities {entity_clause}", entity_params).fetchall()
        entity_ids = {str(row["entity_id"]) for row in entity_rows}
        entity_scope = {str(row["entity_id"]): str(row["workspace_id"] or "local") for row in entity_rows}
        entity_type_by_id = {str(row["entity_id"]): str(row["entity_type"]) for row in entity_rows}

        relation_scope = "r.workspace_id IN (?, 'local')" if workspace else "1 = 1"
        relation_params: tuple[Any, ...] = (workspace,) if workspace else ()
        relation_rows = connection.execute(
            f"""
            SELECT r.*, f.workspace_id AS from_workspace, t.workspace_id AS to_workspace
              FROM ontology_relationships r
              LEFT JOIN ontology_entities f ON f.entity_id = r.from_entity_id
              LEFT JOIN ontology_entities t ON t.entity_id = r.to_entity_id
             WHERE {relation_scope}
            """,
            relation_params,
        ).fetchall()
        evidence_clause = "WHERE workspace_id IN (?, 'local')" if workspace else ""
        evidence_params: tuple[Any, ...] = (workspace,) if workspace else ()
        evidence_rows = connection.execute(f"SELECT * FROM ontology_evidence_refs {evidence_clause}", evidence_params).fetchall()

        stale_entities = 0
        stale_source_names: set[str] = set()
        for row in entity_rows:
            parsed = parse_timestamp(row["freshness_at"])
            if parsed is None or parsed.timestamp() < cutoff_dt:
                stale_entities += 1
                source = normalize_source(row["source"] or "")
                if source:
                    stale_source_names.add(source)

        valid_relation_rows = []
        orphan_relationships = 0
        for row in relation_rows:
            from_scope = str(row["from_workspace"] or "")
            to_scope = str(row["to_workspace"] or "")
            endpoint_ok = bool(row["from_workspace"] and row["to_workspace"])
            if workspace:
                endpoint_ok = endpoint_ok and from_scope in {workspace, "local"} and to_scope in {workspace, "local"}
            if endpoint_ok:
                valid_relation_rows.append(row)
            else:
                orphan_relationships += 1
        relationships = len(relation_rows)
        with_provenance = sum(1 for row in relation_rows if normalize_source(row["source"] or "") not in {"", "unknown"} and str(row["source_record_id"] or ""))
        relationships_with_evidence = sum(1 for row in relation_rows if str(row["evidence_ref_id"] or ""))
        connected_ids = {str(row[field]) for row in valid_relation_rows for field in ("from_entity_id", "to_entity_id") if row[field]}
        orphan_entities = len(entity_ids - connected_ids)
        finding_ids = {item for item, kind in entity_type_by_id.items() if kind == "finding"}
        linked_finding_ids = {
            str(row["from_entity_id"] if entity_type_by_id.get(str(row["from_entity_id"])) == "finding" else row["to_entity_id"])
            for row in valid_relation_rows
            if row["relationship_type"] in {"FINDING_ON_VERSION", "FINDING_ON_ASSET", "CASE_GROUPS_FINDING", "ALERT_DERIVED_FROM_FINDING"}
            and (str(row["from_entity_id"]) in finding_ids or str(row["to_entity_id"]) in finding_ids)
        }
        evidence_with_locator = sum(1 for row in evidence_rows if str(row["locator"] or "") and not str(row["locator"]).startswith("redacted://"))
        canonical_id_count = sum(1 for row in entity_rows if ":" in str(row["entity_id"]) and len(str(row["entity_id"]).encode("utf-8")) <= MAX_ENTITY_ID_BYTES)
        stale_runner_heartbeats = 0
        heartbeat_ages: list[int] = []
        for row in connection.execute("SELECT last_seen_at FROM runner_heartbeats").fetchall():
            parsed = parse_timestamp(row["last_seen_at"])
            if parsed is None or parsed.timestamp() < cutoff_dt:
                stale_runner_heartbeats += 1
            if parsed is not None:
                heartbeat_ages.append(max(0, int((now_dt - parsed).total_seconds())))

        queue_times: list[datetime] = []
        for table in ("intelligence_jobs", "coordinator_commands"):
            for row in connection.execute(f"SELECT queued_at FROM {table} WHERE status IN ('queued','running')").fetchall():
                parsed = parse_timestamp(row["queued_at"])
                if parsed is not None:
                    queue_times.append(parsed)
        queue_age_seconds = max(0, int((now_dt - min(queue_times)).total_seconds())) if queue_times else 0
        open_conflicts = int(connection.execute("SELECT COUNT(*) FROM ontology_conflicts WHERE status = 'open'").fetchone()[0])
        change_count = int(connection.execute("SELECT COUNT(*) FROM ontology_change_log").fetchone()[0])
        duplicate_candidates = int(connection.execute("SELECT COUNT(*) FROM ontology_conflicts WHERE status = 'open' AND conflict_type IN ('duplicate_alias','duplicate_identity','duplicate_entity','duplicate')").fetchone()[0])
        contradictory_relationships = int(connection.execute("SELECT COUNT(*) FROM ontology_conflicts WHERE status = 'open' AND conflict_type IN ('source_contradiction','contradictory_relationship','contradiction')").fetchone()[0])
        by_type = {str(row["entity_type"]): int(row["count"]) for row in connection.execute(f"SELECT entity_type, COUNT(*) AS count FROM ontology_entities {entity_clause} GROUP BY entity_type", entity_params).fetchall()}

        # These ratios are intentionally unmeasured when their denominator is
        # empty.  Returning 100% for an empty review/action set falsely turns
        # missing telemetry into a success signal.
        allowed_finding_ids: set[str] | None = None
        if workspace:
            allowed_finding_ids = set()
            for row in entity_rows:
                if row["entity_type"] == "finding":
                    allowed_finding_ids.add(str(row["source_id"] or ""))
                    allowed_finding_ids.add(str(row["canonical_key"] or ""))
                    allowed_finding_ids.add(str(row["entity_id"] or ""))
        finding_rows = connection.execute("SELECT finding_id, disposition FROM findings").fetchall()
        if allowed_finding_ids is not None:
            finding_rows = [row for row in finding_rows if str(row["finding_id"]) in allowed_finding_ids]
        reviewed_dispositions = {"false_positive", "expected_behavior", "tune_policy", "true_positive", "remediated"}
        reviewed_rows = [row for row in finding_rows if str(row["disposition"] or "").strip().lower() in reviewed_dispositions]
        false_positive_rows = [row for row in reviewed_rows if str(row["disposition"] or "").strip().lower() in {"false_positive", "expected_behavior", "tune_policy"}]
        false_positive_rate = (len(false_positive_rows) / len(reviewed_rows)) if reviewed_rows else None

        triage_rows = connection.execute("SELECT run_id, target_id, status, recommendation_json, decision_json FROM agent_triage_runs").fetchall()
        if allowed_finding_ids is not None:
            triage_rows = [row for row in triage_rows if str(row["target_id"] or "") in allowed_finding_ids]
        terminal_triage = [row for row in triage_rows if str(row["status"] or "") in {"applied", "recommended", "escalated", "rolled_back"}]
        complete_with_evidence = 0
        for row in terminal_triage:
            decision = _loads(row["decision_json"])
            recommendation = _loads(row["recommendation_json"])
            refs = decision.get("validated_evidence_refs") if isinstance(decision, dict) else None
            refs = refs or (recommendation.get("decision_evidence_refs") if isinstance(recommendation, dict) else None)
            if isinstance(refs, list) and any(str(item).strip() for item in refs):
                complete_with_evidence += 1
        ai_evidence_completeness = (complete_with_evidence / len(terminal_triage) * 100) if terminal_triage else None
        recommendation_terminal = [row for row in terminal_triage if str(row["status"] or "") in {"applied", "recommended", "escalated", "rolled_back"}]
        recommendation_accepted = sum(str(row["status"] or "") in {"applied", "escalated", "rolled_back"} for row in recommendation_terminal)
        recommendation_acceptance = (recommendation_accepted / len(recommendation_terminal)) if recommendation_terminal else None
        action_rows = [row for row in entity_rows if row["entity_type"] == "remediation_action"]
        action_completed = sum(str(row["status"] or "").lower() in {"completed", "succeeded", "closed", "applied", "done"} for row in action_rows)
        action_completion = (action_completed / len(action_rows)) if action_rows else None
        rollback_rows = [row for row in triage_rows if str(row["status"] or "") in {"applied", "escalated", "rolled_back"}]
        action_rollback = (sum(str(row["status"] or "") == "rolled_back" for row in rollback_rows) / len(rollback_rows)) if rollback_rows else None

        entities = len(entity_rows)
        evidence = len(evidence_rows)
        finding_total = len(finding_ids)
        linked_findings = len(linked_finding_ids)
    quality_alerts: list[dict[str, Any]] = []
    if stale_runner_heartbeats:
        quality_alerts.append({"code": "stale_runner_heartbeat", "count": stale_runner_heartbeats, "threshold": 0})
    if queue_age_seconds > 3600:
        quality_alerts.append({"code": "queue_age_high", "seconds": queue_age_seconds, "threshold": 3600})
    if orphan_entities or orphan_relationships:
        quality_alerts.append({"code": "orphaned_graph_records", "entities": orphan_entities, "relationships": orphan_relationships, "threshold": 0})
    if relationships and (with_provenance / relationships) < 0.9:
        quality_alerts.append({"code": "provenance_coverage_low", "percent": round((with_provenance / relationships) * 100, 2), "threshold": 90})
    heartbeat_freshness_seconds = min(heartbeat_ages) if heartbeat_ages else None
    heartbeat_measurement_status = "unknown" if heartbeat_freshness_seconds is None else ("stale" if stale_runner_heartbeats else "fresh")
    return {
        "schema_version": SCHEMA_VERSION,
        "workspace_id": workspace or "all",
        "database_present": True,
        "entities": entities,
        "relationships": relationships,
        "evidence_references": evidence,
        "relationships_with_provenance": with_provenance,
        "relationships_with_evidence": relationships_with_evidence,
        "provenance_coverage_percent": round((with_provenance / relationships) * 100, 2) if relationships else None,
        "evidence_with_valid_locator": evidence_with_locator,
        "orphan_relationships": orphan_relationships,
        "orphan_entities": orphan_entities,
        "stale_entities": stale_entities,
        "stale_after_seconds": stale_after,
        "canonical_id_coverage_percent": round((canonical_id_count / entities) * 100, 2) if entities else None,
        "graph_coverage_percent": round((len(connected_ids) / entities) * 100, 2) if entities else None,
        "stale_sources": len(stale_source_names),
        "duplicate_candidates": duplicate_candidates,
        "contradictory_relationships": contradictory_relationships,
        "findings_total": finding_total,
        "findings_linked_percent": round((linked_findings / finding_total) * 100, 2) if finding_total else None,
        "open_conflicts": open_conflicts,
        "change_history_records": change_count,
        "queue_age_seconds": queue_age_seconds,
        "stale_runner_heartbeats": stale_runner_heartbeats,
        "heartbeat_freshness_seconds": heartbeat_freshness_seconds,
        "heartbeat_measurement_status": heartbeat_measurement_status,
        "ai_evidence_completeness_percent": round(ai_evidence_completeness, 2) if ai_evidence_completeness is not None else None,
        "false_positive_rate": round(false_positive_rate, 6) if false_positive_rate is not None else None,
        "recommendation_acceptance_rate": round(recommendation_acceptance, 6) if recommendation_acceptance is not None else None,
        "action_completion_rate": round(action_completion, 6) if action_completion is not None else None,
        "action_rollback_rate": round(action_rollback, 6) if action_rollback is not None else None,
        "quality_alerts": quality_alerts,
        "entities_by_type": by_type,
    }


def export_snapshot(*, db_path: str | None = None, since: str | None = None, limit: int = 200) -> dict[str, Any]:
    """Export a bounded redacted snapshot for the hosted bridge."""
    bounded = _limit(limit, 200)
    with _ontology_read_connection(db_path, _ONTOLOGY_EXPORT_READ_TABLES) as connection:
        if connection is None:
            return {
                "schema_version": SCHEMA_VERSION,
                "exported_at": utc_now(),
                "entities": [],
                "relationships": [],
                "evidence_refs": [],
                "events": [],
            }
        if since:
            entity_rows = connection.execute("SELECT * FROM ontology_entities WHERE updated_at > ? ORDER BY updated_at ASC LIMIT ?", (_text(since, 64), bounded)).fetchall()
            relation_rows = connection.execute("SELECT * FROM ontology_relationships WHERE updated_at > ? ORDER BY updated_at ASC LIMIT ?", (_text(since, 64), bounded * 2)).fetchall()
            event_rows = connection.execute("SELECT event_id, entity_id, event_type, source, source_record_id, summary_json, occurred_at FROM ontology_events WHERE created_at > ? ORDER BY created_at ASC LIMIT ?", (_text(since, 64), bounded * 2)).fetchall()
        else:
            entity_rows = connection.execute("SELECT * FROM ontology_entities ORDER BY updated_at DESC LIMIT ?", (bounded,)).fetchall()
            relation_rows = connection.execute("SELECT * FROM ontology_relationships ORDER BY updated_at DESC LIMIT ?", (bounded * 2,)).fetchall()
            event_rows = connection.execute("SELECT event_id, entity_id, event_type, source, source_record_id, summary_json, occurred_at FROM ontology_events ORDER BY created_at DESC LIMIT ?", (bounded * 2,)).fetchall()
        evidence_rows = connection.execute("SELECT evidence_ref_id, source, locator, content_hash, content_type, workspace_id, summary_json, observed_at FROM ontology_evidence_refs ORDER BY updated_at DESC LIMIT ?", (bounded,)).fetchall()
        # Close the bounded projection over its foreign-key dependencies.  A
        # recent relationship may point at an older endpoint that did not fit
        # the entity window; include that endpoint rather than exporting an
        # edge which a hosted consumer cannot resolve.
        entity_by_id = {str(row["entity_id"]): row for row in entity_rows}
        dependency_ids = {
            str(row[field])
            for row in relation_rows
            for field in ("from_entity_id", "to_entity_id")
            if row[field]
        }
        dependency_ids.update(str(row["entity_id"]) for row in event_rows if row["entity_id"])
        missing_entity_ids = [item for item in dependency_ids if item not in entity_by_id]
        if missing_entity_ids:
            placeholders = ",".join("?" for _ in missing_entity_ids)
            for row in connection.execute(f"SELECT * FROM ontology_entities WHERE entity_id IN ({placeholders})", missing_entity_ids).fetchall():
                entity_by_id[str(row["entity_id"])] = row
        entity_rows = [*entity_rows, *[entity_by_id[item] for item in sorted(entity_by_id) if item not in {str(row["entity_id"]) for row in entity_rows}]]
        entity_ids = set(entity_by_id)
        # Foreign keys normally guarantee these rows exist, but retain the
        # defensive filter for legacy stores with orphaned records.
        relation_rows = [row for row in relation_rows if str(row["from_entity_id"]) in entity_ids and str(row["to_entity_id"]) in entity_ids]
        event_rows = [row for row in event_rows if str(row["entity_id"]) in entity_ids]

        # Evidence references are another dependency of relationships.  The
        # initial bounded evidence window may omit a referenced ref, so fetch
        # those IDs explicitly and union them with the ordinary recent rows.
        evidence_by_id = {str(row["evidence_ref_id"]): row for row in evidence_rows}
        referenced_evidence = {str(row["evidence_ref_id"]) for row in relation_rows if row["evidence_ref_id"]}
        missing_evidence_ids = [item for item in referenced_evidence if item not in evidence_by_id]
        if missing_evidence_ids:
            placeholders = ",".join("?" for _ in missing_evidence_ids)
            for row in connection.execute(
                f"SELECT evidence_ref_id, source, locator, content_hash, content_type, workspace_id, summary_json, observed_at FROM ontology_evidence_refs WHERE evidence_ref_id IN ({placeholders})",
                missing_evidence_ids,
            ).fetchall():
                evidence_by_id[str(row["evidence_ref_id"])] = row
        evidence_rows = list(evidence_by_id.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "exported_at": utc_now(),
        "entities": [_entity_row(row) for row in entity_rows],
        "relationships": [_relationship_row(row) for row in relation_rows],
        "evidence_refs": [{"evidence_ref_id": str(row["evidence_ref_id"]), "source": str(row["source"]), "locator": str(row["locator"]), "content_hash": str(row["content_hash"] or ""), "content_type": str(row["content_type"] or ""), "workspace_id": str(row["workspace_id"] or "local"), "summary": _loads(row["summary_json"]), "observed_at": str(row["observed_at"])} for row in evidence_rows],
        "events": [{"event_id": str(row["event_id"]), "entity_id": str(row["entity_id"]), "event_type": str(row["event_type"]), "source": str(row["source"]), "source_record_id": str(row["source_record_id"] or ""), "summary": _loads(row["summary_json"]), "occurred_at": str(row["occurred_at"])} for row in event_rows],
    }


def materialize_recent(*, db_path: str | None = None, limit: int = 100) -> dict[str, Any]:
    """Project recent records into a bounded semantic snapshot.

    This is intentionally bounded so the always-on research worker can call it
    after a cycle without scanning or copying the full historical ledger.  The
    projection includes the records most likely to change during a surveillance
    cycle (registry releases, alerts, findings, cases, subjects, artifacts,
    evidence, IOCs, candidates, jobs, and automation runs); complete history is
    still handled by :func:`backfill_existing`.
    """
    soc_store.init_db(db_path)
    bound = max(1, min(int(limit), 500))
    entities: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    evidence_refs: list[dict[str, Any]] = []
    graph_reference_by_node_id: dict[str, str] = {}
    with soc_store.read_connect(db_path) as connection:
        for row in connection.execute("SELECT node_id, node_type, label, source, source_id, properties_json, first_seen, last_seen FROM asset_graph_nodes ORDER BY updated_at DESC LIMIT ?", (bound,)).fetchall():
            node_type = str(row["node_type"] or "asset")
            mapped_type = node_type if node_type in ENTITY_TYPES else ("asset" if node_type in {"site", "wifi_network"} else "source")
            source_id = str(row["source_id"] or row["node_id"])
            node_id = str(row["node_id"])
            legacy_item = _legacy_entity(mapped_type, str(row["source"] or "edge"), node_id, str(row["label"] or source_id), _loads(row["properties_json"]), str(row["first_seen"]), str(row["last_seen"]))
            legacy_item["source_id"] = source_id
            legacy_item["aliases"] = _legacy_alias(node_id, str(row["source"] or "edge"))
            # Keep edge endpoints aligned with the exact typed identity used
            # for the node above.  Falling back to a generic asset ID for a
            # service, sensor, or repository causes sync_payload to discard
            # the otherwise valid relationship because its endpoint is not in
            # the entity batch.
            graph_reference_by_node_id[node_id] = str(legacy_item["entity_id"])
            entities.append(legacy_item)
        for row in connection.execute("SELECT edge_id, edge_type, from_node_id, to_node_id, source, properties_json, first_seen, last_seen FROM asset_graph_edges ORDER BY updated_at DESC LIMIT ?", (bound * 2,)).fetchall():
            relation = LEGACY_EDGE_RELATIONS.get(str(row["edge_type"] or ""))
            if relation:
                from_node_id = _text(row["from_node_id"], 512)
                to_node_id = _text(row["to_node_id"], 512)
                relationships.append({"relationship_id": str(row["edge_id"]), "relationship_type": relation, "from_entity_id": graph_reference_by_node_id.get(from_node_id, _stable_graph_reference(from_node_id)), "to_entity_id": graph_reference_by_node_id.get(to_node_id, _stable_graph_reference(to_node_id)), "source": str(row["source"] or "edge"), "source_record_id": str(row["edge_id"]), "properties": _loads(row["properties_json"]), "observed_at": str(row["last_seen"]), "valid_from": str(row["first_seen"]), "freshness_at": str(row["last_seen"])})
        for row in connection.execute("SELECT feed_event_id, collector_id, ecosystem, package, version, event_type, registry_timestamp, page_url, leaf_url, metadata_json, collected_at FROM registry_feed_events ORDER BY collected_at DESC LIMIT ?", (bound,)).fetchall():
            ecosystem = _text(row["ecosystem"], 120).lower() or "unknown"
            package = _text(row["package"], 512)
            version = _text(row["version"], 256)
            if not package:
                continue
            package_id = canonical_entity_id("package", ecosystem, package)
            entities.append({"entity_id": package_id, "entity_type": "package", "namespace": ecosystem, "canonical_key": package, "display_name": package, "source": "registry", "source_id": package, "properties": {"ecosystem": ecosystem}, "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"]})
            if version:
                version_key = f"{package}@{version}"
                version_id = canonical_entity_id("package_version", ecosystem, version_key)
                release_event_id = canonical_entity_id("release_event", "registry", row["feed_event_id"])
                source_id = _text(row["collector_id"], 160) or "registry"
                source_entity_id = canonical_entity_id("source", "registry", source_id)
                entities.append({"entity_id": version_id, "entity_type": "package_version", "namespace": ecosystem, "canonical_key": version_key, "display_name": version_key, "source": "registry", "source_id": row["feed_event_id"], "properties": {"ecosystem": ecosystem, "event_type": row["event_type"]}, "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"]})
                entities.append({"entity_id": release_event_id, "entity_type": "release_event", "namespace": "registry", "canonical_key": row["feed_event_id"], "display_name": f"{package}@{version}", "source": "registry", "source_id": row["feed_event_id"], "properties": {"event_type": row["event_type"], "collector_id": source_id, "page_url": sanitize_locator(row["page_url"])}, "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"]})
                entities.append({"entity_id": source_entity_id, "entity_type": "source", "namespace": "registry", "canonical_key": source_id, "display_name": source_id, "source": "registry", "source_id": source_id, "properties": {"collector_id": source_id}, "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"]})
                relationships.append({"relationship_id": f"rel:package-version:{ecosystem}:{package}:{version}", "relationship_type": "PACKAGE_HAS_VERSION", "from_entity_id": package_id, "to_entity_id": version_id, "source": "registry", "source_record_id": row["feed_event_id"], "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"], "properties": {"event_type": row["event_type"]}})
                relationships.append({"relationship_id": f"rel:release:{row['feed_event_id']}", "relationship_type": "VERSION_RELEASED_IN", "from_entity_id": version_id, "to_entity_id": release_event_id, "source": "registry", "source_record_id": row["feed_event_id"], "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"], "properties": {"event_type": row["event_type"], "page_url": sanitize_locator(row["page_url"])}})
                relationships.append({"relationship_id": f"rel:release-source:{row['feed_event_id']}", "relationship_type": "RELEASE_EVENT_FROM_SOURCE", "from_entity_id": release_event_id, "to_entity_id": source_entity_id, "source": "registry", "source_record_id": row["feed_event_id"], "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"], "properties": {"collector_id": source_id}})
                metadata = _loads(row["metadata_json"])
                artifact_hash = _text(metadata.get("artifact_sha256") or metadata.get("sha256"), 128)
                if artifact_hash:
                    artifact_id = canonical_entity_id("artifact", "sha256", artifact_hash)
                    entities.append({"entity_id": artifact_id, "entity_type": "artifact", "namespace": "sha256", "canonical_key": artifact_hash, "display_name": artifact_hash, "source": "registry", "source_id": row["feed_event_id"], "properties": {"sha256": artifact_hash, "artifact_url": sanitize_locator(metadata.get("artifact_url"))}, "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"]})
                    relationships.append({"relationship_id": f"rel:release-artifact:{row['feed_event_id']}", "relationship_type": "VERSION_HAS_ARTIFACT", "from_entity_id": version_id, "to_entity_id": artifact_id, "source": "registry", "source_record_id": row["feed_event_id"], "observed_at": row["registry_timestamp"], "freshness_at": row["collected_at"], "properties": {"sha256": artifact_hash}})
                events.append({"event_id": f"event:release:{row['feed_event_id']}", "entity_id": version_id, "event_type": row["event_type"] or "release_observed", "source": "registry", "source_record_id": row["feed_event_id"], "occurred_at": row["registry_timestamp"], "summary": {"package": package, "version": version, "leaf_url": row["leaf_url"]}})
        # The durable research registry table is populated by collectors that
        # have not yet emitted a normalized ``registry_feed_events`` row.  It
        # is projected here as the same package/version/release/source shape so
        # hosted Mission Control remains current between full backfills.
        for row in connection.execute("SELECT event_id, source_id, ecosystem, package, version, publisher, source_url, artifact_url, artifact_sha256, observed_at, provenance_json FROM research_registry_events ORDER BY observed_at DESC LIMIT ?", (bound,)).fetchall():
            ecosystem = _text(row["ecosystem"], 120).lower() or "unknown"
            package = _text(row["package"], 512)
            version = _text(row["version"], 256)
            event_id_raw = _text(row["event_id"], 256)
            if not package or not event_id_raw:
                continue
            package_id = canonical_entity_id("package", ecosystem, package)
            version_id = canonical_entity_id("package_version", ecosystem, f"{package}@{version}") if version else ""
            release_event_id = canonical_entity_id("release_event", "registry", event_id_raw)
            source_id = _text(row["source_id"], 160) or "registry"
            source_entity_id = canonical_entity_id("source", "registry", source_id)
            entities.extend([
                {"entity_id": package_id, "entity_type": "package", "namespace": ecosystem, "canonical_key": package, "display_name": package, "source": "registry", "source_id": source_id, "properties": {"ecosystem": ecosystem}, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]},
                {"entity_id": release_event_id, "entity_type": "release_event", "namespace": "registry", "canonical_key": event_id_raw, "display_name": f"{package}@{version}".strip("@"), "source": "registry", "source_id": event_id_raw, "properties": {"ecosystem": ecosystem, "package": package, "version": version, "publisher": row["publisher"], "source_url": sanitize_locator(row["source_url"]), "artifact_url": sanitize_locator(row["artifact_url"]), "artifact_sha256": row["artifact_sha256"], "provenance_summary": _loads(row["provenance_json"])}, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]},
                {"entity_id": source_entity_id, "entity_type": "source", "namespace": "registry", "canonical_key": source_id, "display_name": source_id, "source": "registry", "source_id": source_id, "properties": {"ecosystem": ecosystem}, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]},
            ])
            if version_id:
                entities.append({"entity_id": version_id, "entity_type": "package_version", "namespace": ecosystem, "canonical_key": f"{package}@{version}", "display_name": f"{package}@{version}", "source": "registry", "source_id": event_id_raw, "properties": {"ecosystem": ecosystem}, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]})
                relationships.extend([
                    {"relationship_type": "PACKAGE_HAS_VERSION", "from_entity_id": package_id, "to_entity_id": version_id, "source": "registry", "source_record_id": event_id_raw, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]},
                    {"relationship_type": "VERSION_RELEASED_IN", "from_entity_id": version_id, "to_entity_id": release_event_id, "source": "registry", "source_record_id": event_id_raw, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]},
                ])
                artifact_hash = _text(row["artifact_sha256"], 128)
                if artifact_hash:
                    artifact_id = canonical_entity_id("artifact", "sha256", artifact_hash)
                    entities.append({"entity_id": artifact_id, "entity_type": "artifact", "namespace": "sha256", "canonical_key": artifact_hash, "display_name": artifact_hash, "source": "registry", "source_id": event_id_raw, "properties": {"sha256": artifact_hash, "artifact_url": sanitize_locator(row["artifact_url"])}, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]})
                    relationships.append({"relationship_type": "VERSION_HAS_ARTIFACT", "from_entity_id": version_id, "to_entity_id": artifact_id, "source": "registry", "source_record_id": event_id_raw, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]})
                relationships.append({"relationship_type": "RELEASE_EVENT_FROM_SOURCE", "from_entity_id": release_event_id, "to_entity_id": source_entity_id, "source": "registry", "source_record_id": event_id_raw, "observed_at": row["observed_at"], "freshness_at": row["observed_at"]})
                events.append({"event_id": f"event:release:{event_id_raw}", "entity_id": version_id, "event_type": "release_observed", "source": "registry", "source_record_id": event_id_raw, "occurred_at": row["observed_at"], "summary": {"package": package, "version": version}})
        for row in connection.execute("SELECT alert_id, alert_type, severity, candidate_id, case_id, status, reason, created_at, updated_at, evidence_json FROM research_alerts ORDER BY updated_at DESC LIMIT ?", (bound,)).fetchall():
            raw_alert_id = str(row["alert_id"])
            alert_id = _stable_legacy_id("alert", "secopsai", raw_alert_id)
            entities.append({"entity_id": alert_id, "entity_type": "alert", "namespace": "secopsai", "canonical_key": raw_alert_id, "display_name": str(row["alert_type"]), "source": "secopsai-research", "source_id": raw_alert_id, "aliases": _legacy_alias(raw_alert_id, "secopsai-research"), "status": row["status"], "properties": {"alert_type": row["alert_type"], "severity": row["severity"], "reason": row["reason"], "candidate_id": row["candidate_id"], "case_id": row["case_id"], "evidence_summary": _loads(row["evidence_json"])}, "first_seen_at": row["created_at"], "last_seen_at": row["updated_at"], "observed_at": row["updated_at"], "freshness_at": row["updated_at"]})
            events.append({"event_id": f"event:alert:{raw_alert_id}", "entity_id": alert_id, "event_type": "alert_observed", "source": "secopsai-research", "source_record_id": raw_alert_id, "occurred_at": row["updated_at"], "summary": {"alert_type": row["alert_type"], "severity": row["severity"], "status": row["status"]}})
            if row["case_id"]:
                case_id = _stable_legacy_id("research_case", "secopsai", str(row["case_id"]))
                relationships.append({"relationship_type": "CASE_GROUPS_ALERT", "from_entity_id": case_id, "to_entity_id": alert_id, "source": "secopsai-research", "source_record_id": raw_alert_id, "observed_at": row["updated_at"], "properties": {"relation": "alert_case"}})
            if row["candidate_id"]:
                candidate_raw = str(row["candidate_id"])
                candidate_id = _stable_legacy_id("candidate", "secopsai", candidate_raw)
                entities.append({"entity_id": candidate_id, "entity_type": "candidate", "namespace": "secopsai", "canonical_key": candidate_raw, "display_name": candidate_raw, "source": "secopsai-research", "source_id": candidate_raw, "aliases": _legacy_alias(candidate_raw, "secopsai-research"), "properties": {"alert_id": raw_alert_id}, "observed_at": row["updated_at"], "freshness_at": row["updated_at"]})
                events.append({"event_id": f"event:candidate:{candidate_raw}", "entity_id": candidate_id, "event_type": "candidate_observed", "source": "secopsai-research", "source_record_id": candidate_raw, "occurred_at": row["updated_at"], "summary": {"alert_id": raw_alert_id}})
        for row in connection.execute("SELECT finding_id, title, severity, severity_score, status, source, first_seen, last_seen, updated_at, payload_json FROM findings ORDER BY updated_at DESC LIMIT ?", (bound,)).fetchall():
            raw_finding_id = str(row["finding_id"])
            finding_id = _stable_legacy_id("finding", "secopsai", raw_finding_id)
            payload = _loads(row["payload_json"])
            entities.append({"entity_id": finding_id, "entity_type": "finding", "namespace": "secopsai", "canonical_key": raw_finding_id, "display_name": row["title"], "source": row["source"], "source_id": raw_finding_id, "aliases": _legacy_alias(raw_finding_id, str(row["source"] or "legacy")), "status": row["status"], "properties": {"severity": row["severity"], "severity_score": row["severity_score"], "payload_summary": payload}, "first_seen_at": row["first_seen"], "last_seen_at": row["last_seen"], "observed_at": row["last_seen"], "freshness_at": row["updated_at"]})
            events.append({"event_id": f"event:finding:{raw_finding_id}", "entity_id": finding_id, "event_type": "finding_observed", "source": str(row["source"] or "secopsai"), "source_record_id": raw_finding_id, "occurred_at": row["updated_at"], "summary": {"severity": row["severity"], "status": row["status"], "title": _text(row["title"], 240)}})
            ecosystem = _text(payload.get("ecosystem") or payload.get("package_ecosystem"), 120).lower()
            package = _text(payload.get("package") or payload.get("package_name"), 512)
            version = _text(payload.get("new_version") or payload.get("version"), 256)
            if ecosystem and package:
                package_id = canonical_entity_id("package", ecosystem, package)
                entities.append({"entity_id": package_id, "entity_type": "package", "namespace": ecosystem, "canonical_key": package, "display_name": package, "source": "finding", "source_id": finding_id, "properties": {"ecosystem": ecosystem}, "observed_at": row["last_seen"], "freshness_at": row["updated_at"]})
                if version:
                    version_key = f"{package}@{version}"
                    version_id = canonical_entity_id("package_version", ecosystem, version_key)
                    entities.append({"entity_id": version_id, "entity_type": "package_version", "namespace": ecosystem, "canonical_key": version_key, "display_name": version_key, "source": "finding", "source_id": finding_id, "properties": {"ecosystem": ecosystem}, "observed_at": row["last_seen"], "freshness_at": row["updated_at"]})
                    relationships.append({"relationship_type": "FINDING_ON_VERSION", "from_entity_id": finding_id, "to_entity_id": version_id, "source": "finding", "source_record_id": finding_id, "observed_at": row["last_seen"], "properties": {"severity": row["severity"]}})
                    advisory_key = _text(payload.get("advisory_id") or payload.get("cve") or payload.get("vulnerability_id"), 256)
                    if advisory_key:
                        advisory_type = "vulnerability" if advisory_key.upper().startswith(("CVE-", "GHSA-", "OSV-")) else "advisory"
                        advisory_id = canonical_entity_id(advisory_type, _text(payload.get("advisory_source") or "advisory", 120), advisory_key)
                        entities.append({"entity_id": advisory_id, "entity_type": advisory_type, "namespace": _text(payload.get("advisory_source") or "advisory", 120), "canonical_key": advisory_key, "display_name": advisory_key, "source": "finding", "source_id": finding_id, "properties": {"severity": row["severity"]}, "observed_at": row["last_seen"], "freshness_at": row["updated_at"]})
                        relationships.append({"relationship_type": "VERSION_AFFECTED_BY_ADVISORY", "from_entity_id": version_id, "to_entity_id": advisory_id, "source": "finding", "source_record_id": finding_id, "observed_at": row["last_seen"], "properties": {"severity": row["severity"]}})
                    artifact_hash = _text(payload.get("artifact_sha256") or payload.get("sha256") or payload.get("artifact_hash"), 128)
                    if artifact_hash:
                        artifact_id = canonical_entity_id("artifact", "sha256", artifact_hash)
                        entities.append({"entity_id": artifact_id, "entity_type": "artifact", "namespace": "sha256", "canonical_key": artifact_hash, "display_name": artifact_hash, "source": "finding", "source_id": finding_id, "properties": {"sha256": artifact_hash}, "observed_at": row["last_seen"], "freshness_at": row["updated_at"]})
                        relationships.append({"relationship_type": "VERSION_HAS_ARTIFACT", "from_entity_id": version_id, "to_entity_id": artifact_id, "source": "finding", "source_record_id": finding_id, "observed_at": row["last_seen"], "properties": {"sha256": artifact_hash}})
            asset_ref = _text(payload.get("asset_node_id") or payload.get("asset_id"), 512)
            if asset_ref:
                asset_id = _stable_legacy_id("asset", "legacy", asset_ref)
                if ":" not in asset_ref:
                    entities.append({"entity_id": asset_id, "entity_type": "asset", "namespace": "legacy", "canonical_key": asset_ref, "display_name": asset_ref, "source": "finding", "source_id": asset_ref, "aliases": _legacy_alias(asset_ref, "finding"), "observed_at": row["last_seen"], "freshness_at": row["updated_at"]})
                relationships.append({"relationship_type": "FINDING_ON_ASSET", "from_entity_id": finding_id, "to_entity_id": asset_id, "source": "finding", "source_record_id": finding_id, "observed_at": row["last_seen"], "properties": {"severity": row["severity"]}})
        for row in connection.execute("SELECT case_id, title, summary, case_type, severity, confidence, status, owner, created_at, updated_at, payload_json FROM research_cases ORDER BY updated_at DESC LIMIT ?", (bound,)).fetchall():
            raw_case_id = str(row["case_id"])
            case_id = _stable_legacy_id("research_case", "secopsai", raw_case_id)
            entities.append({"entity_id": case_id, "entity_type": "research_case", "namespace": "secopsai", "canonical_key": raw_case_id, "display_name": row["title"], "source": "secopsai-research", "source_id": raw_case_id, "aliases": _legacy_alias(raw_case_id, "secopsai-research"), "owner_id": row["owner"], "status": row["status"], "confidence": row["confidence"], "properties": {"summary": row["summary"], "case_type": row["case_type"], "severity": row["severity"], "payload_summary": _loads(row["payload_json"])}, "first_seen_at": row["created_at"], "last_seen_at": row["updated_at"], "observed_at": row["updated_at"], "freshness_at": row["updated_at"]})
            events.append({"event_id": f"event:case:{raw_case_id}", "entity_id": case_id, "event_type": "case_observed", "source": "secopsai-research", "source_record_id": raw_case_id, "occurred_at": row["updated_at"], "summary": {"case_type": row["case_type"], "severity": row["severity"], "status": row["status"]}})
            for finding in connection.execute("SELECT finding_id, relationship FROM research_case_findings WHERE case_id = ?", (raw_case_id,)).fetchall():
                raw_finding_id = str(finding["finding_id"])
                relationships.append({"relationship_type": "CASE_GROUPS_FINDING", "from_entity_id": case_id, "to_entity_id": _stable_legacy_id("finding", "secopsai", raw_finding_id), "source": "secopsai-research", "source_record_id": f"{raw_case_id}:{raw_finding_id}", "observed_at": row["updated_at"], "properties": {"relationship": finding["relationship"]}})

        # Recent case-owned records keep the hosted graph useful between full
        # backfills.  These queries use creation/observation timestamps and a
        # strict bound; raw package content is never selected.
        subject_rows = connection.execute(
            "SELECT subject_id, case_id, subject_type, ecosystem, name, version, publisher, status, metadata_json, created_at FROM research_subjects ORDER BY COALESCE(state_checked_at, created_at) DESC LIMIT ?",
            (bound,),
        ).fetchall()
        for row in subject_rows:
            subject_type = normalize_value(row["subject_type"], limit=80)
            ecosystem = normalize_value(row["ecosystem"] or "research", limit=120) or "research"
            name = _text(row["name"] or row["subject_id"], 512)
            version = _text(row["version"], 256)
            if subject_type in {"package", "library", "module", "dependency"}:
                entity_type = "package_version" if version else "package"
                key = f"{name}@{version}" if version else name
            elif subject_type in {"repository", "repo"}:
                entity_type, key = "repository", name
            elif subject_type in {"asset", "service", "sensor", "network"}:
                entity_type, key = subject_type, name
            else:
                entity_type, ecosystem, key = "source", "research", f"subject:{row['subject_id']}"
            try:
                subject_id = canonical_entity_id(entity_type, ecosystem, key)
            except ValueError:
                continue
            observed = _text(row["created_at"], 64) or utc_now()
            entities.append({"entity_id": subject_id, "entity_type": entity_type, "namespace": ecosystem, "canonical_key": key, "display_name": f"{name}@{version}" if version else name, "source": "secopsai-research", "source_id": row["subject_id"], "properties": {"subject_id": row["subject_id"], "case_id": row["case_id"], "subject_type": subject_type, "publisher": row["publisher"], "metadata_summary": _loads(row["metadata_json"])}, "observed_at": observed, "freshness_at": observed})
            events.append({"event_id": f"event:subject:{row['subject_id']}", "entity_id": subject_id, "event_type": "subject_observed", "source": "secopsai-research", "source_record_id": row["subject_id"], "occurred_at": observed, "summary": {"subject_type": subject_type, "case_id": row["case_id"]}})
            if row["case_id"]:
                relationships.append({"relationship_type": "CASE_HAS_SUBJECT", "from_entity_id": _stable_legacy_id("research_case", "secopsai", row["case_id"]), "to_entity_id": subject_id, "source": "secopsai-research", "source_record_id": f"{row['case_id']}:{row['subject_id']}", "observed_at": observed})

        evidence_rows = connection.execute(
            "SELECT evidence_id, case_id, evidence_type, title, locator, sha256, provenance, notes, status, collected_at, created_at, metadata_json FROM research_evidence ORDER BY COALESCE(last_observed_at, collected_at, created_at) DESC LIMIT ?",
            (bound,),
        ).fetchall()
        for row in evidence_rows:
            raw_id = _text(row["evidence_id"], 256)
            case_id = _text(row["case_id"], 256)
            if not raw_id:
                continue
            locator = sanitize_locator(row["locator"])
            evidence_entity_id = canonical_entity_id("evidence", "secopsai", f"{case_id}:{raw_id}")
            evidence_ref_id = "eref:" + hashlib.sha256(f"research|{raw_id}|{locator}|{row['sha256'] or ''}".encode()).hexdigest()[:40]
            observed = _text(row["collected_at"] or row["created_at"], 64) or utc_now()
            entities.append({"entity_id": evidence_entity_id, "entity_type": "evidence", "namespace": "secopsai", "canonical_key": f"{case_id}:{raw_id}", "display_name": _text(row["title"] or row["evidence_type"] or raw_id, 512), "source": "secopsai-research", "source_id": raw_id, "properties": {"case_id": case_id, "evidence_type": row["evidence_type"], "locator": locator, "sha256": row["sha256"], "provenance": row["provenance"], "notes": row["notes"], "metadata_summary": _loads(row["metadata_json"])}, "status": row["status"], "observed_at": observed, "freshness_at": observed})
            events.append({"event_id": f"event:evidence:{case_id}:{raw_id}", "entity_id": evidence_entity_id, "event_type": "evidence_observed", "source": "secopsai-research", "source_record_id": raw_id, "occurred_at": observed, "summary": {"case_id": case_id, "evidence_type": row["evidence_type"], "status": row["status"]}})
            if locator:
                evidence_refs.append({"evidence_ref_id": evidence_ref_id, "source": "secopsai-research", "locator": locator, "content_hash": _text(row["sha256"], 128), "content_type": _text(row["evidence_type"], 120), "workspace_id": "local", "summary": {"evidence_id": raw_id, "case_id": case_id, "title": row["title"], "provenance": row["provenance"], "status": row["status"]}, "observed_at": observed})
                relationships.append({"relationship_type": "CASE_SUPPORTED_BY_EVIDENCE", "from_entity_id": _stable_legacy_id("research_case", "secopsai", case_id), "to_entity_id": evidence_entity_id, "source": "secopsai-research", "source_record_id": f"{case_id}:{raw_id}", "evidence_ref_id": evidence_ref_id, "observed_at": observed})

        for row in connection.execute("SELECT candidate_id, ecosystem, package, version, status, case_id, last_seen FROM research_candidates ORDER BY last_seen DESC LIMIT ?", (bound,)).fetchall():
            raw_id = _text(row["candidate_id"], 256)
            if not raw_id:
                continue
            candidate_id = _stable_legacy_id("candidate", "secopsai", raw_id)
            entities.append({"entity_id": candidate_id, "entity_type": "candidate", "namespace": "secopsai", "canonical_key": raw_id, "display_name": f"{_text(row['package'], 240)}@{_text(row['version'], 120)}".strip("@"), "source": "secopsai-research", "source_id": raw_id, "status": row["status"], "properties": {"ecosystem": row["ecosystem"], "package": row["package"], "version": row["version"]}, "observed_at": row["last_seen"], "freshness_at": row["last_seen"]})
            events.append({"event_id": f"event:candidate:{raw_id}", "entity_id": candidate_id, "event_type": "candidate_observed", "source": "secopsai-research", "source_record_id": raw_id, "occurred_at": row["last_seen"], "summary": {"status": row["status"], "package": _text(row["package"], 240), "version": _text(row["version"], 120)}})
            if row["case_id"]:
                relationships.append({"relationship_type": "CANDIDATE_PROMOTED_TO_CASE", "from_entity_id": candidate_id, "to_entity_id": _stable_legacy_id("research_case", "secopsai", row["case_id"]), "source": "secopsai-research", "source_record_id": f"{raw_id}:{row['case_id']}", "observed_at": row["last_seen"]})
    # De-duplicate records in the batch while retaining the freshest values.
    unique_entities = {str(item.get("entity_id")): item for item in entities if item.get("entity_id")}
    unique_relationships: dict[str, dict[str, Any]] = {}
    for item in relationships:
        if not item.get("from_entity_id") or not item.get("to_entity_id") or item["from_entity_id"] == item["to_entity_id"]:
            continue
        relation = str(item.get("relationship_type") or "")
        if relation not in RELATION_TYPES:
            continue
        item = dict(item)
        item.setdefault("relationship_id", "rel:" + hashlib.sha256(f"{relation}|{item['from_entity_id']}|{item['to_entity_id']}|{item.get('source')}|{item.get('source_record_id')}".encode()).hexdigest()[:40])
        unique_relationships[item["relationship_id"]] = item
    existing_ids = set(unique_entities)
    filtered_relationships = [item for item in unique_relationships.values() if item["from_entity_id"] in existing_ids and item["to_entity_id"] in existing_ids]
    unique_events = {str(item.get("event_id")): item for item in events if item.get("event_id") and item.get("entity_id") in existing_ids}
    return sync_payload({"schema_version": SCHEMA_VERSION, "source_instance": "research-worker", "entities": list(unique_entities.values()), "relationships": filtered_relationships, "evidence_refs": evidence_refs, "events": list(unique_events.values())}, db_path=db_path) | {"snapshot": export_snapshot(db_path=db_path, limit=bound)}


def _legacy_entity(node_type: str, source: str, source_id: str, label: str, properties: dict[str, Any], first_seen: str, last_seen: str) -> dict[str, Any]:
    namespace = source or "legacy"
    canonical_key = source_id or label
    entity_id = _stable_legacy_id(node_type if node_type in ENTITY_TYPES else "asset", namespace, canonical_key)
    return {
        "entity_id": _stable_legacy_id(node_type if node_type in ENTITY_TYPES else "asset", namespace, properties.get("entity_id") or entity_id),
        "entity_type": node_type if node_type in ENTITY_TYPES else "asset",
        "namespace": namespace,
        "canonical_key": canonical_key,
        "display_name": label,
        "source": source or "legacy",
        "source_id": source_id,
        "aliases": _legacy_alias(source_id, source or "legacy"),
        "properties": properties,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "observed_at": last_seen,
        "freshness_at": last_seen,
    }


def backfill_existing(*, db_path: str | None = None, batch_limit: int = 1000, resume: bool = True) -> dict[str, Any]:
    """Backfill legacy stores in checkpointed, idempotent batches.

    Checkpoints live in ``ontology_metadata`` and are advanced only after a
    batch commits.  A process interruption therefore resumes from the last
    completed offset without moving or copying raw evidence.
    """
    soc_store.init_db(db_path)
    try:
        limit = max(1, min(int(batch_limit), 5000))
    except (TypeError, ValueError):
        limit = 1000

    def checkpoint(key: str) -> dict[str, Any]:
        if not resume:
            return {"offset": 0, "cursor": None, "complete": False}
        with soc_store.read_connect(db_path) as connection:
            row = connection.execute("SELECT value_json FROM ontology_metadata WHERE key = ?", (f"backfill:{key}",)).fetchone()
        value = _loads(row["value_json"]) if row else {}
        # Offset-only checkpoints from v10 are deliberately restarted from the
        # beginning.  A source row can be inserted or deleted before that
        # offset, so resuming it would silently skip data.
        cursor = value.get("cursor")
        return {
            "offset": max(0, int(value.get("offset") or 0)) if cursor is not None else 0,
            "cursor": cursor,
            "complete": bool(value.get("complete")),
        }

    def save_checkpoint(key: str, offset: int, complete: bool = False, cursor: Any = None) -> None:
        now = utc_now()
        with sqlite_writer_lock(db_path):
            with soc_store.connect(db_path) as connection:
                connection.execute(
                    "INSERT INTO ontology_metadata (key, value_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                    (f"backfill:{key}", bounded_json({"offset": offset, "cursor": cursor, "complete": complete, "updated_at": now}, MAX_SUMMARY_BYTES), now),
                )
                connection.commit()

    def page_rows(connection: Any, query: str, state: dict[str, Any], cursor_field: str) -> list[Any]:
        """Read a stable keyset page instead of an offset page.

        Every backfill query supplies a unique ordered cursor field.  Rows
        added during a run are picked up on a later invocation, while deletes
        cannot shift a checkpoint past an unprocessed row.
        """
        safe_field = _text(cursor_field, 120)
        wrapped = f'SELECT * FROM ({query}) AS backfill_source'
        cursor = state.get("cursor")
        if cursor is None:
            return connection.execute(
                f'{wrapped} ORDER BY backfill_source."{safe_field}" LIMIT ?',
                (limit,),
            ).fetchall()
        return connection.execute(
            f'{wrapped} WHERE backfill_source."{safe_field}" > ? ORDER BY backfill_source."{safe_field}" LIMIT ?',
            (cursor, limit),
        ).fetchall()

    counts = {
        "entities": 0,
        "relationships": 0,
        "events": 0,
        "evidence_refs": 0,
        "skipped_relationships": 0,
        "pending_backfill": 0,
        # Reconciliation counters describe source rows and projection writes
        # separately.  They are intentionally persisted with the checkpoint
        # so an operator can distinguish a complete scan from a complete
        # projection after a restart.
        "scanned": 0,
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
        "streams": {},
    }

    def stream_counts(stream_key: str) -> dict[str, int]:
        streams = counts.setdefault("streams", {})
        stats = streams.setdefault(
            _text(stream_key, 160),
            {"scanned": 0, "inserted": 0, "updated": 0, "skipped": 0, "failed": 0},
        )
        return stats

    def bump(stream_key: str, field: str, amount: int = 1) -> None:
        if field not in {"scanned", "inserted", "updated", "skipped", "failed"}:
            return
        counts[field] = int(counts.get(field, 0)) + max(0, int(amount))
        stats = stream_counts(stream_key)
        stats[field] = int(stats.get(field, 0)) + max(0, int(amount))

    def pending_id(stream_key: str, item_kind: str, source_cursor: Any, item_index: int) -> str:
        material = f"{stream_key}|{item_kind}|{_text(source_cursor, 512)}|{int(item_index)}"
        return "pending:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:40]

    def pending_payload(item: Any) -> str:
        """Keep a retryable, redacted projection even for oversized rows."""
        safe = sanitize_summary(item if isinstance(item, dict) else {"error": str(item)[:1000]})
        encoded = bounded_json(safe, MAX_SUMMARY_BYTES)
        try:
            marker = json.loads(encoded)
        except json.JSONDecodeError:
            marker = {}
        if isinstance(marker, dict) and marker.get("status") == "truncated":
            # Relationship/event retry needs only these bounded identity fields;
            # never persist an unbounded source payload as a dead-letter.
            minimal = {
                key: item.get(key)
                for key in (
                    "event_id", "entity_id", "event_type", "occurred_at", "source",
                    "source_record_id", "relationship_id", "relationship_type",
                    "from_entity_id", "to_entity_id", "workspace_id", "evidence_ref_id",
                    "graph_from_node_id", "graph_to_node_id", "graph_edge_type",
                )
                if isinstance(item, dict) and item.get(key) is not None
            }
            minimal["properties"] = {}
            encoded = bounded_json(minimal, MAX_SUMMARY_BYTES)
        return encoded

    def queue_pending_connection(
        connection: Any,
        *,
        stream_key: str,
        item_kind: str,
        source_cursor: Any,
        item_index: int,
        item: Any,
        error: Any,
        terminal: bool = False,
    ) -> None:
        now = utc_now()
        source_cursor_text = _text(source_cursor, 512) or "unknown"
        status = "dead_letter" if terminal else "pending"
        connection.execute(
            """
            INSERT INTO ontology_backfill_pending
                (pending_id, stream_key, item_kind, source_cursor, item_index,
                 payload_json, status, attempts, next_attempt_at, last_error,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            ON CONFLICT(stream_key, item_kind, source_cursor, item_index) DO UPDATE SET
                payload_json=excluded.payload_json,
                status=CASE WHEN ontology_backfill_pending.status='dead_letter'
                            THEN ontology_backfill_pending.status ELSE excluded.status END,
                next_attempt_at=CASE WHEN ontology_backfill_pending.status='dead_letter'
                                     THEN ontology_backfill_pending.next_attempt_at ELSE excluded.next_attempt_at END,
                last_error=excluded.last_error,
                updated_at=excluded.updated_at
            """,
            (
                pending_id(stream_key, item_kind, source_cursor_text, item_index),
                _text(stream_key, 160),
                _text(item_kind, 40),
                source_cursor_text,
                int(item_index),
                pending_payload(item),
                status,
                now,
                _text(error, 1000) or "unresolved endpoint",
                now,
                now,
            ),
        )

    def retry_pending(
        stream_key: str,
        item_kind: str,
        handler: Any,
        *,
        limit: int = 100,
        force: bool = False,
    ) -> int:
        """Retry unresolved projections without rewinding source checkpoints."""
        now = utc_now()
        recovered = 0
        with sqlite_writer_lock(db_path):
            with soc_store.connect(db_path) as connection:
                pending_query = """
                    SELECT * FROM ontology_backfill_pending
                     WHERE stream_key=? AND item_kind=? AND status='pending'
                """
                pending_params: list[Any] = [_text(stream_key, 160), _text(item_kind, 40)]
                if not force:
                    pending_query += " AND next_attempt_at <= ?"
                    pending_params.append(now)
                pending_query += " ORDER BY created_at, pending_id LIMIT ?"
                pending_params.append(max(1, min(int(limit), 500)))
                rows = connection.execute(pending_query, pending_params).fetchall()
                for row in rows:
                    item = _loads(row["payload_json"])
                    try:
                        applied, error = handler(connection, item)
                    except Exception as exc:  # pending work must remain durable
                        applied, error = False, str(exc)
                    if applied:
                        connection.execute("DELETE FROM ontology_backfill_pending WHERE pending_id=?", (row["pending_id"],))
                        recovered += 1
                        if item_kind == "relationship":
                            counts["relationships"] += 1
                    else:
                        attempts = int(row["attempts"] or 0) + 1
                        # Keep retrying transient endpoint ordering problems,
                        # but surface permanently malformed rows as dead letters.
                        status = "dead_letter" if attempts >= 8 else "pending"
                        delay = min(86400, max(60, 60 * (2 ** min(attempts, 10))))
                        next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
                        connection.execute(
                            "UPDATE ontology_backfill_pending SET attempts=?, status=?, next_attempt_at=?, last_error=?, updated_at=? WHERE pending_id=?",
                            (attempts, status, next_attempt.isoformat().replace("+00:00", "Z"), _text(error, 1000), now, row["pending_id"]),
                        )
                connection.commit()
        return recovered

    def pending_count() -> int:
        with soc_store.read_connect(db_path) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM ontology_backfill_pending WHERE status='pending'").fetchone()[0])

    def run_entity_table(key: str, query: str, builder: Any) -> None:
        state = checkpoint(key)
        while True:
            with soc_store.read_connect(db_path) as connection:
                probe = connection.execute(f"{query} LIMIT 1").fetchone()
                if probe is None:
                    rows = []
                else:
                    cursor_field = str(probe.keys()[0])
                    rows = page_rows(connection, query, state, cursor_field)
            if not rows:
                save_checkpoint(key, int(state["offset"]), True, state.get("cursor"))
                return
            bump(key, "scanned", len(rows))
            items: list[dict[str, Any]] = []
            for row in rows:
                try:
                    built = builder(row)
                except Exception:
                    # A malformed legacy row must be visible in the
                    # reconciliation metadata without preventing unrelated
                    # rows from being projected or checkpointed.
                    bump(key, "failed")
                    continue
                if isinstance(built, list):
                    valid_items = [item for item in built if isinstance(item, dict)]
                    items.extend(valid_items)
                    bump(key, "skipped", len(built) - len(valid_items))
                elif isinstance(built, dict):
                    items.append(built)
                elif built is not None:
                    bump(key, "skipped")
                else:
                    bump(key, "skipped")
            if items:
                result = upsert_entities(items, db_path=db_path)
                counts["entities"] += int(result.get("count") or 0)
                bump(key, "inserted", int(result.get("inserted") or 0))
                bump(key, "updated", int(result.get("updated") or 0))
            state["offset"] = int(state["offset"]) + len(rows)
            state["cursor"] = rows[-1][str(rows[-1].keys()[0])]
            save_checkpoint(key, int(state["offset"]), False, state.get("cursor"))
            if len(rows) < limit:
                save_checkpoint(key, int(state["offset"]), True, state.get("cursor"))
                return

    def build_graph_node(row: Any) -> dict[str, Any]:
        props = _loads(row["properties_json"])
        node_type = str(row["node_type"] or "asset")
        mapped = node_type if node_type in ENTITY_TYPES else ("asset" if node_type in {"site", "sensor", "service", "wifi_network"} else "source")
        item = _legacy_entity(mapped, str(row["source"] or "legacy"), str(row["source_id"] or row["node_id"]), str(row["label"] or row["node_id"]), props, str(row["first_seen"]), str(row["last_seen"]))
        item["entity_id"] = _stable_legacy_id(mapped, str(row["source"] or "legacy"), str(row["node_id"]))
        item["aliases"] = _legacy_alias(str(row["node_id"]), str(row["source"] or "legacy"))
        return item

    def build_finding(row: Any) -> dict[str, Any]:
        payload = _loads(row["payload_json"])
        raw_id = str(row["finding_id"])
        source = str(row["source"] or "legacy")
        return {"entity_id": _stable_legacy_id("finding", "secopsai", raw_id), "entity_type": "finding", "namespace": "secopsai", "canonical_key": raw_id, "display_name": str(row["title"]), "source": source, "source_id": raw_id, "aliases": _legacy_alias(raw_id, source), "status": str(row["status"]), "properties": {"severity": row["severity"], "severity_score": row["severity_score"] or payload.get("severity_score"), "payload_summary": payload}, "first_seen_at": str(row["first_seen"]), "last_seen_at": str(row["last_seen"]), "observed_at": str(row["last_seen"]), "freshness_at": str(row["updated_at"])}

    def build_case(row: Any) -> dict[str, Any]:
        raw_id = str(row["case_id"])
        return {"entity_id": _stable_legacy_id("research_case", "secopsai", raw_id), "entity_type": "research_case", "namespace": "secopsai", "canonical_key": raw_id, "display_name": str(row["title"]), "source": "secopsai-research", "source_id": raw_id, "aliases": _legacy_alias(raw_id, "secopsai-research"), "owner_id": str(row["owner"] or ""), "status": str(row["status"]), "confidence": row["confidence"], "properties": {"summary": row["summary"], "case_type": row["case_type"], "severity": row["severity"], "payload_summary": _loads(row["payload_json"])}, "first_seen_at": str(row["created_at"]), "last_seen_at": str(row["updated_at"]), "observed_at": str(row["updated_at"]), "freshness_at": str(row["updated_at"])}

    def build_alert(row: Any) -> dict[str, Any]:
        raw_id = str(row["alert_id"])
        return {"entity_id": _stable_legacy_id("alert", "secopsai", raw_id), "entity_type": "alert", "namespace": "secopsai", "canonical_key": raw_id, "display_name": str(row["alert_type"]), "source": "secopsai-research", "source_id": raw_id, "aliases": _legacy_alias(raw_id, "secopsai-research"), "status": str(row["status"]), "properties": {"severity": row["severity"], "reason": row["reason"], "candidate_id": row["candidate_id"] if "candidate_id" in row.keys() else "", "case_id": row["case_id"] if "case_id" in row.keys() else "", "evidence_summary": _loads(row["evidence_json"])}, "first_seen_at": str(row["created_at"]), "last_seen_at": str(row["updated_at"]), "observed_at": str(row["updated_at"]), "freshness_at": str(row["updated_at"])}

    def build_candidate(row: Any) -> dict[str, Any]:
        raw_id = str(row["candidate_id"])
        return {"entity_id": _stable_legacy_id("candidate", "secopsai", raw_id), "entity_type": "candidate", "namespace": "secopsai", "canonical_key": raw_id, "display_name": f"{row['package']}@{row['version']}", "source": "secopsai-research", "source_id": raw_id, "aliases": _legacy_alias(raw_id, "secopsai-research"), "status": str(row["status"]), "properties": {"ecosystem": row["ecosystem"], "package": row["package"], "version": row["version"], "reference_identifier": row["reference_identifier"], "score": row["score"], "reason": row["reason"], "score_components": _loads(row["score_components_json"]), "evidence_summary": _loads(row["evidence_json"])}, "first_seen_at": str(row["first_seen"]), "last_seen_at": str(row["last_seen"]), "observed_at": str(row["last_seen"]), "freshness_at": str(row["last_seen"])}

    def _row_value(row: Any, key: str, default: Any = "") -> Any:
        try:
            return row[key] if key in row.keys() else default
        except (AttributeError, IndexError, KeyError):
            return default

    def _case_entity_id(case_id: Any) -> str:
        return _stable_legacy_id("research_case", "secopsai", str(case_id or ""))

    def _subject_projection(row: Any) -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "subject_id"), 256)
        if not raw_id:
            return None
        case_id = _text(_row_value(row, "case_id"), 256)
        subject_type = normalize_value(_row_value(row, "subject_type"), limit=80)
        ecosystem = normalize_value(_row_value(row, "ecosystem") or "research", limit=120) or "research"
        name = _text(_row_value(row, "name") or raw_id, 512)
        version = _text(_row_value(row, "version"), 256)
        if subject_type in {"package", "library", "module", "dependency"}:
            entity_type = "package_version" if version else "package"
            canonical_key = f"{name}@{version}" if version else name
        elif subject_type in {"artifact", "file", "archive"}:
            entity_type = "artifact"
            canonical_key = _row_value(row, "sha256") or raw_id
            ecosystem = "sha256"
        elif subject_type in {"repository", "repo"}:
            entity_type = "repository"
            canonical_key = name
        elif subject_type in {"asset", "service", "sensor", "network"}:
            entity_type = subject_type
            canonical_key = name
        else:
            # Subjects are a legacy case projection rather than a competing
            # top-level ontology type. Preserve the source identity in a
            # namespaced source object when no stronger semantic type exists.
            entity_type = "source"
            ecosystem = "research"
            canonical_key = f"subject:{raw_id}"
        try:
            entity_id = canonical_entity_id(entity_type, ecosystem, canonical_key)
        except ValueError:
            entity_type = "source"
            ecosystem = "research"
            canonical_key = f"subject:{raw_id}"
            entity_id = canonical_entity_id(entity_type, ecosystem, canonical_key)
        created = _text(_row_value(row, "created_at") or utc_now(), 64)
        metadata = _loads(_row_value(row, "metadata_json"))
        properties = {
            "subject_id": raw_id,
            "case_id": case_id,
            "subject_type": subject_type,
            "publisher": _text(_row_value(row, "publisher"), 240),
            "registry_state": _text(_row_value(row, "registry_state"), 80),
            "artifact_state": _text(_row_value(row, "artifact_state"), 80),
            "validation_state": _text(_row_value(row, "validation_state"), 80),
            "state_reason": _text(_row_value(row, "state_reason"), 1000),
            "metadata_summary": metadata,
        }
        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "namespace": ecosystem,
            "canonical_key": canonical_key,
            "display_name": f"{name}@{version}" if version else name,
            "source": "secopsai-research",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "secopsai-research"),
            "workspace_id": "local",
            "status": _text(_row_value(row, "status") or "active", 80) or "active",
            "properties": properties,
            "first_seen_at": created,
            "last_seen_at": created,
            "observed_at": created,
            "freshness_at": _text(_row_value(row, "state_checked_at") or created, 64),
        }

    def build_subject(row: Any) -> dict[str, Any] | None:
        return _subject_projection(row)

    def build_artifact(row: Any) -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "artifact_id"), 256)
        if not raw_id:
            return None
        digest = _text(_row_value(row, "sha256"), 128) or raw_id
        package = _text(_row_value(row, "package_name"), 512)
        version = _text(_row_value(row, "version"), 256)
        created = _text(_row_value(row, "created_at") or utc_now(), 64)
        updated = _text(_row_value(row, "updated_at") or created, 64)
        return {
            "entity_id": canonical_entity_id("artifact", "sha256", digest),
            "entity_type": "artifact",
            "namespace": "sha256",
            "canonical_key": digest,
            "display_name": _text(_row_value(row, "filename") or digest, 512),
            "source": "secopsai-research",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "secopsai-research") + _legacy_alias(digest, "secopsai-research"),
            "status": _text(_row_value(row, "state") or "active", 80) or "active",
            "properties": {
                "artifact_id": raw_id,
                "filename": _text(_row_value(row, "filename"), 512),
                "ecosystem": _text(_row_value(row, "ecosystem"), 120),
                "package_name": package,
                "version": version,
                "size_bytes": max(0, min(int(_row_value(row, "size_bytes") or 0), 10**12)),
                "state": _text(_row_value(row, "state"), 80),
                "provenance_summary": _loads(_row_value(row, "provenance_json")),
                "analysis_summary": _loads(_row_value(row, "analysis_json")),
            },
            "first_seen_at": created,
            "last_seen_at": updated,
            "observed_at": updated,
            "freshness_at": updated,
        }

    def build_evidence(row: Any) -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "evidence_id"), 256)
        case_id = _text(_row_value(row, "case_id"), 256)
        if not raw_id:
            return None
        observed = _text(_row_value(row, "last_observed_at") or _row_value(row, "collected_at") or _row_value(row, "created_at") or utc_now(), 64)
        locator = sanitize_locator(_row_value(row, "locator"))
        evidence_ref_id = "eref:" + hashlib.sha256(f"research|{raw_id}|{locator}|{_row_value(row, 'sha256')}".encode()).hexdigest()[:40]
        return {
            "entity_id": canonical_entity_id("evidence", "secopsai", f"{case_id}:{raw_id}"),
            "entity_type": "evidence",
            "namespace": "secopsai",
            "canonical_key": f"{case_id}:{raw_id}",
            "display_name": _text(_row_value(row, "title") or _row_value(row, "evidence_type") or raw_id, 512),
            "source": "secopsai-research",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "secopsai-research"),
            "status": _text(_row_value(row, "status") or "active", 80) or "active",
            "properties": {
                "evidence_id": raw_id,
                "case_id": case_id,
                "evidence_type": _text(_row_value(row, "evidence_type"), 120),
                "title": _text(_row_value(row, "title"), 512),
                "locator": locator,
                "sha256": _text(_row_value(row, "sha256"), 128),
                "provenance": _text(_row_value(row, "provenance"), 1000),
                "notes": _text(_row_value(row, "notes"), 2000),
                "metadata_summary": _loads(_row_value(row, "metadata_json")),
                "occurrence_count": max(0, min(int(_row_value(row, "occurrence_count") or 0), 10**6)),
                "evidence_ref_id": evidence_ref_id,
            },
            "first_seen_at": _text(_row_value(row, "first_observed_at") or _row_value(row, "created_at") or observed, 64),
            "last_seen_at": observed,
            "observed_at": observed,
            "freshness_at": observed,
            "evidence_ref_id": evidence_ref_id,
        }

    def build_ioc(row: Any) -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "ioc_id") or _row_value(row, "candidate_id"), 256)
        value = _text(_row_value(row, "value"), 1024)
        if not raw_id or not value:
            return None
        observed = _text(_row_value(row, "last_seen") or _row_value(row, "created_at") or utc_now(), 64)
        return {
            "entity_id": canonical_entity_id("ioc", "secopsai", raw_id),
            "entity_type": "ioc",
            "namespace": "secopsai",
            "canonical_key": raw_id,
            "display_name": f"{_text(_row_value(row, 'ioc_type') or 'ioc', 80)}: {value}"[:512],
            "source": "secopsai-research",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "secopsai-research"),
            "status": _text(_row_value(row, "status") or "active", 80) or "active",
            "confidence": _confidence(_row_value(row, "confidence"), 100),
            "properties": {"ioc_id": raw_id, "case_id": _text(_row_value(row, "case_id"), 256), "ioc_type": _text(_row_value(row, "ioc_type"), 120), "value": value, "reason": _text(_row_value(row, "reason"), 1000), "tags": _loads(_row_value(row, "tags_json")), "source_evidence_id": _text(_row_value(row, "source_evidence_id"), 256)},
            "first_seen_at": _text(_row_value(row, "first_seen") or observed, 64),
            "last_seen_at": observed,
            "observed_at": observed,
            "freshness_at": observed,
        }

    def build_registry_source(row: Any) -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "source_id"), 256)
        if not raw_id:
            return None
        updated = _text(_row_value(row, "updated_at") or _row_value(row, "created_at") or utc_now(), 64)
        return {
            "entity_id": canonical_entity_id("source", "registry", raw_id),
            "entity_type": "source",
            "namespace": "registry",
            "canonical_key": raw_id,
            "display_name": _text(_row_value(row, "name") or raw_id, 512),
            "source": "registry",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "registry"),
            "status": "active" if _row_value(row, "enabled", 1) else "disabled",
            "properties": {"ecosystem": _text(_row_value(row, "ecosystem"), 120), "base_url": sanitize_locator(_row_value(row, "base_url")), "coverage_mode": _text(_row_value(row, "coverage_mode"), 120), "capabilities_summary": _loads(_row_value(row, "capabilities_json"))},
            "first_seen_at": _text(_row_value(row, "created_at") or updated, 64),
            "last_seen_at": updated,
            "observed_at": updated,
            "freshness_at": updated,
        }

    def build_registry_event(row: Any) -> dict[str, Any] | list[dict[str, Any]] | None:
        raw_id = _text(_row_value(row, "event_id"), 256)
        if not raw_id:
            return None
        observed = _text(_row_value(row, "observed_at") or utc_now(), 64)
        source_id = _text(_row_value(row, "source_id"), 256) or "unknown"
        ecosystem = _text(_row_value(row, "ecosystem"), 120).lower() or "unknown"
        package = _text(_row_value(row, "package"), 512)
        version = _text(_row_value(row, "version"), 256)
        records: list[dict[str, Any]] = [{
            "entity_id": canonical_entity_id("release_event", "registry", raw_id),
            "entity_type": "release_event",
            "namespace": "registry",
            "canonical_key": raw_id,
            "display_name": f"{package[:240]}@{version[:120]}".strip("@"),
            "source": "registry",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "registry"),
            "properties": {"source_id": source_id, "ecosystem": ecosystem, "package": package, "version": version, "publisher": _text(_row_value(row, "publisher"), 240), "source_url": sanitize_locator(_row_value(row, "source_url")), "artifact_url": sanitize_locator(_row_value(row, "artifact_url")), "artifact_sha256": _text(_row_value(row, "artifact_sha256"), 128), "provenance_summary": _loads(_row_value(row, "provenance_json"))},
            "first_seen_at": observed,
            "last_seen_at": observed,
            "observed_at": observed,
            "freshness_at": observed,
        }]
        if package:
            records.append({
                "entity_id": canonical_entity_id("package", ecosystem, package),
                "entity_type": "package",
                "namespace": ecosystem,
                "canonical_key": package,
                "display_name": package,
                "source": "registry",
                "source_id": source_id,
                "properties": {"ecosystem": ecosystem},
                "observed_at": observed,
                "freshness_at": observed,
            })
            if version:
                version_key = f"{package}@{version}"
                records.append({
                    "entity_id": canonical_entity_id("package_version", ecosystem, version_key),
                    "entity_type": "package_version",
                    "namespace": ecosystem,
                    "canonical_key": version_key,
                    "display_name": version_key,
                    "source": "registry",
                    "source_id": raw_id,
                    "properties": {"ecosystem": ecosystem},
                    "observed_at": observed,
                    "freshness_at": observed,
                })
        artifact_hash = _text(_row_value(row, "artifact_sha256"), 128)
        if artifact_hash:
            records.append({
                "entity_id": canonical_entity_id("artifact", "sha256", artifact_hash),
                "entity_type": "artifact",
                "namespace": "sha256",
                "canonical_key": artifact_hash,
                "display_name": artifact_hash,
                "source": "registry",
                "source_id": raw_id,
                "properties": {"sha256": artifact_hash, "artifact_url": sanitize_locator(_row_value(row, "artifact_url"))},
                "observed_at": observed,
                "freshness_at": observed,
            })
        return records

    def build_intelligence_job(row: Any) -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "job_id"), 256)
        if not raw_id:
            return None
        updated = _text(_row_value(row, "updated_at") or _row_value(row, "queued_at") or utc_now(), 64)
        return {
            "entity_id": canonical_entity_id("intelligence_job", "secopsai", raw_id),
            "entity_type": "intelligence_job",
            "namespace": "secopsai",
            "canonical_key": raw_id,
            "display_name": _text(_row_value(row, "action") or raw_id, 512),
            "source": "core",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "core"),
            "status": _text(_row_value(row, "status") or "queued", 80) or "queued",
            "properties": {"action": _text(_row_value(row, "action"), 160), "target_id": _text(_row_value(row, "target_id"), 512), "requested_by": _text(_row_value(row, "requested_by"), 160), "attempt": max(0, min(int(_row_value(row, "attempt") or 0), 100)), "provider": _text(_row_value(row, "provider"), 160), "error_code": _text(_row_value(row, "error_code"), 120), "error_message": _text(_row_value(row, "error_message"), 1000), "input_summary": _loads(_row_value(row, "input_json")), "result_summary": _loads(_row_value(row, "result_json"))},
            "first_seen_at": _text(_row_value(row, "queued_at") or updated, 64),
            "last_seen_at": updated,
            "observed_at": updated,
            "freshness_at": updated,
        }

    def build_automation_run(row: Any, *, source: str = "secopsai-research", run_type: str = "automation") -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "run_id") or _row_value(row, "pipeline_id"), 256)
        if not raw_id:
            return None
        updated = _text(_row_value(row, "updated_at") or _row_value(row, "completed_at") or _row_value(row, "started_at") or utc_now(), 64)
        return {
            "entity_id": canonical_entity_id("automation_run", "secopsai", raw_id),
            "entity_type": "automation_run",
            "namespace": "secopsai",
            "canonical_key": raw_id,
            "display_name": _text(_row_value(row, "trigger") or _row_value(row, "current_step") or run_type, 512),
            "source": source,
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, source),
            "status": _text(_row_value(row, "status") or "queued", 80) or "queued",
            "properties": {"run_type": run_type, "trigger": _text(_row_value(row, "trigger"), 160), "requested_by": _text(_row_value(row, "requested_by"), 160), "current_step": _text(_row_value(row, "current_step"), 160), "next_run_at": _text(_row_value(row, "next_run_at"), 64), "summary": _loads(_row_value(row, "summary_json")), "config_summary": _loads(_row_value(row, "config_json")), "error_code": _text(_row_value(row, "error_code"), 120), "error_message": _text(_row_value(row, "error_message"), 1000)},
            "first_seen_at": _text(_row_value(row, "started_at") or _row_value(row, "created_at") or updated, 64),
            "last_seen_at": updated,
            "observed_at": updated,
            "freshness_at": updated,
        }

    def build_edge_sync_state(row: Any) -> list[dict[str, Any]] | None:
        """Project an imported Edge bundle checkpoint and its source identity.

        Edge bundles are exchange records rather than a second graph store.
        Keep their schema, cursor, export time, and sync outcome as a bounded
        automation run while retaining a source object for lineage.
        """
        source_instance = _text(_row_value(row, "source_instance"), 256)
        if not source_instance:
            return None
        last_synced = _text(_row_value(row, "last_synced_at"), 64) or utc_now()
        exported = _text(_row_value(row, "bundle_exported_at"), 64)
        bundle_key = f"edge-bundle:{source_instance}:{exported or last_synced}"
        source_id = canonical_entity_id("source", "edge", source_instance)
        run_id = canonical_entity_id("automation_run", "edge", bundle_key)
        source_item = {
            "entity_id": source_id,
            "entity_type": "source",
            "namespace": "edge",
            "canonical_key": source_instance,
            "display_name": source_instance,
            "source": "edge",
            "source_id": source_instance,
            "aliases": _legacy_alias(source_instance, "edge"),
            "status": "active",
            "properties": {"bundle_schema_version": _text(_row_value(row, "schema_version"), 120), "sync_state": "imported"},
            "first_seen_at": last_synced,
            "last_seen_at": last_synced,
            "observed_at": last_synced,
            "freshness_at": last_synced,
        }
        run_item = {
            "entity_id": run_id,
            "entity_type": "automation_run",
            "namespace": "edge",
            "canonical_key": bundle_key,
            "display_name": f"Edge bundle · {source_instance}",
            "source": "edge",
            "source_id": source_instance,
            "aliases": _legacy_alias(bundle_key, "edge"),
            "status": "succeeded",
            "properties": {
                "run_type": "edge_bundle_import",
                "source_instance": source_instance,
                "schema_version": _text(_row_value(row, "schema_version"), 120),
                "bundle_exported_at": exported,
                "last_synced_at": last_synced,
                "cursor_summary": _loads(_row_value(row, "cursor_json")),
            },
            "first_seen_at": exported or last_synced,
            "last_seen_at": last_synced,
            "observed_at": last_synced,
            "freshness_at": last_synced,
        }
        return [source_item, run_item]

    def build_research_bundle(row: Any) -> dict[str, Any] | None:
        """Project a tamper-evident research bundle without copying payload."""
        raw_id = _text(_row_value(row, "bundle_id"), 256)
        if not raw_id:
            return None
        created = _text(_row_value(row, "created_at"), 64) or utc_now()
        payload = _loads(_row_value(row, "payload_json"))
        # Keep only the names of non-sensitive summary fields.  The payload
        # itself may contain raw evidence or artifact bytes and is never
        # copied into the ontology projection.
        safe_payload = sanitize_summary(payload)
        stage = _text(_row_value(row, "stage"), 80) or "unknown"
        status = _text(_row_value(row, "status"), 80) or "unknown"
        return {
            "entity_id": canonical_entity_id("automation_run", "secopsai", f"research-bundle:{raw_id}"),
            "entity_type": "automation_run",
            "namespace": "secopsai",
            "canonical_key": f"research-bundle:{raw_id}",
            "display_name": f"Research bundle · {stage}",
            "source": "secopsai-research",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "secopsai-research"),
            "status": status,
            "properties": {
                "run_type": "research_run_bundle",
                "bundle_id": raw_id,
                "case_id": _text(_row_value(row, "case_id"), 256),
                "plan_id": _text(_row_value(row, "plan_id"), 256),
                "stage": stage,
                "previous_bundle_hash": _text(_row_value(row, "previous_bundle_hash"), 128),
                "payload_hash": _text(_row_value(row, "payload_hash"), 128),
                "bundle_hash": _text(_row_value(row, "bundle_hash"), 128),
                "completeness_score": max(0, min(int(_row_value(row, "completeness_score") or 0), 100)),
                "payload_keys": sorted(str(key)[:120] for key in safe_payload.keys())[:100],
            },
            "first_seen_at": created,
            "last_seen_at": created,
            "observed_at": created,
            "freshness_at": created,
        }

    def build_triage_decision(row: Any) -> dict[str, Any] | None:
        raw_id = _text(_row_value(row, "run_id"), 256)
        if not raw_id:
            return None
        updated = _text(_row_value(row, "updated_at") or _row_value(row, "queued_at") or utc_now(), 64)
        return {
            "entity_id": canonical_entity_id("triage_decision", "secopsai", raw_id),
            "entity_type": "triage_decision",
            "namespace": "secopsai",
            "canonical_key": raw_id,
            "display_name": f"Triage {raw_id}",
            "source": "secopsai-research",
            "source_id": raw_id,
            "aliases": _legacy_alias(raw_id, "secopsai-research"),
            "status": _text(_row_value(row, "status") or "queued", 80) or "queued",
            "properties": {"target_type": _text(_row_value(row, "target_type"), 80), "target_id": _text(_row_value(row, "target_id"), 512), "target_fingerprint": _text(_row_value(row, "target_fingerprint"), 256), "selected_model": _text(_row_value(row, "selected_model"), 240), "provider": _text(_row_value(row, "provider"), 160), "deterministic_summary": _loads(_row_value(row, "deterministic_json")), "recommendation_summary": _loads(_row_value(row, "recommendation_json")), "decision_summary": _loads(_row_value(row, "decision_json")), "final_action": _text(_row_value(row, "final_action"), 240), "reversible": bool(_row_value(row, "reversible", 1)), "rollback_summary": _loads(_row_value(row, "rollback_json")), "error_code": _text(_row_value(row, "error_code"), 120), "error_message": _text(_row_value(row, "error_message"), 1000)},
            "first_seen_at": _text(_row_value(row, "queued_at") or updated, 64),
            "last_seen_at": updated,
            "observed_at": updated,
            "freshness_at": updated,
        }

    run_entity_table("graph_nodes", "SELECT node_id, node_type, label, source, source_id, properties_json, first_seen, last_seen FROM asset_graph_nodes ORDER BY node_id", build_graph_node)
    run_entity_table("findings", "SELECT finding_id, title, source, first_seen, last_seen, updated_at, severity, severity_score, status, payload_json FROM findings ORDER BY finding_id", build_finding)
    run_entity_table("research_cases", "SELECT case_id, title, summary, case_type, severity, confidence, status, owner, created_at, updated_at, payload_json FROM research_cases ORDER BY case_id", build_case)
    run_entity_table("research_alerts", "SELECT alert_id, alert_type, severity, candidate_id, case_id, status, reason, created_at, updated_at, evidence_json FROM research_alerts ORDER BY alert_id", build_alert)
    run_entity_table("research_candidates", "SELECT candidate_id, ecosystem, package, version, reference_identifier, score, score_components_json, reason, status, case_id, evidence_json, first_seen, last_seen FROM research_candidates ORDER BY candidate_id", build_candidate)
    # Project the owning research records as semantic objects.  These tables
    # can be much larger than the bounded hosted snapshot, so each uses its
    # own resumable checkpoint and only publishes summaries/references.
    run_entity_table(
        "research_subjects",
        "SELECT subject_id, case_id, subject_type, ecosystem, name, version, publisher, status, metadata_json, created_at, registry_state, artifact_state, validation_state, state_reason, state_checked_at FROM research_subjects ORDER BY subject_id",
        build_subject,
    )
    run_entity_table(
        "research_artifacts",
        "SELECT artifact_id, sha256, filename, ecosystem, package_name, version, size_bytes, state, provenance_json, analysis_json, created_at, updated_at FROM research_artifacts ORDER BY artifact_id",
        build_artifact,
    )
    run_entity_table(
        "research_evidence",
        "SELECT evidence_id, case_id, evidence_type, title, locator, sha256, provenance, notes, status, collected_at, created_at, metadata_json, occurrence_count, first_observed_at, last_observed_at FROM research_evidence ORDER BY evidence_id",
        build_evidence,
    )

    def run_evidence_ref_table() -> None:
        state = checkpoint("evidence_refs")
        query = "SELECT evidence_id, case_id, evidence_type, title, locator, sha256, provenance, notes, status, collected_at, created_at, metadata_json, occurrence_count, first_observed_at, last_observed_at FROM research_evidence ORDER BY evidence_id"
        while True:
            with soc_store.read_connect(db_path) as connection:
                rows = page_rows(connection, query, state, "evidence_id")
            if not rows:
                save_checkpoint("evidence_refs", int(state["offset"]), True, state.get("cursor"))
                return
            bump("evidence_refs", "scanned", len(rows))
            with sqlite_writer_lock(db_path):
                with soc_store.connect(db_path) as connection:
                    now = utc_now()
                    for row in rows:
                        item = build_evidence(row)
                        if not item:
                            bump("evidence_refs", "skipped")
                            continue
                        locator = sanitize_locator(_row_value(row, "locator"))
                        evidence_ref_id = str(item.get("evidence_ref_id") or "")
                        if not evidence_ref_id or not locator:
                            bump("evidence_refs", "skipped")
                            continue
                        existed = connection.execute(
                            "SELECT 1 FROM ontology_evidence_refs WHERE evidence_ref_id = ?",
                            (evidence_ref_id,),
                        ).fetchone() is not None
                        connection.execute(
                            "INSERT INTO ontology_evidence_refs (evidence_ref_id, source, locator, content_hash, content_type, workspace_id, summary_json, observed_at, created_at, updated_at) VALUES (?, 'secopsai-research', ?, ?, ?, 'local', ?, ?, ?, ?) ON CONFLICT(evidence_ref_id) DO UPDATE SET locator=excluded.locator, content_hash=excluded.content_hash, content_type=excluded.content_type, workspace_id=excluded.workspace_id, summary_json=excluded.summary_json, observed_at=excluded.observed_at, updated_at=excluded.updated_at",
                            (evidence_ref_id, locator, _text(_row_value(row, "sha256"), 128), _text(_row_value(row, "evidence_type"), 120), bounded_json({"evidence_id": _text(_row_value(row, "evidence_id"), 256), "case_id": _text(_row_value(row, "case_id"), 256), "title": _text(_row_value(row, "title"), 512), "provenance": _text(_row_value(row, "provenance"), 1000), "status": _text(_row_value(row, "status"), 80)}, MAX_SUMMARY_BYTES), _text(_row_value(row, "last_observed_at") or _row_value(row, "collected_at") or now, 64), now, now),
                        )
                        counts["evidence_refs"] = counts.get("evidence_refs", 0) + 1
                        bump("evidence_refs", "updated" if existed else "inserted")
                    connection.commit()
            state["offset"] = int(state["offset"]) + len(rows)
            state["cursor"] = rows[-1]["evidence_id"]
            save_checkpoint("evidence_refs", int(state["offset"]), len(rows) < limit, state.get("cursor"))
            if len(rows) < limit:
                return

    run_evidence_ref_table()
    run_entity_table(
        "research_iocs",
        "SELECT ioc_id, case_id, ioc_type, value, confidence, first_seen, last_seen, source_evidence_id, tags_json, created_at, status FROM research_iocs ORDER BY ioc_id",
        build_ioc,
    )
    run_entity_table(
        "research_ioc_candidates",
        "SELECT candidate_id, case_id, ioc_type, value, confidence, reason, source_evidence_id, status, created_at FROM research_ioc_candidates ORDER BY candidate_id",
        build_ioc,
    )
    run_entity_table(
        "research_registry_sources",
        "SELECT source_id, ecosystem, name, base_url, capabilities_json, coverage_mode, enabled, created_at, updated_at FROM research_registry_sources ORDER BY source_id",
        build_registry_source,
    )
    run_entity_table(
        "research_registry_events",
        "SELECT event_id, source_id, ecosystem, package, version, publisher, source_url, artifact_url, artifact_sha256, observed_at, provenance_json FROM research_registry_events ORDER BY event_id",
        build_registry_event,
    )
    run_entity_table(
        "intelligence_jobs",
        "SELECT job_id, action, target_id, status, requested_by, attempt, provider, queued_at, started_at, completed_at, updated_at, error_code, error_message, input_json, result_json FROM intelligence_jobs ORDER BY job_id",
        build_intelligence_job,
    )
    run_entity_table(
        "research_jobs",
        "SELECT job_id, action, case_id AS target_id, status, requested_by, attempt, queued_at, started_at, completed_at, updated_at, error_code, error_message, config_json AS input_json, result_json FROM research_jobs ORDER BY job_id",
        build_intelligence_job,
    )
    run_entity_table(
        "agent_triage_runs",
        "SELECT run_id, target_type, target_id, target_fingerprint, status, selected_model, provider, deterministic_json, recommendation_json, decision_json, final_action, reversible, rollback_json, error_code, error_message, queued_at, completed_at, updated_at FROM agent_triage_runs ORDER BY run_id",
        build_triage_decision,
    )
    run_entity_table(
        "daily_automation_runs",
        "SELECT run_id, trigger, status, started_at, completed_at, next_run_at, summary_json, error_message, updated_at FROM daily_automation_runs ORDER BY run_id",
        lambda row: build_automation_run(row, source="secopsai-research", run_type="daily_automation"),
    )
    run_entity_table(
        "research_pipeline_runs",
        "SELECT pipeline_id, schema_version, case_id, status, requested_by, current_step, revision, config_json, summary_json, error_code, error_message, created_at, started_at, completed_at, updated_at FROM research_pipeline_runs ORDER BY pipeline_id",
        lambda row: build_automation_run(row, source="secopsai-research", run_type="research_pipeline"),
    )
    run_entity_table(
        "edge_sync_state",
        "SELECT source_instance, schema_version, cursor_json, bundle_exported_at, last_synced_at FROM edge_sync_state ORDER BY source_instance",
        build_edge_sync_state,
    )
    run_entity_table(
        "research_run_bundles",
        "SELECT bundle_id, case_id, plan_id, stage, status, previous_bundle_hash, payload_hash, bundle_hash, completeness_score, payload_json, created_at FROM research_run_bundles ORDER BY bundle_id",
        build_research_bundle,
    )

    def apply_relationship_connection(connection: Any, item: Any, *, now: str | None = None) -> tuple[bool, str]:
        if not isinstance(item, dict):
            return False, "relationship projection is not an object"
        from_id = _text(item.get("from_entity_id") or item.get("from"), 512)
        to_id = _text(item.get("to_entity_id") or item.get("to"), 512)
        if not from_id or not to_id:
            return False, "relationship endpoints are missing"
        if from_id == to_id:
            return False, "relationship endpoints are identical"
        if connection.execute("SELECT 1 FROM ontology_entities WHERE entity_id = ?", (from_id,)).fetchone() is None:
            return False, f"unknown relationship source entity: {from_id}"
        if connection.execute("SELECT 1 FROM ontology_entities WHERE entity_id = ?", (to_id,)).fetchone() is None:
            return False, f"unknown relationship target entity: {to_id}"
        try:
            _upsert_relationship_connection(connection, item, now=now)
            return True, ""
        except (TypeError, ValueError) as exc:
            return False, str(exc)

    def run_relationship_stream(key: str, query: str, builder: Any, *, cursor_field: str | None = None) -> None:
        """Apply a resumable relationship projection from a legacy table.

        Missing endpoints are persisted as pending rows before the source
        checkpoint advances. A later backfill invocation can resolve them once
        the corresponding entity projection exists, without replaying a whole
        source table or silently dropping a relationship.
        """
        retry_pending(key, "relationship", apply_relationship_connection, force=True)
        state = checkpoint(key)
        while True:
            with soc_store.read_connect(db_path) as connection:
                probe = connection.execute(f"{query} LIMIT 1").fetchone()
                field = cursor_field or (str(probe.keys()[0]) if probe is not None else "")
                rows = page_rows(connection, query, state, field) if probe is not None else []
            if not rows:
                save_checkpoint(key, int(state["offset"]), True, state.get("cursor"))
                return
            bump(key, "scanned", len(rows))
            with sqlite_writer_lock(db_path):
                with soc_store.connect(db_path) as connection:
                    now = utc_now()
                    for row in rows:
                        source_cursor = row[field]
                        try:
                            built = builder(row)
                            items = built if isinstance(built, list) else [built]
                        except (KeyError, TypeError, ValueError) as exc:
                            counts["skipped_relationships"] += 1
                            bump(key, "failed")
                            queue_pending_connection(
                                connection,
                                stream_key=key,
                                item_kind="relationship",
                                source_cursor=source_cursor,
                                item_index=0,
                                item={"source_record_id": source_cursor},
                                error=f"relationship builder failed: {exc}",
                                terminal=True,
                            )
                            continue
                        for item_index, item in enumerate(items):
                            if item is None or not isinstance(item, dict):
                                counts["skipped_relationships"] += 1
                                bump(key, "skipped")
                                queue_pending_connection(
                                    connection,
                                    stream_key=key,
                                    item_kind="relationship",
                                    source_cursor=source_cursor,
                                    item_index=item_index,
                                    item={"source_record_id": source_cursor},
                                    error="relationship builder returned no projection",
                                    terminal=True,
                                )
                                continue
                            relation_id = _text(item.get("relationship_id") or item.get("edge_id"), 512) or _semantic_relationship_id(item)
                            existed = connection.execute(
                                "SELECT 1 FROM ontology_relationships WHERE relationship_id = ?",
                                (relation_id,),
                            ).fetchone() is not None
                            applied, error = apply_relationship_connection(connection, item, now=now)
                            if applied:
                                counts["relationships"] += 1
                                bump(key, "updated" if existed else "inserted")
                            else:
                                counts["skipped_relationships"] += 1
                                bump(key, "skipped")
                                queue_pending_connection(
                                    connection,
                                    stream_key=key,
                                    item_kind="relationship",
                                    source_cursor=source_cursor,
                                    item_index=item_index,
                                    item=item,
                                    error=error,
                                    terminal=error in {"relationship endpoints are identical", "relationship projection is not an object"},
                                )
                    connection.commit()
            state["offset"] = int(state["offset"]) + len(rows)
            state["cursor"] = rows[-1][field]
            save_checkpoint(key, int(state["offset"]), len(rows) < limit, state.get("cursor"))
            if len(rows) < limit:
                return

    def _subject_id_from_row(row: Any) -> str:
        projection = _subject_projection(row)
        return str(projection.get("entity_id")) if projection else ""

    def _artifact_id_from_row(row: Any) -> str:
        digest = _text(_row_value(row, "sha256"), 128) or _text(_row_value(row, "artifact_id"), 256)
        return canonical_entity_id("artifact", "sha256", digest) if digest else ""

    def _evidence_id_from_values(case_id: Any, evidence_id: Any) -> str:
        return canonical_entity_id("evidence", "secopsai", f"{_text(case_id, 256)}:{_text(evidence_id, 256)}")

    def _ioc_id_from_row(row: Any) -> str:
        raw = _text(_row_value(row, "ioc_id") or _row_value(row, "candidate_id"), 256)
        return canonical_entity_id("ioc", "secopsai", raw) if raw else ""

    def _target_entity_id(raw_target: Any, action: Any = "", target_type: Any = "") -> str:
        target = _text(raw_target, 512)
        if not target:
            return ""
        if ":" in target:
            # Stored job targets often arrive as a namespaced ID such as
            # ``case:secopsai:RSC-123``.  Treating that value as opaque keeps
            # the producer's original casing and can miss the canonical
            # lower-case entity already projected by the backfill.  Rebuild
            # known ontology prefixes through the canonical ID function while
            # leaving genuinely external/opaque identifiers untouched.
            prefix, remainder = target.split(":", 1)
            entity_type = ENTITY_TYPES_BY_PREFIX.get(normalize_value(prefix, limit=80))
            if entity_type and ":" in remainder:
                namespace, canonical_key = remainder.split(":", 1)
                if namespace and canonical_key:
                    return canonical_entity_id(entity_type, namespace, canonical_key)
            return target
        normalized_type = normalize_value(target_type, limit=80)
        if normalized_type in ENTITY_TYPES:
            return _stable_legacy_id(normalized_type, "secopsai", target)
        normalized_action = normalize_value(action, limit=160)
        if "finding" in normalized_action or normalized_action in {"triage", "explain"}:
            return _stable_legacy_id("finding", "secopsai", target)
        if "case" in normalized_action or "research" in normalized_action:
            return _stable_legacy_id("research_case", "secopsai", target)
        return _stable_legacy_id("asset", "legacy", target)

    # Case-owned subjects, artifacts, evidence, and IOCs are linked explicitly
    # so an analyst can traverse from a case to the underlying proof and safe
    # action context without opening raw research tables.
    run_relationship_stream(
        "case_subjects",
        "SELECT subject_id, case_id, subject_type, ecosystem, name, version, publisher, status, metadata_json, created_at, registry_state, artifact_state, validation_state, state_reason, state_checked_at FROM research_subjects ORDER BY subject_id",
        lambda row: {"relationship_type": "CASE_HAS_SUBJECT", "from_entity_id": _case_entity_id(_row_value(row, "case_id")), "to_entity_id": _subject_id_from_row(row), "source": "secopsai-research", "source_record_id": f"{_row_value(row, 'case_id')}:{_row_value(row, 'subject_id')}", "observed_at": _row_value(row, "state_checked_at") or _row_value(row, "created_at") or UNKNOWN_OBSERVED_AT},
    )
    run_relationship_stream(
        "case_artifacts",
        "SELECT ca.case_id || ':' || ca.artifact_id AS backfill_key, ca.artifact_id, ca.case_id, ca.role, ca.created_at, a.sha256 FROM research_case_artifacts ca JOIN research_artifacts a ON a.artifact_id = ca.artifact_id ORDER BY backfill_key",
        lambda row: {"relationship_type": "CASE_HAS_ARTIFACT", "from_entity_id": _case_entity_id(_row_value(row, "case_id")), "to_entity_id": _artifact_id_from_row(row), "source": "secopsai-research", "source_record_id": f"{_row_value(row, 'case_id')}:{_row_value(row, 'artifact_id')}", "properties": {"role": _text(_row_value(row, "role"), 120)}, "observed_at": _row_value(row, "created_at") or UNKNOWN_OBSERVED_AT},
        cursor_field="backfill_key",
    )
    run_relationship_stream(
        "case_evidence",
        "SELECT evidence_id, case_id, locator, sha256, collected_at, created_at, last_observed_at FROM research_evidence ORDER BY evidence_id",
        lambda row: {"relationship_type": "CASE_SUPPORTED_BY_EVIDENCE", "from_entity_id": _case_entity_id(_row_value(row, "case_id")), "to_entity_id": _evidence_id_from_values(_row_value(row, "case_id"), _row_value(row, "evidence_id")), "source": "secopsai-research", "source_record_id": f"{_row_value(row, 'case_id')}:{_row_value(row, 'evidence_id')}", "evidence_ref_id": "eref:" + hashlib.sha256(f"research|{_row_value(row, 'evidence_id')}|{sanitize_locator(_row_value(row, 'locator'))}|{_row_value(row, 'sha256')}".encode()).hexdigest()[:40], "observed_at": _row_value(row, "last_observed_at") or _row_value(row, "collected_at") or _row_value(row, "created_at") or UNKNOWN_OBSERVED_AT},
    )
    run_relationship_stream(
        "case_iocs",
        "SELECT ioc_id, case_id, created_at, last_seen FROM research_iocs ORDER BY ioc_id",
        lambda row: {"relationship_type": "CASE_HAS_IOC", "from_entity_id": _case_entity_id(_row_value(row, "case_id")), "to_entity_id": _ioc_id_from_row(row), "source": "secopsai-research", "source_record_id": f"{_row_value(row, 'case_id')}:{_row_value(row, 'ioc_id')}", "observed_at": _row_value(row, "last_seen") or _row_value(row, "created_at") or UNKNOWN_OBSERVED_AT},
    )
    run_relationship_stream(
        "case_ioc_candidates",
        "SELECT candidate_id, case_id, created_at FROM research_ioc_candidates ORDER BY candidate_id",
        lambda row: {"relationship_type": "CASE_HAS_IOC", "from_entity_id": _case_entity_id(_row_value(row, "case_id")), "to_entity_id": _ioc_id_from_row(row), "source": "secopsai-research", "source_record_id": f"{_row_value(row, 'case_id')}:{_row_value(row, 'candidate_id')}", "properties": {"candidate": True}, "observed_at": _row_value(row, "created_at") or UNKNOWN_OBSERVED_AT},
    )
    run_relationship_stream(
        "registry_event_links",
        "SELECT event_id, source_id, ecosystem, package, version, artifact_sha256, observed_at FROM research_registry_events ORDER BY event_id",
        lambda row: [
            *([{"relationship_type": "PACKAGE_HAS_VERSION", "from_entity_id": canonical_entity_id("package", _text(_row_value(row, "ecosystem"), 120) or "unknown", _row_value(row, "package")), "to_entity_id": canonical_entity_id("package_version", _text(_row_value(row, "ecosystem"), 120) or "unknown", f"{_text(_row_value(row, 'package'), 512)}@{_text(_row_value(row, 'version'), 256)}"), "source": "registry", "source_record_id": _text(_row_value(row, "event_id"), 256), "observed_at": _row_value(row, "observed_at") or utc_now()}] if _text(_row_value(row, "package"), 512) and _text(_row_value(row, "version"), 256) else []),
            {"relationship_type": "VERSION_RELEASED_IN", "from_entity_id": canonical_entity_id("package_version", _text(_row_value(row, "ecosystem"), 120) or "unknown", f"{_text(_row_value(row, 'package'), 512)}@{_text(_row_value(row, 'version'), 256)}"), "to_entity_id": canonical_entity_id("release_event", "registry", _text(_row_value(row, "event_id"), 256)), "source": "registry", "source_record_id": _text(_row_value(row, "event_id"), 256), "observed_at": _row_value(row, "observed_at") or utc_now()},
            {"relationship_type": "RELEASE_EVENT_FROM_SOURCE", "from_entity_id": canonical_entity_id("release_event", "registry", _text(_row_value(row, "event_id"), 256)), "to_entity_id": canonical_entity_id("source", "registry", _text(_row_value(row, "source_id"), 256) or "unknown"), "source": "registry", "source_record_id": _text(_row_value(row, "event_id"), 256), "observed_at": _row_value(row, "observed_at") or utc_now()},
        ] + ([{"relationship_type": "VERSION_HAS_ARTIFACT", "from_entity_id": canonical_entity_id("package_version", _text(_row_value(row, "ecosystem"), 120) or "unknown", f"{_text(_row_value(row, 'package'), 512)}@{_text(_row_value(row, 'version'), 256)}"), "to_entity_id": canonical_entity_id("artifact", "sha256", _row_value(row, "artifact_sha256")), "source": "registry", "source_record_id": _text(_row_value(row, "event_id"), 256), "observed_at": _row_value(row, "observed_at") or utc_now()}] if _text(_row_value(row, "artifact_sha256"), 128) else []),
    )
    run_relationship_stream(
        "intelligence_job_targets",
        "SELECT job_id, action, target_id, queued_at FROM intelligence_jobs ORDER BY job_id",
        lambda row: {"relationship_type": "JOB_TARGETS_ENTITY", "from_entity_id": canonical_entity_id("intelligence_job", "secopsai", _row_value(row, "job_id")), "to_entity_id": _target_entity_id(_row_value(row, "target_id"), _row_value(row, "action")), "source": "core", "source_record_id": _text(_row_value(row, "job_id"), 256), "observed_at": _row_value(row, "queued_at") or utc_now()},
    )
    run_relationship_stream(
        "research_job_targets",
        "SELECT job_id, action, case_id, queued_at FROM research_jobs ORDER BY job_id",
        lambda row: {"relationship_type": "JOB_TARGETS_ENTITY", "from_entity_id": canonical_entity_id("intelligence_job", "secopsai", _row_value(row, "job_id")), "to_entity_id": _case_entity_id(_row_value(row, "case_id")), "source": "secopsai-research", "source_record_id": _text(_row_value(row, "job_id"), 256), "observed_at": _row_value(row, "queued_at") or utc_now()},
    )
    run_relationship_stream(
        "pipeline_case_targets",
        "SELECT pipeline_id, case_id, started_at, created_at FROM research_pipeline_runs ORDER BY pipeline_id",
        lambda row: {"relationship_type": "RUN_PRODUCED_RESULT", "from_entity_id": canonical_entity_id("automation_run", "secopsai", _row_value(row, "pipeline_id")), "to_entity_id": _case_entity_id(_row_value(row, "case_id")), "source": "secopsai-research", "source_record_id": _text(_row_value(row, "pipeline_id"), 256), "observed_at": _row_value(row, "started_at") or _row_value(row, "created_at") or utc_now()},
    )
    run_relationship_stream(
        "edge_bundle_sources",
        "SELECT source_instance, bundle_exported_at, last_synced_at FROM edge_sync_state ORDER BY source_instance",
        lambda row: {"relationship_type": "RUN_PRODUCED_RESULT", "from_entity_id": canonical_entity_id("automation_run", "edge", f"edge-bundle:{_text(_row_value(row, 'source_instance'), 256)}:{_text(_row_value(row, 'bundle_exported_at'), 64) or _text(_row_value(row, 'last_synced_at'), 64)}"), "to_entity_id": canonical_entity_id("source", "edge", _row_value(row, "source_instance")), "source": "edge", "source_record_id": _text(_row_value(row, "source_instance"), 256), "observed_at": _row_value(row, "last_synced_at") or utc_now()},
    )
    run_relationship_stream(
        "research_bundle_cases",
        "SELECT bundle_id, case_id, created_at FROM research_run_bundles WHERE case_id <> '' ORDER BY bundle_id",
        lambda row: {"relationship_type": "RUN_PRODUCED_RESULT", "from_entity_id": canonical_entity_id("automation_run", "secopsai", f"research-bundle:{_text(_row_value(row, 'bundle_id'), 256)}"), "to_entity_id": _case_entity_id(_row_value(row, "case_id")), "source": "secopsai-research", "source_record_id": _text(_row_value(row, "bundle_id"), 256), "observed_at": _row_value(row, "created_at") or utc_now()},
    )
    run_relationship_stream(
        "triage_targets",
        "SELECT run_id, target_type, target_id, queued_at FROM agent_triage_runs ORDER BY run_id",
        lambda row: {"relationship_type": "TRIAGE_DECISION_FOR_ENTITY", "from_entity_id": canonical_entity_id("triage_decision", "secopsai", _row_value(row, "run_id")), "to_entity_id": _target_entity_id(_row_value(row, "target_id"), "triage", _row_value(row, "target_type")), "source": "secopsai-research", "source_record_id": _text(_row_value(row, "run_id"), 256), "observed_at": _row_value(row, "queued_at") or utc_now()},
    )

    def apply_event_connection(connection: Any, item: Any, *, now: str | None = None) -> tuple[bool, str]:
        if not isinstance(item, dict):
            return False, "event projection is not an object"
        entity_id = _text(item.get("entity_id"), 512)
        if not entity_id:
            return False, "event entity is missing"
        if connection.execute("SELECT 1 FROM ontology_entities WHERE entity_id = ?", (entity_id,)).fetchone() is None:
            return False, f"unknown event entity: {entity_id}"
        now = now or utc_now()
        event_type = _text(item.get("event_type") or "observed", 120) or "observed"
        source = normalize_source(item.get("source") or "legacy") or "legacy"
        source_record_id = _text(item.get("source_record_id"), 512)
        # Keep event IDs and timelines reproducible when a legacy row has no
        # timestamp. The epoch marker is explicit and sortable; using
        # ingestion ``now`` would create a new event on every backfill run.
        occurred_at = _text(item.get("occurred_at") or UNKNOWN_OBSERVED_AT, 64)
        event_id = _text(item.get("event_id"), 512) or "event:" + hashlib.sha256(f"{entity_id}|{event_type}|{source}|{source_record_id}|{occurred_at}".encode()).hexdigest()[:40]
        connection.execute(
            "INSERT INTO ontology_events (event_id, entity_id, event_type, source, source_record_id, summary_json, occurred_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(event_id) DO UPDATE SET event_type=excluded.event_type, source=excluded.source, source_record_id=excluded.source_record_id, summary_json=excluded.summary_json, occurred_at=excluded.occurred_at",
            (event_id, entity_id, event_type, source, source_record_id, bounded_json(item.get("summary") or {}, MAX_SUMMARY_BYTES), occurred_at, now),
        )
        return True, ""

    def run_event_stream(key: str, query: str, builder: Any) -> None:
        retry_pending(key, "event", apply_event_connection, force=True)
        state = checkpoint(key)
        while True:
            with soc_store.read_connect(db_path) as connection:
                probe = connection.execute(f"{query} LIMIT 1").fetchone()
                field = str(probe.keys()[0]) if probe is not None else ""
                rows = page_rows(connection, query, state, field) if probe is not None else []
            if not rows:
                save_checkpoint(key, int(state["offset"]), True, state.get("cursor"))
                return
            bump(key, "scanned", len(rows))
            with sqlite_writer_lock(db_path):
                with soc_store.connect(db_path) as connection:
                    now = utc_now()
                    for row in rows:
                        source_cursor = row[field]
                        try:
                            item = builder(row)
                        except (KeyError, TypeError, ValueError) as exc:
                            counts["skipped_relationships"] += 1
                            bump(key, "failed")
                            queue_pending_connection(
                                connection,
                                stream_key=key,
                                item_kind="event",
                                source_cursor=source_cursor,
                                item_index=0,
                                item={"source_record_id": source_cursor},
                                error=f"event builder failed: {exc}",
                                terminal=True,
                            )
                            continue
                        if item is None or not isinstance(item, dict):
                            counts["skipped_relationships"] += 1
                            bump(key, "skipped")
                            queue_pending_connection(
                                connection,
                                stream_key=key,
                                item_kind="event",
                                source_cursor=source_cursor,
                                item_index=0,
                                item={"source_record_id": source_cursor},
                                error="event builder returned no projection",
                                terminal=True,
                            )
                            continue
                        event_id = _text(item.get("event_id"), 512) or "event:" + hashlib.sha256(
                            f"{_text(item.get('entity_id'), 512)}|{_text(item.get('event_type') or 'observed', 120)}|{normalize_source(item.get('source') or 'legacy') or 'legacy'}|{_text(item.get('source_record_id'), 512)}|{_text(item.get('occurred_at') or UNKNOWN_OBSERVED_AT, 64)}".encode()
                        ).hexdigest()[:40]
                        existed = connection.execute(
                            "SELECT 1 FROM ontology_events WHERE event_id = ?",
                            (event_id,),
                        ).fetchone() is not None
                        applied, error = apply_event_connection(connection, item, now=now)
                        if not applied:
                            counts["skipped_relationships"] += 1
                            bump(key, "skipped")
                            queue_pending_connection(
                                connection,
                                stream_key=key,
                                item_kind="event",
                                source_cursor=source_cursor,
                                item_index=0,
                                item=item,
                                error=error,
                                terminal=False,
                            )
                        else:
                            counts["events"] += 1
                            bump(key, "updated" if existed else "inserted")
                    connection.commit()
            state["offset"] = int(state["offset"]) + len(rows)
            state["cursor"] = rows[-1][field]
            save_checkpoint(key, int(state["offset"]), len(rows) < limit, state.get("cursor"))
            if len(rows) < limit:
                return

    run_event_stream(
        "case_events",
        "SELECT event_id, case_id, event_type, actor, message, data_json, created_at FROM research_case_events ORDER BY event_id",
        lambda row: {"event_id": f"case-event:{_row_value(row, 'event_id')}", "entity_id": _case_entity_id(_row_value(row, "case_id")), "event_type": _row_value(row, "event_type"), "source": "secopsai-research", "source_record_id": _row_value(row, "event_id"), "occurred_at": _row_value(row, "created_at"), "summary": {"actor": _text(_row_value(row, "actor"), 160), "message": _text(_row_value(row, "message"), 2000), "data": _loads(_row_value(row, "data_json"))}},
    )
    run_event_stream(
        "intelligence_job_events",
        "SELECT event_id, job_id, event_type, actor, message, data_json, created_at FROM intelligence_job_events ORDER BY event_id",
        lambda row: {"event_id": f"intelligence-event:{_row_value(row, 'event_id')}", "entity_id": canonical_entity_id("intelligence_job", "secopsai", _row_value(row, "job_id")), "event_type": _row_value(row, "event_type"), "source": "core", "source_record_id": _row_value(row, "event_id"), "occurred_at": _row_value(row, "created_at"), "summary": {"actor": _text(_row_value(row, "actor"), 160), "message": _text(_row_value(row, "message"), 2000), "data": _loads(_row_value(row, "data_json"))}},
    )
    run_event_stream(
        "daily_automation_steps",
        "SELECT step_id, run_id, step_name, status, started_at, completed_at, result_json, error_message FROM daily_automation_steps ORDER BY step_id",
        lambda row: {"event_id": f"daily-step:{_row_value(row, 'step_id')}", "entity_id": canonical_entity_id("automation_run", "secopsai", _row_value(row, "run_id")), "event_type": f"step:{_row_value(row, 'step_name')}", "source": "secopsai-research", "source_record_id": _row_value(row, "step_id"), "occurred_at": _row_value(row, "completed_at") or _row_value(row, "started_at"), "summary": {"status": _row_value(row, "status"), "result": _loads(_row_value(row, "result_json")), "error_message": _text(_row_value(row, "error_message"), 1000)}},
    )
    run_event_stream(
        "pipeline_steps",
        "SELECT step_id, pipeline_id, step_key, step_order, status, intelligence_job_id, result_json, error_code, error_message, started_at, completed_at, updated_at FROM research_pipeline_steps ORDER BY step_id",
        lambda row: {"event_id": f"pipeline-step:{_row_value(row, 'step_id')}", "entity_id": canonical_entity_id("automation_run", "secopsai", _row_value(row, "pipeline_id")), "event_type": f"step:{_row_value(row, 'step_key')}", "source": "secopsai-research", "source_record_id": _row_value(row, "step_id"), "occurred_at": _row_value(row, "completed_at") or _row_value(row, "updated_at") or _row_value(row, "started_at"), "summary": {"status": _row_value(row, "status"), "step_order": _row_value(row, "step_order"), "intelligence_job_id": _row_value(row, "intelligence_job_id"), "result": _loads(_row_value(row, "result_json")), "error_code": _text(_row_value(row, "error_code"), 120), "error_message": _text(_row_value(row, "error_message"), 1000)}},
    )
    # Evidence and registry observations are first-class timeline inputs.  A
    # bounded event summary preserves provenance without copying raw research
    # payloads, and the stream's endpoint check below skips rows whose owning
    # entity was not projected in this database.
    run_event_stream(
        "evidence_events",
        "SELECT evidence_id, case_id, evidence_type, title, locator, sha256, provenance, status, collected_at, created_at, first_observed_at, last_observed_at FROM research_evidence ORDER BY evidence_id",
        lambda row: {
            "event_id": f"evidence-observed:{_row_value(row, 'evidence_id')}",
            "entity_id": _evidence_id_from_values(_row_value(row, "case_id"), _row_value(row, "evidence_id")),
            "event_type": "evidence_observed",
            "source": "secopsai-research",
            "source_record_id": _row_value(row, "evidence_id"),
            "occurred_at": _row_value(row, "last_observed_at") or _row_value(row, "first_observed_at") or _row_value(row, "collected_at") or _row_value(row, "created_at") or UNKNOWN_OBSERVED_AT,
            "summary": {
                "case_id": _text(_row_value(row, "case_id"), 256),
                "evidence_type": _text(_row_value(row, "evidence_type"), 120),
                "title": _text(_row_value(row, "title"), 512),
                "locator": sanitize_locator(_row_value(row, "locator")),
                "sha256": _text(_row_value(row, "sha256"), 128),
                "provenance": _text(_row_value(row, "provenance"), 1000),
                "status": _text(_row_value(row, "status"), 80),
            },
        },
    )
    run_event_stream(
        "registry_events",
        "SELECT event_id, source_id, ecosystem, package, version, publisher, source_url, artifact_url, artifact_sha256, observed_at, provenance_json FROM research_registry_events ORDER BY event_id",
        lambda row: {
            "event_id": f"registry-observed:{_row_value(row, 'event_id')}",
            "entity_id": canonical_entity_id("release_event", "registry", _row_value(row, "event_id")),
            "event_type": "release_observed",
            "source": "registry",
            "source_record_id": _row_value(row, "event_id"),
            "occurred_at": _row_value(row, "observed_at") or UNKNOWN_OBSERVED_AT,
            "summary": {
                "source_id": _text(_row_value(row, "source_id"), 256),
                "ecosystem": _text(_row_value(row, "ecosystem"), 120),
                "package": _text(_row_value(row, "package"), 512),
                "version": _text(_row_value(row, "version"), 256),
                "publisher": _text(_row_value(row, "publisher"), 512),
                "source_url": sanitize_locator(_row_value(row, "source_url")),
                "artifact_url": sanitize_locator(_row_value(row, "artifact_url")),
                "artifact_sha256": _text(_row_value(row, "artifact_sha256"), 128),
                "provenance": _loads(_row_value(row, "provenance_json")),
            },
        },
    )

    def run_relationship_table() -> None:
        def apply_items(items: list[dict[str, Any]]) -> None:
            if not items:
                return
            with sqlite_writer_lock(db_path):
                with soc_store.connect(db_path) as connection:
                    now = utc_now()
                    for raw_item in items:
                        # The source/cursor markers are local backfill metadata;
                        # never persist them in ontology properties or pending
                        # payloads.  They let this older projection family use
                        # the same durable retry path as the newer streams.
                        item = {
                            key: value
                            for key, value in raw_item.items()
                            if not key.startswith("_pending_")
                        }
                        stream_key = _text(raw_item.get("_pending_stream"), 160)
                        source_cursor = raw_item.get("_pending_cursor")
                        item_index = int(raw_item.get("_pending_index") or 0)
                        pending_error = raw_item.get("_pending_error")
                        terminal = bool(raw_item.get("_pending_terminal"))
                        if pending_error:
                            counts["skipped_relationships"] += 1
                            bump(stream_key or key, "failed" if terminal else "skipped")
                            if stream_key:
                                queue_pending_connection(
                                    connection,
                                    stream_key=stream_key,
                                    item_kind="relationship",
                                    source_cursor=source_cursor,
                                    item_index=item_index,
                                    item=item,
                                    error=pending_error,
                                    terminal=terminal,
                                )
                            continue
                        if not isinstance(item, dict):
                            counts["skipped_relationships"] += 1
                            bump(stream_key or key, "skipped")
                            continue
                        relationship_id = _text(item.get("relationship_id") or item.get("edge_id"), 512) or _semantic_relationship_id(item)
                        existed = connection.execute(
                            "SELECT 1 FROM ontology_relationships WHERE relationship_id = ?",
                            (relationship_id,),
                        ).fetchone() is not None
                        applied, error = apply_relationship_connection(connection, item, now=now)
                        if applied:
                            counts["relationships"] += 1
                            bump(stream_key or key, "updated" if existed else "inserted")
                            continue
                        counts["skipped_relationships"] += 1
                        bump(stream_key or key, "skipped")
                        if stream_key:
                            queue_pending_connection(
                                connection,
                                stream_key=stream_key,
                                item_kind="relationship",
                                source_cursor=source_cursor,
                                item_index=item_index,
                                item=item,
                                error=error,
                                terminal=terminal or error in {
                                    "relationship endpoints are identical",
                                    "relationship projection is not an object",
                                } or (
                                    error == "relationship endpoints are missing"
                                    and not ("from_entity_id" in item or "to_entity_id" in item)
                                ),
                            )
                    connection.commit()

        def run_source(key: str, query: str, builder: Any, *, cursor_field: str | None = None) -> None:
            # Resolve rows left behind by an earlier source ordering before
            # reading forward from the checkpoint.  This makes a completed
            # source checkpoint safe even when entities were projected later.
            def retry_handler(connection: Any, item: Any) -> tuple[bool, str]:
                if key == "relationships:graph_edges" and isinstance(item, dict):
                    # Graph endpoints can be projected with a more specific
                    # entity type (for example service) after the edge row was
                    # first observed.  Re-resolve the original node IDs before
                    # retrying instead of persisting an empty/guessed ID.
                    item = dict(item)
                    from_node = _text(item.get("graph_from_node_id"), 512)
                    to_node = _text(item.get("graph_to_node_id"), 512)
                    if from_node and from_node in graph_map:
                        item["from_entity_id"] = graph_map[from_node]
                    if to_node and to_node in graph_map:
                        item["to_entity_id"] = graph_map[to_node]
                return apply_relationship_connection(connection, item)

            retry_pending(key, "relationship", retry_handler, force=True)
            state = checkpoint(key)
            while True:
                with soc_store.read_connect(db_path) as connection:
                    probe = connection.execute(f"{query} LIMIT 1").fetchone()
                    field = cursor_field or (str(probe.keys()[0]) if probe is not None else "")
                    rows = page_rows(connection, query, state, field) if probe is not None else []
                if not rows:
                    save_checkpoint(key, int(state["offset"]), True, state.get("cursor"))
                    return
                bump(key, "scanned", len(rows))
                items: list[dict[str, Any]] = []
                for row in rows:
                    source_cursor = row[field]
                    try:
                        built = builder(row)
                    except (KeyError, TypeError, ValueError) as exc:
                        items.append(
                            {
                                "_pending_stream": key,
                                "_pending_cursor": source_cursor,
                                "_pending_index": 0,
                                "_pending_error": f"relationship builder failed: {exc}",
                                "_pending_terminal": True,
                            }
                        )
                        continue
                    built_items = built if isinstance(built, list) else [built]
                    for item_index, item in enumerate(built_items):
                        if not isinstance(item, dict):
                            items.append(
                                {
                                    "_pending_stream": key,
                                    "_pending_cursor": source_cursor,
                                    "_pending_index": item_index,
                                    "_pending_error": "relationship builder returned no projection",
                                    "_pending_terminal": True,
                                }
                            )
                            continue
                        marked = dict(item)
                        marked.update(
                            {
                                "_pending_stream": key,
                                "_pending_cursor": source_cursor,
                                "_pending_index": item_index,
                            }
                        )
                        items.append(marked)
                apply_items(items)
                state["offset"] = int(state["offset"]) + len(rows)
                field = cursor_field or str(rows[-1].keys()[0])
                state["cursor"] = rows[-1][field]
                save_checkpoint(key, int(state["offset"]), len(rows) < limit, state.get("cursor"))
                if len(rows) < limit:
                    return

        with soc_store.read_connect(db_path) as connection:
            graph_rows = connection.execute("SELECT node_id, node_type, source FROM asset_graph_nodes").fetchall()
        graph_map: dict[str, str] = {}
        for node in graph_rows:
            raw_node = str(node["node_id"])
            mapped_node_type = str(node["node_type"] or "asset")
            mapped_node_type = mapped_node_type if mapped_node_type in ENTITY_TYPES else ("asset" if mapped_node_type in {"site", "sensor", "service", "wifi_network"} else "source")
            graph_map[raw_node] = _stable_legacy_id(mapped_node_type, str(node["source"] or "legacy"), raw_node)

        run_source(
            "relationships:graph_edges",
            "SELECT edge_id, edge_type, from_node_id, to_node_id, source, properties_json, first_seen, last_seen FROM asset_graph_edges ORDER BY edge_id",
            lambda row: ({"relationship_id": str(row["edge_id"]), "relationship_type": LEGACY_EDGE_RELATIONS[str(row["edge_type"] or "")], "from_entity_id": graph_map.get(str(row["from_node_id"]), ""), "to_entity_id": graph_map.get(str(row["to_node_id"]), ""), "graph_from_node_id": str(row["from_node_id"]), "graph_to_node_id": str(row["to_node_id"]), "graph_edge_type": str(row["edge_type"] or ""), "source": str(row["source"] or "legacy"), "source_record_id": str(row["edge_id"]), "properties": _loads(row["properties_json"]), "observed_at": str(row["last_seen"]), "valid_from": str(row["first_seen"]), "freshness_at": str(row["last_seen"])} if str(row["edge_type"] or "") in LEGACY_EDGE_RELATIONS else None),
        )
        run_source(
            "relationships:case_findings",
            "SELECT case_id || ':' || finding_id AS backfill_key, case_id, finding_id, relationship, created_at FROM research_case_findings ORDER BY backfill_key",
            lambda row: {"relationship_type": "CASE_GROUPS_FINDING", "from_entity_id": _stable_legacy_id("research_case", "secopsai", str(row["case_id"])), "to_entity_id": _stable_legacy_id("finding", "secopsai", str(row["finding_id"])), "source": "secopsai-research", "source_record_id": f"{row['case_id']}:{row['finding_id']}", "properties": {"relationship": row["relationship"]}, "observed_at": str(row["created_at"] or UNKNOWN_OBSERVED_AT)},
            cursor_field="backfill_key",
        )
        run_source(
            "relationships:alerts",
            "SELECT alert_id, case_id, updated_at FROM research_alerts WHERE case_id <> '' ORDER BY alert_id",
            lambda row: {"relationship_type": "CASE_GROUPS_ALERT", "from_entity_id": _stable_legacy_id("research_case", "secopsai", str(row["case_id"])), "to_entity_id": _stable_legacy_id("alert", "secopsai", str(row["alert_id"])), "source": "secopsai-research", "source_record_id": str(row["alert_id"]), "properties": {"relation": "alert_case"}, "observed_at": str(row["updated_at"] or UNKNOWN_OBSERVED_AT)},
        )
        run_source(
            "relationships:candidates",
            "SELECT candidate_id, case_id, last_seen FROM research_candidates WHERE case_id <> '' ORDER BY candidate_id",
            lambda row: {"relationship_type": "CANDIDATE_PROMOTED_TO_CASE", "from_entity_id": _stable_legacy_id("candidate", "secopsai", str(row["candidate_id"])), "to_entity_id": _stable_legacy_id("research_case", "secopsai", str(row["case_id"])), "source": "secopsai-research", "source_record_id": f"{row['candidate_id']}:{row['case_id']}", "properties": {"relation": "candidate_case"}, "observed_at": str(row["last_seen"] or UNKNOWN_OBSERVED_AT)},
        )

    run_relationship_table()
    # Surface unresolved projections in the returned summary and metadata.
    # A completed source checkpoint with pending rows is intentionally
    # reported as degraded work rather than a clean zero-loss backfill.
    counts["pending_backfill"] = pending_count()
    with sqlite_writer_lock(db_path):
        with soc_store.connect(db_path) as connection:
            now = utc_now()
            backfill_status = "degraded" if counts["pending_backfill"] or counts["skipped_relationships"] else "completed"
            connection.execute("INSERT INTO ontology_metadata (key, value_json, updated_at) VALUES ('backfill:run', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at", (bounded_json({"status": backfill_status, "completed_at": now, "counts": counts}, MAX_SUMMARY_BYTES), now))
            connection.commit()
    return {"status": backfill_status, "schema_version": SCHEMA_VERSION, **counts, "quality": quality(db_path=db_path)}
