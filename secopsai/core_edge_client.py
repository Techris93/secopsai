"""Small, failure-tolerant client for the hosted Core coordinator.

The research worker remains the execution plane.  This module only exchanges
bounded, redacted state with the Cloudflare control plane and never makes
surveillance depend on a network request succeeding.
"""

from __future__ import annotations

import json
import hashlib
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from threading import Event, Thread
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

import soc_store
from secopsai.intelligence import minimize
from secopsai.sqlite_writer_lock import sqlite_writer_lock


MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
MAX_COMMAND_RESULT_BYTES = 28 * 1024
DEFAULT_URL = "https://core.secopsai.dev"


def _clean(value: Any, limit: int = 2000) -> str:
    return str(value or "").strip()[:limit]


def _bounded_json(value: Any, limit: int = MAX_REQUEST_BYTES, *, preserve_lists: bool = False) -> dict[str, Any]:
    """Return a bounded object without silently dropping ontology records.

    The general intelligence wire format deliberately caps nested lists.  An
    ontology snapshot is already compacted by ``_compact_ontology_snapshot``;
    applying the generic minimizer a second time used to discard all but the
    first 100 entities while still returning a successful request.  Keep the
    explicit snapshot bounds intact and only redact/limit when requested by
    other control-plane payloads.
    """
    cleaned = value if preserve_lists and isinstance(value, dict) else minimize(value if isinstance(value, dict) else {})
    encoded = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) > limit:
        return {"status": "truncated", "bytes": len(encoded.encode("utf-8"))}
    return cleaned


def _bounded_bridge_state(value: dict[str, Any]) -> dict[str, Any]:
    """Minimize runner telemetry while retaining the lease proof fields."""
    cleaned = _bounded_json(value, preserve_lists=False)
    if not isinstance(cleaned, dict):
        cleaned = {}
    for key in ("process_generation", "process_revision", "process_started_at", "lease_token"):
        if key in value:
            cleaned[key] = value[key]
    return cleaned


def _bounded_bridge_command(value: dict[str, Any]) -> dict[str, Any]:
    """Minimize command receipts while retaining the terminal-write proof."""
    cleaned = _bounded_json(value, preserve_lists=False)
    if not isinstance(cleaned, dict):
        cleaned = {}
    for key in ("worker_id", "lease_generation", "lease_token"):
        if key in value:
            cleaned[key] = value[key]
    return cleaned


def _json_size(value: Any) -> int:
    # ``_compact_ontology_snapshot`` performs its own redaction and list
    # budgeting.  Measuring through ``intelligence.minimize`` would cap every
    # list at 100 and make the size calculation disagree with the bytes sent
    # on the wire.
    return len(json.dumps(value if isinstance(value, dict) else {}, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))


def _nested_data_was_bounded(value: Any, *, depth: int = 0) -> bool:
    """Report when the generic minimizer will remove nested source detail.

    ``intelligence.minimize`` intentionally bounds nested maps/lists for
    control-plane payloads.  Ontology records must remain loss-aware: a
    compacted record carries a marker whenever this minimization discarded
    nested values, even if the resulting record still fits the request.
    """
    if depth > 8:
        return True
    if isinstance(value, dict):
        if len(value) > 100:
            return True
        for key, item in value.items():
            if len(str(key)) > 120 or _nested_data_was_bounded(item, depth=depth + 1):
                return True
        return False
    if isinstance(value, (list, tuple, set)):
        if len(value) > 100:
            return True
        return any(_nested_data_was_bounded(item, depth=depth + 1) for item in value)
    return isinstance(value, str) and len(value) > 4000


def _compact_ontology_snapshot(snapshot: Dict[str, Any]) -> dict[str, Any]:
    """Fit a semantic snapshot under the Core request bound without losing its shape.

    The worker may observe a dense cycle.  Sending ``{"status": "truncated"}``
    would look like a successful sync while silently dropping every entity, so
    trim the oldest/least useful list items and optional descriptions first.
    """
    payload = dict(snapshot or {})
    payload.setdefault("schema_version", "secopsai.ontology.v1")
    payload.setdefault("source_instance", "research-worker")
    for key in ("entities", "relationships", "events", "evidence_refs"):
        value = payload.get(key)
        payload[key] = list(value) if isinstance(value, list) else []
    payload["snapshot_truncated"] = False
    target = MAX_REQUEST_BYTES - 512
    if _json_size(payload) <= target:
        return payload

    # Remove optional detail from oversized records before dropping whole
    # records.  This preserves a useful identity/provenance envelope whenever
    # possible.
    if _json_size(payload) > target:
        for key in ("entities", "relationships", "events", "evidence_refs"):
            compacted = []
            for item in payload[key]:
                if not isinstance(item, dict):
                    continue
                entry = dict(item)
                for optional in ("properties", "aliases", "summary"):
                    entry.pop(optional, None)
                compacted.append(entry)
            payload[key] = compacted
        payload["snapshot_truncated"] = True

    # Keep the newest bounded records first (materialize_recent already orders
    # them that way) and progressively halve the largest collection.
    while _json_size(payload) > target and any(payload[key] for key in ("entities", "relationships", "events", "evidence_refs")):
        largest = max((key for key in ("entities", "relationships", "events", "evidence_refs") if payload[key]), key=lambda key: _json_size({key: payload[key]}))
        current = payload[largest]
        # Always make progress.  A singleton can be oversized because of its
        # properties; remove optional fields before deciding whether to retain
        # the identity record.  Keeping one item forever caused a tight loop
        # that blocked the research worker's coordinator cycle.
        keep = len(current) // 2
        payload[largest] = current[:keep]
        payload["snapshot_truncated"] = True

    if _json_size(payload) > target:
        for key in ("entities", "relationships", "events", "evidence_refs"):
            while payload[key] and _json_size(payload) > target:
                payload[key].pop()
                payload["snapshot_truncated"] = True

    # Keep graph batches internally consistent after list trimming.  A
    # relationship/event that points at an entity removed above would be
    # rejected by Core and would make an otherwise useful partial snapshot
    # impossible to apply.  References to entities that were not present in
    # the original batch are retained because they may already exist in D1.
    original_entity_ids = {
        str(item.get("entity_id"))
        for item in (snapshot.get("entities") if isinstance(snapshot, dict) and isinstance(snapshot.get("entities"), list) else [])
        if isinstance(item, dict) and item.get("entity_id")
    }
    kept_entity_ids = {str(item.get("entity_id")) for item in payload["entities"] if isinstance(item, dict) and item.get("entity_id")}
    if original_entity_ids != kept_entity_ids:
        def endpoint_kept(item: Any) -> bool:
            if not isinstance(item, dict):
                return False
            endpoints = [item.get("from_entity_id") or item.get("from"), item.get("to_entity_id") or item.get("to")]
            return all(not endpoint or str(endpoint) not in original_entity_ids or str(endpoint) in kept_entity_ids for endpoint in endpoints)

        payload["relationships"] = [item for item in payload["relationships"] if endpoint_kept(item)]
        payload["events"] = [item for item in payload["events"] if not isinstance(item, dict) or not item.get("entity_id") or str(item.get("entity_id")) not in original_entity_ids or str(item.get("entity_id")) in kept_entity_ids]

    # This final fallback preserves a valid, observable heartbeat-shaped sync
    # rather than allowing _bounded_json to replace the entire payload marker.
    if _json_size(payload) > target:
        payload = {
            "schema_version": payload.get("schema_version", "secopsai.ontology.v1"),
            "source_instance": _clean(payload.get("source_instance"), 160) or "research-worker",
            "exported_at": _clean(payload.get("exported_at"), 64),
            "entities": [],
            "relationships": [],
            "events": [],
            "evidence_refs": [],
            "snapshot_truncated": True,
        }
    return payload


def _ontology_sync_chunks(snapshot: Dict[str, Any]) -> list[dict[str, Any]]:
    """Split an ontology snapshot into dependency-safe, bounded requests.

    D1 validates relationship and event endpoints during ingestion.  When a
    snapshot is larger than one request, entities therefore go first, followed
    by evidence, relationships, and events.  Every source record is retained;
    only optional descriptive fields are removed from an individual record
    when that record itself would exceed the request budget.
    """
    source = dict(snapshot or {})
    base: dict[str, Any] = {
        "schema_version": _clean(source.get("schema_version"), 80) or "secopsai.ontology.v1",
        "source_instance": _clean(source.get("source_instance"), 160) or "research-worker",
    }
    for envelope_key in ("organization_id", "workspace_id", "exported_at"):
        if source.get(envelope_key) is not None:
            base[envelope_key] = _clean(source.get(envelope_key), 160 if envelope_key != "exported_at" else 64)

    target = MAX_REQUEST_BYTES - 512
    records_by_kind = {
        "entities": source.get("entities") if isinstance(source.get("entities"), list) else [],
        "evidence_refs": source.get("evidence_refs") if isinstance(source.get("evidence_refs"), list) else [],
        "relationships": source.get("relationships") if isinstance(source.get("relationships"), list) else [],
        "events": source.get("events") if isinstance(source.get("events"), list) else [],
    }
    optional_fields = ("properties", "aliases", "summary")
    required_fields = {
        "entities": ("entity_id", "entity_type", "namespace", "canonical_key", "display_name", "source", "source_id", "workspace_id", "owner_id", "status", "confidence", "first_seen_at", "last_seen_at", "observed_at", "freshness_at", "valid_from", "valid_to", "schema_version"),
        "evidence_refs": ("evidence_ref_id", "source", "locator", "content_hash", "content_type", "workspace_id", "observed_at"),
        "relationships": ("relationship_id", "relationship_type", "from_entity_id", "to_entity_id", "source", "source_record_id", "workspace_id", "evidence_ref_id", "confidence", "observed_at", "valid_from", "valid_to", "freshness_at"),
        "events": ("event_id", "entity_id", "event_type", "source", "source_record_id", "occurred_at"),
    }
    dropped_detail = False

    def fit_record(kind: str, raw: Any) -> dict[str, Any]:
        nonlocal dropped_detail
        source_record = raw if isinstance(raw, dict) else {}
        nested_truncated = _nested_data_was_bounded(source_record)
        record = minimize(source_record)
        if not isinstance(record, dict):
            record = {}
        if nested_truncated:
            record["_secopsai_truncated"] = True
            dropped_detail = True
        if _json_size({**base, kind: [record]}) <= target:
            return record
        for field in optional_fields:
            if field in record:
                record.pop(field, None)
                dropped_detail = True
                if _json_size({**base, kind: [record]}) <= target:
                    return record
        # Keep the identity/provenance envelope even when a producer supplied
        # unexpected, very large fields.  IDs and timestamps are bounded before
        # they reach this path, so this fallback remains below the wire limit.
        record = {key: record[key] for key in required_fields[kind] if key in record}
        if nested_truncated:
            record["_secopsai_truncated"] = True
        for key, value in list(record.items()):
            if isinstance(value, str):
                record[key] = value[:512]
        dropped_detail = True
        if _json_size({**base, kind: [record]}) > target:
            raise ValueError(f"{kind} record cannot fit the bounded ontology request")
        return record

    chunks: list[dict[str, Any]] = []
    for kind in ("entities", "evidence_refs", "relationships", "events"):
        current: list[dict[str, Any]] = []
        for raw in records_by_kind[kind]:
            record = fit_record(kind, raw)
            candidate = {**base, kind: [*current, record]}
            if current and _json_size(candidate) > target:
                chunks.append({**base, kind: current})
                current = []
                candidate = {**base, kind: [record]}
            if _json_size(candidate) > target:
                raise ValueError(f"{kind} record cannot fit the bounded ontology request")
            current.append(record)
        if current:
            chunks.append({**base, kind: current})
    if not chunks:
        chunks = [dict(base)]
    for index, chunk in enumerate(chunks):
        chunk["snapshot_chunk_index"] = index
        chunk["snapshot_chunk_count"] = len(chunks)
        chunk["snapshot_truncated"] = dropped_detail
        if _json_size(chunk) > target:
            raise ValueError("ontology snapshot chunk exceeds the bounded request size")
    return chunks


def _ontology_idempotency_key(payload: Dict[str, Any]) -> str:
    material = dict(payload or {})
    material.pop("idempotency_key", None)
    # Export snapshots carry observation timestamps for operator visibility;
    # those envelope timestamps are not content identity and must not create a
    # new receipt on every worker cycle.
    for volatile in ("exported_at", "generated_at", "synced_at"):
        material.pop(volatile, None)
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _ontology_chunk_counts(chunk: Dict[str, Any]) -> dict[str, int]:
    return {
        key: len(chunk.get(key) or [])
        for key in ("entities", "relationships", "events", "evidence_refs")
        if isinstance(chunk.get(key), list) and chunk.get(key)
    }


def _merge_counts(target: dict[str, int], source: Dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, int):
            target[key] = target.get(key, 0) + value


def _compact_command_result(value: Any) -> dict[str, Any]:
    """Keep coordinator receipts small while preserving reconciliation keys."""
    if not isinstance(value, dict):
        return {"status": "succeeded", "result": str(value)[:1000]}
    status = _clean(value.get("status"), 40)
    compact: dict[str, Any] = {"status": status or "succeeded"}
    for key in ("run_id", "started_at", "completed_at", "next_run_at", "error"):
        if value.get(key) is not None:
            compact[key] = _clean(value.get(key), 2000)
    summary = value.get("summary")
    if isinstance(summary, dict):
        compact["summary"] = _bounded_json(
            {key: summary.get(key) for key in ("status", "completed_steps", "failed_steps", "error") if summary.get(key) is not None},
            limit=4 * 1024,
        )
    queued = value.get("queued")
    if isinstance(queued, list):
        compact["queued"] = [
            {key: item.get(key) for key in ("run_id", "finding_id", "job_id", "status", "selected_model") if item.get(key) is not None}
            for item in queued[:100]
            if isinstance(item, dict)
        ]
    steps = value.get("steps")
    if isinstance(steps, list):
        compact["steps"] = []
        for step in steps[:32]:
            if not isinstance(step, dict):
                continue
            entry = {key: step.get(key) for key in ("step_name", "status", "started_at", "completed_at", "error", "error_message") if step.get(key) is not None}
            result = step.get("result")
            if isinstance(result, dict):
                entry["result"] = {key: result.get(key) for key in ("status", "run_id", "count", "processed", "sent", "failed", "error") if result.get(key) is not None}
            compact["steps"].append(entry)
    # The edge route has its own 32 KiB bound. Drop optional detail if needed.
    encoded = json.dumps(minimize(compact), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    if len(encoded) <= MAX_COMMAND_RESULT_BYTES:
        return minimize(compact)
    compact.pop("steps", None)
    encoded = json.dumps(minimize(compact), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    if len(encoded) <= MAX_COMMAND_RESULT_BYTES:
        return minimize(compact)
    compact.pop("queued", None)
    return minimize(compact)


def _compact_cycle_component(value: Any, *, limit: int = 12 * 1024) -> dict[str, Any]:
    """Keep the heartbeat's cycle summary observable and bounded.

    ``run_worker_cycle`` intentionally returns rich local diagnostics.  The
    heartbeat is a hosted status record, however, and copying a full daily
    automation result (including every step payload) can exceed the Edge/D1
    bound.  Returning a small status envelope prevents the whole coordinator
    object from being replaced by a generic ``truncated`` marker.
    """
    if not isinstance(value, dict):
        return {}
    source = value.get("run") if isinstance(value.get("run"), dict) else value
    compact: dict[str, Any] = {}
    scalar_keys = (
        "status",
        "run_id",
        "generation",
        "started_at",
        "completed_at",
        "next_run_at",
        "lease_until",
        "error",
        "error_message",
        "error_code",
        "collectors_run",
        "queue_age_seconds",
        "queue_depth",
        "deferred",
        "failed",
        "sent",
        "attempted",
    )
    for key in scalar_keys:
        candidate = source.get(key)
        if candidate is None and source is not value:
            candidate = value.get(key)
        if candidate is not None:
            compact[key] = _clean(candidate, 2000) if isinstance(candidate, str) else candidate
    settings = value.get("settings")
    if isinstance(settings, dict):
        compact["settings"] = {
            key: settings.get(key)
            for key in ("enabled", "interval_hours", "interval_seconds", "daily_enabled", "triage_enabled")
            if settings.get(key) is not None
        }
    steps = source.get("steps")
    if isinstance(steps, list):
        compact["steps"] = [
            {
                key: (_clean(step.get(key), 2000) if isinstance(step.get(key), str) else step.get(key))
                for key in ("step_id", "step_name", "status", "started_at", "completed_at", "error", "error_message")
                if step.get(key) is not None
            }
            for step in steps[:32]
            if isinstance(step, dict)
        ]
    bounded = _bounded_json(compact, limit=limit)
    return bounded if isinstance(bounded, dict) else {}


@dataclass(frozen=True)
class CoreEdgeSettings:
    url: str
    token: str
    worker_id: str
    timeout_seconds: int = 15

    @classmethod
    def from_environment(cls) -> "CoreEdgeSettings":
        url = (
            os.environ.get("SECOPSAI_CORE_COORDINATOR_URL", "").strip()
            or os.environ.get("SECOPSAI_CORE_API_URL", "").strip()
            or DEFAULT_URL
        ).rstrip("/")
        token = (
            os.environ.get("SECOPSAI_CORE_BRIDGE_TOKEN", "").strip()
            or os.environ.get("SECOPSAI_CODEX_BRIDGE_TOKEN", "").strip()
        )
        worker_id = os.environ.get("SECOPSAI_CORE_WORKER_ID", "").strip() or f"{socket.gethostname()}:{os.getpid()}"
        raw_timeout = os.environ.get("SECOPSAI_CORE_COORDINATOR_TIMEOUT_SECONDS", "15").strip()
        try:
            timeout = max(3, min(int(raw_timeout), 60))
        except ValueError:
            timeout = 15
        return cls(url=url, token=token, worker_id=worker_id[:160], timeout_seconds=timeout)

    @property
    def enabled(self) -> bool:
        return bool(self.token and (self.url.startswith("https://") or self.url.startswith("http://127.0.0.1") or self.url.startswith("http://localhost")))


class CoreEdgeClient:
    def __init__(self, settings: Optional[CoreEdgeSettings] = None, session: Any = None) -> None:
        self.settings = settings or CoreEdgeSettings.from_environment()
        self.session = session or requests.Session()
        self.last_error: str = ""
        # A process lease is independent of worker_id. A restarted worker may
        # reuse that configured ID, so each process gets a fresh proof token
        # and monotonically useful generation value.
        # Microseconds stay within JavaScript's safe integer range while being
        # newer than a normal persisted generation on process restart.
        self.process_generation: int = time.time_ns() // 1000
        # Prefer a deployment/source revision so hosted state can be correlated
        # across restarts; local development falls back to a per-process UUID.
        self.process_revision: str = next(
            (
                _clean(os.environ.get(name), 200)
                for name in ("SECOPSAI_BUILD_REVISION", "RENDER_GIT_COMMIT", "GIT_COMMIT")
                if _clean(os.environ.get(name), 200)
            ),
            uuid.uuid4().hex,
        )
        self.process_started_at: str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.process_lease_token: str = uuid.uuid4().hex
        self.last_ontology_sync: dict[str, Any] = {"status": "unknown", "chunks": 0}

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[dict[str, Any]] = None,
        *,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled"}
        request_headers = {
            "Authorization": f"Bearer {self.settings.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SecOpsAI-Research/1.0",
        }
        if headers:
            request_headers.update({str(key): str(value) for key, value in headers.items()})
        body = (
            _bounded_bridge_state(payload or {})
            if path == "/api/v1/intelligence/bridge/state"
            else _bounded_bridge_command(payload or {})
            if path.startswith("/api/v1/intelligence/bridge/commands/")
            else _bounded_json(payload or {}, preserve_lists=path == "/api/v1/ontology/sync")
        )
        if path == "/api/v1/ontology/sync" and isinstance(body, dict) and body.get("status") == "truncated":
            # A marker-only request would be accepted by older Core versions
            # while dropping the entire snapshot. Surface it as a degraded
            # control-plane result so the caller can retain/retry the source
            # payload instead of reporting a false successful sync.
            raise ValueError("ontology snapshot exceeds the bounded request size")
        response = self.session.request(
            method,
            f"{self.settings.url}{path}",
            headers=request_headers,
            json=body,
            timeout=self.settings.timeout_seconds,
            allow_redirects=False,
        )
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise RuntimeError("hosted Core response exceeds the local limit")
        try:
            result = response.json()
        except ValueError as exc:
            raise RuntimeError(f"hosted Core returned invalid JSON ({response.status_code})") from exc
        if not isinstance(result, dict):
            raise RuntimeError("hosted Core response must be an object")
        if not response.ok:
            detail = _clean(result.get("detail") or result.get("error") or "request failed", 500)
            raise RuntimeError(f"hosted Core rejected {path} ({response.status_code}): {detail}")
        return result

    def sync_state(self, summary: Dict[str, Any], *, status: str = "healthy") -> dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled"}
        storage = summary.get("storage") if isinstance(summary, dict) else {}
        hosted_commands = []
        if isinstance(summary, dict) and isinstance(summary.get("hosted_coordinator"), dict):
            for item in (summary["hosted_coordinator"].get("commands") or [])[:5]:
                if not isinstance(item, dict):
                    continue
                hosted_commands.append({
                    "command_id": _clean(item.get("command_id"), 100),
                    "command_type": _clean(item.get("command_type"), 80),
                    "status": _clean(item.get("status"), 40),
                    "result": _compact_command_result(item.get("result") or {}),
                })
        ontology_summary = self.last_ontology_sync
        if isinstance(summary, dict):
            candidate = summary.get("ontology_sync") or summary.get("ontology")
            if isinstance(candidate, dict):
                ontology_summary = candidate
        payload = {
            "worker_id": self.settings.worker_id,
            "process_generation": self.process_generation,
            "process_revision": self.process_revision,
            "process_started_at": self.process_started_at,
            "lease_token": self.process_lease_token,
            "status": _clean(status, 40) or "healthy",
            "last_cycle_at": _clean(summary.get("completed_at") if isinstance(summary, dict) else "", 64),
            "last_cycle_status": _clean(summary.get("status") if isinstance(summary, dict) else "succeeded", 40) or "succeeded",
            "storage": _bounded_json(storage if isinstance(storage, dict) else {}, 16 * 1024),
            "coordinator": _bounded_json({
                "collectors_run": summary.get("collectors_run") if isinstance(summary, dict) else None,
                "daily_automation": _compact_cycle_component(summary.get("daily_automation")) if isinstance(summary, dict) else {},
                "alert_delivery": _compact_cycle_component(summary.get("alert_delivery")) if isinstance(summary, dict) else {},
                "hosted_commands": hosted_commands,
                "ontology": _bounded_json({
                    "status": _clean(ontology_summary.get("status"), 40) or "unknown",
                    "counts": ontology_summary.get("counts") if isinstance(ontology_summary.get("counts"), dict) else {},
                    "chunks": ontology_summary.get("chunks", 0),
                    "accepted_chunk_ids": ontology_summary.get("accepted_chunk_ids", []),
                    "rejected_chunk_ids": ontology_summary.get("rejected_chunk_ids", []),
                    "accepted_chunks": ontology_summary.get("accepted_chunks", 0),
                    "rejected_chunks": ontology_summary.get("rejected_chunks", 0),
                    "error": _clean(ontology_summary.get("error"), 2000),
                }, 16 * 1024),
            }, 16 * 1024),
            "error_message": _clean(summary.get("error") if isinstance(summary, dict) else "", 2000),
        }
        try:
            result = self._request("POST", "/api/v1/intelligence/bridge/state", payload)
            self.last_error = ""
            return result
        except Exception as exc:  # network failure must not stop collection
            self.last_error = _clean(exc, 500)
            return {"status": "degraded", "error": self.last_error}

    def sync_ontology(self, snapshot: Dict[str, Any]) -> dict[str, Any]:
        """Send a bounded semantic snapshot without making collection depend on it."""
        if not self.enabled:
            result = {
                "status": "disabled",
                "chunks": 0,
                "chunk_count": 0,
                "accepted_chunks": 0,
                "rejected_chunks": 0,
                "accepted_chunk_count": 0,
                "rejected_chunk_count": 0,
                "accepted_chunk_ids": [],
                "rejected_chunk_ids": [],
                "chunk_results": [],
                "accepted_counts": {},
                "rejected_counts": {},
                "idempotent": False,
            }
            self.last_ontology_sync = result
            return result
        try:
            payload = dict(snapshot or {})
            payload.setdefault("source_instance", self.settings.worker_id)
            chunks = _ontology_sync_chunks(payload)
            results: list[dict[str, Any]] = []
            accepted_chunk_ids: list[str] = []
            rejected_chunk_ids: list[str] = []
            chunk_results: list[dict[str, Any]] = []
            accepted_counts: dict[str, int] = {}
            rejected_counts: dict[str, int] = {}
            idempotent_results: list[bool] = []
            failure: Optional[str] = None
            for index, chunk in enumerate(chunks):
                # The Core receipt table uses this key to make retries safe
                # across request timeouts and worker restarts.  Each chunk has
                # an independent deterministic receipt; a retry of the whole
                # snapshot is therefore safe after a partial outage.
                idempotency_key = _ontology_idempotency_key(chunk)
                chunk["idempotency_key"] = idempotency_key
                chunk_id = f"{idempotency_key}:{index}"
                if failure is not None:
                    chunk_counts = _ontology_chunk_counts(chunk)
                    rejected_chunk_ids.append(chunk_id)
                    _merge_counts(rejected_counts, chunk_counts)
                    chunk_results.append({
                        "chunk_id": chunk_id,
                        "index": index,
                        "status": "not_attempted",
                        "counts": chunk_counts,
                        "error": "not attempted after an earlier chunk failed",
                    })
                    continue
                try:
                    result = self._request(
                        "POST",
                        "/api/v1/ontology/sync",
                        chunk,
                        headers={"Idempotency-Key": idempotency_key},
                    )
                    if result.get("status") not in {"accepted", "succeeded"} and result.get("idempotent") is not True:
                        raise RuntimeError(str(result.get("error") or result.get("detail") or "hosted Core did not accept ontology chunk"))
                    results.append(result)
                    accepted_chunk_ids.append(chunk_id)
                    result_counts = {key: value for key, value in (result.get("counts") or {}).items() if isinstance(value, int)}
                    chunk_counts = result_counts or _ontology_chunk_counts(chunk)
                    _merge_counts(accepted_counts, chunk_counts)
                    idempotent_results.append(result.get("idempotent") is True)
                    chunk_results.append({
                        "chunk_id": chunk_id,
                        "index": index,
                        "status": "accepted",
                        "idempotent": result.get("idempotent") is True,
                        "counts": chunk_counts,
                    })
                except Exception as exc:
                    failure = _clean(exc, 500)
                    chunk_counts = _ontology_chunk_counts(chunk)
                    rejected_chunk_ids.append(chunk_id)
                    _merge_counts(rejected_counts, chunk_counts)
                    chunk_results.append({
                        "chunk_id": chunk_id,
                        "index": index,
                        "status": "rejected",
                        "counts": chunk_counts,
                        "error": failure,
                    })
            aggregate: dict[str, Any] = {
                "status": "accepted" if failure is None else "degraded",
                "chunks": len(chunks),
                "chunk_count": len(chunks),
                "accepted_chunks": len(accepted_chunk_ids),
                "rejected_chunks": len(rejected_chunk_ids),
                "accepted_chunk_count": len(accepted_chunk_ids),
                "rejected_chunk_count": len(rejected_chunk_ids),
                "accepted_chunk_ids": accepted_chunk_ids,
                "rejected_chunk_ids": rejected_chunk_ids,
                "chunk_results": chunk_results,
                "accepted_counts": accepted_counts,
                "rejected_counts": rejected_counts,
                "idempotent": bool(results) and all(idempotent_results),
            }
            if accepted_counts:
                aggregate["counts"] = accepted_counts
            if results:
                aggregate["schema_version"] = results[-1].get("schema_version", "secopsai.ontology.v1")
            if failure is not None:
                aggregate["error"] = failure
            self.last_error = failure or ""
            self.last_ontology_sync = aggregate
            return aggregate
        except Exception as exc:  # ontology sync is an optional control-plane edge
            self.last_error = _clean(exc, 500)
            result = {
                "status": "degraded",
                "error": self.last_error,
                "chunks": 0,
                "chunk_count": 0,
                "accepted_chunks": 0,
                "rejected_chunks": 0,
                "accepted_chunk_count": 0,
                "rejected_chunk_count": 0,
                "accepted_chunk_ids": [],
                "rejected_chunk_ids": [],
                "chunk_results": [],
                "accepted_counts": {},
                "rejected_counts": {},
                "idempotent": False,
            }
            self.last_ontology_sync = result
            return result

    def enqueue_ontology_snapshot(
        self,
        snapshot: Dict[str, Any],
        *,
        db_path: Optional[str] = None,
        error: Any = "",
    ) -> dict[str, Any]:
        """Persist one bounded snapshot for retry when Core is unavailable.

        The outbox is intentionally compact and latest-observation oriented:
        each idempotency key is unique, and old rows are pruned after 100
        pending observations so a prolonged outage cannot consume the local
        research disk.
        """
        resolved_db = db_path or soc_store.default_db_path()
        try:
            snapshot_payload = dict(snapshot or {})
            snapshot_payload.setdefault("source_instance", self.settings.worker_id)
            payloads = _ontology_sync_chunks(snapshot_payload)
            encoded_payloads: list[tuple[str, str]] = []
            for payload in payloads:
                idempotency_key = _ontology_idempotency_key(payload)
                payload["idempotency_key"] = idempotency_key
                encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
                if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
                    return {"status": "rejected", "error": "ontology outbox payload exceeds the local limit"}
                encoded_payloads.append((idempotency_key, encoded))
            soc_store.init_db(resolved_db)
            now = soc_store.utc_now()
            with sqlite_writer_lock(resolved_db):
                with soc_store.connect(resolved_db) as connection:
                    for idempotency_key, encoded in encoded_payloads:
                        connection.execute(
                            "INSERT INTO ontology_sync_outbox (idempotency_key, payload_json, status, attempts, next_attempt_at, last_error, created_at, updated_at) VALUES (?, ?, 'queued', 0, ?, ?, ?, ?) ON CONFLICT(idempotency_key) DO UPDATE SET payload_json=excluded.payload_json, status='queued', next_attempt_at=excluded.next_attempt_at, last_error=excluded.last_error, updated_at=excluded.updated_at",
                            (idempotency_key, encoded, now, _clean(error, 2000), now, now),
                        )
                    connection.execute(
                        "DELETE FROM ontology_sync_outbox WHERE idempotency_key IN (SELECT idempotency_key FROM ontology_sync_outbox ORDER BY updated_at DESC LIMIT -1 OFFSET 100)"
                    )
                    connection.commit()
            response = {"status": "queued", "chunks": len(encoded_payloads), "idempotency_keys": [key for key, _ in encoded_payloads]}
            if len(encoded_payloads) == 1:
                response["idempotency_key"] = encoded_payloads[0][0]
            return response
        except Exception as exc:  # outbox persistence must not stop surveillance
            self.last_error = _clean(exc, 500)
            return {"status": "degraded", "error": self.last_error}

    def flush_ontology_outbox(
        self,
        *,
        db_path: Optional[str] = None,
        max_items: int = 5,
    ) -> dict[str, Any]:
        """Retry due ontology snapshots and remove only acknowledged receipts."""
        if not self.enabled:
            return {"status": "disabled", "flushed": 0}
        resolved_db = db_path or soc_store.default_db_path()
        try:
            soc_store.init_db(resolved_db)
            now = soc_store.utc_now()
            bound = max(1, min(int(max_items), 10))
            with soc_store.read_connect(resolved_db) as connection:
                rows = connection.execute(
                    "SELECT idempotency_key, payload_json, attempts FROM ontology_sync_outbox WHERE status = 'queued' AND next_attempt_at <= ? ORDER BY next_attempt_at, created_at LIMIT ?",
                    (now, bound),
                ).fetchall()
        except Exception as exc:
            self.last_error = _clean(exc, 500)
            return {"status": "degraded", "flushed": 0, "error": self.last_error}
        flushed = 0
        failed = 0
        for row in rows:
            key = str(row["idempotency_key"])
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            try:
                # The outbox row already contains one bounded chunk and its
                # deterministic receipt key.  Re-chunking it here would
                # change the idempotency material and could replay a timed-out
                # request under a different receipt.  Send the stored payload
                # verbatim so retries remain transactionally idempotent.
                if not payload:
                    raise ValueError("ontology outbox payload is invalid")
                result = self._request(
                    "POST",
                    "/api/v1/ontology/sync",
                    payload,
                    headers={"Idempotency-Key": key},
                )
                if result.get("status") in {"accepted", "succeeded"} or result.get("idempotent") is True:
                    with sqlite_writer_lock(resolved_db):
                        with soc_store.connect(resolved_db) as connection:
                            connection.execute("DELETE FROM ontology_sync_outbox WHERE idempotency_key = ?", (key,))
                            connection.commit()
                    flushed += 1
                    continue
                raise RuntimeError(str(result.get("error") or "hosted Core did not acknowledge ontology snapshot"))
            except Exception as exc:
                failed += 1
                attempts = max(0, int(row["attempts"] or 0)) + 1
                backoff = min(3600, 15 * (2 ** min(attempts - 1, 8)))
                try:
                    from datetime import datetime, timedelta, timezone

                    retry_at = (datetime.now(timezone.utc) + timedelta(seconds=backoff)).isoformat().replace("+00:00", "Z")
                except Exception:
                    retry_at = now
                with sqlite_writer_lock(resolved_db):
                    with soc_store.connect(resolved_db) as connection:
                        connection.execute(
                            "UPDATE ontology_sync_outbox SET status='queued', attempts=?, next_attempt_at=?, last_error=?, updated_at=? WHERE idempotency_key=?",
                            (attempts, retry_at, _clean(exc, 2000), soc_store.utc_now(), key),
                        )
                        connection.commit()
        status = "accepted" if failed == 0 else "degraded"
        return {"status": status, "flushed": flushed, "failed": failed, "pending": max(0, len(rows) - flushed)}

    def hosted_state(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/intelligence/bridge/state")

    def claim_command(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1/intelligence/bridge/commands/claim", {"worker_id": self.settings.worker_id})

    def complete_command(self, command_id: str, result: dict[str, Any], *, status: str = "succeeded", lease_generation: Any = None, lease_token: str = "") -> dict[str, Any]:
        return self._request("POST", f"/api/v1/intelligence/bridge/commands/{command_id}/complete", {"worker_id": self.settings.worker_id, "status": status, "result": _compact_command_result(result), "lease_generation": lease_generation, "lease_token": lease_token})

    def fail_command(self, command_id: str, error: Any, *, lease_generation: Any = None, lease_token: str = "") -> dict[str, Any]:
        return self._request("POST", f"/api/v1/intelligence/bridge/commands/{command_id}/fail", {"worker_id": self.settings.worker_id, "error_message": _clean(error, 2000), "lease_generation": lease_generation, "lease_token": lease_token})

    def heartbeat_command(self, command_id: str, *, lease_generation: Any, lease_token: str) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/intelligence/bridge/commands/{command_id}/heartbeat", {"worker_id": self.settings.worker_id, "lease_generation": lease_generation, "lease_token": lease_token})

    def pull_and_apply_settings(self, db_path: Optional[str] = None) -> dict[str, Any]:
        """Adopt operator settings from D1 without making them mandatory."""
        if not self.enabled:
            return {"status": "disabled"}
        try:
            state = self.hosted_state()
            settings = state.get("settings") if isinstance(state, dict) else {}
            triage = settings.get("agent_triage") if isinstance(settings, dict) else {}
            daily = settings.get("daily_automation") if isinstance(settings, dict) else {}
            if isinstance(triage, dict) and triage.get("mode"):
                from secopsai.agent_triage import update_settings

                update_settings(
                    mode=triage.get("mode"),
                    selected_model=triage.get("selected_model"),
                    poll_interval_seconds=triage.get("poll_interval_seconds"),
                    min_auto_close_confidence=triage.get("min_auto_close_confidence"),
                    min_evidence_refs=triage.get("min_evidence_refs"),
                    max_records_per_cycle=triage.get("max_records_per_cycle"),
                    auto_create_tuning_proposals=triage.get("auto_create_tuning_proposals"),
                    auto_activate_tuning=triage.get("auto_activate_tuning"),
                    actor="hosted-core",
                    db_path=db_path,
                )
            if isinstance(daily, dict) and daily.get("interval_seconds"):
                from secopsai.daily_automation import update_settings

                update_settings(
                    enabled=daily.get("enabled"),
                    interval_seconds=daily.get("interval_seconds"),
                    max_alert_reviews=daily.get("max_alert_reviews"),
                    max_investigations=daily.get("max_investigations"),
                    max_candidate_cases=daily.get("max_candidate_cases"),
                    auto_promote_candidates=daily.get("auto_promote_candidates"),
                    run_learning=daily.get("run_learning"),
                    actor="hosted-core",
                    db_path=db_path,
                )
            self.last_error = ""
            return state
        except Exception as exc:
            self.last_error = _clean(exc, 500)
            return {"status": "degraded", "error": self.last_error}

    def process_commands(self, db_path: Optional[str] = None, *, max_commands: int = 2) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        completed: list[dict[str, Any]] = []
        for _ in range(max(1, min(int(max_commands), 5))):
            try:
                claimed = self.claim_command()
            except Exception as exc:
                self.last_error = _clean(exc, 500)
                break
            command = claimed.get("command") if isinstance(claimed, dict) else None
            if not command:
                break
            command_id = _clean(command.get("command_id"), 100)
            command_type = _clean(command.get("command_type"), 80)
            lease_generation = command.get("lease_generation")
            lease_token = _clean(command.get("lease_token"), 160)
            payload = command.get("payload") if isinstance(command.get("payload"), dict) else {}
            pulse_stop = Event()
            pulse_thread: Thread | None = None
            if command_id and lease_token and lease_generation:
                def pulse() -> None:
                    while not pulse_stop.wait(30):
                        try:
                            self.heartbeat_command(command_id, lease_generation=lease_generation, lease_token=lease_token)
                        except Exception as exc:
                            self.last_error = _clean(exc, 500)
                            # The command may still finish within the lease;
                            # the completion call will surface a lost lease.
                            continue
                pulse_thread = Thread(target=pulse, name=f"secopsai-command-heartbeat-{command_id}", daemon=True)
                pulse_thread.start()
            try:
                if command_type == "daily-run":
                    from secopsai.daily_automation import run_cycle

                    result = run_cycle(db_path=db_path, trigger="hosted-core", force=True)
                elif command_type == "autopilot-run-now":
                    from secopsai.agent_triage import enqueue_due_findings

                    result = enqueue_due_findings(db_path=db_path, requested_by="hosted-core")
                elif command_type == "autopilot-rollback":
                    from secopsai.agent_triage import rollback_run

                    result = rollback_run(_clean(payload.get("run_id"), 80), actor="hosted-core", db_path=db_path)
                elif command_type == "autopilot-rollback-tuning":
                    from secopsai.agent_triage import rollback_tuning_proposal

                    result = rollback_tuning_proposal(_clean(payload.get("proposal_id"), 80), actor="hosted-core", db_path=db_path)
                else:
                    raise ValueError(f"unsupported coordinator command: {command_type}")
                result_status = str(result.get("status") if isinstance(result, dict) else "").lower()
                # Keep terminal runner outcomes visible in the hosted
                # coordinator.  Unknown/queued statuses describe a successful
                # enqueue or command invocation, while failed/canceled states
                # must never be reported as succeeded.
                state = result_status if result_status in {"degraded", "failed", "canceled", "recovered"} else "succeeded"
                self.complete_command(command_id, result if isinstance(result, dict) else {"result": result}, status=state, lease_generation=lease_generation, lease_token=lease_token)
                # Keep the command type in the receipt so the follow-up
                # heartbeat can materialize the hosted run summary in D1.
                completed.append({"command_id": command_id, "command_type": command_type, "status": state, "result": result})
            except Exception as exc:
                message = _clean(exc, 2000)
                try:
                    self.fail_command(command_id, message, lease_generation=lease_generation, lease_token=lease_token)
                except Exception as report_error:
                    self.last_error = _clean(report_error, 500)
                completed.append({"command_id": command_id, "status": "failed", "error": message})
            finally:
                pulse_stop.set()
                if pulse_thread is not None:
                    pulse_thread.join(timeout=1)
        return completed


def coordinator_client() -> CoreEdgeClient:
    return CoreEdgeClient()
