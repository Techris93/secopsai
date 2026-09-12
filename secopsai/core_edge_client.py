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


def _bounded_json(value: Any, limit: int = MAX_REQUEST_BYTES) -> dict[str, Any]:
    cleaned = minimize(value if isinstance(value, dict) else {})
    encoded = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) > limit:
        return {"status": "truncated", "bytes": len(encoded.encode("utf-8"))}
    return cleaned


def _json_size(value: Any) -> int:
    return len(json.dumps(minimize(value if isinstance(value, dict) else {}), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))


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

    # Keep the newest bounded records first (materialize_recent already orders
    # them that way) and progressively halve the largest collection.
    while _json_size(payload) > target and any(payload[key] for key in ("entities", "relationships", "events", "evidence_refs")):
        largest = max((key for key in ("entities", "relationships", "events", "evidence_refs") if payload[key]), key=lambda key: _json_size({key: payload[key]}))
        current = payload[largest]
        keep = max(1, len(current) // 2)
        payload[largest] = current[:keep]
        payload["snapshot_truncated"] = True

    if _json_size(payload) > target:
        # A single unusually large summary can still exceed the bound.  Keep
        # identity/provenance fields and drop optional properties only after
        # the list-level reduction above.
        for key in ("entities", "relationships", "events", "evidence_refs"):
            compacted = []
            for item in payload[key]:
                if not isinstance(item, dict):
                    continue
                entry = dict(item)
                for optional in ("properties", "aliases", "summary"):
                    if optional in entry:
                        entry.pop(optional, None)
                compacted.append(entry)
            payload[key] = compacted
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
            4 * 1024,
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
        response = self.session.request(
            method,
            f"{self.settings.url}{path}",
            headers=request_headers,
            json=_bounded_json(payload or {}),
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
        payload = {
            "worker_id": self.settings.worker_id,
            "status": _clean(status, 40) or "healthy",
            "last_cycle_at": _clean(summary.get("completed_at") if isinstance(summary, dict) else "", 64),
            "last_cycle_status": _clean(summary.get("status") if isinstance(summary, dict) else "succeeded", 40) or "succeeded",
            "storage": _bounded_json(storage if isinstance(storage, dict) else {}, 16 * 1024),
            "coordinator": _bounded_json({
                "collectors_run": summary.get("collectors_run") if isinstance(summary, dict) else None,
                "daily_automation": summary.get("daily_automation") if isinstance(summary, dict) else None,
                "alert_delivery": summary.get("alert_delivery") if isinstance(summary, dict) else None,
                "hosted_commands": hosted_commands,
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
            return {"status": "disabled"}
        payload = dict(snapshot or {})
        payload.setdefault("source_instance", self.settings.worker_id)
        payload = _compact_ontology_snapshot(payload)
        # The Core receipt table uses this key to make retries safe across
        # request timeouts and worker restarts.  Hash the compact payload so
        # the same bounded snapshot always replays the same receipt.
        idempotency_key = _ontology_idempotency_key(payload)
        payload["idempotency_key"] = idempotency_key
        try:
            result = self._request(
                "POST",
                "/api/v1/ontology/sync",
                payload,
                headers={"Idempotency-Key": idempotency_key},
            )
            self.last_error = ""
            return result
        except Exception as exc:  # ontology sync is an optional control-plane edge
            self.last_error = _clean(exc, 500)
            return {"status": "degraded", "error": self.last_error}

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
        payload = _compact_ontology_snapshot(dict(snapshot or {}))
        idempotency_key = _ontology_idempotency_key(payload)
        payload["idempotency_key"] = idempotency_key
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
            return {"status": "rejected", "error": "ontology outbox payload exceeds the local limit"}
        resolved_db = db_path or soc_store.default_db_path()
        try:
            soc_store.init_db(resolved_db)
            now = soc_store.utc_now()
            with sqlite_writer_lock(resolved_db):
                with soc_store.connect(resolved_db) as connection:
                    connection.execute(
                        "INSERT INTO ontology_sync_outbox (idempotency_key, payload_json, status, attempts, next_attempt_at, last_error, created_at, updated_at) VALUES (?, ?, 'queued', 0, ?, ?, ?, ?) ON CONFLICT(idempotency_key) DO UPDATE SET payload_json=excluded.payload_json, status='queued', next_attempt_at=excluded.next_attempt_at, last_error=excluded.last_error, updated_at=excluded.updated_at",
                        (idempotency_key, encoded, now, _clean(error, 2000), now, now),
                    )
                    connection.execute(
                        "DELETE FROM ontology_sync_outbox WHERE idempotency_key IN (SELECT idempotency_key FROM ontology_sync_outbox ORDER BY updated_at DESC LIMIT -1 OFFSET 100)"
                    )
                    connection.commit()
            return {"status": "queued", "idempotency_key": idempotency_key}
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
                result = self.sync_ontology(payload)
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

    def complete_command(self, command_id: str, result: dict[str, Any], *, status: str = "succeeded") -> dict[str, Any]:
        return self._request("POST", f"/api/v1/intelligence/bridge/commands/{command_id}/complete", {"worker_id": self.settings.worker_id, "status": status, "result": _compact_command_result(result)})

    def fail_command(self, command_id: str, error: Any) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/intelligence/bridge/commands/{command_id}/fail", {"worker_id": self.settings.worker_id, "error_message": _clean(error, 2000)})

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
            payload = command.get("payload") if isinstance(command.get("payload"), dict) else {}
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
                state = result_status if result_status in {"degraded", "recovered"} else "succeeded"
                self.complete_command(command_id, result if isinstance(result, dict) else {"result": result}, status=state)
                # Keep the command type in the receipt so the follow-up
                # heartbeat can materialize the hosted run summary in D1.
                completed.append({"command_id": command_id, "command_type": command_type, "status": state, "result": result})
            except Exception as exc:
                message = _clean(exc, 2000)
                try:
                    self.fail_command(command_id, message)
                except Exception as report_error:
                    self.last_error = _clean(report_error, 500)
                completed.append({"command_id": command_id, "status": "failed", "error": message})
        return completed


def coordinator_client() -> CoreEdgeClient:
    return CoreEdgeClient()
