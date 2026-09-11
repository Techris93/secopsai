"""Small, failure-tolerant client for the hosted Core coordinator.

The research worker remains the execution plane.  This module only exchanges
bounded, redacted state with the Cloudflare control plane and never makes
surveillance depend on a network request succeeding.
"""

from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from secopsai.intelligence import minimize


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

    def _request(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled"}
        response = self.session.request(
            method,
            f"{self.settings.url}{path}",
            headers={"Authorization": f"Bearer {self.settings.token}", "Accept": "application/json", "Content-Type": "application/json", "User-Agent": "SecOpsAI-Research/1.0"},
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
                "hosted_commands": (summary.get("hosted_coordinator") or {}).get("commands", []) if isinstance(summary, dict) else [],
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
                state = "degraded" if str(result.get("status") if isinstance(result, dict) else "").lower() == "degraded" else "succeeded"
                self.complete_command(command_id, result if isinstance(result, dict) else {"result": result}, status=state)
                completed.append({"command_id": command_id, "status": state, "result": result})
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
