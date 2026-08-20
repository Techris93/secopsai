from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

import soc_store
from secopsai import __version__
from secopsai.edge_sync import import_bundle, validate_bundle
from secopsai.graph_store import list_assets, list_changes
from secopsai.intelligence import get_action as get_intelligence_action
from secopsai.intelligence import list_actions as list_intelligence_actions
from secopsai.intelligence import prepare_bridge_request, validate_bridge_result
from secopsai.intelligence import run_read_action as run_intelligence_read_action
from secopsai.intelligence_jobs import cancel_job as cancel_intelligence_job
from secopsai.intelligence_jobs import claim_next_job as claim_intelligence_job
from secopsai.intelligence_jobs import complete_job as complete_intelligence_job
from secopsai.intelligence_jobs import enqueue_job as enqueue_intelligence_job
from secopsai.intelligence_jobs import fail_job as fail_intelligence_job
from secopsai.intelligence_jobs import get_job as get_intelligence_job
from secopsai.intelligence_jobs import list_jobs as list_intelligence_jobs
from secopsai.agent_triage import enqueue_due_findings as enqueue_agent_triage_findings
from secopsai.agent_triage import rollback_run as rollback_agent_triage_run
from secopsai.agent_triage import rollback_tuning_proposal as rollback_agent_tuning_proposal
from secopsai.agent_triage import status as agent_triage_status
from secopsai.agent_triage import update_settings as update_agent_triage_settings
from secopsai.research_discovery import _upsert_research_alert_finding
from secopsai.daily_automation import (
    run_cycle as run_daily_automation_cycle,
    status as daily_automation_status,
    update_settings as update_daily_automation_settings,
)
from secopsai.observability import initialize_observability
from secopsai.enterprise_store import EnterpriseContext, build_enterprise_store
from secopsai.enterprise_workflows import pentest_engagement, questionnaire_record, threat_model_record
from secopsai.vulnerability_management import normalize_advisory


LOGGER = logging.getLogger(__name__)
PROTECTED_ENVIRONMENTS = {"pilot", "production"}
MIN_PROTECTED_TOKEN_LENGTH = 32
DEFAULT_MAX_BUNDLE_BYTES = 10 * 1024 * 1024
MAX_RESEARCH_ALERT_BYTES = 64 * 1024
MAX_INTELLIGENCE_REQUEST_BYTES = 64 * 1024
RESEARCH_WEBHOOK_MAX_AGE_SECONDS = 300
RESEARCH_OPERATIONAL_ALERT_TYPES = {"collector_degraded", "collector_retention_risk"}
# These alerts are normalized source-backed leads.  They are accepted by the
# Core bridge so a worker on a separate Render disk cannot silently hide a new
# campaign from the operator console.  They remain unverified until intake and
# analysis produce independent evidence.
RESEARCH_EXTERNAL_ALERT_TYPES = {
    "external_advisory_match",
    "external_advisory_feed_degraded",
    "npm_proactive_anomaly",
    "npm_enrichment_degraded",
}
RESEARCH_ALERT_TYPES = RESEARCH_OPERATIONAL_ALERT_TYPES | RESEARCH_EXTERNAL_ALERT_TYPES
REDACTED_KEYS = {
    "artifact_bytes",
    "artifact_content",
    "authorization",
    "bssid",
    "mac",
    "mac_address",
    "nmap_xml",
    "packet_capture",
    "pcap",
    "password",
    "raw_nmap_output",
    "raw_output",
    "raw_packet_data",
    "raw_scan_log",
    "raw_scan_logs",
    "secret",
    "token",
}


@dataclass(frozen=True)
class CoreAPISettings:
    db_path: str
    ingest_token: str = ""
    read_token: str = ""
    intelligence_token: str = ""
    bridge_token: str = ""
    environment: str = "local"
    organization_id: str = ""
    cors_origins: tuple[str, ...] = ()
    trusted_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES
    research_webhook_secret: str = ""

    @classmethod
    def from_environment(cls) -> "CoreAPISettings":
        return cls(
            db_path=os.environ.get("SECOPSAI_CORE_DB_PATH") or soc_store.default_db_path(),
            ingest_token=os.environ.get("SECOPSAI_CORE_INGEST_TOKEN", "").strip(),
            read_token=os.environ.get("SECOPSAI_CORE_READ_TOKEN", "").strip(),
            intelligence_token=os.environ.get("SECOPSAI_CORE_INTELLIGENCE_TOKEN", "").strip(),
            bridge_token=os.environ.get("SECOPSAI_CORE_BRIDGE_TOKEN", "").strip(),
            environment=os.environ.get("SECOPSAI_CORE_ENVIRONMENT", "local").strip().lower(),
            organization_id=os.environ.get("SECOPSAI_CORE_ORGANIZATION_ID", "").strip(),
            cors_origins=_csv_setting("SECOPSAI_CORE_CORS_ORIGINS"),
            trusted_hosts=_csv_setting(
                "SECOPSAI_CORE_TRUSTED_HOSTS",
                default=("127.0.0.1", "localhost"),
            ),
            max_bundle_bytes=_positive_int_setting(
                "SECOPSAI_CORE_MAX_BUNDLE_BYTES",
                DEFAULT_MAX_BUNDLE_BYTES,
            ),
            research_webhook_secret=os.environ.get("SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET", "").strip(),
        )

    def validate(self) -> None:
        if self.max_bundle_bytes < 1024:
            raise RuntimeError("SECOPSAI_CORE_MAX_BUNDLE_BYTES must be at least 1024")
        if self.environment not in PROTECTED_ENVIRONMENTS:
            return
        if len(self.ingest_token) < MIN_PROTECTED_TOKEN_LENGTH:
            raise RuntimeError("SECOPSAI_CORE_INGEST_TOKEN must contain at least 32 characters")
        if len(self.read_token) < MIN_PROTECTED_TOKEN_LENGTH:
            raise RuntimeError("SECOPSAI_CORE_READ_TOKEN must contain at least 32 characters")
        if self.intelligence_token and len(self.intelligence_token) < MIN_PROTECTED_TOKEN_LENGTH:
            raise RuntimeError("SECOPSAI_CORE_INTELLIGENCE_TOKEN must contain at least 32 characters when configured")
        if self.bridge_token and len(self.bridge_token) < MIN_PROTECTED_TOKEN_LENGTH:
            raise RuntimeError("SECOPSAI_CORE_BRIDGE_TOKEN must contain at least 32 characters when configured")
        if hmac.compare_digest(self.ingest_token, self.read_token):
            raise RuntimeError("Core ingestion and read tokens must be different")
        if self.intelligence_token and any(
            hmac.compare_digest(left, right)
            for left, right in (
                (self.ingest_token, self.intelligence_token),
                (self.read_token, self.intelligence_token),
            )
        ):
            raise RuntimeError("Core ingestion, read, and intelligence tokens must be different")
        configured_tokens = [value for value in (self.ingest_token, self.read_token, self.intelligence_token, self.bridge_token) if value]
        if len({hashlib.sha256(value.encode()).digest() for value in configured_tokens}) != len(configured_tokens):
            raise RuntimeError("All configured Core bearer credentials must be different")
        if not self.organization_id:
            raise RuntimeError("SECOPSAI_CORE_ORGANIZATION_ID is required in pilot/production")
        if not self.trusted_hosts or "*" in self.trusted_hosts:
            raise RuntimeError("SECOPSAI_CORE_TRUSTED_HOSTS must be explicit in pilot/production")
        if "*" in self.cors_origins:
            raise RuntimeError("SECOPSAI_CORE_CORS_ORIGINS cannot use a wildcard in pilot/production")
        if self.research_webhook_secret and len(self.research_webhook_secret) < MIN_PROTECTED_TOKEN_LENGTH:
            raise RuntimeError("SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET must contain at least 32 characters")


def create_app(settings: CoreAPISettings | None = None) -> FastAPI:
    resolved = settings or CoreAPISettings.from_environment()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        initialize_observability(service="secopsai-core-api")
        resolved.validate()
        soc_store.init_db(resolved.db_path)
        application.state.ingest_lock = asyncio.Lock()
        yield

    docs_enabled = resolved.environment not in PROTECTED_ENVIRONMENTS
    application = FastAPI(
        title="SecOpsAI Core API",
        version=__version__,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    application.state.settings = resolved

    if resolved.cors_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
            expose_headers=["X-Request-ID"],
        )
    if resolved.trusted_hosts and "*" not in resolved.trusted_hosts:
        application.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=list(resolved.trusted_hosts),
            www_redirect=False,
        )

    @application.middleware("http")
    async def security_headers(request: Request, call_next: Callable[..., Any]):
        request_id = _request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    require_ingest = _bearer_dependency(lambda: resolved.ingest_token, "edge_ingest")
    require_read = _bearer_dependency(lambda: resolved.read_token, "operator_read")
    require_intelligence = _bearer_dependency(lambda: resolved.intelligence_token, "intelligence_operator")
    require_bridge = _bearer_dependency(lambda: resolved.bridge_token, "intelligence_bridge")

    @application.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "secopsai-core-api", "version": __version__}

    @application.get("/readyz")
    def readiness() -> dict[str, str]:
        try:
            soc_store.init_db(resolved.db_path)
            with soc_store.connect(resolved.db_path) as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error as exc:
            raise HTTPException(status_code=503, detail="Core data store is unavailable") from exc
        return {"status": "ready", "data_store": "sqlite"}

    def enterprise_store_for(role: str):
        context = EnterpriseContext(
            resolved.organization_id or "local",
            actor_id=role,
            role=role,
        )
        return build_enterprise_store(context=context)

    @application.get("/api/v1/enterprise/health")
    def enterprise_health(_role: str = Depends(require_read)) -> dict[str, Any]:
        return enterprise_store_for("operator_read").health()

    @application.get("/api/v1/enterprise/events")
    def enterprise_events(
        limit: int = 100,
        cursor: str = "",
        _role: str = Depends(require_read),
    ) -> dict[str, Any]:
        return enterprise_store_for("operator_read").list_events(limit=limit, cursor=cursor)

    @application.post("/api/v1/enterprise/events")
    async def enterprise_event_ingest(
        request: Request,
        _role: str = Depends(require_ingest),
    ) -> dict[str, Any]:
        payload = await _read_json_object(request, MAX_RESEARCH_ALERT_BYTES, "Enterprise event")
        idempotency_key = request.headers.get("Idempotency-Key", "")[:160]
        event = enterprise_store_for("enterprise_ingest").append_event(payload, idempotency_key=idempotency_key)
        return {"event": event, "request_id": request.state.request_id}

    @application.post("/api/v1/enterprise/vulnerabilities")
    async def enterprise_vulnerability_upsert(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        payload = await _read_json_object(request, MAX_RESEARCH_ALERT_BYTES, "Enterprise vulnerability")
        item = normalize_advisory(payload)
        return {"vulnerability": enterprise_store_for("intelligence_operator").upsert_vulnerability(item), "request_id": request.state.request_id}

    @application.post("/api/v1/enterprise/controls")
    async def enterprise_control_upsert(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        payload = await _read_json_object(request, MAX_RESEARCH_ALERT_BYTES, "Enterprise control")
        return {"control": enterprise_store_for("intelligence_operator").upsert_control(payload), "request_id": request.state.request_id}

    @application.post("/api/v1/enterprise/evidence")
    async def enterprise_evidence_record(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        payload = await _read_json_object(request, MAX_RESEARCH_ALERT_BYTES, "Enterprise evidence")
        return {"evidence": enterprise_store_for("intelligence_operator").record_evidence(payload), "request_id": request.state.request_id}

    @application.post("/api/v1/enterprise/actions")
    async def enterprise_action_propose(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        payload = await _read_json_object(request, MAX_RESEARCH_ALERT_BYTES, "Enterprise action")
        payload.setdefault("approval_required", True)
        payload["status"] = "proposed"
        return {"action": enterprise_store_for("intelligence_operator").create_action(payload), "request_id": request.state.request_id}

    @application.post("/api/v1/enterprise/workflows/{kind}")
    async def enterprise_workflow_record(
        kind: str,
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        payload = await _read_json_object(request, MAX_RESEARCH_ALERT_BYTES, "Enterprise workflow")
        if kind == "questionnaire":
            record = questionnaire_record(**payload)
            persisted = enterprise_store_for("intelligence_operator").upsert_questionnaire(record)
        elif kind == "threat-model":
            record = threat_model_record(**payload)
            persisted = enterprise_store_for("intelligence_operator").upsert_threat_model(record)
        elif kind == "pentest":
            record = pentest_engagement(**payload)
            persisted = enterprise_store_for("intelligence_operator").upsert_pentest_engagement(record)
        else:
            raise HTTPException(status_code=404, detail="unsupported enterprise workflow")
        return {"workflow": persisted, "kind": kind, "request_id": request.state.request_id}

    @application.post("/api/v1/edge/bundles")
    async def ingest_edge_bundle(
        request: Request,
        _role: str = Depends(require_ingest),
    ) -> dict[str, Any]:
        source_instance: str | None = None
        try:
            bundle = await _read_json_object(request, resolved.max_bundle_bytes)
            validate_bundle(bundle)
            _enforce_organization_scope(bundle, resolved.organization_id)
            source_instance = _source_instance_label(bundle)
            async with application.state.ingest_lock:
                result = import_bundle(bundle, db_path=resolved.db_path)
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="edge.bundle.imported",
                actor_role="edge_ingest",
                result="success",
                source_instance=result["source_instance"],
                details={
                    "schema_version": result["schema_version"],
                    "nodes": result["nodes"],
                    "edges": result["edges"],
                    "findings": result["findings"],
                },
            )
            return {
                "status": "imported",
                "schema_version": result["schema_version"],
                "source_instance": result["source_instance"],
                "counts": {
                    "nodes": result["nodes"],
                    "edges": result["edges"],
                    "findings": result["findings"],
                },
                "request_id": request.state.request_id,
            }
        except HTTPException:
            raise
        except ValueError as exc:
            _write_audit_safely(
                resolved.db_path,
                request_id=request.state.request_id,
                action="edge.bundle.rejected",
                actor_role="edge_ingest",
                result="rejected",
                source_instance=source_instance,
                details={"reason": str(exc)[:500]},
            )
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except sqlite3.Error as exc:
            _write_audit_safely(
                resolved.db_path,
                request_id=request.state.request_id,
                action="edge.bundle.failed",
                actor_role="edge_ingest",
                result="failed",
                source_instance=source_instance,
                details={"error_type": type(exc).__name__},
            )
            raise HTTPException(status_code=503, detail="Core data store is unavailable") from exc

    @application.post("/api/v1/research/alerts/webhook")
    async def ingest_research_alert_webhook(request: Request) -> dict[str, Any]:
        secret = resolved.research_webhook_secret
        if not secret:
            raise HTTPException(status_code=503, detail="Research alert webhook is not configured")
        body = await _read_request_bytes(request, MAX_RESEARCH_ALERT_BYTES, "Research alert")
        _verify_research_webhook(request, body, secret)
        payload = _decode_json_object(body)
        alert = _validate_research_alert(payload)
        async with application.state.ingest_lock:
            result = _upsert_research_alert(alert, resolved.db_path)
        _write_audit(
            resolved.db_path,
            request_id=request.state.request_id,
            action="research.alert.ingested",
            actor_role="research_worker",
            result="created" if result["created"] else "updated",
            source_instance="secopsai-research-worker",
            details={
                "alert_id": result["alert_id"],
                "source_alert_id": alert["alert_id"],
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
            },
        )
        return {
            "status": "accepted",
            "alert_id": result["alert_id"],
            "created": result["created"],
            "request_id": request.state.request_id,
        }

    @application.get("/api/v1/workspace")
    def operator_workspace(
        limit: int = 100,
        _role: str = Depends(require_read),
    ) -> dict[str, Any]:
        bounded_limit = max(1, min(int(limit), 500))
        return _workspace_payload(resolved.db_path, bounded_limit)

    @application.get("/api/v1/audit-logs")
    def audit_logs(
        limit: int = 100,
        _role: str = Depends(require_read),
    ) -> dict[str, Any]:
        bounded_limit = max(1, min(int(limit), 500))
        return {"audit_logs": _list_audit_logs(resolved.db_path, bounded_limit)}

    @application.get("/api/v1/intelligence/actions")
    def intelligence_actions(
        _role: str = Depends(require_read),
    ) -> dict[str, Any]:
        return list_intelligence_actions()

    @application.post("/api/v1/intelligence/query")
    async def intelligence_query(
        request: Request,
        _role: str = Depends(require_read),
    ) -> dict[str, Any]:
        try:
            payload = await _read_json_object(request, MAX_INTELLIGENCE_REQUEST_BYTES, "Intelligence query")
            action = str(payload.get("action") or "").strip()
            inputs = payload.get("inputs") or {}
            if not isinstance(inputs, dict):
                raise ValueError("intelligence inputs must be an object")
            result = run_intelligence_read_action(action, inputs, db_path=resolved.db_path)
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.query.completed",
                actor_role="operator_read",
                result="success",
                source_instance="secopsai-core",
                details={"intelligence_action": action},
            )
            return {**result, "request_id": request.state.request_id}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/jobs")
    async def intelligence_job_create(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        try:
            payload = await _read_json_object(request, MAX_INTELLIGENCE_REQUEST_BYTES, "Intelligence job")
            inputs = payload.get("inputs") or {}
            if not isinstance(inputs, dict):
                raise ValueError("intelligence inputs must be an object")
            action = get_intelligence_action(str(payload.get("action") or ""))
            if not action.requires_bridge:
                raise ValueError("only bridge-backed intelligence actions can be queued")
            job = enqueue_intelligence_job(
                action=action.name,
                target_id=str(payload.get("target_id") or ""),
                inputs=inputs,
                requested_by=str(payload.get("requested_by") or "dashboard"),
                idempotency_key=str(payload.get("idempotency_key") or ""),
                db_path=resolved.db_path,
            )
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.job.queued",
                actor_role="intelligence_operator",
                result="success",
                source_instance="secopsai-core",
                details={"job_id": job["job_id"], "intelligence_action": job["action"]},
            )
            return {"job": job, "request_id": request.state.request_id}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get("/api/v1/intelligence/jobs")
    def intelligence_job_list(
        status: str = "",
        limit: int = 100,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        return {"jobs": list_intelligence_jobs(status=status, limit=limit, db_path=resolved.db_path)}

    @application.get("/api/v1/intelligence/autopilot")
    def intelligence_autopilot_status(
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        return agent_triage_status(db_path=resolved.db_path)

    @application.get("/api/v1/intelligence/daily")
    def intelligence_daily_status(
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        return daily_automation_status(db_path=resolved.db_path)

    @application.post("/api/v1/intelligence/daily/configure")
    async def intelligence_daily_configure(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        try:
            payload = await _read_json_object(request, MAX_INTELLIGENCE_REQUEST_BYTES, "Daily automation configuration")
            settings = update_daily_automation_settings(
                enabled=payload.get("enabled"),
                interval_seconds=payload.get("interval_seconds"),
                max_alert_reviews=payload.get("max_alert_reviews"),
                max_investigations=payload.get("max_investigations"),
                max_candidate_cases=payload.get("max_candidate_cases"),
                auto_promote_candidates=payload.get("auto_promote_candidates"),
                run_learning=payload.get("run_learning"),
                actor="mission-control",
                db_path=resolved.db_path,
            )
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.daily.configured",
                actor_role="intelligence_operator",
                result="success",
                source_instance="secopsai-core",
                details={"enabled": settings["enabled"], "interval_seconds": settings["interval_seconds"]},
            )
            return {"settings": settings, "request_id": request.state.request_id}
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/daily/run")
    def intelligence_daily_run(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        result = run_daily_automation_cycle(
            db_path=resolved.db_path,
            trigger="mission-control",
            force=True,
        )
        _write_audit(
            resolved.db_path,
            request_id=request.state.request_id,
            action="intelligence.daily.run",
            actor_role="intelligence_operator",
            result="success" if result.get("status") in {"succeeded", "degraded"} else "conflict",
            source_instance="secopsai-core",
            details={"run_id": result.get("run_id"), "status": result.get("status")},
        )
        return {"result": result, "request_id": request.state.request_id}

    @application.post("/api/v1/intelligence/autopilot/configure")
    async def intelligence_autopilot_configure(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        try:
            payload = await _read_json_object(request, MAX_INTELLIGENCE_REQUEST_BYTES, "Autopilot configuration")
            settings = update_agent_triage_settings(
                mode=payload.get("mode"),
                selected_model=payload.get("selected_model"),
                poll_interval_seconds=payload.get("poll_interval_seconds"),
                min_auto_close_confidence=payload.get("min_auto_close_confidence"),
                min_evidence_refs=payload.get("min_evidence_refs"),
                max_records_per_cycle=payload.get("max_records_per_cycle"),
                auto_create_tuning_proposals=payload.get("auto_create_tuning_proposals"),
                auto_activate_tuning=payload.get("auto_activate_tuning"),
                actor="mission-control",
                db_path=resolved.db_path,
            )
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.autopilot.configured",
                actor_role="intelligence_operator",
                result="success",
                source_instance="secopsai-core",
                details={"mode": settings["mode"], "selected_model": settings["selected_model"]},
            )
            return {"settings": settings, "request_id": request.state.request_id}
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/autopilot/run-now")
    def intelligence_autopilot_run_now(
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        result = enqueue_agent_triage_findings(db_path=resolved.db_path, requested_by="mission-control")
        _write_audit(
            resolved.db_path,
            request_id=request.state.request_id,
            action="intelligence.autopilot.run_now",
            actor_role="intelligence_operator",
            result="success",
            source_instance="secopsai-core",
            details={"queued": len(result.get("queued") or [])},
        )
        return {"result": result, "request_id": request.state.request_id}

    @application.post("/api/v1/intelligence/autopilot/runs/{run_id}/rollback")
    def intelligence_autopilot_rollback(
        run_id: str,
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        try:
            result = rollback_agent_triage_run(run_id, actor="mission-control", db_path=resolved.db_path)
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.autopilot.rolled_back",
                actor_role="intelligence_operator",
                result="success",
                source_instance="secopsai-core",
                details={"run_id": run_id, "target_id": result["target_id"]},
            )
            return {"run": result, "request_id": request.state.request_id}
        except ValueError as exc:
            status_code = 404 if "not found" in str(exc).lower() else 409
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/autopilot/tuning/{proposal_id}/rollback")
    def intelligence_autopilot_tuning_rollback(
        proposal_id: str,
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        try:
            result = rollback_agent_tuning_proposal(proposal_id, actor="mission-control", db_path=resolved.db_path)
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.autopilot.tuning_rolled_back",
                actor_role="intelligence_operator",
                result="success",
                source_instance="secopsai-core",
                details={"proposal_id": proposal_id, "finding_id": result["finding_id"]},
            )
            return {"proposal": result, "request_id": request.state.request_id}
        except ValueError as exc:
            status_code = 404 if "not found" in str(exc).lower() else 409
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc

    @application.get("/api/v1/intelligence/jobs/{job_id}")
    def intelligence_job_show(
        job_id: str,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        try:
            return {"job": get_intelligence_job(job_id, db_path=resolved.db_path)}
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/jobs/{job_id}/cancel")
    def intelligence_job_cancel(
        job_id: str,
        request: Request,
        _role: str = Depends(require_intelligence),
    ) -> dict[str, Any]:
        try:
            job = cancel_intelligence_job(job_id, actor="dashboard", db_path=resolved.db_path)
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.job.canceled",
                actor_role="intelligence_operator",
                result="success",
                source_instance="secopsai-core",
                details={"job_id": job_id},
            )
            return {"job": job, "request_id": request.state.request_id}
        except ValueError as exc:
            status_code = 404 if "not found" in str(exc).lower() else 409
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/bridge/claim")
    async def intelligence_bridge_claim(
        request: Request,
        _role: str = Depends(require_bridge),
    ) -> dict[str, Any]:
        try:
            payload = await _read_json_object(request, MAX_INTELLIGENCE_REQUEST_BYTES, "Bridge claim")
            worker_id = str(payload.get("worker_id") or "remote-codex-bridge").strip()[:160]
            if not worker_id:
                raise ValueError("worker_id is required")
            async with application.state.ingest_lock:
                enqueue_agent_triage_findings(db_path=resolved.db_path, requested_by="remote-bridge-poll")
                job = claim_intelligence_job(
                    provider="codex_chatgpt_subscription",
                    worker_id=worker_id,
                    db_path=resolved.db_path,
                )
                bridge_request = None
                if job:
                    inputs = dict(job.get("input") or {})
                    if job.get("target_id"):
                        inputs.setdefault("target_id", job["target_id"])
                    bridge_request = prepare_bridge_request(job["action"], inputs, db_path=resolved.db_path)
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.bridge.claimed" if job else "intelligence.bridge.idle",
                actor_role="intelligence_bridge",
                result="success",
                source_instance=worker_id,
                details={"job_id": job["job_id"], "intelligence_action": job["action"]} if job else {},
            )
            return {
                "status": "claimed" if job else "idle",
                "job": (
                    {
                        **{key: job.get(key) for key in ("job_id", "action", "target_id", "status", "attempt")},
                        "selected_model": str((job.get("input") or {}).get("selected_model") or ""),
                    }
                    if job
                    else None
                ),
                "bridge_request": bridge_request,
                "request_id": request.state.request_id,
            }
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/bridge/jobs/{job_id}/complete")
    async def intelligence_bridge_complete(
        job_id: str,
        request: Request,
        _role: str = Depends(require_bridge),
    ) -> dict[str, Any]:
        try:
            payload = await _read_json_object(request, MAX_INTELLIGENCE_REQUEST_BYTES, "Bridge result")
            worker_id = str(payload.get("worker_id") or "remote-codex-bridge").strip()[:160]
            job = get_intelligence_job(job_id, db_path=resolved.db_path)
            provider = str(payload.get("provider") or "codex_chatgpt_subscription").strip()[:120] or "codex_chatgpt_subscription"
            result = validate_bridge_result(job["action"], payload.get("result") or {}, provider=provider)
            completed = complete_intelligence_job(job_id, result=result, actor=worker_id, provider=provider, db_path=resolved.db_path)
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.bridge.completed",
                actor_role="intelligence_bridge",
                result="success",
                source_instance=worker_id,
                details={"job_id": job_id, "intelligence_action": job["action"]},
            )
            return {"status": "succeeded", "job": completed, "request_id": request.state.request_id}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.post("/api/v1/intelligence/bridge/jobs/{job_id}/fail")
    async def intelligence_bridge_fail(
        job_id: str,
        request: Request,
        _role: str = Depends(require_bridge),
    ) -> dict[str, Any]:
        try:
            payload = await _read_json_object(request, MAX_INTELLIGENCE_REQUEST_BYTES, "Bridge failure")
            worker_id = str(payload.get("worker_id") or "remote-codex-bridge").strip()[:160]
            failed = fail_intelligence_job(
                job_id,
                error_code=str(payload.get("error_code") or "remote_bridge_failed")[:80],
                error_message=str(payload.get("error_message") or "Remote bridge failed")[:2000],
                actor=worker_id,
                db_path=resolved.db_path,
            )
            _write_audit(
                resolved.db_path,
                request_id=request.state.request_id,
                action="intelligence.bridge.failed",
                actor_role="intelligence_bridge",
                result="failed",
                source_instance=worker_id,
                details={"job_id": job_id, "error_code": failed.get("error_code")},
            )
            return {"status": "failed", "job": failed, "request_id": request.state.request_id}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return application


def _bearer_dependency(token_provider: Callable[[], str], role: str):
    async def authorize(request: Request) -> str:
        expected = token_provider()
        if not expected:
            raise HTTPException(status_code=503, detail=f"Core {role} authentication is not configured")
        authorization = request.headers.get("Authorization", "")
        scheme, _, supplied = authorization.partition(" ")
        if scheme.lower() != "bearer" or not supplied or not hmac.compare_digest(supplied, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return role

    return authorize


async def _read_json_object(request: Request, max_bytes: int, label: str = "Edge bundle") -> dict[str, Any]:
    return _decode_json_object(await _read_request_bytes(request, max_bytes, label))


async def _read_request_bytes(request: Request, max_bytes: int, label: str) -> bytes:
    content_type = request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    if request.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
        raise HTTPException(status_code=415, detail="Compressed request bodies are not accepted")
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise HTTPException(status_code=413, detail=f"{label} exceeds the request size limit")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header") from exc

    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > max_bytes:
            raise HTTPException(status_code=413, detail=f"{label} exceeds the request size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_json_object(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Invalid JSON constant: {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")
    return payload


def _verify_research_webhook(request: Request, body: bytes, secret: str) -> None:
    timestamp_text = request.headers.get("X-SecOpsAI-Timestamp", "").strip()
    signature_header = request.headers.get("X-SecOpsAI-Signature", "").strip()
    try:
        timestamp = int(timestamp_text)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid webhook timestamp") from exc
    if abs(int(datetime.now(timezone.utc).timestamp()) - timestamp) > RESEARCH_WEBHOOK_MAX_AGE_SECONDS:
        raise HTTPException(status_code=401, detail="Webhook timestamp is outside the replay window")
    algorithm, separator, supplied = signature_header.partition("=")
    if separator != "=" or algorithm.lower() != "sha256" or len(supplied) != 64:
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    expected = hmac.new(secret.encode(), timestamp_text.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied.lower(), expected):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


def _validate_research_alert(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "secopsai.research.alert.v1":
        raise HTTPException(status_code=422, detail="Unsupported research alert schema")
    alert_id = str(payload.get("alert_id") or "").strip()
    alert_type = str(payload.get("alert_type") or "").strip()
    severity = str(payload.get("severity") or "").strip().lower()
    reason = str(payload.get("reason") or "").strip()
    evidence = payload.get("evidence")
    if not alert_id or len(alert_id) > 128:
        raise HTTPException(status_code=422, detail="Research alert ID is invalid")
    if alert_type not in RESEARCH_ALERT_TYPES:
        raise HTTPException(status_code=422, detail="Research alert type is not accepted by this endpoint")
    if severity not in {"info", "low", "medium", "high", "critical"}:
        raise HTTPException(status_code=422, detail="Research alert severity is invalid")
    if not reason or len(reason) > 2000:
        raise HTTPException(status_code=422, detail="Research alert reason is invalid")
    if not isinstance(evidence, dict):
        raise HTTPException(status_code=422, detail="Research alert evidence must be an object")
    return {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "severity": severity,
        "candidate_id": str(payload.get("candidate_id") or "")[:128],
        "campaign_id": str(payload.get("campaign_id") or "")[:128],
        "reason": reason,
        "evidence": _sanitize(evidence),
        "occurred_at": str(payload.get("occurred_at") or soc_store.utc_now())[:64],
    }


def _upsert_research_alert(alert: dict[str, Any], db_path: str) -> dict[str, Any]:
    now = soc_store.utc_now()
    digest = hashlib.sha256(alert["alert_id"].encode()).hexdigest()[:24].upper()
    alert_id = f"RAL-WEB-{digest}"
    dedupe_key = f"research-worker:{alert['alert_id']}"
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        existing = connection.execute(
            "SELECT alert_id FROM research_alerts WHERE dedupe_key = ?", (dedupe_key,)
        ).fetchone()
        connection.execute(
            """INSERT INTO research_alerts
            (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
             reason, evidence_json, status, owner, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 'open', '', ?, ?)
            ON CONFLICT(dedupe_key) DO UPDATE SET alert_type=excluded.alert_type,
                severity=excluded.severity, candidate_id=excluded.candidate_id,
                campaign_id=excluded.campaign_id, reason=excluded.reason,
                evidence_json=excluded.evidence_json, updated_at=excluded.updated_at""",
            (
                alert_id,
                alert["alert_type"],
                alert["severity"],
                alert.get("candidate_id") or None,
                alert.get("campaign_id") or None,
                dedupe_key,
                alert["reason"],
                json.dumps(
                    {
                        **alert["evidence"],
                        "source_alert_id": alert["alert_id"],
                        "occurred_at": alert["occurred_at"],
                        "source": "secopsai-research-worker",
                    },
                    sort_keys=True,
                ),
                now,
                now,
            ),
        )
        stored = connection.execute(
            "SELECT * FROM research_alerts WHERE dedupe_key = ?", (dedupe_key,)
        ).fetchone()
        if stored and alert["alert_type"] in RESEARCH_EXTERNAL_ALERT_TYPES:
            evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
            _upsert_external_candidate(connection, alert, evidence)
            candidate = {
                "candidate_id": alert.get("candidate_id"),
                "ecosystem": evidence.get("ecosystem"),
                "package": evidence.get("package"),
                "version": evidence.get("version"),
                "score": evidence.get("score", 99),
                "first_seen": alert.get("occurred_at"),
                "last_seen": alert.get("occurred_at"),
                "evidence": evidence,
            }
            _upsert_research_alert_finding(connection, dict(stored), candidate=candidate)
        connection.commit()
    return {"alert_id": stored["alert_id"], "created": existing is None}


def _upsert_external_candidate(
    connection: sqlite3.Connection,
    alert: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    """Persist a minimized external lead on the Core disk.

    The worker and API have separate Render disks.  Keeping a candidate in the
    API database means a source-backed lead remains available to the operator
    workflow after the worker restarts.  This helper stores metadata only; the
    package artifact is still collected and quarantined by the worker.
    """
    if str(alert.get("alert_type") or "") not in {"external_advisory_match", "npm_proactive_anomaly"}:
        return
    ecosystem = str(evidence.get("ecosystem") or "").strip().lower()
    package = str(evidence.get("package") or "").strip()
    version = str(evidence.get("version") or "").strip()
    if not ecosystem or not package or not version:
        return
    advisory_id = str(
        evidence.get("advisory_id")
        or evidence.get("reference_identifier")
        or "npm-proactive-static.v1"
    ).strip()[:256]
    candidate_id = str(alert.get("candidate_id") or "").strip()
    if not candidate_id:
        candidate_id = "CAN-" + hashlib.sha256(
            f"{advisory_id}|{ecosystem}|{package}|{version}".encode()
        ).hexdigest()[:24].upper()
    now = str(alert.get("occurred_at") or soc_store.utc_now())[:64]
    reason = str(alert.get("reason") or "External source-backed package lead requires verification.")[:4000]
    evidence_json = json.dumps(evidence, sort_keys=True)
    score_components = json.dumps(
        {
            "source_backed": True,
            "local_exposure_required": False,
            "source_url": evidence.get("source_url"),
            "source_hash": evidence.get("source_hash"),
        },
        sort_keys=True,
    )
    connection.execute(
        """INSERT INTO research_candidates
           (candidate_id, event_id, watchlist_id, ecosystem, package, version,
            reference_identifier, score, score_components_json, reason, status,
            case_id, evidence_json, first_seen, last_seen, algorithm_version)
           VALUES (?, NULL, NULL, ?, ?, ?, ?, 99, ?, ?, 'new', NULL, ?, ?, ?, ?)
           ON CONFLICT(ecosystem, package, version, reference_identifier)
           DO UPDATE SET score=excluded.score,
             score_components_json=excluded.score_components_json,
             reason=excluded.reason, evidence_json=excluded.evidence_json,
             last_seen=excluded.last_seen""",
        (
            candidate_id,
            ecosystem,
            package,
            version,
            advisory_id,
            score_components,
            reason,
            evidence_json,
            now,
            now,
            "external-advisory.v1",
        ),
    )
    campaign_id = str(alert.get("campaign_id") or "").strip()
    if campaign_id:
        connection.execute(
            """INSERT INTO research_campaigns
               (campaign_id, title, status, confidence, attribution, summary, created_at, updated_at)
               VALUES (?, ?, 'candidate', 0, 'unattributed', ?, ?, ?)
               ON CONFLICT(campaign_id) DO UPDATE SET summary=excluded.summary, updated_at=excluded.updated_at""",
            (
                campaign_id,
                f"External package campaign: {campaign_id}"[:500],
                "Source-backed campaign lead. Independent artifact verification is required.",
                now,
                now,
            ),
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _workspace_payload(db_path: str, limit: int) -> dict[str, Any]:
    soc_store.init_db(db_path)
    assets = list_assets(db_path=db_path, limit=limit)
    changes = _sanitize(list_changes(db_path=db_path, limit=limit))
    with soc_store.connect(db_path) as connection:
        finding_rows = connection.execute(
            """
            SELECT finding_id, title, summary, severity, severity_score, status,
                   disposition, source, first_seen, last_seen, updated_at
            FROM findings
            ORDER BY severity_score DESC, last_seen DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        node_rows = connection.execute(
            """
            SELECT node_id, node_type, label, source_id, properties_json, last_seen, updated_at
            FROM asset_graph_nodes
            WHERE node_type IN ('site', 'sensor', 'service', 'wifi_network')
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit * 4,),
        ).fetchall()
        sync_rows = connection.execute(
            """
            SELECT source_instance, schema_version, cursor_json, bundle_exported_at, last_synced_at
            FROM edge_sync_state
            ORDER BY last_synced_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        research_alert_rows = connection.execute(
            """SELECT alert_id, alert_type, severity, reason, evidence_json, status,
                      owner, created_at, updated_at
               FROM research_alerts
               WHERE alert_type IN ('collector_degraded', 'collector_retention_risk',
                                    'external_advisory_match', 'external_advisory_feed_degraded',
                                    'npm_proactive_anomaly', 'npm_enrichment_degraded')
               ORDER BY updated_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()

        total_assets = connection.execute(
            "SELECT COUNT(*) FROM asset_graph_nodes WHERE node_type = 'asset'"
        ).fetchone()[0]
        total_findings = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        total_open_findings = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE status NOT IN ('closed', 'resolved', 'research_lead')"
        ).fetchone()[0]
        total_research_leads = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE status = 'research_lead'"
        ).fetchone()[0]
        total_priority_findings = connection.execute(
            """
            SELECT COUNT(*) FROM findings
            WHERE status NOT IN ('closed', 'resolved', 'research_lead')
              AND lower(severity) IN ('critical', 'high')
            """
        ).fetchone()[0]
        total_operational_alerts = connection.execute(
            """SELECT COUNT(*) FROM research_alerts
               WHERE status = 'open'
                 AND alert_type IN ('collector_degraded', 'collector_retention_risk')"""
        ).fetchone()[0]
        total_external_alerts = connection.execute(
            """SELECT COUNT(*) FROM research_alerts
                WHERE status = 'open'
                 AND alert_type IN ('external_advisory_match', 'external_advisory_feed_degraded',
                                    'npm_proactive_anomaly', 'npm_enrichment_degraded')"""
        ).fetchone()[0]
        graph_counts = {
            str(row["node_type"]): int(row["count"])
            for row in connection.execute(
                """
                SELECT node_type, COUNT(*) AS count
                FROM asset_graph_nodes
                WHERE node_type IN ('site', 'sensor', 'wifi_network')
                GROUP BY node_type
                """
            ).fetchall()
        }

    findings = [dict(row) for row in finding_rows]
    nodes: dict[str, list[dict[str, Any]]] = {
        "sites": [],
        "sensors": [],
        "services": [],
        "wifi_networks": [],
    }
    plural = {"site": "sites", "sensor": "sensors", "service": "services", "wifi_network": "wifi_networks"}
    for row in node_rows:
        item = dict(row)
        item["properties"] = _loads_json(item.pop("properties_json"))
        nodes[plural[str(item.pop("node_type"))]].append(_sanitize(item))

    sync_state = []
    for row in sync_rows:
        item = dict(row)
        item["cursor"] = _loads_json(item.pop("cursor_json"))
        sync_state.append(item)

    research_alerts = []
    for row in research_alert_rows:
        item = dict(row)
        item["evidence"] = _loads_json(item.pop("evidence_json"))
        research_alerts.append(_sanitize(item))

    return {
        "schema_version": "secopsai.core.workspace.v1",
        "generated_at": soc_store.utc_now(),
        "data_classification": "minimized_derived_security_context",
        "summary": {
            "assets": int(total_assets),
            "findings": int(total_findings),
            "open_findings": int(total_open_findings),
            "research_lead_findings": int(total_research_leads),
            "priority_findings": int(total_priority_findings),
            "sensors": graph_counts.get("sensor", 0),
            "sites": graph_counts.get("site", 0),
            "wifi_networks": graph_counts.get("wifi_network", 0),
            "operational_research_alerts": int(total_operational_alerts),
            "external_research_alerts": int(total_external_alerts),
        },
        "assets": _sanitize(assets),
        "findings": _sanitize(findings),
        "changes": changes,
        "sync_state": sync_state,
        "research_alerts": research_alerts,
        **nodes,
    }


def _write_audit(
    db_path: str,
    *,
    request_id: str,
    action: str,
    actor_role: str,
    result: str,
    source_instance: str | None,
    details: dict[str, Any],
) -> None:
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO core_api_audit_logs (
                request_id, occurred_at, action, actor_role, result, source_instance, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                soc_store.utc_now(),
                action,
                actor_role,
                result,
                source_instance,
                json.dumps(_sanitize(details), sort_keys=True),
            ),
        )
        connection.commit()


def _write_audit_safely(db_path: str, **kwargs: Any) -> None:
    try:
        _write_audit(db_path, **kwargs)
    except sqlite3.Error:
        LOGGER.exception("Unable to persist Core API audit event")


def _list_audit_logs(db_path: str, limit: int) -> list[dict[str, Any]]:
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT request_id, occurred_at, action, actor_role, result, source_instance, details_json
            FROM core_api_audit_logs
            ORDER BY audit_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    logs = []
    for row in rows:
        item = dict(row)
        item["details"] = _loads_json(item.pop("details_json"))
        logs.append(item)
    return logs


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize(item)
            for key, item in value.items()
            if str(key).strip().lower() not in REDACTED_KEYS
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def _source_instance_label(bundle: dict[str, Any]) -> str | None:
    source = bundle.get("source_instance")
    if not isinstance(source, dict):
        return None
    product = str(source.get("product") or "secopsai_edge")
    api = str(source.get("api") or "edge-api")
    scope = str(source.get("organization_id") or source.get("instance_id") or "legacy")
    return f"{product}:{api}:{scope}"[:500]


def _enforce_organization_scope(bundle: dict[str, Any], expected: str) -> None:
    if not expected:
        return
    source = bundle.get("source_instance")
    organization_id = str(source.get("organization_id") or "") if isinstance(source, dict) else ""
    if not organization_id or not hmac.compare_digest(organization_id, expected):
        raise HTTPException(status_code=403, detail="Edge bundle organization is not authorized")


def _request_id(value: str | None) -> str:
    candidate = str(value or "").strip()
    if candidate and len(candidate) <= 128 and all(character.isalnum() or character in "-_." for character in candidate):
        return candidate
    return str(uuid.uuid4())


def _loads_json(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _csv_setting(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _positive_int_setting(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


app = create_app()
