from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

import soc_store
from secopsai import __version__
from secopsai.edge_sync import import_bundle, validate_bundle
from secopsai.graph_store import list_assets, list_changes


LOGGER = logging.getLogger(__name__)
PROTECTED_ENVIRONMENTS = {"pilot", "production"}
MIN_PROTECTED_TOKEN_LENGTH = 32
DEFAULT_MAX_BUNDLE_BYTES = 10 * 1024 * 1024
REDACTED_KEYS = {
    "bssid",
    "mac",
    "mac_address",
    "nmap_xml",
    "packet_capture",
    "pcap",
    "raw_nmap_output",
    "raw_output",
    "raw_packet_data",
    "raw_scan_log",
    "raw_scan_logs",
}


@dataclass(frozen=True)
class CoreAPISettings:
    db_path: str
    ingest_token: str = ""
    read_token: str = ""
    environment: str = "local"
    organization_id: str = ""
    cors_origins: tuple[str, ...] = ()
    trusted_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES

    @classmethod
    def from_environment(cls) -> "CoreAPISettings":
        return cls(
            db_path=os.environ.get("SECOPSAI_CORE_DB_PATH") or soc_store.default_db_path(),
            ingest_token=os.environ.get("SECOPSAI_CORE_INGEST_TOKEN", "").strip(),
            read_token=os.environ.get("SECOPSAI_CORE_READ_TOKEN", "").strip(),
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
        if hmac.compare_digest(self.ingest_token, self.read_token):
            raise RuntimeError("Core ingestion and read tokens must be different")
        if not self.organization_id:
            raise RuntimeError("SECOPSAI_CORE_ORGANIZATION_ID is required in pilot/production")
        if not self.trusted_hosts or "*" in self.trusted_hosts:
            raise RuntimeError("SECOPSAI_CORE_TRUSTED_HOSTS must be explicit in pilot/production")
        if "*" in self.cors_origins:
            raise RuntimeError("SECOPSAI_CORE_CORS_ORIGINS cannot use a wildcard in pilot/production")


def create_app(settings: CoreAPISettings | None = None) -> FastAPI:
    resolved = settings or CoreAPISettings.from_environment()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
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


async def _read_json_object(request: Request, max_bytes: int) -> dict[str, Any]:
    content_type = request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    if request.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
        raise HTTPException(status_code=415, detail="Compressed request bodies are not accepted")
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise HTTPException(status_code=413, detail="Edge bundle exceeds the request size limit")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header") from exc

    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > max_bytes:
            raise HTTPException(status_code=413, detail="Edge bundle exceeds the request size limit")
        chunks.append(chunk)
    try:
        payload = json.loads(
            b"".join(chunks).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Invalid JSON constant: {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")
    return payload


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

        total_assets = connection.execute(
            "SELECT COUNT(*) FROM asset_graph_nodes WHERE node_type = 'asset'"
        ).fetchone()[0]
        total_findings = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        total_open_findings = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE status NOT IN ('closed', 'resolved')"
        ).fetchone()[0]
        total_priority_findings = connection.execute(
            """
            SELECT COUNT(*) FROM findings
            WHERE status NOT IN ('closed', 'resolved')
              AND lower(severity) IN ('critical', 'high')
            """
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

    return {
        "schema_version": "secopsai.core.workspace.v1",
        "generated_at": soc_store.utc_now(),
        "data_classification": "minimized_derived_security_context",
        "summary": {
            "assets": int(total_assets),
            "findings": int(total_findings),
            "open_findings": int(total_open_findings),
            "priority_findings": int(total_priority_findings),
            "sensors": graph_counts.get("sensor", 0),
            "sites": graph_counts.get("site", 0),
            "wifi_networks": graph_counts.get("wifi_network", 0),
        },
        "assets": _sanitize(assets),
        "findings": _sanitize(findings),
        "changes": changes,
        "sync_state": sync_state,
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
