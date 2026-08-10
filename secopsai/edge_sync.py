from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import requests

import soc_store
from secopsai.graph_store import SOURCE_EDGE, save_sync_state, upsert_graph
from secopsai.sqlite_writer_lock import sqlite_writer_lock


SCHEMA_VERSION = "secopsai.edge.bundle.v1"
MAX_GRAPH_NODES = 100_000
MAX_GRAPH_EDGES = 200_000
MAX_FINDINGS = 50_000
CORE_PUSH_ATTEMPTS = 3
CORE_RETRYABLE_STATUS_CODES = {500, 502, 503, 504}
CORE_RETRY_BACKOFF_SECONDS = 0.5
NODE_TYPES = {"site", "sensor", "scan", "asset", "service", "wifi_network"}
EDGE_TYPES = {
    "site_has_sensor",
    "sensor_ran_scan",
    "scan_observed_asset",
    "asset_exposes_service",
    "sensor_observed_wifi",
}
FORBIDDEN_RAW_KEYS = {
    "nmap_xml",
    "packet_capture",
    "pcap",
    "raw_nmap_output",
    "raw_output",
    "raw_packet_data",
    "raw_scan_log",
    "raw_scan_logs",
}
SEVERITY_SCORES = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 25,
    "info": 10,
}
STATUS_MAPPING = {
    "open": ("open", "unreviewed"),
    "acknowledged": ("in_review", "needs_review"),
    "resolved": ("closed", "remediated"),
    "false_positive": ("closed", "false_positive"),
}


def load_bundle(path: str | Path) -> dict[str, Any]:
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Edge bundle must be a JSON object")
    return payload


def fetch_bundle(edge_api_url: str, access_token: str) -> dict[str, Any]:
    base_url = edge_api_url.rstrip("/")
    response = requests.get(
        f"{base_url}/api/v1/core/export",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Edge API returned an invalid bundle")
    return payload


def push_bundle(bundle: dict[str, Any], core_api_url: str, ingest_token: str) -> dict[str, Any]:
    """Send a validated normalized bundle to the protected hosted Core API."""

    validate_bundle(bundle)
    request_url = f"{core_api_url.rstrip('/')}/api/v1/edge/bundles"
    request_headers = {"Authorization": f"Bearer {ingest_token}", "Accept": "application/json"}
    response = None
    for attempt in range(CORE_PUSH_ATTEMPTS):
        try:
            response = requests.post(
                request_url,
                headers=request_headers,
                json=bundle,
                timeout=30,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            if attempt == CORE_PUSH_ATTEMPTS - 1:
                raise ValueError("Core API request failed while ingesting the Edge bundle") from exc
        else:
            if response.status_code not in CORE_RETRYABLE_STATUS_CODES:
                break
        if attempt < CORE_PUSH_ATTEMPTS - 1:
            time.sleep(CORE_RETRY_BACKOFF_SECONDS * (attempt + 1))

    if response is None:
        raise ValueError("Core API request failed while ingesting the Edge bundle")
    if response.status_code >= 300:
        raise ValueError(f"Core API returned HTTP {response.status_code} while ingesting the Edge bundle")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("Core API returned invalid JSON while ingesting the Edge bundle") from exc
    if not isinstance(payload, dict) or payload.get("status") != "imported":
        raise ValueError("Core API returned an unsupported Edge import response")
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    return {
        "status": "imported",
        "schema_version": payload.get("schema_version"),
        "source_instance": payload.get("source_instance"),
        "counts": {
            "nodes": int(counts.get("nodes", 0)),
            "edges": int(counts.get("edges", 0)),
            "findings": int(counts.get("findings", 0)),
        },
        "request_id": str(payload.get("request_id") or ""),
    }


def import_bundle(bundle: dict[str, Any], *, db_path: str | None = None) -> dict[str, Any]:
    validate_bundle(bundle)
    with sqlite_writer_lock(db_path):
        return _import_bundle_unlocked(bundle, db_path=db_path)


def _import_bundle_unlocked(bundle: dict[str, Any], *, db_path: str | None = None) -> dict[str, Any]:
    graph = bundle["graph"]
    graph_counts = upsert_graph(nodes=graph["nodes"], edges=graph["edges"], db_path=db_path)
    findings = [_normalize_finding(finding) for finding in bundle.get("findings", [])]
    finding_count = _persist_edge_findings(findings, db_path=db_path)
    source_instance = _source_instance_id(bundle.get("source_instance"))
    save_sync_state(
        source_instance=source_instance,
        schema_version=str(bundle["schema_version"]),
        cursor=dict(bundle.get("cursor") or {}),
        bundle_exported_at=bundle.get("exported_at"),
        db_path=db_path,
    )
    return {
        "schema_version": bundle["schema_version"],
        "source_instance": source_instance,
        "nodes": graph_counts["nodes"],
        "edges": graph_counts["edges"],
        "findings": finding_count,
        "db_path": db_path or soc_store.default_db_path(),
    }


def sync_from_api(
    *,
    edge_api_url: str | None = None,
    access_token: str | None = None,
    admin_token: str | None = None,
    core_api_url: str | None = None,
    core_ingest_token: str | None = None,
    remote_only: bool = False,
    db_path: str | None = None,
) -> dict[str, Any]:
    resolved_url = edge_api_url or os.environ.get("SECOPSAI_EDGE_API_URL")
    resolved_token = (
        access_token
        or admin_token
        or os.environ.get("SECOPSAI_EDGE_ACCESS_TOKEN")
        or os.environ.get("SECOPSAI_EDGE_ADMIN_TOKEN")
    )
    if not resolved_url:
        raise ValueError("--edge-api-url or SECOPSAI_EDGE_API_URL is required")
    if not resolved_token:
        raise ValueError("--access-token or SECOPSAI_EDGE_ACCESS_TOKEN is required")
    resolved_core_url = core_api_url or os.environ.get("SECOPSAI_CORE_API_URL")
    resolved_core_token = core_ingest_token or os.environ.get("SECOPSAI_CORE_INGEST_TOKEN")
    if bool(resolved_core_url) != bool(resolved_core_token):
        raise ValueError("SECOPSAI_CORE_API_URL and SECOPSAI_CORE_INGEST_TOKEN must be provided together")
    if remote_only and not resolved_core_url:
        raise ValueError("--remote-only requires SECOPSAI_CORE_API_URL and SECOPSAI_CORE_INGEST_TOKEN")

    bundle = fetch_bundle(resolved_url, resolved_token)
    remote_result = (
        push_bundle(bundle, resolved_core_url, resolved_core_token)
        if resolved_core_url and resolved_core_token
        else None
    )
    local_result = None if remote_only else import_bundle(bundle, db_path=db_path)
    if remote_result is None:
        return local_result or {}
    result = dict(local_result or {})
    result["core"] = remote_result
    result["remote_only"] = remote_only
    return result


def validate_bundle(bundle: dict[str, Any]) -> None:
    if bundle.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Unsupported Edge bundle schema: {bundle.get('schema_version')}")
    graph = bundle.get("graph")
    if not isinstance(graph, dict):
        raise ValueError("Edge bundle missing graph object")
    if not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise ValueError("Edge bundle graph must contain nodes and edges arrays")
    if not isinstance(bundle.get("findings"), list):
        raise ValueError("Edge bundle findings must be an array")
    source_instance = bundle.get("source_instance")
    if not isinstance(source_instance, dict):
        raise ValueError("Edge bundle source_instance must be an object")
    for field in ("product", "api", "organization_id", "instance_id"):
        value = source_instance.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 256):
            raise ValueError(f"Edge bundle source_instance.{field} must be a short string")
    if len(graph["nodes"]) > MAX_GRAPH_NODES:
        raise ValueError(f"Edge bundle exceeds the {MAX_GRAPH_NODES} node limit")
    if len(graph["edges"]) > MAX_GRAPH_EDGES:
        raise ValueError(f"Edge bundle exceeds the {MAX_GRAPH_EDGES} edge limit")
    if len(bundle["findings"]) > MAX_FINDINGS:
        raise ValueError(f"Edge bundle exceeds the {MAX_FINDINGS} finding limit")

    node_ids: set[str] = set()
    for node in graph["nodes"]:
        if not isinstance(node, dict) or not str(node.get("id") or ""):
            raise ValueError("Every Edge graph node must be an object with an id")
        node_id = str(node["id"])
        if len(node_id) > 512 or node_id in node_ids:
            raise ValueError(f"Edge graph node id is invalid or duplicated: {node_id[:100]}")
        node_ids.add(node_id)
        if str(node.get("type") or "") not in NODE_TYPES:
            raise ValueError(f"Unsupported Edge graph node type: {node.get('type')}")
    edge_ids: set[str] = set()
    for edge in graph["edges"]:
        if not isinstance(edge, dict) or not all(str(edge.get(key) or "") for key in ("id", "from", "to")):
            raise ValueError("Every Edge graph edge must include id, from, and to")
        edge_id = str(edge["id"])
        if len(edge_id) > 1024 or edge_id in edge_ids:
            raise ValueError(f"Edge graph edge id is invalid or duplicated: {edge_id[:100]}")
        edge_ids.add(edge_id)
        if str(edge.get("type") or "") not in EDGE_TYPES:
            raise ValueError(f"Unsupported Edge graph edge type: {edge.get('type')}")
        if str(edge["from"]) not in node_ids or str(edge["to"]) not in node_ids:
            raise ValueError(f"Edge graph edge references an unknown node: {edge_id[:100]}")
    for finding in bundle["findings"]:
        if not isinstance(finding, dict) or not str(finding.get("id") or ""):
            raise ValueError("Every Edge finding must be an object with an id")

    forbidden = _find_forbidden_raw_key(bundle)
    if forbidden:
        raise ValueError(f"Edge bundle contains forbidden raw telemetry field: {forbidden}")


def _normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    edge_id = str(finding.get("id") or "")
    if not edge_id:
        raise ValueError("Edge finding is missing id")
    edge_status = str(finding.get("status") or "open")
    status, disposition = _mapped_state(edge_status)
    severity = str(finding.get("severity") or "low").lower()
    timestamp = str(finding.get("updated_at") or finding.get("created_at") or soc_store.utc_now())
    event_id = f"edge-finding:{edge_id}"
    finding_type = str(finding.get("type") or "edge_finding")
    mitre_ids = [
        str(item.get("id"))
        for item in finding.get("mitre_attack", [])
        if isinstance(item, dict) and item.get("id")
    ]
    payload = {
        "finding_id": _core_finding_id(edge_id),
        "title": str(finding.get("title") or finding_type),
        "summary": str(finding.get("summary") or ""),
        "severity": severity,
        "severity_score": SEVERITY_SCORES.get(severity, 25),
        "status": status,
        "disposition": disposition,
        "source": SOURCE_EDGE,
        "platform": "edge",
        "rule_id": f"EDGE-{finding_type.upper()}",
        "rule_ids": [f"EDGE-{finding_type.upper()}"],
        "rule_name": str(finding.get("title") or finding_type),
        "rule_names": [str(finding.get("title") or finding_type)],
        "mitre": mitre_ids[0] if mitre_ids else "",
        "mitre_ids": mitre_ids,
        "first_seen": str(finding.get("created_at") or timestamp),
        "last_seen": timestamp,
        "created_at": str(finding.get("created_at") or timestamp),
        "event_ids": [event_id],
        "event_count": 1,
        "events": [
            {
                "event_id": event_id,
                "timestamp": timestamp,
                "sourcetype": SOURCE_EDGE,
                "event_type": finding_type,
                "message": str(finding.get("summary") or finding.get("title") or finding_type),
                "severity_hint": severity,
                "asset_node_id": finding.get("asset_node_id"),
                "wifi_node_id": finding.get("wifi_node_id"),
            }
        ],
        "evidence": finding.get("evidence") or {},
        "asset_node_id": finding.get("asset_node_id"),
        "wifi_node_id": finding.get("wifi_node_id"),
        "site_node_id": finding.get("site_node_id"),
        "secopsai_edge": {
            "finding_id": edge_id,
            "finding_type": finding_type,
            "edge_status": edge_status,
        },
        "recommended_actions": _recommended_actions(finding_type),
    }
    return payload


def _persist_edge_findings(findings: list[dict[str, Any]], *, db_path: str | None = None) -> int:
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    with soc_store.connect(db_path) as connection:
        for finding in findings:
            existing = connection.execute(
                "SELECT status, disposition, created_at, payload_json FROM findings WHERE finding_id = ?",
                (finding["finding_id"],),
            ).fetchone()
            status = finding["status"]
            disposition = finding["disposition"]
            created_at = finding.get("created_at") or now
            if existing is not None:
                created_at = str(existing["created_at"])
                if _analyst_state_changed(existing):
                    status = str(existing["status"])
                    disposition = str(existing["disposition"])

            persisted = dict(finding)
            persisted["status"] = status
            persisted["disposition"] = disposition
            connection.execute(
                """
                INSERT INTO findings (
                    finding_id, title, summary, severity, severity_score, status,
                    disposition, source, first_seen, last_seen, created_at,
                    updated_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    title = excluded.title,
                    summary = excluded.summary,
                    severity = excluded.severity,
                    severity_score = excluded.severity_score,
                    status = excluded.status,
                    disposition = excluded.disposition,
                    source = excluded.source,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at,
                    payload_json = excluded.payload_json
                """,
                (
                    persisted["finding_id"],
                    persisted["title"],
                    persisted["summary"],
                    persisted["severity"],
                    int(persisted["severity_score"]),
                    status,
                    disposition,
                    SOURCE_EDGE,
                    persisted["first_seen"],
                    persisted["last_seen"],
                    created_at,
                    now,
                    json.dumps(persisted, sort_keys=True),
                ),
            )
            connection.execute("DELETE FROM finding_events WHERE finding_id = ?", (persisted["finding_id"],))
            connection.executemany(
                "INSERT INTO finding_events (finding_id, event_id) VALUES (?, ?)",
                [(persisted["finding_id"], event_id) for event_id in persisted.get("event_ids", [])],
            )
        connection.commit()
    return len(findings)


def _analyst_state_changed(existing: Any) -> bool:
    try:
        payload = json.loads(str(existing["payload_json"]))
    except json.JSONDecodeError:
        return str(existing["disposition"]) != "unreviewed"
    previous_status = str(((payload.get("secopsai_edge") or {}).get("edge_status")) or "open")
    managed_status, managed_disposition = _mapped_state(previous_status)
    return (str(existing["status"]), str(existing["disposition"])) != (managed_status, managed_disposition)


def _mapped_state(edge_status: str) -> tuple[str, str]:
    return STATUS_MAPPING.get(str(edge_status or "").lower(), ("open", "unreviewed"))


def _core_finding_id(edge_id: str) -> str:
    digest = hashlib.blake2s(edge_id.encode("utf-8"), digest_size=8).hexdigest().upper()
    return f"EDGE-{digest}"


def _source_instance_id(source_instance: Any) -> str:
    if isinstance(source_instance, dict):
        product = str(source_instance.get("product") or "secopsai_edge")
        api = str(source_instance.get("api") or "edge-api")
        organization_id = str(source_instance.get("organization_id") or "").strip()
        instance_id = str(source_instance.get("instance_id") or "").strip()
        stable_scope = organization_id or instance_id or "legacy"
        return f"{product}:{api}:{stable_scope}"
    return "secopsai_edge:edge-api:legacy"


def _find_forbidden_raw_key(value: Any) -> str | None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, nested in item.items():
                normalized = str(key).strip().lower()
                if normalized in FORBIDDEN_RAW_KEYS:
                    return normalized
                pending.append(nested)
        elif isinstance(item, list):
            pending.extend(item)
    return None


def _recommended_actions(finding_type: str) -> list[str]:
    actions = {
        "new_device": [
            "Verify device ownership and expected business purpose.",
            "Add the device to the approved inventory if legitimate.",
        ],
        "risky_open_port": [
            "Confirm the exposed service is required on the internal network.",
            "Restrict administrative services to trusted hosts or VPN users.",
        ],
        "weak_wifi": [
            "Disable open or weak wireless networks.",
            "Confirm the SSID and BSSID are authorized.",
        ],
        "duplicate_ssid": [
            "Compare the BSSID against approved access points.",
            "Investigate possible rogue or evil-twin wireless infrastructure.",
        ],
    }
    return actions.get(
        finding_type,
        [
            "Review the Edge evidence and affected graph context.",
            "Decide whether this is expected behavior, accepted risk, or requires remediation.",
        ],
    )
