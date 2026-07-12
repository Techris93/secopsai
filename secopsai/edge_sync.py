from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import requests

import soc_store
from secopsai.graph_store import SOURCE_EDGE, save_sync_state, upsert_graph


SCHEMA_VERSION = "secopsai.edge.bundle.v1"
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


def fetch_bundle(edge_api_url: str, admin_token: str) -> dict[str, Any]:
    base_url = edge_api_url.rstrip("/")
    response = requests.get(
        f"{base_url}/api/v1/core/export",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Edge API returned an invalid bundle")
    return payload


def import_bundle(bundle: dict[str, Any], *, db_path: str | None = None) -> dict[str, Any]:
    _validate_bundle(bundle)
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
    admin_token: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    resolved_url = edge_api_url or os.environ.get("SECOPSAI_EDGE_API_URL")
    resolved_token = admin_token or os.environ.get("SECOPSAI_EDGE_ADMIN_TOKEN")
    if not resolved_url:
        raise ValueError("--edge-api-url or SECOPSAI_EDGE_API_URL is required")
    if not resolved_token:
        raise ValueError("--admin-token or SECOPSAI_EDGE_ADMIN_TOKEN is required")
    return import_bundle(fetch_bundle(resolved_url, resolved_token), db_path=db_path)


def _validate_bundle(bundle: dict[str, Any]) -> None:
    if bundle.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Unsupported Edge bundle schema: {bundle.get('schema_version')}")
    graph = bundle.get("graph")
    if not isinstance(graph, dict):
        raise ValueError("Edge bundle missing graph object")
    if not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise ValueError("Edge bundle graph must contain nodes and edges arrays")
    if not isinstance(bundle.get("findings"), list):
        raise ValueError("Edge bundle findings must be an array")


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
        version = str(source_instance.get("version") or "unknown")
        return f"{product}:{api}:{version}"
    return "secopsai_edge:edge-api:unknown"


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
