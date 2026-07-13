from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secopsai.core_api import CoreAPISettings, create_app


INGEST_TOKEN = "ingest-token-with-at-least-thirty-two-characters"
READ_TOKEN = "read-token-with-at-least-thirty-two-characters--"


def _bundle() -> dict:
    return {
        "schema_version": "secopsai.edge.bundle.v1",
        "exported_at": "2026-07-13T12:00:00Z",
        "source_instance": {
            "product": "secopsai_edge",
            "api": "secopsai-edge-api",
            "version": "0.2.7",
            "organization_id": "org-pilot-1",
        },
        "cursor": {"mode": "full", "last_observed_at": "2026-07-13T12:00:00Z"},
        "graph": {
            "nodes": [
                {
                    "id": "edge:site:site-1",
                    "type": "site",
                    "label": "Pilot Office",
                    "source_id": "site-1",
                    "properties": {"name": "Pilot Office"},
                },
                {
                    "id": "edge:sensor:sensor-1",
                    "type": "sensor",
                    "label": "MacBook Sensor",
                    "source_id": "sensor-1",
                    "properties": {"status": "online", "site_id": "site-1"},
                },
                {
                    "id": "edge:asset:asset-1",
                    "type": "asset",
                    "label": "pilot-mac",
                    "source_id": "asset-1",
                    "properties": {
                        "site_id": "site-1",
                        "ip_address": "192.168.1.10",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "hostname": "pilot-mac",
                        "status": "active",
                        "last_seen_at": "2026-07-13T12:00:00Z",
                    },
                },
            ],
            "edges": [
                {
                    "id": "edge:site_has_sensor:1",
                    "type": "site_has_sensor",
                    "from": "edge:site:site-1",
                    "to": "edge:sensor:sensor-1",
                    "properties": {},
                }
            ],
        },
        "findings": [
            {
                "id": "finding-1",
                "type": "new_device",
                "title": "New device observed",
                "summary": "A new device appeared on the approved network.",
                "severity": "medium",
                "status": "open",
                "asset_node_id": "edge:asset:asset-1",
                "site_node_id": "edge:site:site-1",
                "evidence": {
                    "ip": "192.168.1.10",
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                },
                "created_at": "2026-07-13T12:00:00Z",
                "updated_at": "2026-07-13T12:00:00Z",
            }
        ],
    }


@pytest.fixture
def client(tmp_path: Path):
    settings = CoreAPISettings(
        db_path=str(tmp_path / "core.db"),
        ingest_token=INGEST_TOKEN,
        read_token=READ_TOKEN,
        environment="test",
        organization_id="org-pilot-1",
        cors_origins=("https://console.example.test",),
        trusted_hosts=("testserver",),
        max_bundle_bytes=100_000,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client, settings


def test_health_and_readiness_are_public(client):
    test_client, _ = client
    assert test_client.get("/healthz").json()["status"] == "ok"
    assert test_client.get("/readyz").json() == {"status": "ready", "data_store": "sqlite"}


def test_ingest_and_workspace_use_separate_scoped_tokens(client):
    test_client, settings = client
    assert test_client.post("/api/v1/edge/bundles", json=_bundle()).status_code == 401
    assert test_client.get("/api/v1/workspace").status_code == 401
    assert (
        test_client.post(
            "/api/v1/edge/bundles",
            json=_bundle(),
            headers={"Authorization": f"Bearer {READ_TOKEN}"},
        ).status_code
        == 401
    )

    imported = test_client.post(
        "/api/v1/edge/bundles",
        json=_bundle(),
        headers={"Authorization": f"Bearer {INGEST_TOKEN}", "X-Request-ID": "test-import-1"},
    )
    assert imported.status_code == 200
    assert imported.json()["status"] == "imported"
    assert imported.json()["counts"] == {"nodes": 3, "edges": 1, "findings": 1}
    assert imported.headers["X-Request-ID"] == "test-import-1"

    workspace = test_client.get(
        "/api/v1/workspace",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    )
    assert workspace.status_code == 200
    payload = workspace.json()
    assert payload["schema_version"] == "secopsai.core.workspace.v1"
    assert payload["summary"]["assets"] == 1
    assert payload["summary"]["findings"] == 1
    assert "mac_address" not in json.dumps(payload)

    audit = test_client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    ).json()["audit_logs"]
    assert audit[0]["action"] == "edge.bundle.imported"
    assert audit[0]["request_id"] == "test-import-1"

    with sqlite3.connect(settings.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM core_api_audit_logs").fetchone()[0] == 1


def test_ingest_rejects_raw_telemetry_and_records_rejection(client):
    test_client, _ = client
    bundle = _bundle()
    bundle["graph"]["nodes"][0]["properties"]["raw_nmap_output"] = "secret raw output"
    response = test_client.post(
        "/api/v1/edge/bundles",
        json=bundle,
        headers={"Authorization": f"Bearer {INGEST_TOKEN}"},
    )
    assert response.status_code == 422
    assert "forbidden raw telemetry" in response.json()["detail"]

    audit = test_client.get(
        "/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    ).json()["audit_logs"]
    assert audit[0]["action"] == "edge.bundle.rejected"
    assert "secret raw output" not in json.dumps(audit)


def test_ingest_rejects_a_bundle_from_another_organization(client):
    test_client, _ = client
    bundle = _bundle()
    bundle["source_instance"]["organization_id"] = "org-other"
    response = test_client.post(
        "/api/v1/edge/bundles",
        json=bundle,
        headers={"Authorization": f"Bearer {INGEST_TOKEN}"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Edge bundle organization is not authorized"


def test_ingest_rejects_oversized_duplicate_and_compressed_json(client):
    test_client, _ = client
    headers = {"Authorization": f"Bearer {INGEST_TOKEN}", "Content-Type": "application/json"}
    oversized = test_client.post(
        "/api/v1/edge/bundles",
        content=b"{" + b" " * 100_001 + b"}",
        headers=headers,
    )
    assert oversized.status_code == 413

    duplicate = test_client.post(
        "/api/v1/edge/bundles",
        content=b'{"schema_version":"a","schema_version":"b"}',
        headers=headers,
    )
    assert duplicate.status_code == 400

    compressed = test_client.post(
        "/api/v1/edge/bundles",
        content=b"not-really-compressed",
        headers={**headers, "Content-Encoding": "gzip"},
    )
    assert compressed.status_code == 415


def test_production_settings_fail_closed():
    settings = CoreAPISettings(
        db_path=":memory:",
        ingest_token="short",
        read_token="also-short",
        environment="production",
        cors_origins=("*",),
        trusted_hosts=("*",),
    )
    with pytest.raises(RuntimeError, match="INGEST_TOKEN"):
        with TestClient(create_app(settings)):
            pass

    missing_scope = CoreAPISettings(
        db_path=":memory:",
        ingest_token=INGEST_TOKEN,
        read_token=READ_TOKEN,
        environment="production",
        cors_origins=("https://console.example.test",),
        trusted_hosts=("core.example.test",),
    )
    with pytest.raises(RuntimeError, match="ORGANIZATION_ID"):
        with TestClient(create_app(missing_scope)):
            pass
