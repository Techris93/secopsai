from __future__ import annotations

import json
import hashlib
import hmac
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import soc_store
from secopsai.core_api import CoreAPISettings, create_app


INGEST_TOKEN = "ingest-token-with-at-least-thirty-two-characters"
READ_TOKEN = "read-token-with-at-least-thirty-two-characters--"
WEBHOOK_SECRET = "research-webhook-secret-with-at-least-thirty-two-characters"
INTELLIGENCE_TOKEN = "intelligence-token-with-at-least-thirty-two-characters"
BRIDGE_TOKEN = "bridge-token-with-at-least-thirty-two-characters----"


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
        intelligence_token=INTELLIGENCE_TOKEN,
        bridge_token=BRIDGE_TOKEN,
        environment="test",
        organization_id="org-pilot-1",
        cors_origins=("https://console.example.test",),
        trusted_hosts=("testserver",),
        max_bundle_bytes=100_000,
        research_webhook_secret=WEBHOOK_SECRET,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client, settings


def test_health_and_readiness_are_public(client):
    test_client, _ = client
    assert test_client.get("/healthz").json()["status"] == "ok"
    assert test_client.get("/readyz").json() == {"status": "ready", "data_store": "sqlite"}


def test_intelligence_read_and_job_routes_use_separate_credentials(client):
    test_client, settings = client
    actions = test_client.get(
        "/api/v1/intelligence/actions",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    )
    assert actions.status_code == 200
    assert any(item["name"] == "workspace_summary" for item in actions.json()["actions"])

    query = test_client.post(
        "/api/v1/intelligence/query",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
        json={"action": "workspace_summary", "inputs": {}},
    )
    assert query.status_code == 200
    assert query.json()["read_only"] is True

    denied = test_client.post(
        "/api/v1/intelligence/jobs",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
        json={"action": "prioritize_findings"},
    )
    assert denied.status_code == 401

    queued = test_client.post(
        "/api/v1/intelligence/jobs",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
        json={"action": "prioritize_findings", "requested_by": "dashboard"},
    )
    assert queued.status_code == 200
    job_id = queued.json()["job"]["job_id"]
    listed = test_client.get(
        "/api/v1/intelligence/jobs",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
    )
    assert listed.status_code == 200
    assert listed.json()["jobs"][0]["job_id"] == job_id

    canceled = test_client.post(
        f"/api/v1/intelligence/jobs/{job_id}/cancel",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
    )
    assert canceled.status_code == 200
    assert canceled.json()["job"]["status"] == "canceled"

    with sqlite3.connect(settings.db_path) as connection:
        audit_actions = [row[0] for row in connection.execute("SELECT action FROM core_api_audit_logs ORDER BY audit_id")]
    assert "intelligence.query.completed" in audit_actions
    assert "intelligence.job.queued" in audit_actions
    assert "intelligence.job.canceled" in audit_actions


def test_intelligence_autopilot_is_configurable_and_queues_findings(client):
    test_client, settings = client
    now = soc_store.utc_now()
    soc_store.persist_findings(
        [
            {
                "finding_id": "FND-AUTOPILOT-API",
                "title": "Finding awaiting model triage",
                "summary": "Normalized host evidence is ready for review.",
                "severity": "medium",
                "severity_score": 55,
                "status": "open",
                "disposition": "unreviewed",
                "source": "test-host",
                "first_seen": now,
                "last_seen": now,
                "event_ids": [],
                "rule_ids": ["TEST-HOST-RULE"],
                "evidence": {},
            }
        ],
        source="test-host",
        db_path=settings.db_path,
    )
    denied = test_client.get(
        "/api/v1/intelligence/autopilot",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    )
    assert denied.status_code == 401
    configured = test_client.post(
        "/api/v1/intelligence/autopilot/configure",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
        json={
            "mode": "guarded",
            "selected_model": "kimi/kimi-k2.7-code-highspeed",
            "min_auto_close_confidence": 98,
            "min_evidence_refs": 2,
            "max_records_per_cycle": 10,
            "auto_create_tuning_proposals": True,
            "auto_activate_tuning": False,
        },
    )
    assert configured.status_code == 200
    assert configured.json()["settings"]["mode"] == "guarded"
    queued = test_client.post(
        "/api/v1/intelligence/autopilot/run-now",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
    )
    assert queued.status_code == 200
    assert queued.json()["result"]["queued"][0]["finding_id"] == "FND-AUTOPILOT-API"
    status_payload = test_client.get(
        "/api/v1/intelligence/autopilot",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
    ).json()
    assert status_payload["summary"]["awaiting_model"] == 1
    assert status_payload["settings"]["selected_model"].startswith("kimi/")


def test_daily_automation_routes_are_protected_configurable_and_audited(client, monkeypatch):
    test_client, settings = client
    assert test_client.get(
        "/api/v1/intelligence/daily",
        headers={"Authorization": f"Bearer {READ_TOKEN}"},
    ).status_code == 401
    initial = test_client.get(
        "/api/v1/intelligence/daily",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
    )
    assert initial.status_code == 200
    assert initial.json()["settings"]["interval_seconds"] == 86400

    configured = test_client.post(
        "/api/v1/intelligence/daily/configure",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
        json={
            "enabled": True,
            "interval_seconds": 3600,
            "max_alert_reviews": 10,
            "max_investigations": 2,
            "max_candidate_cases": 5,
            "auto_promote_candidates": False,
            "run_learning": True,
        },
    )
    assert configured.status_code == 200
    assert configured.json()["settings"]["interval_seconds"] == 3600
    monkeypatch.setattr(
        "secopsai.core_api.run_daily_automation_cycle",
        lambda **kwargs: {"run_id": "DAR-0123456789ABCDEF", "status": "succeeded", "summary": {}},
    )
    ran = test_client.post(
        "/api/v1/intelligence/daily/run",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
    )
    assert ran.status_code == 200
    assert ran.json()["result"]["status"] == "succeeded"
    with sqlite3.connect(settings.db_path) as connection:
        audit_actions = [row[0] for row in connection.execute("SELECT action FROM core_api_audit_logs ORDER BY audit_id")]
    assert "intelligence.daily.configured" in audit_actions
    assert "intelligence.daily.run" in audit_actions


def test_remote_bridge_claims_and_completes_a_hosted_job(client):
    test_client, _ = client
    with soc_store.connect(client[1].db_path) as connection:
        now = soc_store.utc_now()
        connection.execute(
            """INSERT INTO findings
            (finding_id, title, summary, severity, severity_score, status, disposition,
             source, first_seen, last_seen, created_at, updated_at, payload_json)
            VALUES (?, ?, ?, 'high', 80, 'open', 'unreviewed', 'test', ?, ?, ?, ?, ?)""",
            (
                "FND-REMOTE-1",
                "Remote bridge test",
                "Normalized evidence for the bridge.",
                now,
                now,
                now,
                now,
                json.dumps({
                    "finding_id": "FND-REMOTE-1",
                    "title": "Remote bridge test",
                    "summary": "Normalized evidence for the bridge.",
                    "severity": "high",
                    "severity_score": 80,
                    "source": "test",
                    "first_seen": now,
                    "last_seen": now,
                }),
            ),
        )
        connection.commit()
    queued = test_client.post(
        "/api/v1/intelligence/jobs",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
        json={"action": "explain_finding", "target_id": "FND-REMOTE-1"},
    ).json()["job"]
    assert test_client.post(
        "/api/v1/intelligence/bridge/claim",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
        json={"worker_id": "wrong-role"},
    ).status_code == 401
    claimed = test_client.post(
        "/api/v1/intelligence/bridge/claim",
        headers={"Authorization": f"Bearer {BRIDGE_TOKEN}"},
        json={"worker_id": "macbook-bridge"},
    )
    assert claimed.status_code == 200
    claim_payload = claimed.json()
    assert claim_payload["job"]["job_id"] == queued["job_id"]
    assert claim_payload["bridge_request"]["safety"]["raw_telemetry_included"] is False

    running_cancel = test_client.post(
        f"/api/v1/intelligence/jobs/{queued['job_id']}/cancel",
        headers={"Authorization": f"Bearer {INTELLIGENCE_TOKEN}"},
    )
    assert running_cancel.status_code == 409
    assert "cannot be canceled safely" in running_cancel.json()["detail"]

    completed = test_client.post(
        f"/api/v1/intelligence/bridge/jobs/{queued['job_id']}/complete",
        headers={"Authorization": f"Bearer {BRIDGE_TOKEN}"},
        json={
            "worker_id": "macbook-bridge",
            "result": {
                "summary": "Evidence-grounded summary.",
                "risk_assessment": "High priority.",
                "evidence": ["Normalized evidence."],
                "recommended_actions": ["Review ownership."],
                "limitations": ["No runtime evidence."],
            },
        },
    )
    assert completed.status_code == 200
    assert completed.json()["job"]["status"] == "succeeded"
    assert completed.json()["job"]["result"]["provider"] == "codex_chatgpt_subscription"


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


def _signed_webhook_headers(body: bytes, *, timestamp: int | None = None, secret: str = WEBHOOK_SECRET):
    sent_at = str(timestamp if timestamp is not None else int(time.time()))
    signature = hmac.new(secret.encode(), sent_at.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-SecOpsAI-Timestamp": sent_at,
        "X-SecOpsAI-Signature": f"sha256={signature}",
    }


def test_research_alert_webhook_is_verified_sanitized_and_idempotent(client):
    test_client, settings = client
    event = {
        "schema_version": "secopsai.research.alert.v1",
        "alert_id": "RAL-WORKER-1",
        "alert_type": "collector_degraded",
        "severity": "high",
        "reason": "NuGet registry coverage is degraded",
        "evidence": {
            "ecosystem": "nuget",
            "coverage": "gap",
            "token": "must-not-persist",
        },
        "occurred_at": "2026-07-22T06:30:00Z",
    }
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    headers = _signed_webhook_headers(body)

    first = test_client.post("/api/v1/research/alerts/webhook", content=body, headers=headers)
    second = test_client.post("/api/v1/research/alerts/webhook", content=body, headers=headers)
    assert first.status_code == 200
    assert first.json()["created"] is True
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert first.json()["alert_id"] == second.json()["alert_id"]

    workspace = test_client.get(
        "/api/v1/workspace", headers={"Authorization": f"Bearer {READ_TOKEN}"}
    ).json()
    assert workspace["summary"]["operational_research_alerts"] == 1
    assert workspace["research_alerts"][0]["evidence"]["source"] == "secopsai-research-worker"

    with sqlite3.connect(settings.db_path) as connection:
        connection.row_factory = sqlite3.Row
        alerts = connection.execute(
            "SELECT * FROM research_alerts WHERE alert_type = 'collector_degraded'"
        ).fetchall()
        audits = connection.execute(
            "SELECT action, result FROM core_api_audit_logs WHERE action = 'research.alert.ingested'"
        ).fetchall()
    assert len(alerts) == 1
    assert "must-not-persist" not in alerts[0]["evidence_json"]
    assert [row["result"] for row in audits] == ["created", "updated"]


def test_research_alert_webhook_rejects_tampering_replay_and_nonoperational_types(client):
    test_client, _ = client
    event = {
        "schema_version": "secopsai.research.alert.v1",
        "alert_id": "RAL-WORKER-2",
        "alert_type": "collector_degraded",
        "severity": "high",
        "reason": "coverage gap",
        "evidence": {},
    }
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    tampered = body.replace(b"coverage gap", b"coverage bad")
    assert test_client.post(
        "/api/v1/research/alerts/webhook", content=tampered, headers=_signed_webhook_headers(body)
    ).status_code == 401
    assert test_client.post(
        "/api/v1/research/alerts/webhook",
        content=body,
        headers=_signed_webhook_headers(body, timestamp=int(time.time()) - 600),
    ).status_code == 401

    event["alert_type"] = "candidate_detected"
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    response = test_client.post(
        "/api/v1/research/alerts/webhook", content=body, headers=_signed_webhook_headers(body)
    )
    assert response.status_code == 422
    assert "not accepted" in response.json()["detail"]


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
        intelligence_token=INTELLIGENCE_TOKEN,
        bridge_token=BRIDGE_TOKEN,
        environment="production",
        cors_origins=("https://console.example.test",),
        trusted_hosts=("core.example.test",),
    )
    with pytest.raises(RuntimeError, match="ORGANIZATION_ID"):
        with TestClient(create_app(missing_scope)):
            pass
