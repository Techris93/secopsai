from __future__ import annotations

import json

import pytest

from secopsai.cloud_connectors import (
    AwsReadOnlyConnector,
    ConnectorConfig,
    GcpReadOnlyConnector,
    KubernetesReadOnlyConnector,
    collect_connector,
    normalize_aws_cloudtrail_event,
    normalize_gcp_audit_log,
    normalize_kubernetes_audit_event,
)
from secopsai.awareness import recommend_from_findings
from secopsai.dast import DastTarget, build_zap_command, dedupe_findings, parse_sarif, validate_scope
from secopsai.enterprise_store import EnterpriseContext, RateLimiter, SQLiteEnterpriseStore
from secopsai.enterprise_workflows import (
    TicketProposal,
    control_record,
    evidence_record,
    pentest_engagement,
    questionnaire_record,
    threat_model_record,
)
from secopsai.kubernetes_security import dry_run_admission, scan_manifest
from secopsai.siem import MetricsRegistry, export_normalized_events
from secopsai.ticketing import GitHubIssueAdapter, JiraIssueAdapter, TicketRequest
from secopsai.vulnerability_management import normalize_advisory, prioritize_vulnerability


def test_enterprise_store_redacts_isolates_and_deduplicates(tmp_path):
    store = SQLiteEnterpriseStore(str(tmp_path / "enterprise.db"), context=EnterpriseContext("org-a", actor_id="analyst-1", role="analyst"))
    first = store.append_event(
        {"source": "aws.cloudtrail", "event_type": "aws.createaccesskey", "payload": {"token": "do-not-store", "event": "ok"}},
        idempotency_key="cloudtrail-1",
    )
    second = store.append_event(
        {"source": "aws.cloudtrail", "event_type": "aws.createaccesskey", "payload": {"token": "different"}},
        idempotency_key="cloudtrail-1",
    )
    assert first["event_id"] == second["event_id"]
    assert first["payload"]["token"] == "[redacted]"
    with pytest.raises(PermissionError):
        store.append_event({"organization_id": "org-b", "source": "x", "event_type": "y", "payload": {}})


def test_rate_limiter_bounds_connector_calls():
    limiter = RateLimiter(limit=2, window_seconds=60)
    assert limiter.allow("client") is True
    assert limiter.allow("client") is True
    assert limiter.allow("client") is False


def test_enterprise_store_paginates_events(tmp_path):
    store = SQLiteEnterpriseStore(str(tmp_path / "enterprise.db"), context=EnterpriseContext("org-a"))
    for index in range(3):
        store.append_event({"event_id": f"EVT-{index}", "source": "fixture", "event_type": "test", "payload": {"index": index}}, idempotency_key=f"fixture-{index}")
    page = store.list_events(limit=2)
    assert len(page["events"]) == 2
    assert page["has_more"] is True
    next_page = store.list_events(limit=2, cursor=page["next_cursor"])
    assert len(next_page["events"]) == 1


def test_enterprise_store_summary_reports_truthful_operator_state(tmp_path):
    db_path = str(tmp_path / "enterprise.db")
    operator = SQLiteEnterpriseStore(
        db_path,
        context=EnterpriseContext("org-a", actor_id="operator-1", role="operator"),
    )
    operator.append_event(
        {"event_id": "EVT-1", "source": "aws.cloudtrail", "event_type": "aws.consolelogin", "payload": {}},
        idempotency_key="aws-1",
    )
    operator.upsert_source_cursor({"source": "aws.cloudtrail", "status": "healthy", "last_success_at": "2026-08-22T10:00:00Z"})
    operator.upsert_vulnerability({"vulnerability_id": "VUL-1", "severity": "high", "status": "open"})
    operator.upsert_control(control_record(control_id="AC-1", framework="soc2", title="Access review", owner="security"))
    operator.upsert_questionnaire(questionnaire_record(questionnaire_id="Q-1", title="Customer review", owner="security", questions=[]))

    summary = operator.summary(limit=10)

    assert summary["counts"]["events"] == 1
    assert summary["counts"]["open_vulnerabilities"] == 1
    assert summary["counts"]["controls"] == 1
    assert summary["counts"]["questionnaires"] == 1
    assert summary["sources"][0]["source"] == "aws.cloudtrail"
    assert summary["recent_events"][0]["event_id"] == "EVT-1"
    assert summary["recent_workflows"][0]["kind"] == "questionnaire"
    assert summary["recent_workflows"][0]["title"] == "Customer review"
    assert summary["generated_at"].endswith("Z")


def test_enterprise_rbac_and_explicit_domain_repositories(tmp_path):
    analyst = SQLiteEnterpriseStore(str(tmp_path / "enterprise.db"), context=EnterpriseContext("org-a", actor_id="analyst-1", role="analyst"))
    assert analyst.upsert_finding({"finding_id": "F-1", "title": "Finding", "status": "open"})["finding_id"] == "F-1"
    assert analyst.upsert_alert({"alert_id": "A-1", "title": "Alert", "status": "open"})["alert_id"] == "A-1"
    assert analyst.upsert_case({"case_id": "C-1", "title": "Case", "status": "draft"})["case_id"] == "C-1"
    with pytest.raises(PermissionError):
        analyst.create_action({"action_type": "revoke_key", "target_id": "key-1"})
    admin = SQLiteEnterpriseStore(str(tmp_path / "enterprise.db"), context=EnterpriseContext("org-a", actor_id="admin", role="administrator"))
    admin.append_event({"event_id": "EVT-OLD", "source": "fixture", "event_type": "old", "received_at": "2020-01-01T00:00:00Z", "payload": {}})
    with pytest.raises(PermissionError):
        admin.purge_events(before="2030-01-01T00:00:00Z")
    assert admin.purge_events(before="2030-01-01T00:00:00Z", approved=True)["deleted"] >= 1


def test_cloud_normalizers_remove_raw_credentials():
    aws = normalize_aws_cloudtrail_event({"eventName": "CreateAccessKey", "eventTime": "2026-08-20T00:00:00Z", "userIdentity": {"arn": "arn:aws:iam::1:user/a", "sessionToken": "secret"}})
    gcp = normalize_gcp_audit_log({"insertId": "i-1", "timestamp": "2026-08-20T00:00:00Z", "protoPayload": {"methodName": "SetIamPolicy", "authenticationInfo": {"principalEmail": "operator@example.com", "token": "secret"}}})
    k8s = normalize_kubernetes_audit_event({"auditID": "a-1", "verb": "create", "objectRef": {"resource": "clusterrolebindings", "name": "admin"}, "user": {"username": "alice", "token": "secret"}})
    assert aws["severity"] == "high"
    assert gcp["severity"] == "high"
    assert k8s["severity"] == "high"
    assert "secret" not in json.dumps([aws, gcp, k8s])


def test_read_only_runtime_connectors_use_only_get_style_methods():
    class FakeAwsClient:
        def lookup_events(self, **kwargs): return {"Events": [{"eventID": "e1", "eventName": "ConsoleLogin"}]}
        def list_findings(self, **kwargs): return {"FindingIds": ["f1"]}
        def get_findings(self, **kwargs): return {"Findings": [{"id": "f1", "severity": 8}]}

    class FakeAwsSession:
        def client(self, name, region_name=None): return FakeAwsClient()

    aws = AwsReadOnlyConnector(region="us-east-1", session=FakeAwsSession())
    assert aws.cloudtrail_events()[0]["eventID"] == "e1"
    assert aws.guardduty_findings("detector")[0]["id"] == "f1"
    assert aws.securityhub_findings()[0]["id"] == "f1"

    class FakeGcp:
        def list_entries(self, **kwargs): return [{"timestamp": "now"}]
        def list_findings(self, **kwargs): return [{"name": "finding"}]

    class FakeKube:
        def list_audit_events(self, **kwargs): return [{"auditID": "a1"}]
        def list_namespaces(self): return [{"metadata": {"name": "default"}}]
        def list_workloads(self): return []
        def list_rbac(self): return []
        def list_network_policies(self): return []

    assert GcpReadOnlyConnector(FakeGcp()).audit_logs()[0]["timestamp"] == "now"
    assert KubernetesReadOnlyConnector(FakeKube()).audit_events()[0]["auditID"] == "a1"
    ConnectorConfig("aws.cloudtrail", enabled=True).validate()
    with pytest.raises(PermissionError):
        ConnectorConfig("aws.cloudtrail", read_only=False).validate()


def test_connector_cycle_persists_cursor_and_dead_letters(tmp_path):
    store = SQLiteEnterpriseStore(str(tmp_path / "enterprise.db"), context=EnterpriseContext("org-a"))
    result = collect_connector(
        "aws.cloudtrail",
        fetcher=lambda source, cursor: {"events": [{"eventID": "event-1", "eventName": "ConsoleLogin"}], "nextToken": "n2"},
        store=store,
        context=EnterpriseContext("org-a"),
    )
    assert result.status == "healthy"
    assert result.cursor == "n2"
    assert len(store.list_events()["events"]) == 1
    degraded = collect_connector("aws.cloudtrail", fetcher=lambda source, cursor: {"events": "bad"}, store=store, context=EnterpriseContext("org-a"))
    assert degraded.status == "degraded"


def test_kubernetes_manifest_and_admission_are_deterministic():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: risky}
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: example/app:latest
          securityContext: {privileged: true}
      volumes:
        - name: host
          hostPath: {path: /var/lib}
"""
    result = scan_manifest(manifest)
    assert result["finding_count"] >= 3
    assert dry_run_admission(manifest)["admission"] == "deny"


def test_dast_requires_authorization_and_parses_sarif():
    target = DastTarget("web-1", "https://app.example.test", "security", "change-123")
    assert build_zap_command(target, mode="passive")[0] == "zaproxy"
    with pytest.raises(PermissionError):
        build_zap_command(target, mode="active")
    assert validate_scope(target, "https://app.example.test/login") is True
    sarif = {"runs": [{"tool": {"driver": {"name": "ZAP", "rules": [{"id": "XSS", "name": "XSS", "help": {"text": "Escape output"}}]}}, "results": [{"ruleId": "XSS", "level": "error", "message": {"text": "reflected input"}, "locations": []}]}]}
    findings = parse_sarif(json.dumps(sarif), target_id="web-1")
    assert findings[0]["severity"] == "critical"
    assert findings[0]["finding_id"].startswith("DAST-")
    merged = dedupe_findings(findings + [{**findings[0], "severity": "high", "evidence_refs": ["EV-1"]}])
    assert len(merged) == 1
    assert merged[0]["severity"] == "critical"


def test_vulnerability_priority_and_sla():
    item = normalize_advisory({"advisory_id": "CVE-1", "package_name": "lib", "package_version": "1", "cvss_score": 9.8, "exploitability_score": 8, "kev": True, "internet_exposed": True, "asset_criticality": "critical"})
    assert item["priority_severity"] == "critical"
    assert item["severity"] == "critical"
    assert item["metadata"]["priority_score"] == item["priority_score"]
    assert "active exploitation or KEV match" in item["metadata"]["priority_reasons"]
    assert item["sla_due_at"].endswith("Z")
    assert prioritize_vulnerability({"advisory_id": "CVE-2", "cvss_score": 0})["priority_severity"] == "low"


def test_enterprise_workflows_are_evidence_and_approval_aware():
    control = control_record(control_id="AC-1", framework="soc2", title="Access review", owner="security")
    evidence = evidence_record(control_id="AC-1", source="github://audit/1", content="reviewed")
    questionnaire = questionnaire_record(questionnaire_id="Q-1", title="Customer review", owner="security", questions=[{"id": "Q1", "question": "How is privileged access reviewed?", "answer": "Yes", "evidence_refs": [evidence["sha256"]]}])
    threat = threat_model_record(threat_model_id="TM-1", title="API", owner="security", assets=[{"id": "api"}], threats=[{"id": "spoofing"}])
    pentest = pentest_engagement(engagement_id="PT-1", title="API review", owner="security", scope=["https://app.example"], authorized_by="signed-roe")
    ticket = TicketProposal("github", "Fix AC-1", "Review access", "VUL-1").as_record()
    assert control["framework"] == "soc2"
    assert evidence["sha256"]
    assert questionnaire["questions"][0]["evidence_refs"]
    assert questionnaire["questions"][0]["question"] == "How is privileged access reviewed?"
    assert threat["status"] == "draft"
    assert pentest["authorized_by"] == "signed-roe"
    assert ticket["approval_required"] is True


def test_siem_metrics_and_export():
    metrics = MetricsRegistry()
    metrics.increment("events_ingested")
    metrics.gauge("queue_depth", 2)
    metrics.observe("ingest_latency_ms", 12)
    assert "secopsai_events_ingested" in metrics.prometheus()
    rendered = export_normalized_events([{"event_id": "EVT-1", "payload": {"token": "[redacted]"}, "payload_json": "secret"}])
    assert "payload_json" not in rendered
    assert "[redacted]" in rendered


def test_ticketing_is_proposed_until_explicitly_approved():
    request = TicketRequest("github", "Techris93/secopsai", "Fix vulnerability", "Evidence", "VUL-1")
    proposal = GitHubIssueAdapter().create(request)
    assert proposal["status"] == "proposed"
    assert proposal["network_called"] is False

    calls = []
    def requester(method, url, headers, payload):
        calls.append((method, url, headers, payload))
        return {"status": "created", "id": "123"}

    approved = GitHubIssueAdapter(requester=requester).create(TicketRequest("github", "Techris93/secopsai", "Fix", "Evidence", "VUL-1", approved=True))
    assert approved["status"] == "created"
    assert calls[0][0:2] == ("POST", "https://api.github.com/repos/Techris93/secopsai/issues")

    jira = JiraIssueAdapter(api_base="https://jira.example", requester=requester)
    assert jira.create(TicketRequest("jira", "SEC", "Fix", "Evidence", "VUL-1"))["network_called"] is False


def test_awareness_recommendations_link_back_to_findings():
    recommendations = recommend_from_findings([{"finding_id": "F-1", "title": "Suspicious package credential token access"}])
    module_ids = {item["module_id"] for item in recommendations}
    assert "dependency-safety" in module_ids
    assert "credential-hygiene" in module_ids
    assert all("F-1" in item["finding_ids"] for item in recommendations)
