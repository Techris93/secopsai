"""Workflow version history, penetration-test reports and retests, and store-backed metrics."""
import json
import sqlite3
from pathlib import Path

import pytest

from secopsai import cli
from secopsai.enterprise_store import EnterpriseContext, SQLiteEnterpriseStore
from secopsai.enterprise_workflows import pentest_engagement
from secopsai.siem import enterprise_metrics

ENGAGEMENT = {"engagement_id": "PT-1", "title": "Web test", "owner": "security",
              "scope": ["https://app.example.test"], "authorized_by": "SOW-1"}


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_ENTERPRISE_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    return SQLiteEnterpriseStore(str(tmp_path / "e.db"), context=EnterpriseContext("acme", actor_id="alice", role="security_engineer"))


def _report(store, tmp_path, body=b"%PDF report"):
    store.upsert_pentest_engagement(pentest_engagement(**ENGAGEMENT))
    path = tmp_path / "report.pdf"
    path.write_bytes(body)
    return store.quarantine_pentest_report("PT-1", path)


def test_every_save_keeps_a_numbered_version(store):
    store.upsert_pentest_engagement(pentest_engagement(**ENGAGEMENT))
    store.upsert_pentest_engagement(pentest_engagement(**{**ENGAGEMENT, "title": "Web test v2"}))
    versions = store.list_record_versions("engagement", "PT-1")
    assert [v["version"] for v in versions] == [2, 1]
    assert versions[0]["actor_id"] == "alice"
    assert store.get_record_version("engagement", "PT-1", 1)["payload"]["title"] == "Web test"
    with pytest.raises(ValueError):
        store.get_record_version("engagement", "PT-1", 9)


def test_reports_are_quarantined_by_hash_and_reviewed_once(store, tmp_path):
    report = _report(store, tmp_path)
    assert report["status"] == "quarantined"
    target = Path(report["quarantine_path"])
    assert target.read_bytes() == b"%PDF report"
    assert target.suffix == ".quarantine", "never stored under a name a viewer would open"
    assert oct(target.stat().st_mode)[-3:] == "600"
    assert _report(store, tmp_path)["duplicate"] is True
    with pytest.raises(PermissionError):
        store.add_pentest_item(report_id=report["report_id"], title="XSS", severity="high")
    assert store.review_pentest_report(report["report_id"], decision="accepted")["reviewed_by"] == "alice"
    with pytest.raises(ValueError):
        store.review_pentest_report(report["report_id"], decision="rejected")


def test_reports_need_an_authorized_engagement(store, tmp_path):
    path = tmp_path / "r.pdf"
    path.write_bytes(b"x")
    with pytest.raises(ValueError):
        store.quarantine_pentest_report("PT-missing", path)


def test_items_link_findings_and_move_through_retest(store, tmp_path):
    report = _report(store, tmp_path)
    store.review_pentest_report(report["report_id"], decision="accepted")
    item = store.add_pentest_item(report_id=report["report_id"], title="Stored XSS", severity="high", owner="web")
    item = store.update_pentest_item(item["item_id"], status="fixed_pending_retest", finding_id="OCF-9")
    assert item["finding_id"] == "OCF-9"
    with pytest.raises(ValueError):
        store.update_pentest_item(item["item_id"], status="open")
    item = store.update_pentest_item(item["item_id"], status="retest_failed")
    item = store.update_pentest_item(item["item_id"], status="fixed_pending_retest")
    item = store.update_pentest_item(item["item_id"], status="retest_passed", note="verified")
    assert item["retested_at"] and [h.get("status") for h in item["history"]][-1] == "retest_passed"
    view = store.pentest_engagement_view("PT-1")
    assert view["retest_status"] == "complete" and view["item_counts"] == {"retest_passed": 1}


def test_only_security_roles_accept_risk(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_ENTERPRISE_QUARANTINE_DIR", str(tmp_path / "q"))
    lead = SQLiteEnterpriseStore(str(tmp_path / "e.db"), context=EnterpriseContext("acme", actor_id="lead", role="security_engineer"))
    report = _report(lead, tmp_path)
    lead.review_pentest_report(report["report_id"], decision="accepted")
    item = lead.add_pentest_item(report_id=report["report_id"], title="Weak TLS", severity="low")
    auditor = SQLiteEnterpriseStore(str(tmp_path / "e.db"), context=EnterpriseContext("acme", actor_id="aud", role="auditor"))
    with pytest.raises(PermissionError):
        auditor.update_pentest_item(item["item_id"], status="accepted_risk")
    assert lead.update_pentest_item(item["item_id"], status="accepted_risk")["status"] == "accepted_risk"


def test_existing_version_one_databases_gain_the_new_tables(tmp_path):
    path = tmp_path / "old.db"
    SQLiteEnterpriseStore(str(path), context=EnterpriseContext("acme"))
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE enterprise_record_versions")
        conn.execute("UPDATE enterprise_schema_meta SET version=1")
    store = SQLiteEnterpriseStore(str(path), context=EnterpriseContext("acme", role="operator"))
    store.upsert_threat_model({"threat_model_id": "TM-1", "title": "t", "owner": "o"})
    assert store.list_record_versions("threat_model", "TM-1")[0]["version"] == 1


def test_metrics_come_from_the_store(store, tmp_path):
    store.upsert_vulnerability({"vulnerability_id": "V1", "severity": "critical", "status": "open", "sla_due_at": "2020-01-01T00:00:00Z"})
    store.upsert_vulnerability({"vulnerability_id": "V2", "severity": "low", "status": "open", "sla_due_at": "2999-01-01T00:00:00Z"})
    store.upsert_source_cursor({"source": "aws.cloudtrail", "status": "healthy", "last_success_at": "2026-11-21T10:00:00Z", "metadata": {"latency_ms": 42.5}})
    store.upsert_source_cursor({"source": "gcp.audit", "status": "degraded"})
    store.append_event({"source": "aws.cloudtrail", "event_type": "x", "observed_at": "2026-11-21T09:59:00Z", "severity": "info", "payload": {}})
    snapshot = enterprise_metrics(store).snapshot()
    gauges = snapshot["gauges"]
    assert gauges["open_vulnerabilities_total"] == 2 and gauges["vulnerabilities_overdue"] == 1
    assert gauges["sources_degraded"] == 1 and gauges["source_latency_ms_aws.cloudtrail"] == 42.5
    assert snapshot["counters"]["open_vulnerabilities_critical"] == 1
    assert snapshot["histograms"]["ingest_delay_seconds"]["count"] == 1
    assert "secopsai_source_latency_ms_aws_cloudtrail 42.5" in enterprise_metrics(store).prometheus()


def test_cli_metrics_and_stable_vulnerability_ids(tmp_path, capsys, monkeypatch):
    db = str(tmp_path / "e.db")
    vuln = tmp_path / "v.json"
    vuln.write_text(json.dumps({"advisory_id": "GHSA-1", "package_name": "lib", "package_version": "1.0", "asset_id": "a", "cvss_score": 9.8}))
    for _ in range(2):
        assert cli.main(["--json", "enterprise", "prioritize-vulnerability", "--input", str(vuln), "--db-path", db]) == 0
    capsys.readouterr()
    assert cli.main(["enterprise", "metrics", "--prometheus", "--db-path", db]) == 0
    text = capsys.readouterr().out
    assert "secopsai_vulnerabilities_total 1" in text, "re-running updates the same record"
