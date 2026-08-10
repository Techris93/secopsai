import json

import soc_store
from secopsai.agent_triage import enqueue_due_findings
from secopsai.research_discovery import create_candidate_alert, resolve_alert
from secopsai.research_external_intel import refresh_and_sync
from secopsai.research_intake import SafeFetcher


def _db(tmp_path):
    return str(tmp_path / "external-intel.db")


def _fetcher(body: bytes):
    def fetch(_url, _max_bytes):
        return 200, {"content-type": "text/csv"}, body

    return SafeFetcher(fetch=fetch)


def test_source_backed_package_leads_do_not_require_watchlists(tmp_path):
    db_path = _db(tmp_path)
    body = b"Package,Malicious Versions\nkeyv,6.0.0\ncacheable,2.5.1\n"

    result = refresh_and_sync(
        db_path=db_path,
        fetcher=_fetcher(body),
        force=True,
    )

    assert result["refresh"]["status"] == "completed"
    assert result["refresh"]["records"] == 2
    assert result["sync"]["candidates_created"] == 2
    with soc_store.connect(db_path) as connection:
        candidates = connection.execute(
            "SELECT package, version, watchlist_id, evidence_json FROM research_candidates ORDER BY package"
        ).fetchall()
        alerts = connection.execute(
            "SELECT alert_type, severity, campaign_id FROM research_alerts ORDER BY alert_id"
        ).fetchall()
        findings = connection.execute("SELECT source, severity, status FROM findings").fetchall()

    assert [(row["package"], row["version"], row["watchlist_id"]) for row in candidates] == [
        ("cacheable", "2.5.1", None),
        ("keyv", "6.0.0", None),
    ]
    evidence = json.loads(candidates[0]["evidence_json"])
    assert evidence["local_exposure_required"] is False
    assert evidence["validation_state"] == "unverified"
    assert all(row["alert_type"] == "external_advisory_match" for row in alerts)
    assert all(row["severity"] == "high" for row in alerts)
    assert all(row["campaign_id"] == "keyv-cacheable-npm-worm-2026-08" for row in alerts)
    assert len(findings) == 2
    assert all(row["source"] == "secopsai_research" for row in findings)
    assert all(row["severity"] == "high" for row in findings)
    assert all(row["status"] == "research_lead" for row in findings)

    triage = enqueue_due_findings(db_path=db_path, limit_override=1)
    assert triage["investigations"]
    with soc_store.connect(db_path) as connection:
        investigation = connection.execute(
            "SELECT run_id, status, case_id FROM investigation_autopilot_runs ORDER BY created_at LIMIT 1"
        ).fetchone()
    assert investigation["status"] == "queued"
    assert investigation["run_id"].startswith("IAR-")


def test_external_feed_refresh_is_idempotent_and_stale_rows_are_deactivated(tmp_path):
    db_path = _db(tmp_path)
    first = b"Package,Malicious Versions\nkeyv,6.0.0\ncacheable,2.5.1\n"
    second = b"Package,Malicious Versions\nkeyv,6.0.0\n"

    refresh_and_sync(db_path=db_path, fetcher=_fetcher(first), force=True)
    result = refresh_and_sync(db_path=db_path, fetcher=_fetcher(second), force=True)
    assert result["sync"]["records_seen"] == 1
    with soc_store.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT package, active FROM research_external_advisory_records ORDER BY package"
        ).fetchall()
    assert [(row["package"], row["active"]) for row in rows] == [("cacheable", 0), ("keyv", 1)]


def test_external_feed_failure_preserves_previous_records_and_creates_health_alert(tmp_path):
    db_path = _db(tmp_path)
    body = b"Package,Malicious Versions\nkeyv,6.0.0\n"
    refresh_and_sync(db_path=db_path, fetcher=_fetcher(body), force=True)

    def fail(_url, _max_bytes):
        return 503, {"content-type": "text/plain"}, b"temporarily unavailable"

    result = refresh_and_sync(db_path=db_path, fetcher=SafeFetcher(fetch=fail), force=True)
    assert result["refresh"]["status"] == "failed"
    with soc_store.connect(db_path) as connection:
        record = connection.execute(
            "SELECT active FROM research_external_advisory_records WHERE package='keyv'"
        ).fetchone()
        alert = connection.execute(
            "SELECT status, alert_type FROM research_alerts WHERE alert_type='external_advisory_feed_degraded'"
        ).fetchone()
    assert record["active"] == 1
    assert alert["status"] == "open"
    assert alert["alert_type"] == "external_advisory_feed_degraded"


def test_sync_repairs_an_alert_when_candidate_already_exists(tmp_path):
    db_path = _db(tmp_path)
    body = b"Package,Malicious Versions\nkeyv,6.0.0\n"
    refresh_and_sync(db_path=db_path, fetcher=_fetcher(body), force=True)
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "DELETE FROM research_alerts WHERE alert_type='external_advisory_match'"
        )
        connection.commit()

    result = refresh_and_sync(db_path=db_path, fetcher=_fetcher(body), force=False)
    assert result["sync"]["records_seen"] == 1
    assert result["sync"]["candidates_created"] == 0
    assert result["sync"]["alerts_upserted"] == 1
    with soc_store.connect(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM research_alerts WHERE alert_type='external_advisory_match'"
        ).fetchone()[0] == 1


def test_external_matches_same_package_and_version_group_into_one_lead(tmp_path):
    db_path = _db(tmp_path)
    base = {
        "ecosystem": "nuget",
        "package": "Braintree.Net",
        "version": "3.36.1",
        "score": 99,
        "reason": "public advisory requires independent verification",
        "evidence": {"source_url": "https://example.test/advisory"},
    }
    first = create_candidate_alert(
        {**base, "candidate_id": "RCD-ONE", "campaign_id": "campaign-a"},
        alert_type="external_advisory_match",
        dedupe_key="source-a",
        db_path=db_path,
    )
    second = create_candidate_alert(
        {**base, "candidate_id": "RCD-TWO", "campaign_id": "campaign-b"},
        alert_type="external_advisory_match",
        dedupe_key="source-b",
        db_path=db_path,
    )
    assert first["alert_id"] == second["alert_id"]
    with soc_store.connect(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM research_alerts WHERE alert_type='external_advisory_match'"
        ).fetchone()[0] == 1
        row = connection.execute(
            "SELECT severity, status FROM findings WHERE source='secopsai_research'"
        ).fetchone()
    assert row["severity"] == "high"
    assert row["status"] == "research_lead"


def test_resolving_a_research_lead_updates_its_canonical_finding(tmp_path):
    db_path = _db(tmp_path)
    alert = create_candidate_alert(
        {
            "candidate_id": "RCD-RESOLVE",
            "ecosystem": "npm",
            "package": "example-package",
            "version": "1.0.0",
            "score": 99,
            "evidence": {"source_url": "https://example.test/advisory"},
        },
        alert_type="external_advisory_match",
        db_path=db_path,
    )
    resolved = resolve_alert(alert["alert_id"], db_path=db_path)
    assert resolved["status"] == "resolved"
    with soc_store.connect(db_path) as connection:
        row = connection.execute(
            "SELECT status, disposition FROM findings WHERE finding_id=?",
            (alert["finding_id"],),
        ).fetchone()
    assert row["status"] == "triaged"
    assert row["disposition"] == "needs_review"
