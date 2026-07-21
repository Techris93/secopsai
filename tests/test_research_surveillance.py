import json
import re
import urllib.parse
from pathlib import Path

import pytest

import soc_store
from secopsai.research_intake import SafeFetcher
from secopsai.research_surveillance import (
    CollectorError,
    collector_status,
    coverage_report,
    ensure_collectors,
    list_feed_events,
    recover_interrupted_runs,
    retry_dead_letters,
    run_registry_collector,
    set_collector_enabled,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nuget_catalog"

PAGE0_TS = "2026-07-19T10:00:00.000Z"
PAGE1_TS = "2026-07-20T12:00:00.000Z"
SINCE_ALL = "2026-07-19T00:00:00Z"

LEAF_URLS = {
    "https://api.nuget.org/v3/catalog0/data/2026.07.19.09.00.00/contoso.library.1.0.0.json": "leaf_details.json",
    "https://api.nuget.org/v3/catalog0/data/2026.07.19.09.30.00/contoso.library.1.0.1.json": "leaf_details.json",
    "https://api.nuget.org/v3/catalog0/data/2026.07.20.11.00.00/adventureworks.core.2.0.0.json": "leaf_details.json",
    "https://api.nuget.org/v3/catalog0/data/2026.07.20.12.00.00/adventureworks.core.2.0.1.json": "leaf_details.json",
}


def _fetcher(fail_urls=()):
    routes = {
        "https://api.nuget.org/v3/catalog0/index.json": "index.json",
        "https://api.nuget.org/v3/catalog0/page0.json": "page0.json",
        "https://api.nuget.org/v3/catalog0/page1.json": "page1.json",
        **LEAF_URLS,
    }

    def fetch(url, max_bytes):
        if url in fail_urls:
            return 500, {"content-type": "application/json"}, b'{"error": "registry unavailable"}'
        name = routes.get(url)
        if name is None:
            return 404, {"content-type": "application/json"}, b'{"error": "not found"}'
        return 200, {"content-type": "application/json"}, (FIXTURES / name).read_bytes()

    return SafeFetcher(fetch=fetch)


def _db(tmp_path):
    return str(tmp_path / "surveillance.db")


def _cursor_value(db_path, collector_id="COL-NUGET-CATALOG"):
    ensure_collectors(db_path=db_path)
    connection = soc_store.connect(db_path)
    try:
        row = connection.execute(
            "SELECT cursor_value FROM registry_cursors WHERE collector_id = ?", (collector_id,)
        ).fetchone()
        return str(row["cursor_value"])
    finally:
        connection.close()


def _dead_letters(db_path, status="pending"):
    connection = soc_store.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM registry_dead_letters WHERE status = ? ORDER BY created_at", (status,)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def _make_dead_letters_due(db_path):
    connection = soc_store.connect(db_path)
    try:
        connection.execute("UPDATE registry_dead_letters SET next_retry_at = '2000-01-01T00:00:00.000Z' WHERE status = 'pending'")
        connection.commit()
    finally:
        connection.close()


def test_ensure_collectors_seeds_nuget_catalog(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    nuget = next(item for item in collectors if item["collector_id"] == "COL-NUGET-CATALOG")
    assert nuget["mode"] == "event_feed"
    assert nuget["ecosystem"] == "nuget"
    assert nuget["cursor"] is not None
    assert nuget["cursor"]["cursor_value"]


def test_run_stores_events_and_advances_cursor(tmp_path):
    db_path = _db(tmp_path)
    result = run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=_fetcher())
    assert result["status"] == "completed"
    assert result["pages_processed"] == 2
    assert result["events_seen"] == 5
    assert result["events_stored"] == 5
    assert result["events_duplicate"] == 0
    assert result["cursor_after"] == PAGE1_TS
    assert result["coverage"] == "complete"
    assert _cursor_value(db_path) == PAGE1_TS

    events = list_feed_events(db_path=db_path)
    assert len(events) == 5
    by_package = {event["package"]: event for event in events}
    assert by_package["Fabrikam.Bad"]["event_type"] == "deleted"
    assert by_package["Contoso.Library"]["event_type"] == "published"
    assert all(event["processing_state"] == "pending" for event in events)


def test_second_run_selects_no_new_pages(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=_fetcher())
    result = run_registry_collector(ecosystem="nuget", db_path=db_path, fetcher=_fetcher())
    assert result["status"] == "completed"
    assert result["pages_selected"] == 0
    assert result["events_stored"] == 0


def test_rerun_with_backfill_cursor_is_idempotent(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=_fetcher())
    result = run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=_fetcher())
    assert result["status"] == "completed"
    assert result["events_seen"] == 5
    assert result["events_stored"] == 0
    assert result["events_duplicate"] == 5
    assert len(list_feed_events(db_path=db_path)) == 5


def test_page_failure_stops_cursor_records_gap_and_recovers(tmp_path):
    db_path = _db(tmp_path)
    failing = _fetcher(fail_urls={"https://api.nuget.org/v3/catalog0/page1.json"})
    result = run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=failing)
    assert result["status"] == "failed"
    assert result["pages_processed"] == 1
    assert result["events_stored"] == 3
    assert result["coverage"] == "gap"
    assert _cursor_value(db_path) == PAGE0_TS
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "page"

    windows = coverage_report(db_path=db_path)
    assert windows[0]["state"] == "gap"
    assert windows[0]["expected_pages"] == 2
    assert windows[0]["processed_pages"] == 1

    recovered = run_registry_collector(ecosystem="nuget", db_path=db_path, fetcher=_fetcher())
    assert recovered["status"] == "completed"
    assert recovered["pages_processed"] == 1
    assert recovered["events_stored"] == 2
    assert _cursor_value(db_path) == PAGE1_TS


def test_retry_dead_letters_resolves_with_working_registry(tmp_path):
    db_path = _db(tmp_path)
    failing = _fetcher(fail_urls={"https://api.nuget.org/v3/catalog0/page1.json"})
    run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=failing)

    # Freshly dead-lettered items back off before their first retry.
    not_due = retry_dead_letters(db_path=db_path, fetcher=failing)
    assert not_due["retried"] == 0

    _make_dead_letters_due(db_path)
    still_failing = retry_dead_letters(db_path=db_path, fetcher=failing)
    assert still_failing["retried"] == 1
    assert still_failing["resolved"] == 0
    letter = _dead_letters(db_path)[0]
    assert letter["attempts"] == 2

    _make_dead_letters_due(db_path)
    resolved = retry_dead_letters(db_path=db_path, fetcher=_fetcher())
    assert resolved["resolved"] == 1
    assert _dead_letters(db_path) == []


def test_since_cannot_move_cursor_forward(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=_fetcher())
    result = run_registry_collector(ecosystem="nuget", since="2026-07-21T00:00:00Z", db_path=db_path, fetcher=_fetcher())
    assert result["cursor_before"] == PAGE1_TS
    assert result["pages_selected"] == 0


def test_concurrent_run_is_rejected(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    connection = soc_store.connect(db_path)
    try:
        connection.execute(
            """INSERT INTO registry_ingestion_runs
            (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at)
            VALUES ('RIR-TEST-RUNNING', 'COL-NUGET-CATALOG', 'running', ?, ?, 'event_feed', ?)""",
            (PAGE0_TS, PAGE0_TS, PAGE1_TS),
        )
        connection.commit()
    finally:
        connection.close()
    result = run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=_fetcher())
    assert result["status"] == "rejected"
    assert "active run" in result["reason"]


def test_recover_interrupted_runs_marks_old_running(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    connection = soc_store.connect(db_path)
    try:
        connection.execute(
            """INSERT INTO registry_ingestion_runs
            (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at)
            VALUES ('RIR-TEST-STALE', 'COL-NUGET-CATALOG', 'running', ?, ?, 'event_feed', '2026-07-20T00:00:00.000Z')""",
            (PAGE0_TS, PAGE0_TS),
        )
        connection.commit()
    finally:
        connection.close()
    result = recover_interrupted_runs(max_age_seconds=3600, db_path=db_path)
    assert result["interrupted"] == 1
    status = collector_status(ecosystem="nuget", db_path=db_path)[0]
    assert status["last_run"]["status"] == "interrupted"


def test_fetch_leaves_enriches_metadata_and_dead_letters_leaf_failure(tmp_path):
    db_path = _db(tmp_path)
    failing_leaf = "https://api.nuget.org/v3/catalog0/data/2026.07.20.11.00.00/adventureworks.core.2.0.0.json"
    result = run_registry_collector(
        ecosystem="nuget",
        since=SINCE_ALL,
        fetch_leaves=True,
        db_path=db_path,
        fetcher=_fetcher(fail_urls={failing_leaf}),
    )
    assert result["status"] == "completed"
    assert result["events_stored"] == 5
    assert result["leaf_failures"] == 1

    events = {event["leaf_url"]: event for event in list_feed_events(db_path=db_path)}
    enriched = events["https://api.nuget.org/v3/catalog0/data/2026.07.19.09.00.00/contoso.library.1.0.0.json"]
    assert enriched["leaf_fetched"] == 1
    assert enriched["metadata"]["authors"] == "Contoso"
    failed = events[failing_leaf]
    assert failed["leaf_fetched"] == 0
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "leaf"

    _make_dead_letters_due(db_path)
    resolved = retry_dead_letters(db_path=db_path, fetcher=_fetcher())
    assert resolved["resolved"] == 1
    fixed = {event["leaf_url"]: event for event in list_feed_events(db_path=db_path)}[failing_leaf]
    assert fixed["leaf_fetched"] == 1
    assert fixed["metadata"]["authors"] == "Contoso"


def test_collector_status_reports_lag_gaps_and_counts(tmp_path):
    db_path = _db(tmp_path)
    failing = _fetcher(fail_urls={"https://api.nuget.org/v3/catalog0/page1.json"})
    run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=failing)
    status = collector_status(ecosystem="nuget", db_path=db_path)
    assert len(status) == 1
    item = status[0]
    assert item["events_stored"] == 3
    assert item["pending_dead_letters"] == 1
    assert item["coverage_gaps"] == 1
    assert item["cursor"] == PAGE0_TS
    assert item["lag_seconds"] is not None
    assert item["last_run"]["status"] == "failed"


def test_unknown_ecosystem_is_rejected(tmp_path):
    with pytest.raises(CollectorError):
        run_registry_collector(ecosystem="cpan", db_path=_db(tmp_path), fetcher=_fetcher())


def test_registry_hosts_outside_allowlist_are_refused(tmp_path):
    db_path = _db(tmp_path)

    def malicious_fetch(url, max_bytes):
        if url.endswith("index.json"):
            payload = {
                "commitTimestamp": PAGE1_TS,
                "count": 1,
                "items": [{"@id": "https://evil.example.com/page.json", "commitTimestamp": PAGE0_TS, "count": 1}],
            }
            return 200, {"content-type": "application/json"}, json.dumps(payload).encode()
        return 200, {"content-type": "application/json"}, b"{}"

    result = run_registry_collector(
        ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=SafeFetcher(fetch=malicious_fetch)
    )
    assert result["status"] == "failed"
    assert "allowlist" in (result["error"] or "")
    assert _dead_letters(db_path)[0]["item_kind"] == "page"


PACKAGIST_FIXTURES = Path(__file__).parent / "fixtures" / "packagist_changes"
PACKAGIST_SINCE = "17846400000000"


def _packagist_fetcher(captured_urls, fail=False, fixture="changes.json"):
    def fetch(url, max_bytes):
        captured_urls.append(url)
        if fail:
            return 500, {"content-type": "application/json"}, b'{"error": "registry unavailable"}'
        if "changes.json" in url:
            return 200, {"content-type": "application/json"}, (PACKAGIST_FIXTURES / fixture).read_bytes()
        return 404, {"content-type": "application/json"}, b'{"error": "not found"}'

    return SafeFetcher(fetch=fetch)


def _alerts(db_path, alert_type="collector_retention_risk"):
    connection = soc_store.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM research_alerts WHERE alert_type = ?", (alert_type,)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def test_packagist_collector_seeds_with_bootstrap_cursor(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    packagist = next(item for item in collectors if item["collector_id"] == "COL-PACKAGIST-CHANGES")
    assert packagist["mode"] == "event_feed"
    assert packagist["cursor"]["cursor_value"] == "0"


def test_packagist_bootstrap_run_starts_live(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="packagist", db_path=db_path, fetcher=_packagist_fetcher(urls, fixture="changes_empty.json")
    )
    assert result["status"] == "completed"
    assert result["events_seen"] == 0
    assert result["cursor_after"].isdigit()
    assert int(result["cursor_after"]) > 0
    assert urls and "since=" in urls[0]


def test_packagist_run_stores_actions_and_maps_types(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="packagist", since=PACKAGIST_SINCE, db_path=db_path, fetcher=_packagist_fetcher(urls)
    )
    assert result["status"] == "completed"
    assert result["events_seen"] == 3
    assert result["events_stored"] == 3
    assert result["cursor_after"] == "17846401200017"
    # The request overlaps the cursor by the configured skew window.
    assert f"since={int(PACKAGIST_SINCE) - 300 * 10000}" in urls[0]

    events = list_feed_events(db_path=db_path)
    assert len(events) == 3
    by_time = {event["registry_timestamp"]: event for event in events}
    release = by_time["2026-07-21T13:20:00.000Z"]
    assert release["package"] == "acme/payments"
    assert release["event_type"] == "published"
    assert release["metadata"]["channel"] == "release"
    assert release["leaf_url"] == "https://repo.packagist.org/p2/acme/payments.json"
    dev = by_time["2026-07-21T13:21:00.000Z"]
    assert dev["package"] == "acme/payments"
    assert dev["metadata"]["channel"] == "dev"
    deleted = by_time["2026-07-21T13:22:00.000Z"]
    assert deleted["package"] == "acme/abandoned"
    assert deleted["event_type"] == "deleted"


def test_packagist_rerun_is_idempotent(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="packagist", since=PACKAGIST_SINCE, db_path=db_path, fetcher=_packagist_fetcher(urls))
    result = run_registry_collector(
        ecosystem="packagist", since=PACKAGIST_SINCE, db_path=db_path, fetcher=_packagist_fetcher(urls)
    )
    assert result["events_stored"] == 0
    assert result["events_duplicate"] == 3
    assert len(list_feed_events(db_path=db_path)) == 3


def test_packagist_feed_failure_keeps_cursor_and_records_gap(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="packagist", since=PACKAGIST_SINCE, db_path=db_path, fetcher=_packagist_fetcher(urls, fail=True)
    )
    assert result["status"] == "failed"
    assert result["coverage"] == "gap"
    assert result["cursor_after"] == PACKAGIST_SINCE
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "feed"
    assert _cursor_value(db_path, collector_id="COL-PACKAGIST-CHANGES") == "0"


def test_packagist_empty_feed_still_advances_cursor(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="packagist",
        since=PACKAGIST_SINCE,
        db_path=db_path,
        fetcher=_packagist_fetcher(urls, fixture="changes_empty.json"),
    )
    assert result["status"] == "completed"
    assert result["events_seen"] == 0
    # An idle registry still advances the cursor so it stays inside retention.
    assert result["cursor_after"] == "17846424000042"


def test_packagist_cursor_never_moves_backward(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    # First run lands on the later cursor from the empty fixture.
    run_registry_collector(
        ecosystem="packagist",
        since=PACKAGIST_SINCE,
        db_path=db_path,
        fetcher=_packagist_fetcher(urls, fixture="changes_empty.json"),
    )
    # A later run against an older response must not rewind the cursor.
    result = run_registry_collector(ecosystem="packagist", db_path=db_path, fetcher=_packagist_fetcher(urls))
    assert result["cursor_after"] == "17846424000042"


def test_packagist_retention_risk_raises_deduped_alert(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    # Cursor 70,000 seconds old: beyond the 64,800s safety window.
    stale = str((int(__import__("time").time()) - 70000) * 10000)
    connection = soc_store.connect(db_path)
    try:
        connection.execute(
            "UPDATE registry_cursors SET cursor_value = ? WHERE collector_id = 'COL-PACKAGIST-CHANGES'",
            (stale,),
        )
        connection.commit()
    finally:
        connection.close()

    status = collector_status(ecosystem="packagist", db_path=db_path)[0]
    assert status["retention"]["retention_risk"] is True
    assert status["retention"]["cursor_age_seconds"] >= 70000
    alerts = _alerts(db_path)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert "silent event loss" in alerts[0]["reason"]

    collector_status(ecosystem="packagist", db_path=db_path)
    assert len(_alerts(db_path)) == 1


def test_packagist_since_accepts_iso_datetime(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="packagist", since="2026-07-21T13:20:00Z", db_path=db_path, fetcher=_packagist_fetcher(urls)
    )
    assert result["cursor_before"] == "17846400000000"


PYPI_FIXTURES = Path(__file__).parent / "fixtures" / "pypi_simple"


def _pypi_fetcher(fixture="index_s100.json", serial="100", fail=False, include_serial_header=True):
    def fetch(url, max_bytes):
        if fail:
            return 500, {"content-type": "application/json"}, b'{"error": "registry unavailable"}'
        headers = {"content-type": "application/vnd.pypi.simple.v1+json"}
        if include_serial_header:
            headers["x-pypi-last-serial"] = serial
        return 200, headers, (PYPI_FIXTURES / fixture).read_bytes()

    return SafeFetcher(fetch=fetch)


def _snapshots(db_path):
    connection = soc_store.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM registry_snapshots WHERE collector_id = 'COL-PYPI-INDEX' ORDER BY created_at"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def test_pypi_collector_seeds_with_zero_cursor(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    pypi = next(item for item in collectors if item["collector_id"] == "COL-PYPI-INDEX")
    assert pypi["mode"] == "index_reconcile"
    assert pypi["cursor"]["cursor_value"] == "0"


def test_pypi_baseline_run_stores_snapshot_without_events(tmp_path):
    db_path = _db(tmp_path)
    result = run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher())
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert result["cursor_after"] == "100"
    snapshots = _snapshots(db_path)
    assert len(snapshots) == 1
    assert snapshots[0]["serial"] == "100"
    assert snapshots[0]["item_count"] == 3

    status = collector_status(ecosystem="pypi", db_path=db_path)[0]
    assert status["last_snapshot"]["serial"] == "100"
    assert status["last_snapshot"]["item_count"] == 3
    assert status["lag_seconds"] is None


def test_pypi_unchanged_serial_skips_snapshot(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher())
    result = run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher())
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert len(_snapshots(db_path)) == 1


def test_pypi_reconciliation_emits_add_remove_events(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher())
    result = run_registry_collector(
        ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher(fixture="index_s101.json", serial="101")
    )
    assert result["status"] == "completed"
    assert result["events_stored"] == 3
    assert result["cursor_after"] == "101"
    assert len(_snapshots(db_path)) == 2

    events = list_feed_events(db_path=db_path)
    by_name = {event["package"]: event for event in events}
    assert by_name["delta-sdk"]["event_type"] == "project_added"
    assert by_name["epsilon-client"]["event_type"] == "project_added"
    assert by_name["gamma-utils"]["event_type"] == "project_removed"
    assert by_name["delta-sdk"]["leaf_url"] == "https://pypi.org/pypi/delta-sdk/json"
    assert by_name["delta-sdk"]["metadata"]["serial"] == "101"


def test_pypi_rerun_same_serial_is_idempotent(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher())
    run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher(fixture="index_s101.json", serial="101"))
    result = run_registry_collector(
        ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher(fixture="index_s101.json", serial="101")
    )
    assert result["events_stored"] == 0
    assert len(_snapshots(db_path)) == 2
    assert len(list_feed_events(db_path=db_path)) == 3


def test_pypi_serial_regression_is_flagged_not_fatal(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher(fixture="index_s101.json", serial="101"))
    result = run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher())
    assert result["status"] == "completed"
    assert result["anomalies"]
    assert "serial regressed" in result["anomalies"][0]
    assert result["cursor_after"] == "101"
    assert len(_snapshots(db_path)) == 1


def test_pypi_fetch_failure_records_dead_letter_and_gap(tmp_path):
    db_path = _db(tmp_path)
    result = run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher(fail=True))
    assert result["status"] == "failed"
    assert result["coverage"] == "gap"
    assert result["cursor_after"] == "0"
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "feed"


def test_pypi_malformed_index_errors_without_snapshot(tmp_path):
    db_path = _db(tmp_path)
    result = run_registry_collector(
        ecosystem="pypi",
        db_path=db_path,
        fetcher=_pypi_fetcher(fixture="index_malformed.json", serial="102"),
    )
    assert result["status"] == "failed"
    assert "projects list" in result["error"]
    assert _snapshots(db_path) == []


def test_pypi_meta_serial_fallback_when_header_missing(tmp_path):
    db_path = _db(tmp_path)
    result = run_registry_collector(
        ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher(include_serial_header=False)
    )
    assert result["status"] == "completed"
    assert result["cursor_after"] == "100"


def test_pypi_diff_truncation_flag(tmp_path):
    db_path = _db(tmp_path)
    run_registry_collector(ecosystem="pypi", db_path=db_path, fetcher=_pypi_fetcher())
    result = run_registry_collector(
        ecosystem="pypi",
        max_diff_events=2,
        db_path=db_path,
        fetcher=_pypi_fetcher(fixture="index_s101.json", serial="101"),
    )
    assert result["diff_truncated"] is True
    assert result["events_stored"] == 2


RUBYGEMS_FIXTURES = Path(__file__).parent / "fixtures" / "rubygems_timeframe"


def _rubygems_fetcher(captured_urls, fail_pages=()):
    def fetch(url, max_bytes):
        captured_urls.append(url)
        match = re.search(r"page=(\d+)", url)
        page = int(match.group(1)) if match else 1
        if page in fail_pages:
            return 500, {"content-type": "application/json"}, b'{"error": "registry unavailable"}'
        name = f"page{min(page, 3)}.json"
        return 200, {"content-type": "application/json"}, (RUBYGEMS_FIXTURES / name).read_bytes()

    return SafeFetcher(fetch=fetch)


def _set_cursor(db_path, collector_id, value):
    connection = soc_store.connect(db_path)
    try:
        connection.execute("UPDATE registry_cursors SET cursor_value = ? WHERE collector_id = ?", (value, collector_id))
        connection.commit()
    finally:
        connection.close()


def _window_from_param(url):
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    return query["from"][0]


def test_rubygems_collector_seeds_with_lookback_cursor(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    rubygems = next(item for item in collectors if item["collector_id"] == "COL-RUBYGEMS-TIMEFRAME")
    assert rubygems["mode"] == "timeframe_poll"
    cursor = rubygems["cursor"]["cursor_value"]
    assert cursor != "0"
    assert "T" in cursor


def test_rubygems_run_stores_version_events_and_advances_cursor(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    cursor_before = _cursor_value(db_path, collector_id="COL-RUBYGEMS-TIMEFRAME")
    result = run_registry_collector(ecosystem="rubygems", db_path=db_path, fetcher=_rubygems_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 3
    assert result["cursor_after"] > cursor_before
    assert "window_incomplete" not in result

    events = list_feed_events(db_path=db_path)
    assert len(events) == 3
    by_key = {(event["package"], event["version"], event["metadata"]["platform"]): event for event in events}
    published = by_key[("acme-tools", "2.1.0", "ruby")]
    assert published["event_type"] == "published"
    assert published["metadata"]["sha256"] == "abc123"
    assert published["registry_timestamp"] == "2026-07-21T12:00:00.000Z"
    yanked = by_key[("evil-skimmer", "0.0.1", "ruby")]
    assert yanked["event_type"] == "yanked"
    assert yanked["metadata"]["yanked"] is True
    java = by_key[("acme-tools", "2.1.0", "java")]
    assert java["event_type"] == "published"
    assert java["metadata"]["platform"] == "java"


def test_rubygems_rerun_is_idempotent(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="rubygems", db_path=db_path, fetcher=_rubygems_fetcher(urls))
    result = run_registry_collector(ecosystem="rubygems", db_path=db_path, fetcher=_rubygems_fetcher(urls))
    assert result["events_stored"] == 0
    assert result["events_duplicate"] == 3
    assert len(list_feed_events(db_path=db_path)) == 3


def test_rubygems_page_budget_flags_incomplete_and_holds_cursor(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    cursor_before = _cursor_value(db_path, collector_id="COL-RUBYGEMS-TIMEFRAME")
    result = run_registry_collector(
        ecosystem="rubygems", max_pages=1, db_path=db_path, fetcher=_rubygems_fetcher(urls)
    )
    assert result["status"] == "completed"
    assert result["window_incomplete"] is True
    assert result["events_stored"] == 2
    # The cursor must not advance past an undrained window.
    assert result["cursor_after"] == cursor_before


def test_rubygems_page_failure_dead_letters_and_records_gap(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    cursor_before = _cursor_value(db_path, collector_id="COL-RUBYGEMS-TIMEFRAME")
    result = run_registry_collector(
        ecosystem="rubygems", db_path=db_path, fetcher=_rubygems_fetcher(urls, fail_pages={2})
    )
    assert result["status"] == "failed"
    assert result["coverage"] == "gap"
    assert result["cursor_after"] == cursor_before
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "page"


def test_rubygems_backfill_window_slices_forward(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    _set_cursor(db_path, "COL-RUBYGEMS-TIMEFRAME", "2026-07-18T00:00:00.000Z")
    urls = []
    result = run_registry_collector(ecosystem="rubygems", db_path=db_path, fetcher=_rubygems_fetcher(urls))
    assert result["status"] == "completed"
    # from = cursor - 300s overlap; to = from + 24h slice (not "now").
    assert _window_from_param(urls[0]) == "2026-07-17T23:55:00.000Z"
    assert result["cursor_after"] == "2026-07-18T23:55:00.000Z"


def test_rubygems_request_overlaps_cursor(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    _set_cursor(db_path, "COL-RUBYGEMS-TIMEFRAME", "2026-07-20T12:00:00.000Z")
    urls = []
    run_registry_collector(ecosystem="rubygems", db_path=db_path, fetcher=_rubygems_fetcher(urls))
    assert _window_from_param(urls[0]) == "2026-07-20T11:55:00.000Z"


NPM_FIXTURES = Path(__file__).parent / "fixtures" / "npm_changes"


def _npm_fetcher(captured_urls, fail=()):
    def fetch(url, max_bytes):
        captured_urls.append(url)
        if url == "https://replicate.npmjs.com/":
            if "root" in fail:
                return 500, {"content-type": "application/json"}, b'{"error": "down"}'
            return 200, {"content-type": "application/json"}, (NPM_FIXTURES / "root.json").read_bytes()
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        since = int(params.get("since", ["0"])[0])
        if since in fail:
            return 500, {"content-type": "application/json"}, b'{"error": "down"}'
        if since < 98:
            name = "page1.json"
        elif since == 98:
            name = "page2.json"
        else:
            name = "empty.json"
        return 200, {"content-type": "application/json"}, (NPM_FIXTURES / name).read_bytes()

    return SafeFetcher(fetch=fetch)


@pytest.fixture
def _npm_page_limit_3(monkeypatch):
    # ensure_collectors rebuilds config_json from COLLECTOR_DEFINITIONS on
    # every call, so the definition is the only durable override point.
    from secopsai import research_surveillance

    monkeypatch.setitem(research_surveillance.COLLECTOR_DEFINITIONS["npm"], "page_limit", 3)


def _set_npm_page_limit(db_path, limit):
    ensure_collectors(db_path=db_path)
    connection = soc_store.connect(db_path)
    try:
        row = connection.execute(
            "SELECT config_json FROM registry_collectors WHERE collector_id = 'COL-NPM-CHANGES'"
        ).fetchone()
        config = json.loads(row["config_json"])
        config["page_limit"] = limit
        connection.execute(
            "UPDATE registry_collectors SET config_json = ? WHERE collector_id = 'COL-NPM-CHANGES'",
            (json.dumps(config),),
        )
        connection.commit()
    finally:
        connection.close()


def test_npm_collector_seeds_with_zero_cursor(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    npm = next(item for item in collectors if item["collector_id"] == "COL-NPM-CHANGES")
    assert npm["mode"] == "event_feed"
    assert npm["cursor"]["cursor_value"] == "0"


def test_npm_bootstrap_adopts_registry_sequence(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(ecosystem="npm", db_path=db_path, fetcher=_npm_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert result["cursor_after"] == "9000"
    assert urls == ["https://replicate.npmjs.com/"]


def test_npm_bootstrap_failure_dead_letters_without_cursor_move(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(ecosystem="npm", db_path=db_path, fetcher=_npm_fetcher(urls, fail={"root"}))
    assert result["status"] == "failed"
    assert result["cursor_after"] == "0"
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "feed"


def test_npm_backfill_stores_changes_and_maps_deleted(tmp_path, _npm_page_limit_3):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(ecosystem="npm", since="95", db_path=db_path, fetcher=_npm_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 4
    assert result["pages_processed"] == 2
    assert result["cursor_after"] == "99"

    events = list_feed_events(db_path=db_path)
    by_name = {event["package"]: event for event in events}
    assert by_name["chalk-tempalte"]["event_type"] == "published"
    assert by_name["chalk-tempalte"]["metadata"]["timestamp_source"] == "collector"
    assert by_name["chalk-tempalte"]["leaf_url"] == "https://registry.npmjs.org/chalk-tempalte"
    assert by_name["deleted-package"]["event_type"] == "deleted"
    assert "@scope/nested-package" in by_name


def test_npm_page_failure_holds_cursor_at_last_persisted_batch(tmp_path, _npm_page_limit_3):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(ecosystem="npm", since="95", db_path=db_path, fetcher=_npm_fetcher(urls, fail={98}))
    assert result["status"] == "failed"
    assert result["coverage"] == "gap"
    assert result["events_stored"] == 3
    assert result["cursor_after"] == "98"
    assert _cursor_value(db_path, collector_id="COL-NPM-CHANGES") == "98"
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "page"


def test_npm_idle_run_advances_cursor_without_events(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    _set_cursor(db_path, "COL-NPM-CHANGES", "99")
    urls = []
    result = run_registry_collector(ecosystem="npm", db_path=db_path, fetcher=_npm_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert result["cursor_after"] == "102"


def test_npm_rerun_is_idempotent(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="npm", since="95", db_path=db_path, fetcher=_npm_fetcher(urls))
    result = run_registry_collector(ecosystem="npm", since="95", db_path=db_path, fetcher=_npm_fetcher(urls))
    assert result["events_stored"] == 0
    assert result["events_duplicate"] == 3
    assert len(list_feed_events(db_path=db_path)) == 3


GO_FIXTURES = Path(__file__).parent / "fixtures" / "go_index"


def _go_fetcher(captured_urls, fail_sinces=()):
    def fetch(url, max_bytes):
        captured_urls.append(url)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        since = params.get("since", [""])[0]
        if since in fail_sinces:
            return 500, {"content-type": "text/plain"}, b"internal error"
        if since < "2026-07-21T12:03:00.999Z":
            return 200, {"content-type": "text/plain"}, (GO_FIXTURES / "page1.ndjson").read_bytes()
        if since == "2026-07-21T12:03:00.999Z":
            return 200, {"content-type": "text/plain"}, (GO_FIXTURES / "page2.ndjson").read_bytes()
        return 200, {"content-type": "text/plain"}, b""

    return SafeFetcher(fetch=fetch)


@pytest.fixture
def _go_page_limit_3(monkeypatch):
    from secopsai import research_surveillance

    monkeypatch.setitem(research_surveillance.COLLECTOR_DEFINITIONS["go"], "page_limit", 3)


def test_go_collector_seeds_with_lookback_cursor(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    go = next(item for item in collectors if item["collector_id"] == "COL-GO-INDEX")
    assert go["mode"] == "event_feed"
    assert "T" in go["cursor"]["cursor_value"]


def test_go_run_stores_module_versions_and_advances_cursor(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="go", since="2026-07-21T12:00:00Z", db_path=db_path, fetcher=_go_fetcher(urls)
    )
    assert result["status"] == "completed"
    assert result["events_stored"] == 3
    assert result["cursor_after"] == "2026-07-21T12:03:00.999Z"

    events = list_feed_events(db_path=db_path)
    by_version = {(event["package"], event["version"]): event for event in events}
    toolkit = by_version[("github.com/acme/toolkit", "v1.2.0")]
    assert toolkit["event_type"] == "published"
    assert toolkit["registry_timestamp"] == "2026-07-21T12:01:00.123Z"
    assert toolkit["leaf_url"] == "https://proxy.golang.org/github.com/acme/toolkit/@v/v1.2.0.info"


def test_go_multi_page_walk_persists_batches(tmp_path, _go_page_limit_3):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="go", since="2026-07-21T12:00:00Z", db_path=db_path, fetcher=_go_fetcher(urls)
    )
    assert result["events_stored"] == 4
    assert result["pages_processed"] == 2
    assert result["cursor_after"] == "2026-07-21T12:04:00.000Z"


def test_go_page_failure_holds_cursor_at_last_batch(tmp_path, _go_page_limit_3):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="go",
        since="2026-07-21T12:00:00Z",
        db_path=db_path,
        fetcher=_go_fetcher(urls, fail_sinces={"2026-07-21T12:03:00.999Z"}),
    )
    assert result["status"] == "failed"
    assert result["coverage"] == "gap"
    assert result["events_stored"] == 3
    assert result["cursor_after"] == "2026-07-21T12:03:00.999Z"
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "page"


def test_go_caught_up_run_keeps_cursor(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    _set_cursor(db_path, "COL-GO-INDEX", "2026-07-21T12:04:00.000Z")
    urls = []
    result = run_registry_collector(ecosystem="go", db_path=db_path, fetcher=_go_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert result["cursor_after"] == "2026-07-21T12:04:00.000Z"


def test_go_rerun_is_idempotent(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="go", since="2026-07-21T12:00:00Z", db_path=db_path, fetcher=_go_fetcher(urls))
    result = run_registry_collector(ecosystem="go", since="2026-07-21T12:00:00Z", db_path=db_path, fetcher=_go_fetcher(urls))
    assert result["events_stored"] == 0
    assert result["events_duplicate"] == 3
    assert len(list_feed_events(db_path=db_path)) == 3


MAVEN_FIXTURES = Path(__file__).parent / "fixtures" / "maven_solr"


def _maven_fetcher(captured_urls, fail_starts=(), backlog=False):
    def fetch(url, max_bytes):
        captured_urls.append(url)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        query = params.get("q", [""])[0]
        start = int(params.get("start", ["0"])[0])
        if query == "*:*":
            return 200, {"content-type": "application/json"}, (MAVEN_FIXTURES / "bootstrap.json").read_bytes()
        if start in fail_starts:
            return 500, {"content-type": "application/json"}, b'{"error": "solr down"}'
        if backlog:
            name = "page1.json" if start == 0 else "page1.json"
        elif start == 0:
            name = "page1.json"
        elif start == 3:
            name = "page2.json"
        else:
            name = "empty.json"
        return 200, {"content-type": "application/json"}, (MAVEN_FIXTURES / name).read_bytes()

    return SafeFetcher(fetch=fetch)


@pytest.fixture
def _maven_backlog_fetcher(monkeypatch):
    # numFound 4 with only 3 docs per page repeated: page budget of 1
    # cannot drain the backlog, so the cursor must hold.
    from secopsai import research_surveillance

    monkeypatch.setitem(research_surveillance.COLLECTOR_DEFINITIONS["maven"], "page_limit", 3)


def test_maven_collector_seeds_with_zero_cursor(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    maven = next(item for item in collectors if item["collector_id"] == "COL-MAVEN-SOLR")
    assert maven["mode"] == "event_feed"
    assert maven["cursor"]["cursor_value"] == "0"


def test_maven_bootstrap_adopts_newest_timestamp(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(ecosystem="maven", db_path=db_path, fetcher=_maven_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert result["cursor_after"] == "1782000000000"


def test_maven_tail_stores_versions_and_drains(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(ecosystem="maven", since="1781999900000", db_path=db_path, fetcher=_maven_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 4
    assert result["pages_processed"] == 2
    assert result["cursor_after"] == "1782000100000"
    assert "window_incomplete" not in result

    events = list_feed_events(db_path=db_path)
    by_id = {f"{event['package']}:{event['version']}": event for event in events}
    imposter = by_id["org.evil:paypa1-sdk:1.0.0"]
    assert imposter["event_type"] == "published"
    assert imposter["registry_timestamp"] == "2026-06-21T00:00:50.000Z"
    assert imposter["metadata"]["search_derived"] is True
    assert imposter["leaf_url"] == "https://repo1.maven.org/maven2/org/evil/paypa1-sdk/1.0.0/"


def test_maven_undrained_backlog_holds_cursor(tmp_path, _maven_backlog_fetcher):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="maven", since="1781999900000", max_pages=1, db_path=db_path,
        fetcher=_maven_fetcher(urls, backlog=True),
    )
    assert result["status"] == "completed"
    assert result["window_incomplete"] is True
    assert result["events_stored"] == 3
    assert result["cursor_after"] == "1781999900000"


def test_maven_page_failure_dead_letters_and_holds_cursor(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="maven", since="1781999900000", db_path=db_path,
        fetcher=_maven_fetcher(urls, fail_starts={3}),
    )
    assert result["status"] == "failed"
    assert result["coverage"] == "gap"
    assert result["cursor_after"] == "1781999900000"
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "page"


def test_maven_caught_up_run_keeps_cursor(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    _set_cursor(db_path, "COL-MAVEN-SOLR", "1782000100000")

    def empty_fetch(url, max_bytes):
        return 200, {"content-type": "application/json"}, (MAVEN_FIXTURES / "empty.json").read_bytes()

    result = run_registry_collector(ecosystem="maven", db_path=db_path, fetcher=SafeFetcher(fetch=empty_fetch))
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert result["cursor_after"] == "1782000100000"


def test_maven_rerun_is_idempotent(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="maven", since="1781999900000", db_path=db_path, fetcher=_maven_fetcher(urls))
    result = run_registry_collector(ecosystem="maven", since="1781999900000", db_path=db_path, fetcher=_maven_fetcher(urls))
    assert result["events_stored"] == 0
    assert result["events_duplicate"] == 4
    assert len(list_feed_events(db_path=db_path)) == 4


OPENVSX_FIXTURES = Path(__file__).parent / "fixtures" / "openvsx_search"


def _openvsx_fetcher(captured_urls, variant="base", fail_letters=()):
    def fetch(url, max_bytes):
        captured_urls.append(url)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        letter = params.get("query", [""])[0]
        offset = int(params.get("offset", ["0"])[0])
        if letter in fail_letters:
            return 500, {"content-type": "application/json"}, b'{"error": "registry down"}'
        if letter != "a":
            return 200, {"content-type": "application/json"}, b'{"offset": 0, "totalSize": 0, "extensions": []}'
        name = ("page1_changed.json" if variant == "changed" else "page1.json") if offset == 0 else "page2.json"
        return 200, {"content-type": "application/json"}, (OPENVSX_FIXTURES / name).read_bytes()

    return SafeFetcher(fetch=fetch)


def _openvsx_snapshots(db_path):
    connection = soc_store.connect(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM registry_snapshots WHERE collector_id = 'COL-OPENVSX-SEARCH' ORDER BY created_at"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def test_openvsx_collector_seeds_with_zero_cursor(tmp_path):
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    openvsx = next(item for item in collectors if item["collector_id"] == "COL-OPENVSX-SEARCH")
    assert openvsx["mode"] == "index_reconcile"
    assert openvsx["cursor"]["cursor_value"] == "0"


def test_openvsx_baseline_stores_snapshot_without_events(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(ecosystem="open-vsx", max_pages=60, db_path=db_path, fetcher=_openvsx_fetcher(urls))
    assert result["status"] == "completed"
    assert result["events_stored"] == 0
    assert result["cursor_after"] == "2026-07-21T09:00:00.000Z"
    assert result["partitions_completed"] == 36
    snapshots = _openvsx_snapshots(db_path)
    assert len(snapshots) == 1
    assert snapshots[0]["item_count"] == 3


def test_openvsx_reconciliation_emits_added_updated_removed(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="open-vsx", max_pages=60, db_path=db_path, fetcher=_openvsx_fetcher(urls))
    result = run_registry_collector(
        ecosystem="open-vsx", max_pages=60, db_path=db_path, fetcher=_openvsx_fetcher(urls, variant="changed")
    )
    assert result["status"] == "completed"
    assert result["events_stored"] == 3
    assert result["cursor_after"] == "2026-07-21T12:00:00.000Z"

    events = list_feed_events(db_path=db_path)
    by_package = {event["package"]: event for event in events}
    added = by_package["newcomer/helper"]
    assert added["event_type"] == "extension_added"
    assert added["registry_timestamp"] == "2026-07-21T11:00:00.000Z"
    assert added["leaf_url"] == "https://open-vsx.org/api/newcomer/helper"
    updated = by_package["acme/tools"]
    assert updated["event_type"] == "version_updated"
    assert updated["version"] == "2.1.0"
    assert updated["metadata"]["previous_version"] == "2.0.0"
    removed = by_package["acme/linter"]
    assert removed["event_type"] == "extension_removed"
    assert removed["version"] == "1.5.0"


def test_openvsx_unchanged_registry_skips_snapshot(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="open-vsx", max_pages=60, db_path=db_path, fetcher=_openvsx_fetcher(urls))
    run_registry_collector(ecosystem="open-vsx", max_pages=60, db_path=db_path, fetcher=_openvsx_fetcher(urls, variant="changed"))
    result = run_registry_collector(
        ecosystem="open-vsx", max_pages=60, db_path=db_path, fetcher=_openvsx_fetcher(urls, variant="changed")
    )
    assert result["events_stored"] == 0
    assert len(_openvsx_snapshots(db_path)) == 2
    assert len(list_feed_events(db_path=db_path)) == 3


def test_openvsx_partial_enumeration_holds_cursor_and_snapshot(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    run_registry_collector(ecosystem="open-vsx", max_pages=60, db_path=db_path, fetcher=_openvsx_fetcher(urls))
    result = run_registry_collector(
        ecosystem="open-vsx",
        max_pages=2,
        db_path=db_path,
        fetcher=_openvsx_fetcher(urls),
    )
    assert result["status"] == "completed"
    assert result["window_incomplete"] is True
    # Partial data must never infer removals or replace the snapshot.
    assert len(_openvsx_snapshots(db_path)) == 1
    assert list_feed_events(db_path=db_path) == []


def test_openvsx_page_failure_dead_letters_and_records_gap(tmp_path):
    db_path = _db(tmp_path)
    urls = []
    result = run_registry_collector(
        ecosystem="open-vsx", db_path=db_path, fetcher=_openvsx_fetcher(urls, fail_letters={"a"})
    )
    assert result["status"] == "failed"
    assert result["coverage"] == "gap"
    letters = _dead_letters(db_path)
    assert len(letters) == 1
    assert letters[0]["item_kind"] == "page"


def test_paused_collector_refuses_runs_and_keeps_cursor(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    cursor_before = _cursor_value(db_path)

    paused = set_collector_enabled(ecosystem="nuget", enabled=False, db_path=db_path)
    assert paused["enabled"] is False
    assert paused["cursor"] == cursor_before
    with pytest.raises(CollectorError, match="paused"):
        run_registry_collector(ecosystem="nuget", db_path=db_path, fetcher=_fetcher())
    assert _cursor_value(db_path) == cursor_before

    resumed = set_collector_enabled(ecosystem="nuget", enabled=True, db_path=db_path)
    assert resumed["enabled"] is True
    result = run_registry_collector(ecosystem="nuget", since=SINCE_ALL, db_path=db_path, fetcher=_fetcher())
    assert result["status"] == "completed"
