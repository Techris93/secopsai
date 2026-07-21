import json
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
    soc_store.init_db(db_path)
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
    status = collector_status(db_path=db_path)[0]
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
        run_registry_collector(ecosystem="npm", db_path=_db(tmp_path), fetcher=_fetcher())


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
