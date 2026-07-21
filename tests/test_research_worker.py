from datetime import datetime, timedelta, timezone

import soc_store
from secopsai.research_surveillance import ensure_collectors, run_registry_collector
from secopsai.research_worker import (
    collector_schedules,
    due_collectors,
    run_worker_cycle,
    run_worker_loop,
)
from secopsai.research_intake import SafeFetcher


def _db(tmp_path):
    return str(tmp_path / "worker.db")


def _fail_fetcher():
    def fetch(url, max_bytes):
        return 500, {"content-type": "application/json"}, b'{"error": "down"}'

    return SafeFetcher(fetch=fetch)


def test_collector_schedules_have_respectful_intervals():
    schedules = collector_schedules()
    assert schedules["nuget"] == 900
    assert schedules["packagist"] == 900
    assert schedules["pypi"] == 3600
    assert schedules["rubygems"] == 1800
    assert schedules["npm"] == 900
    assert schedules["go"] == 900


def test_due_collectors_all_due_when_never_run(tmp_path):
    db_path = _db(tmp_path)
    due = due_collectors(db_path=db_path)
    assert len(due) == 6
    assert all(item["due"] for item in due)
    assert all(item["last_started_at"] is None for item in due)


def test_due_collectors_respect_intervals_and_pause(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    connection = soc_store.connect(db_path)
    try:
        # NuGet ran 10 seconds ago: not due. PyPI ran 2 hours ago: due.
        # RubyGems is paused: reported paused, never due.
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
        old = (now - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        for collector_id, started, status in (
            ("COL-NUGET-CATALOG", recent, "completed"),
            ("COL-PYPI-INDEX", old, "completed"),
        ):
            connection.execute(
                """INSERT INTO registry_ingestion_runs
                (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at, completed_at)
                VALUES (?, ?, ?, '0', '0', 'event_feed', ?, ?)""",
                (f"RIR-TEST-{collector_id}", collector_id, status, started, started),
            )
        connection.execute("UPDATE registry_collectors SET enabled = 0 WHERE collector_id = 'COL-RUBYGEMS-TIMEFRAME'")
        connection.commit()
    finally:
        connection.close()

    due = {item["ecosystem"]: item for item in due_collectors(db_path=db_path)}
    assert due["nuget"]["due"] is False
    assert due["pypi"]["due"] is True
    assert due["rubygems"]["due"] is False
    assert due["rubygems"]["paused"] is True
    assert due["packagist"]["due"] is True  # never ran


def test_worker_cycle_isolates_collector_failures(tmp_path):
    db_path = _db(tmp_path)
    # Every registry fetch fails; the cycle must complete and record
    # per-collector failures instead of raising.
    result = run_worker_cycle(db_path=db_path, fetcher=_fail_fetcher())
    assert result["collectors_run"] == 6
    statuses = {item["ecosystem"]: item["status"] for item in result["collector_results"]}
    assert set(statuses) == {"nuget", "packagist", "pypi", "rubygems", "npm", "go"}
    assert all(status == "failed" for status in statuses.values())
    assert "scoring" in result
    assert "retries" in result
    assert "recovery" in result


def test_worker_cycle_skips_collectors_not_yet_due(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    connection = soc_store.connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for row in connection.execute("SELECT collector_id FROM registry_collectors").fetchall():
            connection.execute(
                """INSERT INTO registry_ingestion_runs
                (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at, completed_at)
                VALUES (?, ?, 'completed', '0', '0', 'event_feed', ?, ?)""",
                (f"RIR-RECENT-{row['collector_id']}", row["collector_id"], now, now),
            )
        connection.commit()
    finally:
        connection.close()
    result = run_worker_cycle(db_path=db_path, fetcher=_fail_fetcher())
    assert result["collectors_run"] == 0


def test_worker_loop_honors_max_cycles(tmp_path):
    db_path = _db(tmp_path)
    cycles = []
    result = run_worker_loop(
        db_path=db_path,
        fetcher=_fail_fetcher(),
        interval_seconds=15,
        max_cycles=2,
        on_cycle=lambda summary: cycles.append(summary),
    )
    assert result["cycles"] == 2
    assert len(cycles) == 2
    assert result["stopped_by_signal"] is False
