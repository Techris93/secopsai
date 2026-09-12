import hashlib
from datetime import datetime, timedelta, timezone

import soc_store
from secopsai.research_surveillance import ensure_collectors
from secopsai.research_worker import (
    _record_collector_degraded_alert,
    _record_npm_enrichment_alert,
    _record_storage_capacity_alert,
    collector_schedules,
    collector_page_budget,
    due_collectors,
    run_worker_cycle,
    run_worker_loop,
)
from secopsai.research_storage import ResearchStorageCapacityError
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
    assert schedules["maven"] == 3600
    assert schedules["open-vsx"] == 3600


def test_dense_collectors_receive_complete_bounded_page_budgets():
    assert collector_page_budget("rubygems", 25) == 250
    assert collector_page_budget("open-vsx", 25) == 400
    assert collector_page_budget("nuget", 25) == 25
    assert collector_page_budget("rubygems", 300) == 300


def test_due_collectors_all_due_when_never_run(tmp_path):
    db_path = _db(tmp_path)
    due = due_collectors(db_path=db_path)
    assert len(due) == 8
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


def test_worker_cycle_isolates_collector_failures(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_COLLECTOR_ALERT_THRESHOLD", "1")
    # Keep this collector-failure test independent of the host filesystem's
    # own utilization; storage warning behavior is covered separately.
    monkeypatch.setenv("SECOPSAI_STORAGE_MIN_FREE_BYTES", "0")
    monkeypatch.setenv("SECOPSAI_STORAGE_WARNING_USED_PERCENT", "100")
    monkeypatch.setenv("SECOPSAI_STORAGE_MAX_USED_PERCENT", "100")
    db_path = _db(tmp_path)
    # Every registry fetch fails; the cycle must complete and record
    # per-collector failures instead of raising.
    result = run_worker_cycle(db_path=db_path, fetcher=_fail_fetcher())
    assert result["collectors_run"] == 8
    statuses = {item["ecosystem"]: item["status"] for item in result["collector_results"]}
    assert set(statuses) == {"nuget", "packagist", "pypi", "rubygems", "npm", "go", "maven", "open-vsx"}
    assert all(status == "failed" for status in statuses.values())
    assert "scoring" in result
    assert "retries" in result
    assert "recovery" in result
    assert "investigations" in result
    assert "storage" in result
    assert len(result["operational_alert_ids"]) == 8
    assert result["alert_delivery"]["enabled"] is False
    with soc_store.connect(db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM research_alerts WHERE alert_type = 'collector_degraded'"
        ).fetchone()["count"]
    assert count == 8


def test_storage_capacity_warning_is_deduplicated_and_resolved(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_STORAGE_MIN_FREE_BYTES", "0")
    db_path = _db(tmp_path)
    warning = {
        "filesystem_used_percent": 72.0,
        "warning_used_percent": 70.0,
        "maximum_used_percent": 85.0,
        "filesystem_free_bytes": 28,
        "filesystem_total_bytes": 100,
        "database_bytes": 64,
        "pressure": False,
        "warning": True,
    }

    first = _record_storage_capacity_alert(warning, db_path=db_path)
    second = _record_storage_capacity_alert(warning, db_path=db_path)

    assert first == second
    with soc_store.connect(db_path) as connection:
        row = connection.execute(
            "SELECT alert_id, severity, status FROM research_alerts WHERE alert_type='storage_capacity_warning'"
        ).fetchone()
    assert row["alert_id"] == first
    assert row["severity"] == "medium"
    assert row["status"] == "open"

    _record_storage_capacity_alert({"warning": False}, db_path=db_path)
    with soc_store.connect(db_path) as connection:
        assert connection.execute(
            "SELECT status FROM research_alerts WHERE alert_id=?", (first,)
        ).fetchone()["status"] == "resolved"


def test_collector_degraded_alert_threshold_and_auto_resolve(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_COLLECTOR_ALERT_THRESHOLD", "3")
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)

    result_fail = {
        "ecosystem": "nuget",
        "collector_id": "COL-NUGET-CATALOG",
        "status": "failed",
        "coverage": "gap",
        "error": "registry unavailable",
    }

    # 1. First failure - should not alert
    connection = soc_store.connect(db_path)
    try:
        connection.execute(
            """INSERT INTO registry_ingestion_runs
               (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at, error_message)
               VALUES ('RIR-F1', 'COL-NUGET-CATALOG', 'failed', '0', '0', 'event_feed', '2026-07-24T00:00:00Z', 'err')"""
        )
        connection.commit()
    finally:
        connection.close()
    alert_id = _record_collector_degraded_alert(result_fail, db_path=db_path)
    assert alert_id is None

    # 2. Second failure - should not alert
    connection = soc_store.connect(db_path)
    try:
        connection.execute(
            """INSERT INTO registry_ingestion_runs
               (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at, error_message)
               VALUES ('RIR-F2', 'COL-NUGET-CATALOG', 'failed', '0', '0', 'event_feed', '2026-07-24T00:05:00Z', 'err')"""
        )
        connection.commit()
    finally:
        connection.close()
    alert_id = _record_collector_degraded_alert(result_fail, db_path=db_path)
    assert alert_id is None

    # 3. Third failure - should alert
    connection = soc_store.connect(db_path)
    try:
        connection.execute(
            """INSERT INTO registry_ingestion_runs
               (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at, error_message)
               VALUES ('RIR-F3', 'COL-NUGET-CATALOG', 'failed', '0', '0', 'event_feed', '2026-07-24T00:10:00Z', 'err')"""
        )
        connection.commit()
    finally:
        connection.close()
    alert_id = _record_collector_degraded_alert(result_fail, db_path=db_path)
    assert alert_id is not None

    # Verify it is stored as open
    with soc_store.connect(db_path) as connection:
        alert = connection.execute("SELECT * FROM research_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        assert alert["status"] == "open"

    # 4. Successful run - should auto-resolve the alert
    result_success = {
        "ecosystem": "nuget",
        "collector_id": "COL-NUGET-CATALOG",
        "status": "completed",
        "coverage": "complete",
        "window_incomplete": False,
        "diff_truncated": False,
    }
    res = _record_collector_degraded_alert(result_success, db_path=db_path)
    assert res is None

    # Verify it is resolved
    with soc_store.connect(db_path) as connection:
        alert = connection.execute("SELECT * FROM research_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        assert alert["status"] == "resolved"


def test_collector_degraded_alert_is_deduplicated_per_day(tmp_path):
    db_path = _db(tmp_path)
    result = {
        "ecosystem": "nuget",
        "status": "failed",
        "coverage": "gap",
        "error": "registry unavailable",
    }
    first = _record_collector_degraded_alert(result, db_path=db_path)
    second = _record_collector_degraded_alert(result, db_path=db_path)
    assert first == second
    with soc_store.connect(db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM research_alerts WHERE alert_type = 'collector_degraded'"
        ).fetchone()["count"]
    assert count == 1


def test_npm_enrichment_degraded_alert_is_visible_and_resolves(tmp_path):
    db_path = _db(tmp_path)
    degraded = {
        "run_id": "NEN-TEST",
        "status": "degraded",
        "events_seen": 4,
        "packages_fetched": 2,
        "versions_created": 3,
        "failures": 2,
        "enrichment_failures": 1,
        "analysis_failures": 1,
        "static": {"analyses_started": 2},
    }
    alert_id = _record_npm_enrichment_alert(degraded, db_path=db_path)
    assert alert_id
    with soc_store.connect(db_path) as connection:
        alert = connection.execute("SELECT * FROM research_alerts WHERE alert_id=?", (alert_id,)).fetchone()
        finding = connection.execute("SELECT * FROM findings WHERE finding_id=?", (f"RSCF-{hashlib.sha256(alert_id.encode()).hexdigest()[:16].upper()}",)).fetchone()
    assert alert["alert_type"] == "npm_enrichment_degraded"
    assert alert["status"] == "open"
    assert finding is not None

    assert _record_npm_enrichment_alert({"status": "completed", "failures": 0}, db_path=db_path) is None
    with soc_store.connect(db_path) as connection:
        assert connection.execute("SELECT status FROM research_alerts WHERE alert_id=?", (alert_id,)).fetchone()["status"] == "resolved"


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


def test_worker_loop_stays_alive_in_degraded_storage_state(tmp_path, monkeypatch):
    import secopsai.research_worker as worker_module

    monkeypatch.setattr(
        worker_module,
        "run_worker_cycle",
        lambda **kwargs: (_ for _ in ()).throw(ResearchStorageCapacityError("disk full")),
    )
    monkeypatch.setattr(
        worker_module,
        "storage_status",
        lambda **kwargs: {"pressure": True, "filesystem_free_bytes": 0},
    )
    cycles = []
    result = run_worker_loop(
        db_path=_db(tmp_path),
        interval_seconds=15,
        max_cycles=1,
        on_cycle=cycles.append,
    )
    assert result["cycles"] == 1
    assert cycles[0]["status"] == "degraded"
    assert cycles[0]["error_code"] == "storage_capacity_exhausted"


def test_worker_loop_publishes_ontology_snapshot_without_making_collection_depend_on_core(tmp_path, monkeypatch):
    import secopsai.core_edge_client as client_module

    class FakeCoordinator:
        enabled = True

        def __init__(self):
            self.ontology_snapshots = []
            self.states = []

        def pull_and_apply_settings(self, **kwargs):
            return {"status": "accepted"}

        def sync_state(self, summary, **kwargs):
            self.states.append(summary)
            return {"status": "accepted", "runner": {"status": "healthy"}}

        def sync_ontology(self, snapshot):
            self.ontology_snapshots.append(snapshot)
            return {"status": "accepted"}

        def process_commands(self, **kwargs):
            return []

    coordinator = FakeCoordinator()
    monkeypatch.setattr(client_module, "coordinator_client", lambda: coordinator)
    monkeypatch.setattr("secopsai.research_worker.run_worker_cycle", lambda **kwargs: {"status": "succeeded", "completed_at": "2026-09-12T00:00:00Z"})
    result = run_worker_loop(db_path=_db(tmp_path), fetcher=_fail_fetcher(), interval_seconds=15, max_cycles=1)
    assert result["cycles"] == 1
    assert coordinator.ontology_snapshots
    assert coordinator.ontology_snapshots[0]["schema_version"] == "secopsai.ontology.v1"
    assert result["last_cycle"]["ontology"]["status"] == "accepted"


def test_worker_loop_keeps_surveillance_running_when_core_is_unavailable(tmp_path, monkeypatch):
    import secopsai.core_edge_client as client_module

    class OfflineCoordinator:
        enabled = True

        def pull_and_apply_settings(self, **kwargs):
            raise OSError("core unavailable")

        def sync_state(self, *args, **kwargs):
            return {"status": "degraded"}

        def sync_ontology(self, *args, **kwargs):
            return {"status": "degraded", "error": "core unavailable"}

        def process_commands(self, **kwargs):
            return []

    monkeypatch.setattr(client_module, "coordinator_client", OfflineCoordinator)
    monkeypatch.setattr("secopsai.research_worker.run_worker_cycle", lambda **kwargs: {"status": "succeeded", "completed_at": "2026-09-12T00:00:00Z"})
    result = run_worker_loop(db_path=_db(tmp_path), fetcher=_fail_fetcher(), interval_seconds=15, max_cycles=1)
    assert result["cycles"] == 1
    assert result["last_cycle"]["ontology"]["status"] == "degraded"
