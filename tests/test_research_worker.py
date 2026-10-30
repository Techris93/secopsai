import hashlib
import json
from datetime import datetime, timedelta, timezone

import soc_store
from secopsai.research_surveillance import ensure_collectors
from secopsai.research_worker import (
    _record_collector_degraded_alert,
    _record_npm_enrichment_alert,
    _record_storage_capacity_alert,
    _run_collector_with_transient_retry,
    collector_schedules,
    collector_page_budget,
    due_collectors,
    run_worker_cycle,
    run_worker_loop,
)
from secopsai.research_discovery import sync_actionable_alert_findings
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
    assert len(due) == 11
    # The Marketplace collector ships paused until the operator enables it.
    assert {item["ecosystem"] for item in due if not item["due"]} == {"vscode-marketplace"}
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


def test_failed_collector_gets_short_restart_safe_retry_interval(tmp_path):
    db_path = _db(tmp_path)
    ensure_collectors(db_path=db_path)
    now = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
    started = (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    completed = (now - timedelta(minutes=4, seconds=30)).isoformat().replace("+00:00", "Z")
    with soc_store.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO registry_ingestion_runs
            (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at, completed_at)
            VALUES ('RIR-FAILED-MAVEN', 'COL-MAVEN-SOLR', 'failed', '0', '0', 'event_feed', ?, ?)""",
            (started, completed),
        )
        connection.commit()

    before_backoff = {item["ecosystem"]: item for item in due_collectors(db_path=db_path, now=now)}["maven"]
    assert before_backoff["last_run_status"] == "failed"
    assert before_backoff["effective_interval_seconds"] == 300
    assert before_backoff["consecutive_failures"] == 1
    assert before_backoff["due"] is False

    after_backoff = {item["ecosystem"]: item for item in due_collectors(db_path=db_path, now=now + timedelta(seconds=40))}["maven"]
    assert after_backoff["due"] is True


def test_collector_retry_is_bounded_to_transient_transport_failures(monkeypatch):
    calls = []
    outcomes = [
        {"run_id": "failed-run", "status": "failed", "failure_category": "transient_transport",
         "retryable": True, "error": "transport failed", "transport_diagnostic": "timeout"},
        {"run_id": "recovered-run", "status": "completed", "failure_category": "",
         "retryable": False, "events_stored": 2},
    ]

    def collect(**kwargs):
        calls.append(kwargs["ecosystem"])
        return outcomes.pop(0)

    monkeypatch.setattr("secopsai.research_worker.run_registry_collector", collect)
    monkeypatch.setattr("secopsai.research_worker.time.sleep", lambda _seconds: None)
    result, retries = _run_collector_with_transient_retry(
        ecosystem="maven", max_pages=25, db_path=None, fetcher=SafeFetcher(fetch=lambda *_: (200, {}, b"{}")), retry_budget=1
    )
    assert calls == ["maven", "maven"]
    assert retries == result["retry_attempts"] == 1
    assert result["status"] == "completed"
    assert result["retry_history"] == [{"run_id": "failed-run", "error": "transport failed", "transport_diagnostic": "timeout"}]


def test_non_transport_collector_failure_is_not_retried(monkeypatch):
    calls = []

    def collect(**kwargs):
        calls.append(kwargs["ecosystem"])
        return {"run_id": "rejected-run", "status": "failed", "failure_category": "source_error",
                "retryable": False, "error": "invalid source response"}

    monkeypatch.setattr("secopsai.research_worker.run_registry_collector", collect)
    result, retries = _run_collector_with_transient_retry(
        ecosystem="mcp-registry", max_pages=30, db_path=None, fetcher=SafeFetcher(fetch=lambda *_: (200, {}, b"{}")), retry_budget=1
    )
    assert calls == ["mcp-registry"]
    assert retries == 0
    assert result["status"] == "failed"


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
    assert result["collectors_run"] == 10
    statuses = {item["ecosystem"]: item["status"] for item in result["collector_results"]}
    assert set(statuses) == {"nuget", "packagist", "pypi", "rubygems", "npm", "go", "maven", "open-vsx", "crates", "mcp-registry"}
    assert all(status == "failed" for status in statuses.values())
    assert result["status"] == "degraded"
    assert "scoring" in result
    assert "retries" in result
    assert "recovery" in result
    assert "investigations" in result
    assert "storage" in result
    assert len(result["operational_alert_ids"]) == 10
    assert result["alert_delivery"]["enabled"] is False
    with soc_store.connect(db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM research_alerts WHERE alert_type = 'collector_degraded'"
        ).fetchone()["count"]
    assert count == 10


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


def test_storage_capacity_alert_does_not_run_actionable_finding_sync(tmp_path, monkeypatch):
    db_path = _db(tmp_path)

    def fail_if_called(**kwargs):
        raise AssertionError("operational storage alerts must not trigger alert finding synchronization")

    monkeypatch.setattr("secopsai.research_worker.sync_actionable_alert_findings", fail_if_called)
    alert_id = _record_storage_capacity_alert(
        {"warning": True, "filesystem_used_percent": 72, "warning_used_percent": 70},
        db_path=db_path,
    )
    assert alert_id


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
    sync_actionable_alert_findings(db_path=db_path, alert_ids=[alert_id])
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


def test_worker_loop_survives_unexpected_cycle_writer_failure(tmp_path, monkeypatch):
    import secopsai.research_worker as worker_module

    monkeypatch.setattr(
        worker_module,
        "run_worker_cycle",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("temporary writer failure")),
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
    assert cycles[0]["error_code"] == "worker_cycle_failed"


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


def test_collector_degradation_reuses_one_open_alert_across_days(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from contextlib import closing

    import soc_store
    from secopsai import research_worker

    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    for day in (1, 2, 3):
        monkeypatch.setattr(research_worker, "_utcnow", lambda day=day: datetime(2026, 9, day, tzinfo=timezone.utc))
        research_worker._record_collector_degraded_alert(
            {"status": "rejected", "coverage": "unknown", "ecosystem": "rubygems"}, db_path=db
        )
    with closing(soc_store.connect(db)) as connection:
        rows = connection.execute("SELECT status FROM research_alerts WHERE alert_type='collector_degraded'").fetchall()
    assert [row["status"] for row in rows] == ["open"]


def test_operator_can_enable_paused_collectors_by_environment(tmp_path, monkeypatch):
    db_path = _db(tmp_path)
    monkeypatch.setenv("SECOPSAI_ENABLE_COLLECTORS", "vscode-marketplace")
    due = due_collectors(db_path=db_path)
    assert all(item["due"] for item in due)


def test_shutdown_skips_expensive_followup_stages_and_returns_cleanly(tmp_path, monkeypatch):
    import secopsai.research_worker as worker
    from secopsai.worker_control import request_shutdown,shutdown_requested
    class Disabled:
        enabled=False
    monkeypatch.setattr('secopsai.core_edge_client.coordinator_client',lambda:Disabled())
    def stopped_cycle(**kwargs):
        request_shutdown()
        return {'status':'succeeded'}
    monkeypatch.setattr(worker,'run_worker_cycle',stopped_cycle)
    result = worker.run_worker_loop(db_path=_db(tmp_path),max_cycles=1)
    assert result['stopped_by_signal'] and result['cycles']==0
    assert result['last_cycle']=={'status':'succeeded'}
    assert not shutdown_requested(), 'one stopped loop must not poison later tasks'


def test_fresh_restore_recovers_dead_daily_owners_once(tmp_path, monkeypatch):
    import secopsai.research_worker as worker
    from secopsai.worker_control import request_shutdown
    calls = []
    class Disabled:
        enabled = False
    monkeypatch.setattr('secopsai.core_edge_client.coordinator_client', lambda: Disabled())
    monkeypatch.setattr('secopsai.daily_automation.recover_interrupted_runs', lambda **kwargs: calls.append(kwargs) or 1)
    def stopped_cycle(**kwargs):
        request_shutdown()
        return {'status': 'succeeded'}
    monkeypatch.setattr(worker, 'run_worker_cycle', stopped_cycle)
    monkeypatch.setenv('SECOPSAI_RESTORED_LEDGER_RECOVERY', '1')
    db = _db(tmp_path)
    worker.run_worker_loop(db_path=db, max_cycles=1)
    worker.run_worker_loop(db_path=db, max_cycles=1)
    assert calls == [{'db_path': db, 'restored_snapshot': True}]


def test_cycle_outcomes_report_age_out_and_investigation_blockers_in_a_short_line():
    from secopsai.research_worker import _cycle_outcomes

    outcomes = _cycle_outcomes({
        "editorial": {"age_out": {"status": "report_only", "would_archive": 12},
                      "automated_verification": {"verified": 1, "needs_review_ids": ["x"] * 500}},
        "investigations": {"processed": 3, "queue": {"queued_before_backfill": 700},
                           "runs": [{"blocker_code": "package_version_removed", "evidence_summary": "y" * 9000},
                                    {"blocker_code": "package_version_removed"}, {"blocker_code": None}]},
    })
    assert outcomes["age_out"]["would_archive"] == 12
    assert outcomes["automated_verification"] == {"verified": 1}
    assert outcomes["investigations"] == {"processed": 3, "blockers": {"package_version_removed": 2, "none": 1}, "queued_before_backfill": 700}
    assert len(json.dumps(outcomes)) < 1000
    assert _cycle_outcomes({})["age_out"] is None


def test_operator_commands_run_before_the_cycle_can_use_up_its_time(tmp_path, monkeypatch):
    import secopsai.core_edge_client as client_module

    order = []

    class Coordinator:
        enabled = True

        def pull_and_apply_settings(self, **kwargs):
            return {}

        def sync_state(self, *args, **kwargs):
            return {"status": "accepted", "runner": {"status": "healthy"}}

        def sync_ontology(self, *args, **kwargs):
            return {"status": "accepted"}

        def process_commands(self, **kwargs):
            order.append("commands")
            return [{"command_id": "CMD-1", "status": "succeeded"}] if len(order) == 1 else []

    def cycle(**kwargs):
        order.append("cycle")
        return {"status": "succeeded", "completed_at": "2026-10-30T00:00:00Z"}

    monkeypatch.setattr(client_module, "coordinator_client", Coordinator)
    monkeypatch.setattr("secopsai.research_worker.run_worker_cycle", cycle)
    result = run_worker_loop(db_path=_db(tmp_path), fetcher=_fail_fetcher(), interval_seconds=15, max_cycles=1)
    assert order == ["commands", "cycle", "commands"]
    assert result["last_cycle"]["hosted_coordinator"]["commands"][0]["command_id"] == "CMD-1"
