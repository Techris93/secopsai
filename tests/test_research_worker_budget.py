"""Collectors start only when the worker has time to finish them."""
import time

import soc_store
from secopsai import research_worker


def _completed_run(db, collector_id, seconds):
    with soc_store.connect(db) as connection:
        connection.execute(
            """INSERT INTO registry_ingestion_runs (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at, completed_at)
               VALUES (?, ?, 'completed', 'a', 'b', 'index_reconcile', '2026-10-25T00:00:00Z', ?)""",
            (f"RIR-{collector_id}-{seconds}", collector_id, f"2026-10-25T00:{seconds // 60:02d}:{seconds % 60:02d}Z"),
        )
        connection.commit()


def test_time_needed_comes_from_recent_completed_runs(tmp_path):
    db = str(tmp_path / "soc.db")
    soc_store.init_db(db)
    from secopsai.research_surveillance import ensure_collectors
    ensure_collectors(db_path=db)
    assert research_worker.collector_time_needed("COL-OPENVSX-SEARCH", db_path=db) == 60 + 30, "default without history"
    _completed_run(db, "COL-OPENVSX-SEARCH", 300)
    _completed_run(db, "COL-OPENVSX-SEARCH", 120)
    assert research_worker.collector_time_needed("COL-OPENVSX-SEARCH", db_path=db) == 300 + 30, "slowest recent run plus margin"


def test_seconds_left_reads_the_supervisor_deadline(monkeypatch):
    monkeypatch.delenv("SECOPSAI_WORKER_DEADLINE_EPOCH", raising=False)
    assert research_worker.seconds_left() is None, "unbounded runs are unaffected"
    monkeypatch.setenv("SECOPSAI_WORKER_DEADLINE_EPOCH", str(time.time() + 60))
    assert 55 < research_worker.seconds_left() <= 60


def test_a_long_collector_is_deferred_near_the_deadline_and_runs_with_time_to_spare(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    soc_store.init_db(db)
    from secopsai.research_surveillance import ensure_collectors
    ensure_collectors(db_path=db)
    _completed_run(db, "COL-OPENVSX-SEARCH", 300)
    item = {"collector_id": "COL-OPENVSX-SEARCH", "ecosystem": "open-vsx", "due": True}
    monkeypatch.setenv("SECOPSAI_WORKER_DEADLINE_EPOCH", str(time.time() + 13))  # production: 13 s left at 01:16:32
    deferral = research_worker.budget_deferral(item, db_path=db)
    assert deferral["status"] == "deferred_budget" and deferral["seconds_needed"] == 330
    monkeypatch.setenv("SECOPSAI_WORKER_DEADLINE_EPOCH", str(time.time() + 1200))
    assert research_worker.budget_deferral(item, db_path=db) is None
    monkeypatch.delenv("SECOPSAI_WORKER_DEADLINE_EPOCH")
    assert research_worker.budget_deferral(item, db_path=db) is None, "no deadline, no deferral"


def test_investigations_per_cycle_defaults_to_filling_free_slots(monkeypatch):
    monkeypatch.delenv("SECOPSAI_INVESTIGATIONS_PER_CYCLE", raising=False)
    assert research_worker.investigations_per_cycle() == 3
    monkeypatch.setenv("SECOPSAI_INVESTIGATIONS_PER_CYCLE", "50")
    assert research_worker.investigations_per_cycle() == 10
    monkeypatch.setenv("SECOPSAI_INVESTIGATIONS_PER_CYCLE", "x")
    assert research_worker.investigations_per_cycle() == 3


def test_finished_investigations_are_applied_before_the_cycle_reconciles_them(tmp_path, monkeypatch):
    from secopsai import core_edge_client
    from secopsai.worker_control import request_shutdown

    class Core:
        enabled = True

        def pull_and_apply_settings(self, **kw):
            return None

        def process_commands(self, **kw):
            return []

    order = []

    def cycle(**kw):
        order.append("cycle")
        request_shutdown()
        return {"status": "succeeded"}

    monkeypatch.setattr(core_edge_client, "coordinator_client", lambda: Core())
    monkeypatch.setattr(research_worker, "_sync_investigation_jobs", lambda *a, **kw: order.append("sync") or {"status": "ok"})
    monkeypatch.setattr(research_worker, "run_worker_cycle", cycle)
    research_worker.run_worker_loop(db_path=str(tmp_path / "research.db"), max_cycles=1)
    assert order[:2] == ["sync", "cycle"]


def test_deployment_can_raise_investigation_slots_within_bounds(monkeypatch):
    from secopsai.investigation_autopilot import max_active_runs

    monkeypatch.delenv("SECOPSAI_INVESTIGATION_MAX_ACTIVE_RUNS", raising=False)
    assert max_active_runs({"max_active_runs": 3}) == 3
    monkeypatch.setenv("SECOPSAI_INVESTIGATION_MAX_ACTIVE_RUNS", "10")
    assert max_active_runs({"max_active_runs": 3}) == 10
    monkeypatch.setenv("SECOPSAI_INVESTIGATION_MAX_ACTIVE_RUNS", "500")
    assert max_active_runs({"max_active_runs": 3}) == 20
    monkeypatch.setenv("SECOPSAI_INVESTIGATION_MAX_ACTIVE_RUNS", "x")
    assert max_active_runs({"max_active_runs": 3}) == 3

