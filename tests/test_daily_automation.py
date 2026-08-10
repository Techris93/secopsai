from secopsai import daily_automation


def _stub_modules(monkeypatch, *, fail_step=None):
    calls = []

    def stub(name, result=None):
        def run(**kwargs):
            calls.append(name)
            if name == fail_step:
                raise RuntimeError(f"{name} failed")
            return result or {"status": "ok", "step": name}

        return run

    monkeypatch.setattr(
        "secopsai.research_worker.run_worker_cycle",
        stub("registry_surveillance"),
    )
    monkeypatch.setattr(
        "secopsai.research_discovery.run_promotion_policy",
        stub("candidate_promotion"),
    )
    monkeypatch.setattr(
        "secopsai.agent_triage.enqueue_due_findings",
        stub("alert_review_queue"),
    )
    monkeypatch.setattr(
        "secopsai.investigation_autopilot.run_due",
        stub("evidence_investigations"),
    )
    monkeypatch.setattr(
        "secopsai.detection_learning.run_cycle",
        stub("detection_learning"),
    )
    monkeypatch.setattr(
        "secopsai.research_delivery.deliver_pending_operational_alerts",
        stub("operational_alert_delivery"),
    )
    monkeypatch.setattr(
        "secopsai.research_storage.archive_and_prune_history",
        stub("storage_retention"),
    )
    return calls


def test_daily_cycle_runs_all_steps_and_is_persisted(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    calls = _stub_modules(monkeypatch)

    result = daily_automation.run_cycle(db_path=db, trigger="test", force=True)

    assert result["status"] == "succeeded"
    assert result["summary"]["completed_steps"] == 7
    assert result["summary"]["failed_steps"] == 0
    assert calls == [
        "registry_surveillance",
        "candidate_promotion",
        "alert_review_queue",
        "evidence_investigations",
        "detection_learning",
        "storage_retention",
        "operational_alert_delivery",
    ]
    stored = daily_automation.get_run(result["run_id"], db_path=db)
    assert len(stored["steps"]) == 7
    assert stored["steps"][0]["status"] == "succeeded"
    status = daily_automation.status(db_path=db)
    assert status["summary"]["last_status"] == "succeeded"
    assert status["settings"]["next_run_at"]


def test_daily_cycle_continues_after_step_failure_and_marks_degraded(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    calls = _stub_modules(monkeypatch, fail_step="candidate_promotion")

    result = daily_automation.run_cycle(db_path=db, trigger="test", force=True)

    assert result["status"] == "degraded"
    assert result["summary"]["failed_steps"] == 1
    assert calls[-1] == "operational_alert_delivery"
    failed = [step for step in result["steps"] if step["status"] == "failed"]
    assert failed[0]["step_name"] == "candidate_promotion"
    assert "candidate_promotion failed" in failed[0]["error_message"]


def test_due_cycle_respects_schedule_and_can_be_paused(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    _stub_modules(monkeypatch)

    assert daily_automation.run_due(db_path=db)["status"] == "succeeded"
    assert daily_automation.run_due(db_path=db)["status"] == "not_due"
    daily_automation.update_settings(enabled=False, db_path=db)
    assert daily_automation.run_due(db_path=db)["status"] == "skipped"
    forced = daily_automation.run_cycle(db_path=db, trigger="operator", force=True)
    assert forced["status"] == "succeeded"


def test_daily_settings_reject_unsafe_limits(tmp_path):
    db = str(tmp_path / "soc.db")
    try:
        daily_automation.update_settings(interval_seconds=30, db_path=db)
    except ValueError as exc:
        assert "interval" in str(exc)
    else:
        raise AssertionError("unsafe automation interval was accepted")
