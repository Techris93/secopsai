import soc_store

from secopsai.research_delivery import deliver_pending_operational_alerts, send_research_alert
from secopsai.research_discovery import create_candidate_alert
from secopsai.research_worker import _record_collector_degraded_alert


def test_research_alert_delivery_is_audited_without_exposing_raw_artifacts(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    alert = create_candidate_alert({
        "candidate_id": "CAN-TEST",
        "score": 91,
        "reason": "similarity requires review",
        "evidence": {"artifact_sha256": "a" * 64},
        "last_seen": "2026-07-18T00:00:00Z",
    }, db_path=db)
    sent = {}

    def fake_send_email(**kwargs):
        sent.update(kwargs)
        return {"channel": "email", "status": "sent"}

    monkeypatch.setattr("secopsai.research_delivery.send_email", fake_send_email)
    result = send_research_alert(alert["alert_id"], db_path=db)
    assert result["ok"] is True
    assert sent["sender"] == "research@secopsai.dev"
    with soc_store.connect(db) as connection:
        row = connection.execute("SELECT status, attempts, destination FROM research_notification_deliveries WHERE alert_id = ?", (alert["alert_id"],)).fetchone()
    assert row["status"] == "sent"
    assert row["attempts"] == 1
    assert row["destination"] == "research@secopsai.dev"


def test_operational_alert_delivery_is_disabled_without_explicit_channels(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    _record_collector_degraded_alert(
        {"ecosystem": "nuget", "status": "failed", "coverage": "gap"}, db_path=db
    )
    monkeypatch.delenv("SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS", raising=False)
    result = deliver_pending_operational_alerts(db_path=db)
    assert result == {"enabled": False, "channels": [], "attempted": 0, "sent": 0, "failed": 0, "deferred": 0}


def test_operational_alert_delivery_sends_once_per_channel(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    _record_collector_degraded_alert(
        {"ecosystem": "nuget", "status": "failed", "coverage": "gap"}, db_path=db
    )
    monkeypatch.setenv("SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS", "email")
    monkeypatch.setattr(
        "secopsai.research_delivery.send_email",
        lambda **kwargs: {"channel": "email", "status": "sent"},
    )
    first = deliver_pending_operational_alerts(db_path=db)
    second = deliver_pending_operational_alerts(db_path=db)
    assert first["attempted"] == 1
    assert first["sent"] == 1
    assert second["attempted"] == 0


def test_operational_alert_failure_is_audited_and_backed_off(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    _record_collector_degraded_alert(
        {"ecosystem": "pypi", "status": "failed", "coverage": "gap"}, db_path=db
    )
    monkeypatch.setenv("SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS", "email")

    def fail_email(**kwargs):
        raise RuntimeError("smtp unavailable")

    monkeypatch.setattr("secopsai.research_delivery.send_email", fail_email)
    first = deliver_pending_operational_alerts(db_path=db)
    second = deliver_pending_operational_alerts(db_path=db)
    assert first["failed"] == 1
    assert second["deferred"] == 1
    with soc_store.connect(db) as connection:
        delivery = connection.execute(
            "SELECT status, last_error FROM research_notification_deliveries"
        ).fetchone()
    assert delivery["status"] == "failed"
    assert delivery["last_error"] == "smtp unavailable"
