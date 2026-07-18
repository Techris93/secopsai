import soc_store

from secopsai.research_delivery import send_research_alert
from secopsai.research_discovery import create_candidate_alert


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
