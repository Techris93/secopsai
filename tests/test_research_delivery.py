import hashlib
import hmac
import json

import soc_store

from secopsai.research_delivery import deliver_pending_operational_alerts, send_email, send_research_alert
from secopsai.research_discovery import create_candidate_alert, resolve_alert, sync_actionable_alert_findings
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


def test_candidate_alert_enters_canonical_agent_triage_without_local_dependency(tmp_path):
    db = str(tmp_path / "research.db")
    alert = create_candidate_alert({
        "candidate_id": "CAN-GLOBAL-TEST",
        "ecosystem": "nuget",
        "package": "Brand.Security.Update",
        "version": "1.2.3",
        "score": 92,
        "reason": "Package identity is highly similar to a protected brand.",
        "evidence": {"metadata_url": "https://api.nuget.org/v3/registration5-semver1/brand.security.update/index.json"},
        "last_seen": "2026-07-18T00:00:00Z",
    }, db_path=db)

    finding = soc_store.get_finding(alert["finding_id"], db)
    assert finding is not None
    assert finding["source"] == "secopsai_research"
    assert finding["platform"] == "supply_chain"
    assert finding["package"] == "Brand.Security.Update"
    assert finding["local_dependency_reference"] == "not_required_for_package_verification"
    assert finding["status"] == "open"

    resolved = resolve_alert(alert["alert_id"], db_path=db)
    assert resolved["finding_id"] == alert["finding_id"]
    finding = soc_store.get_finding(alert["finding_id"], db)
    assert finding["status"] == "triaged"
    assert finding["disposition"] == "needs_review"


def test_historical_research_alerts_are_backfilled_but_collector_health_is_not(tmp_path):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    now = soc_store.utc_now()
    with soc_store.connect(db) as connection:
        connection.execute(
            """INSERT INTO research_alerts
               (alert_id, alert_type, severity, candidate_id, campaign_id, case_id,
                dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
               VALUES ('RAL-HISTORICAL', 'watched_package_version', 'info', NULL, NULL, NULL,
                       'historical-package-change', 'Watched package changed version', ?, 'open', '', ?, ?)""",
            (json.dumps({"ecosystem": "pypi", "package": "example", "version": "2.0.0"}), now, now),
        )
        connection.execute(
            """INSERT INTO research_alerts
               (alert_id, alert_type, severity, candidate_id, campaign_id, case_id,
                dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
               VALUES ('RAL-HEALTH', 'collector_degraded', 'high', NULL, NULL, NULL,
                       'historical-health', 'Collector timed out', '{}', 'open', '', ?, ?)""",
            (now, now),
        )
        connection.commit()

    first = sync_actionable_alert_findings(db_path=db)
    second = sync_actionable_alert_findings(db_path=db)

    assert first["synced"] == 1
    assert second["finding_ids"] == first["finding_ids"]
    finding = soc_store.get_finding(first["finding_ids"][0], db)
    assert finding["source"] == "secopsai_research"
    assert finding["package"] == "example"
    assert finding["status"] == "open"
    with soc_store.connect(db) as connection:
        health_count = connection.execute(
            "SELECT COUNT(*) AS count FROM findings WHERE payload_json LIKE '%RAL-HEALTH%'"
        ).fetchone()["count"]
    assert health_count == 0


def test_email_uses_branded_multipart_content_and_safe_sender(monkeypatch):
    captured = {}

    class SMTP:
        def __init__(self, host, port, context, timeout):
            captured.update({"host": host, "port": port, "timeout": timeout})

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def login(self, username, password):
            captured.update({"username": username, "password": password})

        def send_message(self, message):
            captured["message"] = message

    monkeypatch.setenv("SECOPSAI_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SECOPSAI_SMTP_PORT", "465")
    monkeypatch.setenv("SECOPSAI_SMTP_USERNAME", "mailer")
    monkeypatch.setenv("SECOPSAI_SMTP_PASSWORD", "secret-value")
    monkeypatch.setattr("secopsai.research_delivery.smtplib.SMTP_SSL", SMTP)

    result = send_email(
        recipient="analyst@example.test",
        subject="Research alert",
        body="Review <script>alert('unsafe')</script>",
        sender="research@secopsai.dev",
    )

    assert result["status"] == "sent"
    message = captured["message"]
    assert message["From"] == "SecOpsAI Research <research@secopsai.dev>"
    assert message["Date"]
    assert message["Message-ID"].endswith("@secopsai.dev>")
    assert message.get_content_type() == "multipart/alternative"
    plain, branded = list(message.iter_parts())
    assert plain.get_content_type() == "text/plain"
    assert "<script>" in plain.get_content()
    assert branded.get_content_type() == "text/html"
    html_body = branded.get_content()
    assert "https://secopsai.dev/assets/favicon-512.png" in html_body
    assert 'alt="SecOpsAI"' in html_body
    assert "&lt;script&gt;" in html_body
    assert "<script>" not in html_body


def test_email_uses_security_display_name_for_disclosures(monkeypatch):
    captured = {}

    class SMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def login(self, username, password):
            pass

        def send_message(self, message):
            captured["from"] = message["From"]

    monkeypatch.setenv("SECOPSAI_SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr("secopsai.research_delivery.smtplib.SMTP_SSL", SMTP)
    send_email(
        recipient="vendor@example.test",
        subject="Coordinated disclosure",
        body="Defensive notification",
        sender="security@secopsai.dev",
    )
    assert captured["from"] == "SecOpsAI Security <security@secopsai.dev>"


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


def test_external_campaign_alerts_use_webhook_channel_without_email_flood(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    alert = create_candidate_alert(
        {
            "candidate_id": "CAN-EXT-DELIVERY",
            "ecosystem": "npm",
            "package": "keyv",
            "version": "6.0.0",
            "campaign_id": "keyv-cacheable-npm-worm-2026-08",
            "score": 99,
            "reason": "Source-backed campaign lead",
            "evidence": {"ecosystem": "npm", "package": "keyv", "version": "6.0.0"},
        },
        alert_type="external_advisory_match",
        severity_override="critical",
        dedupe_key="external-advisory:test:keyv:6.0.0:hash",
        db_path=db,
    )
    captured = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    monkeypatch.setenv("SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS", "email,webhook")
    monkeypatch.setenv("SECOPSAI_RESEARCH_EXTERNAL_ALERT_CHANNELS", "webhook")
    monkeypatch.setenv("SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL", "https://core.example.test/api/v1/research/alerts/webhook")
    monkeypatch.setenv("SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET", "a" * 48)
    monkeypatch.setattr("secopsai.research_delivery.urllib.request.urlopen", lambda request, timeout: (captured.append(request), Response())[1])
    monkeypatch.setattr("secopsai.research_delivery.send_email", lambda **kwargs: (_ for _ in ()).throw(AssertionError("external alerts must not email")))

    result = deliver_pending_operational_alerts(db_path=db)
    assert result["attempted"] == 1
    assert result["sent"] == 1
    assert len(captured) == 1


def test_signed_webhook_uses_timestamped_hmac_and_normalized_evidence(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    alert_id = _record_collector_degraded_alert(
        {"ecosystem": "nuget", "status": "failed", "coverage": "gap"}, db_path=db
    )
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    def fake_urlopen(request, timeout):
        captured["request"] = request
        return Response()

    monkeypatch.setenv("SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL", "https://core.example.test/api/v1/research/alerts/webhook")
    monkeypatch.setenv("SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET", "a" * 48)
    monkeypatch.setattr("secopsai.research_delivery.urllib.request.urlopen", fake_urlopen)
    result = send_research_alert(alert_id, channel="webhook", db_path=db)
    assert result["ok"] is True
    request = captured["request"]
    timestamp = request.headers["X-secopsai-timestamp"]
    supplied = request.headers["X-secopsai-signature"].split("=", 1)[1]
    expected = hmac.new(
        ("a" * 48).encode(), timestamp.encode() + b"." + request.data, hashlib.sha256
    ).hexdigest()
    assert hmac.compare_digest(supplied, expected)
    payload = json.loads(request.data)
    assert isinstance(payload["evidence"], dict)
    assert payload["alert_type"] == "collector_degraded"
