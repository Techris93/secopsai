import hashlib
import hmac
import json
from contextlib import contextmanager

import soc_store

from secopsai.research_delivery import deliver_pending_operational_alerts, deliver_urgent_review_alert, send_email, send_research_alert
from secopsai.research_discovery import create_candidate_alert, sync_actionable_alert_findings
from secopsai import research_discovery
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


def test_similarity_candidate_alert_does_not_create_canonical_finding(tmp_path):
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

    assert alert["finding_id"] is None
    assert soc_store.list_findings(db, source="secopsai_research") == []
    with soc_store.connect(db) as connection:
        row = connection.execute("SELECT severity, status FROM research_alerts WHERE alert_id=?", (alert["alert_id"],)).fetchone()
    assert row["severity"] == "info"
    assert row["status"] == "open"


def test_registry_alert_score_is_not_finding_confidence(tmp_path):
    db = str(tmp_path / "research.db")
    alert = create_candidate_alert({
        "candidate_id": "CAN-STATIC-SCORE",
        "ecosystem": "npm",
        "package": "example-package",
        "version": "1.0.0",
        "score": 97,
        "reason": "Multiple static observations require validation.",
        "evidence": {"source": "npm_registry_proactive_static", "score": 97, "artifact_sha256": "a" * 64},
    }, db_path=db, alert_type="npm_proactive_anomaly")
    finding = soc_store.get_finding(alert["finding_id"], db)
    assert finding is not None
    assert finding["confidence"] == 0
    assert finding["evidence"]["discovery_score"] == {"value": 97.0, "kind": "static_signal_score"}


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


def test_alert_sync_reads_bounded_batches_outside_writer_lock_and_can_scope_ids(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    now = soc_store.utc_now()
    with soc_store.connect(db) as connection:
        for index in range(5):
            connection.execute(
                """INSERT INTO research_alerts
                   (alert_id, alert_type, severity, candidate_id, campaign_id, case_id,
                    dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
                   VALUES (?, 'watched_package_version', 'info', NULL, NULL, NULL,
                           ?, 'Package version changed', ?, 'open', '', ?, ?)""",
                (f"RAL-BATCH-{index}", f"batch-{index}", json.dumps({"package": f"pkg-{index}", "ecosystem": "npm"}), now, now),
            )
        connection.execute(
            """INSERT INTO research_alerts
               (alert_id, alert_type, severity, candidate_id, campaign_id, case_id,
                dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
               VALUES ('RAL-BATCH-HEALTH', 'collector_degraded', 'high', NULL, NULL, NULL,
                       'batch-health', 'Collector is delayed', '{}', 'open', '', ?, ?)""",
            (now, now),
        )

    state = {"writer": False, "reads": 0}

    @contextmanager
    def tracked_writer_lock(db_path=None):
        assert not state["writer"], "alert sync must not nest writer locks"
        state["writer"] = True
        try:
            yield None
        finally:
            state["writer"] = False

    original_read = soc_store.read_connect

    def tracked_read(*args, **kwargs):
        assert not state["writer"], "evidence scans must run outside the writer lock"
        state["reads"] += 1
        return original_read(*args, **kwargs)

    original_upsert = research_discovery._upsert_research_alert_finding

    def tracked_upsert(*args, **kwargs):
        assert state["writer"], "finding writes must remain serialized"
        return original_upsert(*args, **kwargs)

    monkeypatch.setattr(research_discovery, "sqlite_writer_lock", tracked_writer_lock)
    monkeypatch.setattr(soc_store, "read_connect", tracked_read)
    monkeypatch.setattr(research_discovery, "_upsert_research_alert_finding", tracked_upsert)

    result = sync_actionable_alert_findings(db_path=db, batch_size=2)
    assert result["synced"] == 5
    assert result["batches"] == 3
    # A final empty keyset read confirms the cursor has drained the queue.
    assert state["reads"] == 4
    assert state["writer"] is False

    scoped = sync_actionable_alert_findings(db_path=db, alert_ids=["RAL-BATCH-3"], batch_size=1)
    assert scoped["synced"] == 1
    assert scoped["finding_ids"] == [f"RSCF-{hashlib.sha256(b'RAL-BATCH-3').hexdigest()[:16].upper()}"]
    assert scoped["batches"] == 1
    assert state["reads"] == 5


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


def test_urgent_review_alert_uses_only_its_explicit_reviewer_channel(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    now = soc_store.utc_now()
    with soc_store.connect(db) as connection:
        connection.execute(
            """INSERT INTO research_alerts
               (alert_id, alert_type, severity, case_id, dedupe_key, reason, evidence_json,
                status, owner, created_at, updated_at)
               VALUES ('URGENT-1', 'urgent_case_review', 'high', 'RSC-1', 'urgent:1',
                       'Qualified review requires immediate attention', ?, 'open', '', ?, ?)""",
            (json.dumps({"route": "urgent_review", "evidence_ids": ["EVD-1"]}), now, now),
        )
        connection.commit()

    captured = []
    monkeypatch.setenv("SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS", "email")
    monkeypatch.setenv("SECOPSAI_RESEARCH_ALERT_EMAIL", "general@example.test")
    monkeypatch.setenv("SECOPSAI_RESEARCH_URGENT_ALERT_CHANNELS", "email")
    monkeypatch.setenv("SECOPSAI_RESEARCH_URGENT_REVIEWER_EMAIL", "duty@example.test")
    monkeypatch.setattr(
        "secopsai.research_delivery.send_email",
        lambda **kwargs: (captured.append(kwargs) or {"status": "sent", "provider_id": "fixture"}),
    )

    result = deliver_urgent_review_alert("URGENT-1", db_path=db)
    duplicate_attempt = deliver_urgent_review_alert("URGENT-1", db_path=db)

    assert result == {"enabled": True, "channels": ["email"], "attempted": 1, "sent": 1, "failed": 0, "deferred": 0}
    assert duplicate_attempt["deferred"] == 1
    assert [item["recipient"] for item in captured] == ["duty@example.test"]
    with soc_store.connect(db) as connection:
        alert = connection.execute("SELECT status FROM research_alerts WHERE alert_id='URGENT-1'").fetchone()
        delivery_count = connection.execute(
            "SELECT COUNT(*) FROM research_notification_deliveries WHERE alert_id='URGENT-1'"
        ).fetchone()[0]
    assert alert["status"] == "open"
    assert delivery_count == 1


def test_urgent_alert_is_not_sent_through_general_channels_when_urgent_channel_is_unconfigured(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    now = soc_store.utc_now()
    with soc_store.connect(db) as connection:
        connection.execute(
            """INSERT INTO research_alerts
               (alert_id, alert_type, severity, case_id, dedupe_key, reason, evidence_json,
                status, owner, created_at, updated_at)
               VALUES ('URGENT-2', 'urgent_case_review', 'high', 'RSC-2', 'urgent:2',
                       'Qualified review requires immediate attention', '{}', 'open', '', ?, ?)""",
            (now, now),
        )
        connection.commit()
    monkeypatch.setenv("SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS", "email")
    monkeypatch.delenv("SECOPSAI_RESEARCH_URGENT_ALERT_CHANNELS", raising=False)
    monkeypatch.setattr(
        "secopsai.research_delivery.send_email",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("general email must not receive urgent review notices")),
    )

    immediate = deliver_urgent_review_alert("URGENT-2", db_path=db)
    scheduled = deliver_pending_operational_alerts(db_path=db)

    assert immediate["status"] == "not_configured"
    assert scheduled["attempted"] == 0


def test_failed_urgent_notification_is_audited_and_retried_with_backoff(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    now = datetime.now(timezone.utc)
    with soc_store.connect(db) as connection:
        connection.execute(
            """INSERT INTO research_alerts
               (alert_id, alert_type, severity, case_id, dedupe_key, reason, evidence_json,
                status, owner, created_at, updated_at)
               VALUES ('URGENT-3', 'urgent_case_review', 'critical', 'RSC-3', 'urgent:3',
                       'Qualified review requires immediate attention', '{}', 'open', '', ?, ?)""",
            (now.isoformat(), now.isoformat()),
        )
        connection.commit()
    monkeypatch.setenv("SECOPSAI_RESEARCH_URGENT_ALERT_CHANNELS", "email")
    monkeypatch.setenv("SECOPSAI_RESEARCH_URGENT_REVIEWER_EMAIL", "duty@example.test")
    monkeypatch.setattr(
        "secopsai.research_delivery.send_email",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("temporary provider outage")),
    )

    first = deliver_urgent_review_alert("URGENT-3", db_path=db)
    second = deliver_pending_operational_alerts(db_path=db, now=now + timedelta(seconds=10))
    later = deliver_pending_operational_alerts(db_path=db, now=now + timedelta(minutes=2))

    assert first["failed"] == 1
    assert second["deferred"] == 1
    assert later["failed"] == 1
    with soc_store.connect(db) as connection:
        deliveries = connection.execute(
            "SELECT status, last_error FROM research_notification_deliveries WHERE alert_id='URGENT-3' ORDER BY created_at"
        ).fetchall()
        status = connection.execute("SELECT status FROM research_alerts WHERE alert_id='URGENT-3'").fetchone()["status"]
    assert [item["status"] for item in deliveries] == ["failed", "failed"]
    assert all("temporary provider outage" in item["last_error"] for item in deliveries)
    assert status == "open"


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
