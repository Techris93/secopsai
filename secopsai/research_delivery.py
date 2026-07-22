"""Approval-gated disclosure and alert delivery providers."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import smtplib
import ssl
import urllib.request
import secrets
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Dict, List


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _record_delivery(disclosure_id: str, *, channel: str, destination: str, status: str, attempts: int, provider_id: str = "", last_error: str = "", db_path: str | None = None) -> Dict[str, Any]:
    import soc_store
    soc_store.init_db(db_path)
    delivery_id = f"DLV-{secrets.token_hex(8).upper()}"
    now = _now()
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO research_disclosure_deliveries (delivery_id, disclosure_id, channel, destination, status, attempts, provider_id, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (delivery_id, disclosure_id, channel, destination[:320], status, max(0, int(attempts)), provider_id[:240], last_error[:2000], now, now),
        )
        connection.commit()
    return {"delivery_id": delivery_id, "disclosure_id": disclosure_id, "channel": channel, "status": status, "attempts": attempts, "provider_id": provider_id}


def _record_alert_delivery(alert_id: str, *, channel: str, destination: str, status: str, attempts: int, provider_id: str = "", last_error: str = "", db_path: str | None = None) -> Dict[str, Any]:
    import soc_store
    soc_store.init_db(db_path)
    delivery_id = f"ADL-{secrets.token_hex(8).upper()}"
    now = _now()
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO research_notification_deliveries (delivery_id, alert_id, channel, destination, status, attempts, provider_id, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (delivery_id, alert_id, channel, destination[:320], status, max(0, int(attempts)), provider_id[:240], last_error[:2000], now, now),
        )
        connection.commit()
    return {"delivery_id": delivery_id, "alert_id": alert_id, "channel": channel, "status": status, "attempts": attempts, "provider_id": provider_id}


def _redact(text: str) -> str:
    value = str(text or "")
    value = value.replace("Authorization:", "Authorization: [REDACTED]")
    return value[:30000]


def send_email(*, recipient: str, subject: str, body: str, sender: str = "research@secopsai.dev") -> Dict[str, Any]:
    host = os.environ.get("SECOPSAI_SMTP_HOST", "")
    if not host:
        raise RuntimeError("SECOPSAI_SMTP_HOST is not configured")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject[:240]
    message.set_content(_redact(body))
    port = int(os.environ.get("SECOPSAI_SMTP_PORT", "465"))
    username = os.environ.get("SECOPSAI_SMTP_USERNAME", "")
    password = os.environ.get("SECOPSAI_SMTP_PASSWORD", "")
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as client:
        if username:
            client.login(username, password)
        client.send_message(message)
    return {"channel": "email", "recipient": recipient, "sender": sender, "status": "sent"}


def send_signed_webhook(*, endpoint: str, secret: str, event: Dict[str, Any]) -> Dict[str, Any]:
    if not endpoint.startswith("https://"):
        raise ValueError("webhook endpoint must use HTTPS")
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    request = urllib.request.Request(endpoint, data=payload, method="POST", headers={"Content-Type": "application/json", "X-SecOpsAI-Signature": f"sha256={signature}", "X-SecOpsAI-Schema": str(event.get("schema_version") or "secopsai.research.alert.v1")})
    with urllib.request.urlopen(request, timeout=20) as response:
        status = int(response.status)
    if status < 200 or status >= 300:
        raise RuntimeError(f"webhook returned HTTP {status}")
    return {"channel": "webhook", "endpoint": endpoint, "status": "sent", "signature": f"sha256={signature}"}


def send_approved_disclosure(disclosure_id: str, *, channel: str = "email", db_path: str | None = None) -> Dict[str, Any]:
    """Deliver a disclosure only after the existing workflow marks it approved."""
    from secopsai.research_workflow import get_disclosure, set_disclosure_status

    disclosure = get_disclosure(disclosure_id, db_path=db_path)
    if disclosure["status"] != "approved":
        raise RuntimeError("disclosure must be approved before delivery")
    destination = disclosure["recipient"]
    try:
        if channel == "email":
            sender = os.environ.get("SECOPSAI_DISCLOSURE_FROM_EMAIL", "security@secopsai.dev")
            result = send_email(recipient=destination, subject=disclosure["subject"], body=disclosure["body"], sender=sender)
        elif channel == "webhook":
            endpoint = os.environ.get("SECOPSAI_DISCLOSURE_WEBHOOK_URL", "")
            secret = os.environ.get("SECOPSAI_DISCLOSURE_WEBHOOK_SECRET", "")
            if not endpoint or not secret:
                raise RuntimeError("disclosure webhook configuration is incomplete")
            destination = endpoint
            result = send_signed_webhook(endpoint=endpoint, secret=secret, event={"schema_version": "secopsai.research.disclosure-delivery.v1", "disclosure_id": disclosure_id, "recipient": disclosure["recipient"], "subject": disclosure["subject"], "body": _redact(disclosure["body"])})
        else:
            raise ValueError("unsupported disclosure channel")
    except Exception as exc:
        delivery = _record_delivery(disclosure_id, channel=channel, destination=destination, status="failed", attempts=1, last_error=str(exc), db_path=db_path)
        return {"ok": False, "delivery": delivery, "error": "disclosure delivery failed"}
    delivery = _record_delivery(disclosure_id, channel=channel, destination=destination, status="sent", attempts=1, provider_id=str(result.get("provider_id") or ""), db_path=db_path)
    updated = set_disclosure_status(disclosure_id, "sent", actor="disclosure-worker", db_path=db_path)
    return {"ok": True, "delivery": {**result, **delivery}, "disclosure": updated}


def send_research_alert(alert_id: str, *, channel: str = "email", db_path: str | None = None) -> Dict[str, Any]:
    """Deliver one normalized discovery alert and retain a delivery audit row."""
    import soc_store
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        row = connection.execute("SELECT * FROM research_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if row is None:
        raise ValueError("research alert not found")
    alert = dict(row)
    destination = os.environ.get("SECOPSAI_RESEARCH_ALERT_EMAIL", "research@secopsai.dev")
    attempts = 1
    try:
        event = {
            "schema_version": "secopsai.research.alert.v1",
            "alert_id": alert_id,
            "alert_type": alert.get("alert_type"),
            "severity": alert.get("severity"),
            "candidate_id": alert.get("candidate_id"),
            "campaign_id": alert.get("campaign_id"),
            "reason": _redact(alert.get("reason", "")),
            "evidence": _redact(alert.get("evidence_json", "")),
        }
        if channel == "email":
            sender = os.environ.get("SECOPSAI_RESEARCH_FROM_EMAIL", "research@secopsai.dev")
            result = send_email(recipient=destination, subject=f"SecOpsAI research alert: {alert.get('severity', 'review')}", body=json.dumps(event, indent=2), sender=sender)
        elif channel == "webhook":
            endpoint = os.environ.get("SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL", "")
            secret = os.environ.get("SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET", "")
            if not endpoint or not secret:
                raise RuntimeError("research alert webhook configuration is incomplete")
            destination = endpoint
            result = send_signed_webhook(endpoint=endpoint, secret=secret, event=event)
        else:
            raise ValueError("unsupported alert channel")
    except Exception as exc:
        delivery = _record_alert_delivery(alert_id, channel=channel, destination=destination, status="failed", attempts=attempts, last_error=str(exc), db_path=db_path)
        return {"ok": False, "delivery": delivery, "error": "research alert delivery failed"}
    delivery = _record_alert_delivery(alert_id, channel=channel, destination=destination, status="sent", attempts=attempts, provider_id=str(result.get("provider_id") or ""), db_path=db_path)
    return {"ok": True, "delivery": {**result, **delivery}, "alert": alert}


def configured_auto_alert_channels() -> List[str]:
    """Return explicitly enabled automatic channels.

    An empty setting is intentionally disabled. Candidate and campaign alerts
    remain manual even when operational coverage alerts are enabled.
    """
    raw = os.environ.get("SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS", "")
    channels = []
    for item in raw.split(","):
        channel = item.strip().lower()
        if channel in {"email", "webhook"} and channel not in channels:
            channels.append(channel)
    return channels


def deliver_pending_operational_alerts(*, db_path: str | None = None, now: datetime | None = None) -> Dict[str, Any]:
    """Deliver undelivered collector-health alerts with bounded backoff."""
    import soc_store

    channels = configured_auto_alert_channels()
    if not channels:
        return {"enabled": False, "channels": [], "attempted": 0, "sent": 0, "failed": 0, "deferred": 0}

    allowed_types = {"collector_degraded", "collector_retention_risk"}
    max_attempts = max(1, min(int(os.environ.get("SECOPSAI_RESEARCH_ALERT_MAX_ATTEMPTS", "5")), 10))
    current = now or datetime.now(timezone.utc)
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        alerts = connection.execute(
            "SELECT * FROM research_alerts WHERE status = 'open' ORDER BY created_at LIMIT 100"
        ).fetchall()

    summary = {"enabled": True, "channels": channels, "attempted": 0, "sent": 0, "failed": 0, "deferred": 0}
    for row in alerts:
        alert = dict(row)
        if alert.get("alert_type") not in allowed_types:
            continue
        for channel in channels:
            with soc_store.connect(db_path) as connection:
                deliveries = connection.execute(
                    """SELECT status, created_at FROM research_notification_deliveries
                    WHERE alert_id = ? AND channel = ? ORDER BY created_at DESC""",
                    (alert["alert_id"], channel),
                ).fetchall()
            if any(item["status"] == "sent" for item in deliveries):
                continue
            failures = sum(1 for item in deliveries if item["status"] == "failed")
            if failures >= max_attempts:
                summary["deferred"] += 1
                continue
            if deliveries:
                latest_text = str(deliveries[0]["created_at"] or "").replace("Z", "+00:00")
                try:
                    latest = datetime.fromisoformat(latest_text)
                    if latest.tzinfo is None:
                        latest = latest.replace(tzinfo=timezone.utc)
                    delay = min(3600, 60 * (2 ** max(0, failures - 1)))
                    if (current - latest).total_seconds() < delay:
                        summary["deferred"] += 1
                        continue
                except ValueError:
                    pass
            summary["attempted"] += 1
            result = send_research_alert(alert["alert_id"], channel=channel, db_path=db_path)
            if result.get("ok"):
                summary["sent"] += 1
            else:
                summary["failed"] += 1
    return summary
