"""Who gets an email, and when.

Only critical alerts are emailed as they happen. Everything else becomes an
entry in a daily digest (``scripts/alert_digest.py``) that links to the
dashboard. ``SECOPSAI_EMAIL_PAUSED`` (the repository variable of the same
name) stops every notification email, the immediate ones and the digest;
alerts keep reaching Core and the dashboard, and digest entries are still
recorded, so nothing is lost while paused. Approved disclosures to package
registries are not notifications and are not affected.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Optional

IMMEDIATE_SEVERITIES = {"critical"}
DASHBOARD_INBOX = "https://dashboard.secopsai.dev/#research/inbox"
DASHBOARD_REVIEW = "https://dashboard.secopsai.dev/#research/review"


def email_paused() -> bool:
    return os.environ.get("SECOPSAI_EMAIL_PAUSED", "").strip().lower() in {"1", "true", "yes", "on"}


# Urgent findings: the strongest machine signals, emailed at once so a person
# can review and publish within minutes. They have their own switch because
# they are rare (0-2 a day, 2026-11-10..17) while ordinary alerts are many:
# SECOPSAI_URGENT_FINDING_EMAIL=1 sends them even while SECOPSAI_EMAIL_PAUSED
# holds every other email. Nothing here publishes; review stays human.
URGENT_MIN_MALICIOUS_PROBABILITY = 90


def urgent_email_enabled() -> bool:
    return os.environ.get("SECOPSAI_URGENT_FINDING_EMAIL", "").strip().lower() in {"1", "true", "yes", "on"}


def urgent_fast_lane(severity: Any) -> bool:
    """A Fast Lane verdict worth an immediate email: critical only (high was
    38-52 a day after 2026-11-15, too many to page on)."""
    return str(severity or "").strip().lower() == "critical"


def urgent_verdict(result: Dict[str, Any]) -> bool:
    """A model triage verdict worth an immediate email."""
    try:
        probability = int(result.get("malicious_probability") or 0)
    except (TypeError, ValueError):
        return False
    return result.get("finding_verdict") == "true_positive" and probability >= URGENT_MIN_MALICIOUS_PROBABILITY


def email_now(severity: Any, *, urgent: bool = False) -> bool:
    """True for a critical alert while email is not paused, and for an urgent
    finding whenever urgent email is switched on."""
    if urgent and urgent_email_enabled():
        return True
    return str(severity or "").strip().lower() in IMMEDIATE_SEVERITIES and not email_paused()


def core_alert_id(source_alert_id: str) -> str:
    """The id Core and the dashboard show for an alert delivered by webhook."""
    return "RAL-WEB-" + hashlib.sha256(str(source_alert_id).encode("utf-8")).hexdigest()[:24].upper()


def digest_entry(*, source: str, alert_id: str, severity: Any, title: str, reason: str = "", occurred_at: str = "",
                 ecosystem: str = "", package: str = "", version: str = "", emailed: bool = False,
                 dashboard_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "source": source, "alert_id": str(alert_id), "dashboard_id": dashboard_id or "",
        "severity": str(severity or "unknown").lower(), "title": str(title)[:200], "reason": str(reason)[:600],
        "occurred_at": str(occurred_at), "ecosystem": ecosystem, "package": package, "version": version,
        "emailed": bool(emailed),
    }
