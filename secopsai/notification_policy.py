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


def email_paused() -> bool:
    return os.environ.get("SECOPSAI_EMAIL_PAUSED", "").strip().lower() in {"1", "true", "yes", "on"}


def email_now(severity: Any) -> bool:
    """True only for a critical alert while email is not paused."""
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
