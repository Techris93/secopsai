"""Daily alert digest with automated first-pass triage.

Every alert that was not emailed immediately (and critical ones, marked as
already sent) is collected from the ledger store for the last 24 hours. Each
package alert is checked without downloading the package:

- ``known_malicious``: ossf/malicious-packages lists that version (the
  install firewall's blocklist), so it is already confirmed and blocked;
- ``removed``: the version is no longer on the registry, which usually means
  the registry took it down;
- ``needs_review``: still published and not listed: these are the ones a
  person should look at, highest severity first.

Alerts that are not about one package (collector problems and the like) are
``operational``. The only automated closure: a Fast Lane alert whose exact
version ossf lists (``MAL-`` advisory) is resolved in Core with that reason.
Everything else stays open for a person, and nothing contacts a registry.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Callable, Dict, Iterable, List, Optional

from secopsai import notification_policy

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}
GROUPS = (
    ("needs_review", "Needs review: still published, not in any public malicious-package list"),
    ("known_malicious", "Already confirmed malicious by ossf/malicious-packages (blocked by the install firewall)"),
    ("removed", "Removed from the registry (usually taken down already)"),
    ("operational", "Operational alerts (collectors, storage, rules)"),
    ("unchecked", "Not checked (registry or blocklist unavailable)"),
)


def _parse(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def window(entries: Iterable[Dict[str, Any]], now: datetime, hours: int = 24) -> List[Dict[str, Any]]:
    """Entries from the last ``hours``, one per alert (the latest write wins)."""
    start = now - timedelta(hours=hours)
    latest: Dict[tuple, Dict[str, Any]] = {}
    for entry in entries:
        when = _parse(entry.get("occurred_at"))
        if when is None or not (start <= when <= now):
            continue
        latest[(entry.get("source"), entry.get("alert_id"))] = entry
    return sorted(latest.values(), key=lambda e: (SEVERITY_ORDER.get(e.get("severity"), 5), e.get("occurred_at", "")))


def triage(entries: List[Dict[str, Any]], *, blocked: Callable[[str, str, str], Optional[List[str]]],
           published: Callable[[str, str, str], Optional[bool]], workers: int = 16) -> List[Dict[str, Any]]:
    """Adds ``group`` (and ``advisories``) to each entry. ``blocked`` returns advisory ids or
    None when unknown; ``published`` returns True/False, or None when the registry did not answer."""
    def one(entry: Dict[str, Any]) -> Dict[str, Any]:
        eco, name, version = entry.get("ecosystem"), entry.get("package"), entry.get("version")
        if eco not in {"npm", "pypi"} or not name or not version:
            return {**entry, "group": "operational"}
        try:
            advisories = blocked(eco, name, version)
            if advisories:
                return {**entry, "group": "known_malicious", "advisories": advisories}
            state = published(eco, name, version)
        except Exception:  # noqa: BLE001 - one failed lookup must not stop the digest
            return {**entry, "group": "unchecked"}
        if state is None or advisories is None:
            return {**entry, "group": "unchecked"}
        return {**entry, "group": "needs_review" if state else "removed"}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(one, entries))


OSSF_ADVISORY = re.compile(r"^MAL-\d{4}-\d{1,7}$")


def resolutions(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Signed-webhook payloads that close Fast Lane alerts ossf already lists."""
    out = []
    for entry in entries:
        advisories = [item for item in entry.get("advisories") or [] if OSSF_ADVISORY.match(str(item))][:5]
        if entry.get("group") == "known_malicious" and entry.get("source") == "fast_lane" and advisories:
            out.append({"schema_version": "secopsai.research.alert-resolution.v1", "source_alert_id": entry["alert_id"],
                        "resolution": "listed_by_ossf", "ecosystem": entry["ecosystem"], "package": entry["package"],
                        "version": entry["version"], "advisories": advisories})
    return out


def render(entries: List[Dict[str, Any]], now: datetime, *, paused: bool = False) -> Dict[str, str]:
    counts = {key: sum(1 for e in entries if e.get("group") == key) for key, _ in GROUPS}
    review = counts["needs_review"]
    subject = (f"SecOpsAI daily digest: {review} to review, {len(entries)} alert{'s' if len(entries) != 1 else ''}"
               f" ({now:%d %b})")
    lines = [f"Alerts from the 24 hours to {now:%Y-%m-%d %H:%M} UTC: {len(entries)}.",
             "Critical alerts were emailed when they happened and are marked [sent].", "",
             f"Open the inbox to work them: {notification_policy.DASHBOARD_INBOX}", ""]
    for key, title in GROUPS:
        items = [e for e in entries if e.get("group") == key]
        if not items:
            continue
        lines += [f"{title}: {len(items)}", ""]
        for e in items[:150]:
            subject_line = f"{e['package']}@{e['version']} ({e['ecosystem']})" if e.get("package") else e.get("title", "alert")
            extra = f" [{', '.join(e['advisories'][:2])}]" if e.get("advisories") else ""
            sent = (" [sent]" if e.get("emailed") else "") + (" [closed automatically]" if e.get("auto_resolved") else "")
            reason = (e.get("reason") or "").replace("\n", " ")
            lines.append(f"- {str(e.get('severity', '')).upper()} {subject_line}{extra}{sent}: {reason[:160]}")
            lines.append(f"  id {e.get('dashboard_id') or e.get('alert_id')}")
        if len(items) > 150:
            lines.append(f"- and {len(items) - 150} more in the dashboard")
        lines.append("")
    if not entries:
        lines.append("No alerts in this period.")
    if paused:
        lines = ["(Email is paused; this digest was not sent.)", ""] + lines
    return {"subject": subject, "body": "\n".join(lines)}
