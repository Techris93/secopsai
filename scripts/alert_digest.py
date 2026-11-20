#!/usr/bin/env python3
"""Build and send the daily alert digest (see secopsai/alert_digest.py)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai import alert_digest, blocklist, notification_policy  # noqa: E402

STORE = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")


def _get(url: str, *, token: str = "", accept: str = "application/json", timeout: int = 30):
    headers = {"Accept": accept, "User-Agent": "secopsai-alert-digest"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed https hosts
        return json.loads(response.read())


def _digest_page(url: str, token: str) -> dict:
    """One page of a day; allow for a slow read and one retry."""
    for attempt in range(2):
        try:
            return _get(url, token=token, timeout=120)
        except (TimeoutError, OSError):
            if attempt:
                raise
            time.sleep(10)
    return {}


def _digest_day(day: str, token: str) -> dict:
    """A busy day is thousands of entries, served a page at a time (follow ``cursor``)."""
    entries: list = []
    cursor = ""
    for _ in range(400):  # 100,000 entries at 250 a page
        query = "?cursor=" + urllib.parse.quote(cursor, safe="") if cursor else ""
        page = _digest_page(f"{STORE}/digest/{day}{query}", token)
        entries += page.get("entries") or []
        cursor = page.get("cursor") or ""
        if not cursor:
            break
    return {"entries": entries}


def _last_digest() -> Optional[datetime]:
    """When the last digest run that completed on main started (None when unknown).

    The next digest starts there, so a failed or late run leaves no gap."""
    repo, gh_token = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_TOKEN", "")
    if not repo or not gh_token:
        return None
    url = (f"https://api.github.com/repos/{repo}/actions/workflows/alert-digest.yml/runs"
           "?status=success&branch=main&per_page=1")
    try:
        runs = _get(url, token=gh_token, accept="application/vnd.github+json").get("workflow_runs") or []
        stamp = runs[0].get("run_started_at") or runs[0].get("created_at") if runs else None
        return datetime.fromisoformat(str(stamp).replace("Z", "+00:00")) if stamp else None
    except (OSError, ValueError, AttributeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, default=Path("reports/alert-digest.json"))
    args = parser.parse_args()
    token = os.environ["LEDGER_STORE_TOKEN"]
    now = datetime.now(timezone.utc)
    start = alert_digest.window_start(now, _last_digest())
    raw = []
    for day in alert_digest.days(start, now):
        raw += _digest_day(day, token).get("entries") or []
    entries = alert_digest.window(raw, now, start=start)

    shards: dict = {}

    def blocked(eco: str, name: str, version: str) -> Optional[List[str]]:
        key = f"{eco}/{blocklist.shard_of(eco, name)}"
        if key not in shards:
            try:
                shards[key] = _get(f"{STORE}/firewall/{key}", token=token)
            except urllib.error.HTTPError as exc:
                shards[key] = {} if exc.code == 404 else None
            except (OSError, ValueError):
                shards[key] = None
        if shards[key] is None:
            return None
        entry = shards[key].get(blocklist.normalize(eco, name))
        return (entry.get("ids") or ["listed"]) if entry and (entry.get("all") or version in (entry.get("versions") or [])) else []

    def published(eco: str, name: str, version: str) -> Optional[bool]:
        try:
            if eco == "npm":
                doc = _get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"),
                           accept="application/vnd.npm.install-v1+json")
                return version in (doc.get("versions") or {})
            _get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
            return True
        except urllib.error.HTTPError as exc:
            return False if exc.code == 404 else None
        except (OSError, ValueError):
            return None

    triaged = alert_digest.triage(entries, blocked=blocked, published=published)
    # The one automated closure: Fast Lane alerts whose exact version ossf lists.
    endpoint = os.environ.get("SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL", "")
    secret = os.environ.get("SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET", "")
    closed = set()
    if endpoint and secret:
        from secopsai.research_delivery import send_signed_webhook

        for payload in alert_digest.resolutions(triaged):
            try:
                send_signed_webhook(endpoint=endpoint, secret=secret, event=payload)
                closed.add(payload["source_alert_id"])
            except Exception as exc:  # noqa: BLE001 - stays open for a person
                print(f"could not close {payload['source_alert_id']}: {type(exc).__name__}", file=sys.stderr)
    triaged = [{**entry, "auto_resolved": entry.get("alert_id") in closed} for entry in triaged]
    paused = notification_policy.email_paused()
    message = alert_digest.render(triaged, now, paused=paused, start=start)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"generated_at": now.isoformat(), "window_start": start.isoformat(), "paused": paused, "entries": triaged, **message}, indent=1), encoding="utf-8")
    status = "paused"
    recipient = os.environ.get("SECOPSAI_RESEARCH_ALERT_EMAIL", "")
    if not paused and recipient and os.environ.get("SECOPSAI_SMTP_PASSWORD"):
        from secopsai.research_delivery import send_email

        send_email(recipient=recipient, subject=message["subject"], body=message["body"])
        status = "sent"
    elif not paused:
        status = "not configured"
    text = f"### Alert digest ({status})\n\n**{message['subject']}**\n\n```\n{message['body'][:60000]}\n```\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
