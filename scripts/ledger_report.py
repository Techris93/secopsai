#!/usr/bin/env python3
"""Read-only summary of the production research ledger (triage, retriage, labels, campaigns, alerts)."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cloudflare" / "secopsai-research-runner" / "container"))


def query(connection: sqlite3.Connection, sql: str) -> list:
    try:
        return [tuple(row) for row in connection.execute(sql).fetchall()]
    except sqlite3.Error as exc:
        return [("unavailable", str(exc)[:80])]


def main() -> int:
    from supervisor import LedgerStore

    db = Path(tempfile.mkdtemp(prefix="ledger-report-")) / "ledger.db"
    if not LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"]).download(db):
        raise SystemExit("no ledger snapshot")
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    sections = {
        "AI triage by status/verdict": "SELECT status, verdict, COUNT(*) FROM research_ai_triage GROUP BY 1, 2 ORDER BY 3 DESC",
        "AI triage by score band": "SELECT CASE WHEN score >= 80 THEN '80+' WHEN score >= 60 THEN '60-79' ELSE '<60' END, status, COUNT(*) FROM research_ai_triage GROUP BY 1, 2 ORDER BY 1, 3 DESC",
        "Retriage progress": "SELECT json_extract(context_json, '$.rescan'), COUNT(*) FROM research_ai_triage WHERE json_extract(context_json, '$.rescanned_at') IS NOT NULL GROUP BY 1",
        "Rule training labels": "SELECT source, label, COUNT(*) FROM rule_training_labels GROUP BY 1, 2",
        "Campaigns (largest)": "SELECT campaign_id, json_array_length(members_json), first_seen, last_seen FROM actor_campaigns ORDER BY 2 DESC LIMIT 10",
        "Open alerts by type": "SELECT alert_type, severity, COUNT(*) FROM research_alerts WHERE status = 'open' GROUP BY 1, 2 ORDER BY 3 DESC",
        "Content funnel (last 24 h)": "SELECT ecosystem, json_extract(metadata_json, '$.content_prescan.status'), COUNT(*) FROM registry_feed_events WHERE json_extract(metadata_json, '$.content_prescan.at') >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day') GROUP BY 1, 2",
    }
    lines = ["## Ledger report", ""]
    for title, sql in sections.items():
        lines += [f"### {title}", "", "```"] + [" | ".join(str(value) for value in row) for row in query(connection, sql)] + ["```", ""]
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
