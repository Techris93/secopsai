"""
Local findings store for OpenClaw and future SOC workflows.

This module provides a minimal SQLite-backed persistence layer for findings,
event mappings, and analyst notes while preserving analyst state across
regeneration runs.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, UTC
from typing import Any, Dict, Iterable, List


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(ROOT_DIR, "data", "openclaw", "findings", "openclaw_soc.db")


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def connect(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    with closing(connect(db_path)) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity TEXT NOT NULL,
                severity_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                disposition TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS finding_events (
                finding_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (finding_id, event_id),
                FOREIGN KEY (finding_id) REFERENCES findings (finding_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                author TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings (finding_id) ON DELETE CASCADE
            );
            """
        )


def _existing_state(connection: sqlite3.Connection, finding_id: str) -> Dict[str, str] | None:
    row = connection.execute(
        "SELECT status, disposition, created_at FROM findings WHERE finding_id = ?",
        (finding_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "status": str(row["status"]),
        "disposition": str(row["disposition"]),
        "created_at": str(row["created_at"]),
    }


def upsert_finding(connection: sqlite3.Connection, finding: Dict[str, Any], source: str) -> None:
    existing = _existing_state(connection, finding["finding_id"])
    now = utc_now()
    status = existing["status"] if existing else str(finding.get("status", "open"))
    disposition = existing["disposition"] if existing else str(finding.get("disposition", "unreviewed"))
    created_at = existing["created_at"] if existing else str(finding.get("created_at", now))

    persisted = dict(finding)
    persisted["status"] = status
    persisted["disposition"] = disposition

    connection.execute(
        """
        INSERT INTO findings (
            finding_id, title, summary, severity, severity_score, status,
            disposition, source, first_seen, last_seen, created_at,
            updated_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_id) DO UPDATE SET
            title = excluded.title,
            summary = excluded.summary,
            severity = excluded.severity,
            severity_score = excluded.severity_score,
            source = excluded.source,
            first_seen = excluded.first_seen,
            last_seen = excluded.last_seen,
            updated_at = excluded.updated_at,
            payload_json = excluded.payload_json
        """,
        (
            persisted["finding_id"],
            persisted["title"],
            persisted["summary"],
            persisted["severity"],
            int(persisted["severity_score"]),
            status,
            disposition,
            source,
            persisted["first_seen"],
            persisted["last_seen"],
            created_at,
            now,
            json.dumps(persisted, sort_keys=True),
        ),
    )

    connection.execute("DELETE FROM finding_events WHERE finding_id = ?", (persisted["finding_id"],))
    connection.executemany(
        "INSERT INTO finding_events (finding_id, event_id) VALUES (?, ?)",
        [(persisted["finding_id"], event_id) for event_id in persisted.get("event_ids", [])],
    )


def persist_findings(findings: Iterable[Dict[str, Any]], source: str, db_path: str = DEFAULT_DB_PATH) -> str:
    init_db(db_path)
    findings = list(findings)
    current_ids = {finding["finding_id"] for finding in findings}
    with closing(connect(db_path)) as connection:
        for finding in findings:
            upsert_finding(connection, finding, source)

        stale_rows = connection.execute(
            "SELECT finding_id FROM findings WHERE source = ?",
            (source,),
        ).fetchall()
        stale_ids = [str(row["finding_id"]) for row in stale_rows if str(row["finding_id"]) not in current_ids]
        for finding_id in stale_ids:
            connection.execute("DELETE FROM findings WHERE finding_id = ?", (finding_id,))

        connection.commit()
    return db_path


def set_finding_status(finding_id: str, status: str, db_path: str = DEFAULT_DB_PATH) -> None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        connection.execute(
            "UPDATE findings SET status = ?, updated_at = ? WHERE finding_id = ?",
            (status, utc_now(), finding_id),
        )
        connection.commit()


def set_finding_disposition(finding_id: str, disposition: str, db_path: str = DEFAULT_DB_PATH) -> None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        connection.execute(
            "UPDATE findings SET disposition = ?, updated_at = ? WHERE finding_id = ?",
            (disposition, utc_now(), finding_id),
        )
        connection.commit()


def add_note(finding_id: str, author: str, note: str, db_path: str = DEFAULT_DB_PATH) -> None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        connection.execute(
            "INSERT INTO notes (finding_id, author, note, created_at) VALUES (?, ?, ?, ?)",
            (finding_id, author, note, utc_now()),
        )
        connection.commit()


def list_findings(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT finding_id, title, severity, severity_score, status, disposition, first_seen, last_seen FROM findings ORDER BY severity_score DESC, first_seen ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_finding(finding_id: str, db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any] | None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT payload_json, status, disposition FROM findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        if row is None:
            return None

        finding = json.loads(str(row["payload_json"]))
        finding["status"] = str(row["status"])
        finding["disposition"] = str(row["disposition"])
        notes = connection.execute(
            "SELECT author, note, created_at FROM notes WHERE finding_id = ? ORDER BY note_id ASC",
            (finding_id,),
        ).fetchall()
        finding["notes"] = [dict(note) for note in notes]
        return finding


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local SOC findings store CLI")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH, help="SQLite database path")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List stored findings")

    show_parser = subparsers.add_parser("show", help="Show one finding with notes")
    show_parser.add_argument("finding_id", help="Finding identifier")

    disposition_parser = subparsers.add_parser("set-disposition", help="Update finding disposition")
    disposition_parser.add_argument("finding_id", help="Finding identifier")
    disposition_parser.add_argument("disposition", help="New disposition value")

    status_parser = subparsers.add_parser("set-status", help="Update finding status")
    status_parser.add_argument("finding_id", help="Finding identifier")
    status_parser.add_argument("status", help="New status value")

    note_parser = subparsers.add_parser("add-note", help="Attach a note to a finding")
    note_parser.add_argument("finding_id", help="Finding identifier")
    note_parser.add_argument("author", help="Note author")
    note_parser.add_argument("note", help="Note text")

    return parser.parse_args()


def format_finding_row(finding: Dict[str, Any]) -> str:
    return (
        f"{finding['finding_id']} | {finding['severity'].upper():8s} | "
        f"status={finding['status']} | disposition={finding['disposition']} | {finding['title']}"
    )


def main() -> int:
    args = parse_args()

    if args.command == "list":
        findings = list_findings(args.db_path)
        for finding in findings:
            print(format_finding_row(finding))
        print(f"total_findings={len(findings)}")
        return 0

    if args.command == "show":
        finding = get_finding(args.finding_id, args.db_path)
        if finding is None:
            print(f"error: finding not found: {args.finding_id}")
            return 1
        print(json.dumps(finding, indent=2))
        return 0

    if args.command == "set-disposition":
        set_finding_disposition(args.finding_id, args.disposition, args.db_path)
        print(f"updated_disposition={args.disposition}")
        return 0

    if args.command == "set-status":
        set_finding_status(args.finding_id, args.status, args.db_path)
        print(f"updated_status={args.status}")
        return 0

    if args.command == "add-note":
        add_note(args.finding_id, args.author, args.note, args.db_path)
        print(f"note_added_for={args.finding_id}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
