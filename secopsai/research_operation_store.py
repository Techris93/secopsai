"""Durable, versioned records for the research and editorial operation.

No migrations rewrite existing evidence or publication history. Records are
append-only; validity is evaluated against the current content fingerprint.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from contextlib import closing, contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

import soc_store
from secopsai.sqlite_writer_lock import sqlite_writer_lock

_ACTIVE: ContextVar[Any] = ContextVar("research_operation_transaction", default=None)

SCHEMA = """
CREATE TABLE IF NOT EXISTS research_operation_records (
  record_id TEXT PRIMARY KEY, kind TEXT NOT NULL, case_id TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL, payload_json TEXT NOT NULL, actor TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS research_operation_records_case ON research_operation_records(case_id,kind,created_at);
CREATE INDEX IF NOT EXISTS research_operation_records_kind ON research_operation_records(kind,created_at);
CREATE TABLE IF NOT EXISTS research_people (
  person_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, roles_json TEXT NOT NULL,
  qualification TEXT NOT NULL, active INTEGER NOT NULL, registered_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS research_intel_sources (
  source_id TEXT PRIMARY KEY, config_json TEXT NOT NULL, cursor TEXT NOT NULL DEFAULT '',
  last_attempt_at TEXT, last_success_at TEXT, error_category TEXT NOT NULL DEFAULT '',
  consecutive_failures INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS research_source_snapshots (
  snapshot_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, sha256 TEXT NOT NULL,
  object_path TEXT NOT NULL, acquired_at TEXT NOT NULL, parser_version TEXT NOT NULL, content BLOB NOT NULL,
  UNIQUE(source_id,sha256), FOREIGN KEY(source_id) REFERENCES research_intel_sources(source_id)
);
CREATE TABLE IF NOT EXISTS research_source_ingest_progress (
  source_id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, next_index INTEGER NOT NULL DEFAULT 0,
  total_items INTEGER NOT NULL, window_start TEXT NOT NULL DEFAULT '', events_total INTEGER NOT NULL DEFAULT 0,
  historical_excluded INTEGER NOT NULL DEFAULT 0, inserted_items INTEGER NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  FOREIGN KEY(source_id) REFERENCES research_intel_sources(source_id),
  FOREIGN KEY(snapshot_id) REFERENCES research_source_snapshots(snapshot_id)
);
CREATE TABLE IF NOT EXISTS research_source_collection_runs (
  run_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
  status TEXT NOT NULL, events_total INTEGER NOT NULL, events_in_scope INTEGER NOT NULL,
  historical_excluded INTEGER NOT NULL, inserted_events INTEGER NOT NULL,
  window_start TEXT NOT NULL DEFAULT '', acquired_at TEXT NOT NULL, completed_at TEXT NOT NULL,
  FOREIGN KEY(source_id) REFERENCES research_intel_sources(source_id),
  FOREIGN KEY(snapshot_id) REFERENCES research_source_snapshots(snapshot_id)
);
CREATE INDEX IF NOT EXISTS research_source_collection_runs_latest
  ON research_source_collection_runs(source_id, completed_at DESC);
CREATE TABLE IF NOT EXISTS research_intel_events (
  event_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, root_source_key TEXT NOT NULL,
  snapshot_id TEXT NOT NULL, published_at TEXT, collected_at TEXT NOT NULL,
  first_observed_at TEXT NOT NULL, payload_json TEXT NOT NULL,
  FOREIGN KEY(snapshot_id) REFERENCES research_source_snapshots(snapshot_id)
);
CREATE INDEX IF NOT EXISTS research_intel_events_root ON research_intel_events(root_source_key);
CREATE INDEX IF NOT EXISTS research_intel_events_collected ON research_intel_events(collected_at);
CREATE INDEX IF NOT EXISTS research_intel_events_source ON research_intel_events(source_id,first_observed_at);
CREATE INDEX IF NOT EXISTS research_source_snapshots_source ON research_source_snapshots(source_id,acquired_at);
CREATE TABLE IF NOT EXISTS research_operation_queue (
  job_id TEXT PRIMARY KEY, kind TEXT NOT NULL, event_id TEXT NOT NULL,
  payload_json TEXT NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0,
  lease_token TEXT NOT NULL DEFAULT '', lease_until TEXT, retry_at TEXT NOT NULL,
  result_json TEXT, error_category TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, UNIQUE(kind,event_id)
);
CREATE INDEX IF NOT EXISTS research_operation_queue_due ON research_operation_queue(state,retry_at,lease_until);
CREATE TABLE IF NOT EXISTS research_editorial_editions (
  edition_id TEXT PRIMARY KEY, edition_date TEXT NOT NULL, product TEXT NOT NULL,
  author_id TEXT NOT NULL, draft_json TEXT NOT NULL, fingerprint TEXT NOT NULL,
  state TEXT NOT NULL, published_url TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, UNIQUE(edition_date,product)
);
CREATE TABLE IF NOT EXISTS research_coverage_events (
  source_id TEXT NOT NULL, event_key TEXT NOT NULL, stage TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '', observed_at TEXT NOT NULL,
  PRIMARY KEY(source_id,event_key,stage)
);
"""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def text(value: Any, field: str, *, limit: int = 8000, required: bool = True) -> str:
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"invalid {field}")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required")
    return value


def timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires an explicit time zone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def transaction(db_path: str | None = None):
    active = _ACTIVE.get()
    if active is not None:
        if active[0] != (db_path or soc_store.default_db_path()):
            raise ValueError("nested operation uses a different database")
        yield active[1]
        return
    soc_store.init_db(db_path)
    with sqlite_writer_lock(db_path), closing(soc_store.connect(db_path)) as connection:
        with connection:
            token = _ACTIVE.set((db_path or soc_store.default_db_path(), connection))
            try:
                yield connection
            finally:
                _ACTIVE.reset(token)


@contextmanager
def read_connection(db_path=None):
    active = _ACTIVE.get()
    if active is not None and active[0] == (db_path or soc_store.default_db_path()):
        yield active[1]
    else:
        with closing(soc_store.connect(db_path)) as conn:
            yield conn


def append(kind: str, payload: dict, *, actor: str, case_id: str = "", fingerprint: str = "", db_path=None, connection=None) -> dict:
    record = {"record_id": "ROP-" + secrets.token_hex(12).upper(), "kind": kind,
              "case_id": case_id, "fingerprint": fingerprint or digest(payload),
              "payload": payload, "actor": text(actor, "actor", limit=160), "created_at": soc_store.utc_now()}
    def write(conn):
        conn.execute("INSERT INTO research_operation_records VALUES (?,?,?,?,?,?,?)",
                     (record["record_id"], kind, case_id, record["fingerprint"], canonical(payload), actor, record["created_at"]))
        if case_id:
            conn.execute("UPDATE research_cases SET updated_at=? WHERE case_id=?", (record["created_at"], case_id))
    if connection is not None:
        write(connection)
    else:
        with transaction(db_path) as conn:
            write(conn)
    return record


def records(kind: str, *, case_id: str = "", db_path=None, limit: int = 1000) -> list[dict]:
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        rows = conn.execute("SELECT * FROM research_operation_records WHERE kind=? AND case_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                            (kind, case_id, min(10000, max(1, limit)))).fetchall()
    return [{**dict(row), "payload": json.loads(row["payload_json"])} for row in rows]
