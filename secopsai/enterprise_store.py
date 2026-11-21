"""Tenant-scoped enterprise security data contracts and storage adapters.

The local adapter uses SQLite and is intentionally independent from the legacy
SOC schema. Hosted deployments may use PostgreSQL through the optional
``psycopg_pool`` dependency. Both adapters expose the same bounded, redacting
repository methods so connector and dashboard code cannot accidentally depend
on a database-specific query shape.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Protocol

from secopsai.sqlite_writer_lock import sqlite_writer_lock


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "migrations" / "enterprise" / "001_enterprise_security.sql"
MIGRATION_002_PATH = ROOT / "migrations" / "enterprise" / "002_workflow_history_and_pentest.sql"
SCHEMA_VERSION = 2
# Workflow records whose every save is kept as a numbered version.
VERSIONED_KINDS = {"questionnaire", "threat_model", "engagement"}
MAX_REPORT_BYTES = 50 * 1024 * 1024
PENTEST_SEVERITIES = {"critical", "high", "medium", "low", "info"}
# Item lifecycle: open -> fixed_pending_retest -> retest_passed | retest_failed (-> fixed_pending_retest again).
PENTEST_TRANSITIONS = {
    "open": {"fixed_pending_retest", "accepted_risk"},
    "fixed_pending_retest": {"retest_passed", "retest_failed"},
    "retest_failed": {"fixed_pending_retest", "accepted_risk"},
    "retest_passed": set(),
    "accepted_risk": {"open"},
}
MAX_EVENT_BYTES = 256 * 1024
MAX_PAGE_SIZE = 500
SENSITIVE_KEY = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|authorization|cookie|private[_-]?key)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16].upper()}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _bounded_text(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def redact(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact credential-shaped keys and bound nested payloads."""
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:500]:
            key_text = _bounded_text(key, 120)
            result[key_text] = "[redacted]" if SENSITIVE_KEY.search(key_text) else redact(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [redact(item, depth=depth + 1) for item in value[:500]]
    if isinstance(value, str):
        return value[:20_000]
    return value


def _payload(value: Any) -> str:
    rendered = _json(redact(value))
    if len(rendered.encode("utf-8")) > MAX_EVENT_BYTES:
        raise ValueError("enterprise payload exceeds the safety limit")
    return rendered


@dataclass(frozen=True)
class EnterpriseContext:
    organization_id: str
    actor_id: str = "system"
    role: str = "service"

    def validate(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}", self.organization_id or ""):
            raise ValueError("organization_id is required and must be safe")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}", self.actor_id or ""):
            raise ValueError("actor_id is invalid")
        if self.role not in {"operator", "analyst", "security_engineer", "auditor", "reviewer", "administrator", "service", "enterprise_ingest", "intelligence_operator", "operator_read"}:
            raise PermissionError("role is not allowed for enterprise operations")

    def require_action_write(self) -> None:
        if self.role not in {"operator", "security_engineer", "administrator", "intelligence_operator"}:
            raise PermissionError("role cannot create enterprise actions")

    def require_governance_write(self) -> None:
        if self.role not in {"operator", "security_engineer", "administrator", "auditor", "reviewer", "intelligence_operator"}:
            raise PermissionError("role cannot write governance records")


class RateLimiter:
    """Small process-local fixed-window limiter for connector/API boundaries."""

    def __init__(self, *, limit: int = 120, window_seconds: int = 60) -> None:
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._windows: dict[str, tuple[int, int]] = {}

    def allow(self, key: str) -> bool:
        now = int(time.time())
        bucket = now // self.window_seconds
        previous_bucket, count = self._windows.get(str(key), (bucket, 0))
        if previous_bucket != bucket:
            count = 0
        count += 1
        self._windows[str(key)] = (bucket, count)
        return count <= self.limit


class EnterpriseRepository(Protocol):
    def health(self) -> dict[str, Any]: ...
    def summary(self, *, limit: int = 25) -> dict[str, Any]: ...
    def append_event(self, event: dict[str, Any], *, idempotency_key: str = "") -> dict[str, Any]: ...
    def list_events(self, *, limit: int = 100, cursor: str = "") -> dict[str, Any]: ...
    def export_events(self, *, limit: int = 500) -> list[dict[str, Any]]: ...
    def purge_events(self, *, before: str, approved: bool = False) -> dict[str, Any]: ...
    def upsert_asset(self, asset: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_vulnerability(self, vulnerability: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_finding(self, finding: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_alert(self, alert: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_case(self, case: dict[str, Any]) -> dict[str, Any]: ...
    def create_action(self, action: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_source_cursor(self, cursor: dict[str, Any]) -> dict[str, Any]: ...
    def list_source_cursors(self, *, limit: int = 100) -> list[dict[str, Any]]: ...
    def record_dead_letter(self, item: dict[str, Any]) -> dict[str, Any]: ...
    def list_dead_letters(self, *, limit: int = 100) -> list[dict[str, Any]]: ...
    def upsert_control(self, control: dict[str, Any]) -> dict[str, Any]: ...
    def record_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_questionnaire(self, questionnaire: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_threat_model(self, threat_model: dict[str, Any]) -> dict[str, Any]: ...
    def upsert_pentest_engagement(self, engagement: dict[str, Any]) -> dict[str, Any]: ...



def _quarantine_root(organization_id: str) -> Path:
    base = Path(os.environ.get("SECOPSAI_ENTERPRISE_QUARANTINE_DIR") or (ROOT / "data" / "enterprise" / "quarantine"))
    return base.expanduser() / re.sub(r"[^A-Za-z0-9_.-]", "_", organization_id)


class _WorkflowExtensions:
    """Version history, penetration-test reports and items, and metric inputs.

    Shared by both adapters through ``_query(sql, params, fetch)``; SQL is
    written with ``?`` placeholders and the PostgreSQL adapter converts them.
    """

    context: EnterpriseContext

    def _query(self, sql: str, params: tuple = (), fetch: str = "") -> Any:  # pragma: no cover - per adapter
        raise NotImplementedError

    # -- version history -------------------------------------------------
    def _record_version(self, kind: str, record_id: str, item: dict[str, Any]) -> None:
        if kind not in VERSIONED_KINDS:
            return
        org = self.context.organization_id
        self._query(
            """INSERT INTO enterprise_record_versions
               (organization_id, record_kind, record_id, version, status, actor_id, payload_json, created_at)
               SELECT ?, ?, ?, COALESCE(MAX(version), 0) + 1, ?, ?, ?, ?
               FROM enterprise_record_versions WHERE organization_id=? AND record_kind=? AND record_id=?""",
            (org, kind, record_id, _bounded_text(item.get("status") or "draft", 40), self.context.actor_id, _payload(item), utc_now(), org, kind, record_id),
        )

    def list_record_versions(self, kind: str, record_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            """SELECT record_kind, record_id, version, status, actor_id, created_at FROM enterprise_record_versions
               WHERE organization_id=? AND record_kind=? AND record_id=? ORDER BY version DESC LIMIT 500""",
            (self.context.organization_id, kind, record_id), "all")
        return [dict(row) for row in rows]

    def get_record_version(self, kind: str, record_id: str, version: int) -> dict[str, Any]:
        row = self._query(
            "SELECT * FROM enterprise_record_versions WHERE organization_id=? AND record_kind=? AND record_id=? AND version=?",
            (self.context.organization_id, kind, record_id, int(version)), "one")
        if not row:
            raise ValueError(f"{kind} {record_id} has no version {version}")
        return self._row(row)

    # -- penetration-test reports -----------------------------------------
    def _engagement(self, engagement_id: str) -> dict[str, Any]:
        row = self._query("SELECT * FROM enterprise_pentest_engagements WHERE organization_id=? AND engagement_id=?",
                          (self.context.organization_id, engagement_id), "one")
        if not row:
            raise ValueError(f"engagement {engagement_id} does not exist")
        engagement = self._row(row)
        payload = engagement.get("payload") if isinstance(engagement.get("payload"), dict) else {}
        if not payload.get("scope") or not payload.get("authorized_by"):
            raise PermissionError("engagement has no recorded scope and authorization")
        return engagement

    def quarantine_pentest_report(self, engagement_id: str, source_path: str | Path, *, filename: str = "") -> dict[str, Any]:
        """Hash and copy a partner report into quarantine. The file is never opened as a document or executed."""
        self.context.require_governance_write()
        self._engagement(engagement_id)
        source = Path(source_path)
        size = source.stat().st_size
        if size > MAX_REPORT_BYTES:
            raise ValueError("report exceeds the 50 MiB quarantine limit")
        digest = hashlib.sha256()
        with source.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        sha = digest.hexdigest()
        existing = self._query("SELECT * FROM enterprise_pentest_reports WHERE organization_id=? AND engagement_id=? AND sha256=?",
                               (self.context.organization_id, engagement_id, sha), "one")
        if existing:
            return {**self._row(existing), "duplicate": True}
        root = _quarantine_root(self.context.organization_id)
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        target = root / f"{sha}.quarantine"
        if not target.exists():
            with source.open("rb") as src, open(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    dst.write(chunk)
        safe_name = re.sub(r"[^A-Za-z0-9._ -]", "_", filename or source.name)[:200] or "report"
        report_id = _safe_id("PTR")
        self._query(
            """INSERT INTO enterprise_pentest_reports
               (report_id, organization_id, engagement_id, filename, sha256, size_bytes, status, quarantine_path, submitted_by, received_at)
               VALUES (?, ?, ?, ?, ?, ?, 'quarantined', ?, ?, ?)""",
            (report_id, self.context.organization_id, engagement_id, safe_name, sha, size, str(target), self.context.actor_id, utc_now()))
        return self.get_pentest_report(report_id)

    def get_pentest_report(self, report_id: str) -> dict[str, Any]:
        row = self._query("SELECT * FROM enterprise_pentest_reports WHERE organization_id=? AND report_id=?",
                          (self.context.organization_id, report_id), "one")
        if not row:
            raise ValueError(f"report {report_id} does not exist")
        return dict(row)

    def review_pentest_report(self, report_id: str, *, decision: str, note: str = "") -> dict[str, Any]:
        self.context.require_governance_write()
        if decision not in {"accepted", "rejected"}:
            raise ValueError("decision must be accepted or rejected")
        report = self.get_pentest_report(report_id)
        if report["status"] != "quarantined":
            raise ValueError(f"report is already {report['status']}")
        self._query("UPDATE enterprise_pentest_reports SET status=?, reviewed_by=?, review_note=?, reviewed_at=? WHERE organization_id=? AND report_id=?",
                    (decision, self.context.actor_id, _bounded_text(note, 2000), utc_now(), self.context.organization_id, report_id))
        return self.get_pentest_report(report_id)

    # -- penetration-test items and retests -------------------------------
    def add_pentest_item(self, *, report_id: str, title: str, severity: str, owner: str = "", finding_id: str = "", due_at: str = "") -> dict[str, Any]:
        self.context.require_governance_write()
        report = self.get_pentest_report(report_id)
        if report["status"] != "accepted":
            raise PermissionError("items can only come from an accepted report")
        severity = severity.strip().lower()
        if severity not in PENTEST_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(PENTEST_SEVERITIES)}")
        if not _bounded_text(title, 300):
            raise ValueError("title is required")
        item_id = _safe_id("PTI")
        now = utc_now()
        history = [{"at": now, "actor": self.context.actor_id, "status": "open"}]
        self._query(
            """INSERT INTO enterprise_pentest_items
               (item_id, organization_id, engagement_id, report_id, title, severity, owner, finding_id, status, due_at, history_json, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)""",
            (item_id, self.context.organization_id, report["engagement_id"], report_id, _bounded_text(title, 300), severity,
             _bounded_text(owner, 200), _bounded_text(finding_id, 120), _bounded_text(due_at, 40), _json(history), now))
        return self.get_pentest_item(item_id)

    def get_pentest_item(self, item_id: str) -> dict[str, Any]:
        row = self._query("SELECT * FROM enterprise_pentest_items WHERE organization_id=? AND item_id=?",
                          (self.context.organization_id, item_id), "one")
        if not row:
            raise ValueError(f"item {item_id} does not exist")
        item = dict(row)
        item["history"] = json.loads(item.pop("history_json") or "[]")
        return item

    def update_pentest_item(self, item_id: str, *, status: str = "", owner: str | None = None, finding_id: str | None = None, note: str = "") -> dict[str, Any]:
        self.context.require_governance_write()
        item = self.get_pentest_item(item_id)
        now = utc_now()
        entry: dict[str, Any] = {"at": now, "actor": self.context.actor_id}
        new_status = item["status"]
        if status:
            if status not in PENTEST_TRANSITIONS.get(item["status"], set()):
                raise ValueError(f"cannot move an item from {item['status']} to {status}")
            if status == "accepted_risk" and self.context.role not in {"security_engineer", "administrator"}:
                raise PermissionError("accepting risk needs the security_engineer or administrator role")
            new_status = entry["status"] = status
        if owner is not None:
            entry["owner"] = owner = _bounded_text(owner, 200)
        if finding_id is not None:
            entry["finding_id"] = finding_id = _bounded_text(finding_id, 120)
        if note:
            entry["note"] = _bounded_text(note, 2000)
        history = (item["history"] + [entry])[-200:]
        retested_at = now if new_status in {"retest_passed", "retest_failed"} else item["retested_at"]
        self._query(
            "UPDATE enterprise_pentest_items SET status=?, owner=?, finding_id=?, retested_at=?, history_json=?, updated_at=? WHERE organization_id=? AND item_id=?",
            (new_status, item["owner"] if owner is None else owner, item["finding_id"] if finding_id is None else finding_id,
             retested_at, _json(history), now, self.context.organization_id, item_id))
        return self.get_pentest_item(item_id)

    def pentest_engagement_view(self, engagement_id: str) -> dict[str, Any]:
        engagement = self._engagement(engagement_id)
        org = self.context.organization_id
        reports = [dict(row) for row in self._query(
            "SELECT * FROM enterprise_pentest_reports WHERE organization_id=? AND engagement_id=? ORDER BY received_at", (org, engagement_id), "all")]
        items = [self.get_pentest_item(row["item_id"]) for row in self._query(
            "SELECT item_id FROM enterprise_pentest_items WHERE organization_id=? AND engagement_id=? ORDER BY updated_at", (org, engagement_id), "all")]
        counts: dict[str, int] = {}
        for item in items:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        closed = sum(counts.get(key, 0) for key in ("retest_passed", "accepted_risk"))
        retest = "no_items" if not items else "complete" if closed == len(items) else "in_progress"
        return {"engagement": engagement, "reports": reports, "items": items, "item_counts": counts, "retest_status": retest}

    # -- metrics inputs -----------------------------------------------------
    def metrics_inputs(self, *, limit: int = 1000) -> dict[str, Any]:
        org = self.context.organization_id
        bounded = max(1, min(int(limit), 5000))
        open_vulns = [dict(row) for row in self._query(
            "SELECT severity, sla_due_at FROM enterprise_vulnerabilities WHERE organization_id=? AND status NOT IN ('closed','resolved','fixed') LIMIT ?",
            (org, bounded), "all")]
        events = [dict(row) for row in self._query(
            "SELECT observed_at, received_at FROM enterprise_events WHERE organization_id=? ORDER BY received_at DESC LIMIT ?",
            (org, bounded), "all")]
        items = [dict(row) for row in self._query(
            "SELECT status FROM enterprise_pentest_items WHERE organization_id=?", (org,), "all")]
        return {"open_vulnerabilities": open_vulns, "recent_events": events, "pentest_items": items}


class SQLiteEnterpriseStore(_WorkflowExtensions):
    """Local enterprise repository with mandatory organization scoping."""

    def __init__(self, db_path: str | None = None, *, context: EnterpriseContext | None = None) -> None:
        self.db_path = str(db_path or os.environ.get("SECOPSAI_ENTERPRISE_DB_PATH") or (ROOT / "data" / "enterprise" / "enterprise.db"))
        self.context = context or EnterpriseContext(
            os.environ.get("SECOPSAI_ENTERPRISE_ORGANIZATION_ID", "local") or "local"
        )
        self.context.validate()
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        path = Path(self.db_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        conn = sqlite3.connect(path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return conn

    def init_schema(self) -> None:
        migration = MIGRATION_PATH.read_text(encoding="utf-8")
        with self.connect() as conn:
            try:
                version = int(conn.execute("SELECT version FROM enterprise_schema_meta LIMIT 1").fetchone()[0])
            except (sqlite3.Error, TypeError, ValueError):
                version = 0
        if version >= SCHEMA_VERSION:
            return
        with sqlite_writer_lock(self.db_path):
            with self.connect() as conn:
                if version < 1:
                    conn.executescript(migration)
                conn.executescript(MIGRATION_002_PATH.read_text(encoding="utf-8"))
                conn.execute("CREATE TABLE IF NOT EXISTS enterprise_schema_meta (version INTEGER NOT NULL)")
                conn.execute("DELETE FROM enterprise_schema_meta")
                conn.execute("INSERT INTO enterprise_schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
                conn.commit()

    def _query(self, sql: str, params: tuple = (), fetch: str = "") -> Any:
        with self.transaction() as conn:
            cursor = conn.execute(sql, params)
            if fetch == "one":
                return cursor.fetchone()
            if fetch == "all":
                return cursor.fetchall()
            return None

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _scoped(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        supplied = str(result.get("organization_id") or self.context.organization_id)
        if supplied != self.context.organization_id:
            raise PermissionError("organization scope mismatch")
        result["organization_id"] = self.context.organization_id
        result["updated_at"] = _bounded_text(result.get("updated_at") or utc_now(), 40)
        return result

    def health(self) -> dict[str, Any]:
        with self.connect() as conn:
            conn.execute("SELECT 1").fetchone()
        return {"status": "ready", "backend": "sqlite", "organization_id": self.context.organization_id}

    def summary(self, *, limit: int = 25) -> dict[str, Any]:
        """Return bounded, organization-scoped data for the operator console."""
        bounded = max(1, min(int(limit), 100))
        count_queries = {
            "events": "SELECT COUNT(*) FROM enterprise_events WHERE organization_id=?",
            "assets": "SELECT COUNT(*) FROM enterprise_assets WHERE organization_id=?",
            "vulnerabilities": "SELECT COUNT(*) FROM enterprise_vulnerabilities WHERE organization_id=?",
            "open_vulnerabilities": "SELECT COUNT(*) FROM enterprise_vulnerabilities WHERE organization_id=? AND status NOT IN ('closed','resolved','fixed')",
            "controls": "SELECT COUNT(*) FROM enterprise_controls WHERE organization_id=?",
            "evidence": "SELECT COUNT(*) FROM enterprise_evidence WHERE organization_id=?",
            "questionnaires": "SELECT COUNT(*) FROM enterprise_questionnaires WHERE organization_id=?",
            "threat_models": "SELECT COUNT(*) FROM enterprise_threat_models WHERE organization_id=?",
            "pentests": "SELECT COUNT(*) FROM enterprise_pentest_engagements WHERE organization_id=?",
            "actions": "SELECT COUNT(*) FROM enterprise_actions WHERE organization_id=?",
            "dead_letters": "SELECT COUNT(*) FROM enterprise_dead_letters WHERE organization_id=?",
        }
        with self.connect() as conn:
            counts = {
                key: int(conn.execute(query, (self.context.organization_id,)).fetchone()[0])
                for key, query in count_queries.items()
            }
            vulnerabilities = conn.execute(
                """SELECT * FROM enterprise_vulnerabilities
                   WHERE organization_id=? ORDER BY updated_at DESC, vulnerability_id DESC LIMIT ?""",
                (self.context.organization_id, bounded),
            ).fetchall()
            controls = conn.execute(
                """SELECT * FROM enterprise_controls
                   WHERE organization_id=? ORDER BY updated_at DESC, control_id DESC LIMIT ?""",
                (self.context.organization_id, bounded),
            ).fetchall()
            workflow_rows: list[dict[str, Any]] = []
            for table, id_column, kind in (
                ("enterprise_questionnaires", "questionnaire_id", "questionnaire"),
                ("enterprise_threat_models", "threat_model_id", "threat_model"),
                ("enterprise_pentest_engagements", "engagement_id", "pentest"),
            ):
                rows = conn.execute(
                    f"SELECT * FROM {table} WHERE organization_id=? ORDER BY updated_at DESC LIMIT ?",
                    (self.context.organization_id, bounded),
                ).fetchall()
                for row in rows:
                    normalized = self._row(row)
                    payload = normalized.get("payload") if isinstance(normalized.get("payload"), dict) else {}
                    workflow_rows.append({**payload, **normalized, "kind": kind, "record_id": row[id_column]})
        workflow_rows.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
        return {
            "counts": counts,
            "sources": self.list_source_cursors(limit=bounded),
            "recent_events": self.list_events(limit=bounded)["events"],
            "recent_vulnerabilities": [self._row(row) for row in vulnerabilities],
            "recent_controls": [self._row(row) for row in controls],
            "recent_workflows": workflow_rows[:bounded],
            "dead_letters": self.list_dead_letters(limit=min(bounded, 25)),
            "generated_at": utc_now(),
        }

    def append_event(self, event: dict[str, Any], *, idempotency_key: str = "") -> dict[str, Any]:
        item = self._scoped(event)
        event_id = _bounded_text(item.get("event_id") or _safe_id("EVT"), 80)
        idem = _bounded_text(idempotency_key or item.get("idempotency_key"), 160)
        received_at = utc_now()
        payload = _payload(item.get("payload") or item.get("data") or {})
        with self.transaction() as conn:
            if idem:
                existing = conn.execute(
                    "SELECT * FROM enterprise_events WHERE organization_id=? AND idempotency_key=?",
                    (self.context.organization_id, idem),
                ).fetchone()
                if existing:
                    return self._row(existing)
            conn.execute(
                """INSERT INTO enterprise_events
                (event_id, organization_id, source, event_type, observed_at, received_at,
                 severity, correlation_id, idempotency_key, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_id, self.context.organization_id, _bounded_text(item.get("source"), 120),
                    _bounded_text(item.get("event_type"), 160), _bounded_text(item.get("observed_at") or received_at, 40),
                    received_at, _bounded_text(item.get("severity") or "info", 20).lower(),
                    _bounded_text(item.get("correlation_id"), 160), idem, payload,
                ),
            )
            self._audit(conn, "event.appended", "success", {"event_id": event_id, "source": item.get("source")})
            row = conn.execute("SELECT * FROM enterprise_events WHERE event_id=?", (event_id,)).fetchone()
        return self._row(row)

    def list_events(self, *, limit: int = 100, cursor: str = "") -> dict[str, Any]:
        bounded = max(1, min(int(limit), MAX_PAGE_SIZE))
        params: list[Any] = [self.context.organization_id]
        where = "organization_id=?"
        if cursor:
            where += " AND received_at < ?"
            params.append(_bounded_text(cursor, 40))
        params.append(bounded + 1)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM enterprise_events WHERE {where} ORDER BY received_at DESC, event_id DESC LIMIT ?",
                params,
            ).fetchall()
        has_more = len(rows) > bounded
        rows = rows[:bounded]
        next_cursor = str(rows[-1]["received_at"]) if has_more and rows else ""
        return {"events": [self._row(row) for row in rows], "next_cursor": next_cursor, "has_more": has_more}

    def export_events(self, *, limit: int = 500) -> list[dict[str, Any]]:
        return self.list_events(limit=limit)["events"]

    def purge_events(self, *, before: str, approved: bool = False) -> dict[str, Any]:
        if not approved or self.context.role not in {"administrator", "security_engineer"}:
            raise PermissionError("event retention deletion requires administrator approval")
        with self.transaction() as conn:
            result = conn.execute("DELETE FROM enterprise_events WHERE organization_id=? AND received_at < ?", (self.context.organization_id, _bounded_text(before, 40)))
            self._audit(conn, "events.purged", "success", {"before": before, "deleted": result.rowcount})
        return {"status": "purged", "deleted": int(result.rowcount), "before": before}

    def upsert_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        item = self._scoped(asset)
        asset_id = _bounded_text(item.get("asset_id") or _safe_id("AST"), 100)
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO enterprise_assets
                (asset_id, organization_id, asset_type, name, owner, criticality, metadata_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET name=excluded.name, owner=excluded.owner,
                criticality=excluded.criticality, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
                WHERE enterprise_assets.organization_id=excluded.organization_id""",
                (
                    asset_id, self.context.organization_id, _bounded_text(item.get("asset_type") or "service", 80),
                    _bounded_text(item.get("name") or asset_id, 240), _bounded_text(item.get("owner"), 200),
                    _bounded_text(item.get("criticality") or "normal", 40), _payload(item.get("metadata") or {}),
                    item["updated_at"],
                ),
            )
            row = conn.execute("SELECT * FROM enterprise_assets WHERE asset_id=?", (asset_id,)).fetchone()
        return self._row(row)

    def upsert_vulnerability(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        item = self._scoped(vulnerability)
        vuln_id = _bounded_text(item.get("vulnerability_id") or _safe_id("VUL"), 100)
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO enterprise_vulnerabilities
                (vulnerability_id, organization_id, asset_id, advisory_id, package_name, package_version,
                 severity, cvss_score, exploitability_score, status, sla_due_at, metadata_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vulnerability_id) DO UPDATE SET severity=excluded.severity,
                cvss_score=excluded.cvss_score, exploitability_score=excluded.exploitability_score,
                status=excluded.status, sla_due_at=excluded.sla_due_at, metadata_json=excluded.metadata_json,
                updated_at=excluded.updated_at
                WHERE enterprise_vulnerabilities.organization_id=excluded.organization_id""",
                (
                    vuln_id, self.context.organization_id, _bounded_text(item.get("asset_id"), 100),
                    _bounded_text(item.get("advisory_id"), 160), _bounded_text(item.get("package_name"), 260),
                    _bounded_text(item.get("package_version"), 160), _bounded_text(item.get("severity") or "unknown", 20).lower(),
                    item.get("cvss_score"), item.get("exploitability_score"), _bounded_text(item.get("status") or "open", 40),
                    _bounded_text(item.get("sla_due_at"), 40), _payload(item.get("metadata") or {}), item["updated_at"],
                ),
            )
            row = conn.execute("SELECT * FROM enterprise_vulnerabilities WHERE vulnerability_id=?", (vuln_id,)).fetchone()
        return self._row(row)

    def upsert_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_findings", "finding_id", finding, "finding")

    def upsert_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_alerts", "alert_id", alert, "alert")

    def upsert_case(self, case: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_cases", "case_id", case, "case")

    def create_action(self, action: dict[str, Any]) -> dict[str, Any]:
        self.context.require_action_write()
        item = self._scoped(action)
        action_id = _bounded_text(item.get("action_id") or _safe_id("ACT"), 100)
        idem = _bounded_text(item.get("idempotency_key"), 160)
        with self.transaction() as conn:
            if idem:
                existing = conn.execute(
                    "SELECT * FROM enterprise_actions WHERE organization_id=? AND idempotency_key=?",
                    (self.context.organization_id, idem),
                ).fetchone()
                if existing:
                    return self._row(existing)
            conn.execute(
                """INSERT INTO enterprise_actions
                (action_id, organization_id, action_type, target_id, status, approval_required,
                 idempotency_key, payload_json, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action_id, self.context.organization_id, _bounded_text(item.get("action_type"), 100),
                    _bounded_text(item.get("target_id"), 160), _bounded_text(item.get("status") or "proposed", 40),
                    1 if item.get("approval_required", True) else 0, idem, _payload(item.get("payload") or {}),
                    self.context.actor_id, utc_now(), item["updated_at"],
                ),
            )
            self._audit(conn, "action.created", "success", {"action_id": action_id, "action_type": item.get("action_type")})
            row = conn.execute("SELECT * FROM enterprise_actions WHERE action_id=?", (action_id,)).fetchone()
        return self._row(row)

    def upsert_source_cursor(self, cursor: dict[str, Any]) -> dict[str, Any]:
        item = self._scoped(cursor)
        source = _bounded_text(item.get("source"), 160)
        if not source:
            raise ValueError("source is required")
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO enterprise_source_cursors
                (organization_id, source, cursor_value, last_success_at, last_error_at, status, metadata_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(organization_id, source) DO UPDATE SET cursor_value=excluded.cursor_value,
                last_success_at=excluded.last_success_at, last_error_at=excluded.last_error_at,
                status=excluded.status, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at""",
                (
                    self.context.organization_id, source, _bounded_text(item.get("cursor_value"), 400),
                    _bounded_text(item.get("last_success_at"), 40), _bounded_text(item.get("last_error_at"), 40),
                    _bounded_text(item.get("status") or "healthy", 40), _payload(item.get("metadata") or {}), item["updated_at"],
                ),
            )
            row = conn.execute("SELECT * FROM enterprise_source_cursors WHERE organization_id=? AND source=?", (self.context.organization_id, source)).fetchone()
        return self._row(row)

    def record_dead_letter(self, item: dict[str, Any]) -> dict[str, Any]:
        data = self._scoped(item)
        dead_id = _bounded_text(data.get("dead_letter_id") or _safe_id("DLQ"), 100)
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO enterprise_dead_letters
                (dead_letter_id, organization_id, source, reason, payload_json, retryable, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (dead_id, self.context.organization_id, _bounded_text(data.get("source"), 160), _bounded_text(data.get("reason"), 1000), _payload(data.get("payload") or {}), 1 if data.get("retryable", True) else 0, utc_now()),
            )
            row = conn.execute("SELECT * FROM enterprise_dead_letters WHERE dead_letter_id=?", (dead_id,)).fetchone()
        return self._row(row)

    def list_source_cursors(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_PAGE_SIZE))
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM enterprise_source_cursors WHERE organization_id=? ORDER BY updated_at DESC LIMIT ?", (self.context.organization_id, bounded)).fetchall()
        return [self._row(row) for row in rows]

    def list_dead_letters(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_PAGE_SIZE))
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM enterprise_dead_letters WHERE organization_id=? ORDER BY created_at DESC LIMIT ?", (self.context.organization_id, bounded)).fetchall()
        return [self._row(row) for row in rows]

    def upsert_control(self, control: dict[str, Any]) -> dict[str, Any]:
        self.context.require_governance_write()
        item = self._scoped(control)
        control_id = _bounded_text(item.get("control_id") or _safe_id("CTL"), 120)
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO enterprise_controls
                (control_id, organization_id, framework, title, status, owner, review_due_at, metadata_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(control_id) DO UPDATE SET status=excluded.status, owner=excluded.owner,
                review_due_at=excluded.review_due_at, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
                WHERE enterprise_controls.organization_id=excluded.organization_id""",
                (control_id, self.context.organization_id, _bounded_text(item.get("framework"), 80), _bounded_text(item.get("title"), 300), _bounded_text(item.get("status") or "not_started", 40), _bounded_text(item.get("owner"), 200), _bounded_text(item.get("review_due_at"), 40), _payload(item.get("metadata") or {}), item["updated_at"]),
            )
            row = conn.execute("SELECT * FROM enterprise_controls WHERE control_id=?", (control_id,)).fetchone()
        return self._row(row)

    def record_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        self.context.require_governance_write()
        item = self._scoped(evidence)
        evidence_id = _bounded_text(item.get("evidence_id") or _safe_id("EVD"), 120)
        body = _payload(item.get("metadata") or item.get("content") or {})
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO enterprise_evidence
                (evidence_id, organization_id, control_id, evidence_type, source, sha256,
                 collected_at, expires_at, reviewer, status, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (evidence_id, self.context.organization_id, _bounded_text(item.get("control_id"), 120), _bounded_text(item.get("evidence_type") or "other", 80), _bounded_text(item.get("source"), 500), _bounded_text(item.get("sha256") or digest, 64), _bounded_text(item.get("collected_at") or utc_now(), 40), _bounded_text(item.get("expires_at"), 40), _bounded_text(item.get("reviewer"), 200), _bounded_text(item.get("status") or "pending_review", 40), body),
            )
            row = conn.execute("SELECT * FROM enterprise_evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        return self._row(row)

    def upsert_questionnaire(self, questionnaire: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_questionnaires", "questionnaire_id", questionnaire, "questionnaire")

    def upsert_threat_model(self, threat_model: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_threat_models", "threat_model_id", threat_model, "threat_model")

    def upsert_pentest_engagement(self, engagement: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_pentest_engagements", "engagement_id", engagement, "engagement")

    def _upsert_json_record(self, table: str, id_column: str, value: dict[str, Any], kind: str) -> dict[str, Any]:
        item = self._scoped(value)
        record_id = _bounded_text(item.get(id_column) or _safe_id(kind[:3].upper()), 120)
        with self.transaction() as conn:
            conn.execute(
                f"""INSERT INTO {table} ({id_column}, organization_id, status, owner, payload_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT({id_column}) DO UPDATE SET status=excluded.status, owner=excluded.owner,
                payload_json=excluded.payload_json, updated_at=excluded.updated_at
                WHERE {table}.organization_id=excluded.organization_id""",
                (record_id, self.context.organization_id, _bounded_text(item.get("status") or "draft", 40), _bounded_text(item.get("owner"), 200), _payload(item), item["updated_at"]),
            )
            row = conn.execute(f"SELECT * FROM {table} WHERE {id_column}=?", (record_id,)).fetchone()
        self._record_version(kind, record_id, item)
        return self._row(row)

    def _audit(self, conn: sqlite3.Connection, action: str, result: str, details: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO enterprise_audit_logs (audit_id, organization_id, action, actor_id, actor_role, result, request_id, details_json, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (_safe_id("AUD"), self.context.organization_id, action, self.context.actor_id, self.context.role, result, _safe_id("REQ"), _payload(details), utc_now()),
        )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            raise RuntimeError("enterprise record was not persisted")
        result = dict(row)
        for key in ("payload_json", "metadata_json"):
            if key in result:
                try:
                    result[key[:-5] if key.endswith("_json") else key] = json.loads(result[key])
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
        return result


class PostgresEnterpriseStore(_WorkflowExtensions):
    """Hosted adapter using psycopg's bounded connection pool.

    The optional dependency is intentionally imported only when this adapter is
    selected, so local installs remain lightweight and offline-capable.
    """

    def __init__(self, database_url: str, *, context: EnterpriseContext | None = None, min_size: int = 1, max_size: int = 10) -> None:
        if not database_url or not database_url.startswith(("postgres://", "postgresql://")):
            raise ValueError("a PostgreSQL database URL is required")
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:
            raise RuntimeError("install the enterprise extra to use PostgreSQL: psycopg[binary,pool]") from exc
        self.context = context or EnterpriseContext(os.environ.get("SECOPSAI_ENTERPRISE_ORGANIZATION_ID", ""))
        self.context.validate()
        self.pool = ConnectionPool(database_url, min_size=max(1, min_size), max_size=max(min_size, max_size), kwargs={"row_factory": dict_row}, open=True)
        self.migrate()

    def health(self) -> dict[str, Any]:
        with self.pool.connection() as conn:
            conn.execute("SELECT 1")
        return {"status": "ready", "backend": "postgres", "organization_id": self.context.organization_id, "pool_max": self.pool.max_size}

    def summary(self, *, limit: int = 25) -> dict[str, Any]:
        """Return the same bounded operator summary as the SQLite adapter."""
        bounded = max(1, min(int(limit), 100))
        organization_id = self.context.organization_id
        count_queries = {
            "events": "SELECT COUNT(*) AS count FROM enterprise_events WHERE organization_id=%s",
            "assets": "SELECT COUNT(*) AS count FROM enterprise_assets WHERE organization_id=%s",
            "vulnerabilities": "SELECT COUNT(*) AS count FROM enterprise_vulnerabilities WHERE organization_id=%s",
            "open_vulnerabilities": "SELECT COUNT(*) AS count FROM enterprise_vulnerabilities WHERE organization_id=%s AND status NOT IN ('closed','resolved','fixed')",
            "controls": "SELECT COUNT(*) AS count FROM enterprise_controls WHERE organization_id=%s",
            "evidence": "SELECT COUNT(*) AS count FROM enterprise_evidence WHERE organization_id=%s",
            "questionnaires": "SELECT COUNT(*) AS count FROM enterprise_questionnaires WHERE organization_id=%s",
            "threat_models": "SELECT COUNT(*) AS count FROM enterprise_threat_models WHERE organization_id=%s",
            "pentests": "SELECT COUNT(*) AS count FROM enterprise_pentest_engagements WHERE organization_id=%s",
            "actions": "SELECT COUNT(*) AS count FROM enterprise_actions WHERE organization_id=%s",
            "dead_letters": "SELECT COUNT(*) AS count FROM enterprise_dead_letters WHERE organization_id=%s",
        }
        with self.pool.connection() as conn:
            counts = {
                key: int(conn.execute(query, (organization_id,)).fetchone()["count"])
                for key, query in count_queries.items()
            }
            vulnerabilities = list(conn.execute(
                "SELECT * FROM enterprise_vulnerabilities WHERE organization_id=%s ORDER BY updated_at DESC, vulnerability_id DESC LIMIT %s",
                (organization_id, bounded),
            ).fetchall())
            controls = list(conn.execute(
                "SELECT * FROM enterprise_controls WHERE organization_id=%s ORDER BY updated_at DESC, control_id DESC LIMIT %s",
                (organization_id, bounded),
            ).fetchall())
            workflow_rows: list[dict[str, Any]] = []
            for table, id_column, kind in (
                ("enterprise_questionnaires", "questionnaire_id", "questionnaire"),
                ("enterprise_threat_models", "threat_model_id", "threat_model"),
                ("enterprise_pentest_engagements", "engagement_id", "pentest"),
            ):
                rows = conn.execute(
                    f"SELECT * FROM {table} WHERE organization_id=%s ORDER BY updated_at DESC LIMIT %s",
                    (organization_id, bounded),
                ).fetchall()
                for row in rows:
                    normalized = self._row(row)
                    payload = normalized.get("payload") if isinstance(normalized.get("payload"), dict) else {}
                    workflow_rows.append({**payload, **normalized, "kind": kind, "record_id": row[id_column]})
        workflow_rows.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
        return {
            "counts": counts,
            "sources": self.list_source_cursors(limit=bounded),
            "recent_events": self.list_events(limit=bounded)["events"],
            "recent_vulnerabilities": [self._row(row) for row in vulnerabilities],
            "recent_controls": [self._row(row) for row in controls],
            "recent_workflows": workflow_rows[:bounded],
            "dead_letters": self.list_dead_letters(limit=min(bounded, 25)),
            "generated_at": utc_now(),
        }

    def migrate(self) -> None:
        with self.pool.connection() as conn:
            conn.execute(MIGRATION_PATH.read_text(encoding="utf-8"))
            conn.execute(MIGRATION_002_PATH.read_text(encoding="utf-8"))

    def _query(self, sql: str, params: tuple = (), fetch: str = "") -> Any:
        with self.pool.connection() as conn:
            cursor = conn.execute(sql.replace("?", "%s"), params)
            if fetch == "one":
                return cursor.fetchone()
            if fetch == "all":
                return list(cursor.fetchall())
            return None

    def close(self) -> None:
        self.pool.close()

    def _scoped(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        supplied = str(result.get("organization_id") or self.context.organization_id)
        if supplied != self.context.organization_id:
            raise PermissionError("organization scope mismatch")
        result["organization_id"] = self.context.organization_id
        result["updated_at"] = _bounded_text(result.get("updated_at") or utc_now(), 40)
        return result

    def _row(self, row: dict[str, Any] | None) -> dict[str, Any]:
        if row is None:
            raise RuntimeError("enterprise record was not persisted")
        result = dict(row)
        for key in ("payload_json", "metadata_json"):
            if key not in result:
                continue
            if isinstance(result[key], str):
                try:
                    result[key[:-5]] = json.loads(result[key])
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
            elif isinstance(result[key], (dict, list)):
                result[key[:-5]] = result[key]
        return result

    def append_event(self, event: dict[str, Any], *, idempotency_key: str = "") -> dict[str, Any]:
        item = self._scoped(event)
        event_id = _bounded_text(item.get("event_id") or _safe_id("EVT"), 80)
        idem = _bounded_text(idempotency_key or item.get("idempotency_key"), 160)
        received_at = utc_now()
        payload = _payload(item.get("payload") or item.get("data") or {})
        with self.pool.connection() as conn:
            if idem:
                row = conn.execute("SELECT * FROM enterprise_events WHERE organization_id=%s AND idempotency_key=%s", (self.context.organization_id, idem)).fetchone()
                if row:
                    return self._row(row)
            row = conn.execute(
                """INSERT INTO enterprise_events
                (event_id, organization_id, source, event_type, observed_at, received_at, severity,
                 correlation_id, idempotency_key, payload_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *""",
                (event_id, self.context.organization_id, _bounded_text(item.get("source"), 120), _bounded_text(item.get("event_type"), 160), _bounded_text(item.get("observed_at") or received_at, 40), received_at, _bounded_text(item.get("severity") or "info", 20).lower(), _bounded_text(item.get("correlation_id"), 160), idem, payload),
            ).fetchone()
            conn.execute("INSERT INTO enterprise_audit_logs (audit_id, organization_id, action, actor_id, actor_role, result, request_id, details_json, occurred_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", (_safe_id("AUD"), self.context.organization_id, "event.appended", self.context.actor_id, self.context.role, "success", _safe_id("REQ"), _payload({"event_id": event_id}), utc_now()))
        return self._row(row)

    def list_events(self, *, limit: int = 100, cursor: str = "") -> dict[str, Any]:
        bounded = max(1, min(int(limit), MAX_PAGE_SIZE))
        params: list[Any] = [self.context.organization_id]
        where = "organization_id=%s"
        if cursor:
            where += " AND received_at < %s"
            params.append(_bounded_text(cursor, 40))
        params.append(bounded + 1)
        with self.pool.connection() as conn:
            rows = conn.execute(f"SELECT * FROM enterprise_events WHERE {where} ORDER BY received_at DESC, event_id DESC LIMIT %s", params).fetchall()
        has_more = len(rows) > bounded
        rows = rows[:bounded]
        return {"events": [self._row(row) for row in rows], "next_cursor": str(rows[-1]["received_at"]) if has_more and rows else "", "has_more": has_more}

    def export_events(self, *, limit: int = 500) -> list[dict[str, Any]]:
        return self.list_events(limit=limit)["events"]

    def purge_events(self, *, before: str, approved: bool = False) -> dict[str, Any]:
        if not approved or self.context.role not in {"administrator", "security_engineer"}:
            raise PermissionError("event retention deletion requires administrator approval")
        with self.pool.connection() as conn:
            result = conn.execute("DELETE FROM enterprise_events WHERE organization_id=%s AND received_at < %s", (self.context.organization_id, _bounded_text(before, 40)))
        return {"status": "purged", "deleted": result.rowcount, "before": before}

    def upsert_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        item = self._scoped(asset)
        asset_id = _bounded_text(item.get("asset_id") or _safe_id("AST"), 100)
        with self.pool.connection() as conn:
            row = conn.execute(
                """INSERT INTO enterprise_assets (asset_id, organization_id, asset_type, name, owner, criticality, metadata_json, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(asset_id) DO UPDATE SET name=excluded.name, owner=excluded.owner, criticality=excluded.criticality, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
                WHERE enterprise_assets.organization_id=excluded.organization_id RETURNING *""",
                (asset_id, self.context.organization_id, _bounded_text(item.get("asset_type") or "service", 80), _bounded_text(item.get("name") or asset_id, 240), _bounded_text(item.get("owner"), 200), _bounded_text(item.get("criticality") or "normal", 40), _payload(item.get("metadata") or {}), item["updated_at"]),
            ).fetchone()
        return self._row(row)

    def upsert_vulnerability(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        item = self._scoped(vulnerability)
        vuln_id = _bounded_text(item.get("vulnerability_id") or _safe_id("VUL"), 100)
        with self.pool.connection() as conn:
            row = conn.execute(
                """INSERT INTO enterprise_vulnerabilities (vulnerability_id, organization_id, asset_id, advisory_id, package_name, package_version, severity, cvss_score, exploitability_score, status, sla_due_at, metadata_json, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(vulnerability_id) DO UPDATE SET severity=excluded.severity, cvss_score=excluded.cvss_score, exploitability_score=excluded.exploitability_score, status=excluded.status, sla_due_at=excluded.sla_due_at, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
                WHERE enterprise_vulnerabilities.organization_id=excluded.organization_id RETURNING *""",
                (vuln_id, self.context.organization_id, _bounded_text(item.get("asset_id"), 100), _bounded_text(item.get("advisory_id"), 160), _bounded_text(item.get("package_name"), 260), _bounded_text(item.get("package_version"), 160), _bounded_text(item.get("severity") or "unknown", 20).lower(), item.get("cvss_score"), item.get("exploitability_score"), _bounded_text(item.get("status") or "open", 40), _bounded_text(item.get("sla_due_at"), 40), _payload(item.get("metadata") or {}), item["updated_at"]),
            ).fetchone()
        return self._row(row)

    def upsert_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_findings", "finding_id", finding, "finding")

    def upsert_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_alerts", "alert_id", alert, "alert")

    def upsert_case(self, case: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_cases", "case_id", case, "case")

    def create_action(self, action: dict[str, Any]) -> dict[str, Any]:
        self.context.require_action_write()
        item = self._scoped(action)
        action_id = _bounded_text(item.get("action_id") or _safe_id("ACT"), 100)
        idem = _bounded_text(item.get("idempotency_key"), 160)
        with self.pool.connection() as conn:
            if idem:
                row = conn.execute("SELECT * FROM enterprise_actions WHERE organization_id=%s AND idempotency_key=%s", (self.context.organization_id, idem)).fetchone()
                if row:
                    return self._row(row)
            row = conn.execute(
                """INSERT INTO enterprise_actions (action_id, organization_id, action_type, target_id, status, approval_required, idempotency_key, payload_json, created_by, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (action_id, self.context.organization_id, _bounded_text(item.get("action_type"), 100), _bounded_text(item.get("target_id"), 160), _bounded_text(item.get("status") or "proposed", 40), bool(item.get("approval_required", True)), idem, _payload(item.get("payload") or {}), self.context.actor_id, utc_now(), item["updated_at"]),
            ).fetchone()
        return self._row(row)

    def upsert_source_cursor(self, cursor: dict[str, Any]) -> dict[str, Any]:
        item = self._scoped(cursor)
        source = _bounded_text(item.get("source"), 160)
        if not source:
            raise ValueError("source is required")
        with self.pool.connection() as conn:
            row = conn.execute(
                """INSERT INTO enterprise_source_cursors (organization_id, source, cursor_value, last_success_at, last_error_at, status, metadata_json, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(organization_id, source) DO UPDATE SET cursor_value=excluded.cursor_value, last_success_at=excluded.last_success_at, last_error_at=excluded.last_error_at, status=excluded.status, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at RETURNING *""",
                (self.context.organization_id, source, _bounded_text(item.get("cursor_value"), 400), _bounded_text(item.get("last_success_at"), 40), _bounded_text(item.get("last_error_at"), 40), _bounded_text(item.get("status") or "healthy", 40), _payload(item.get("metadata") or {}), item["updated_at"]),
            ).fetchone()
        return self._row(row)

    def record_dead_letter(self, item: dict[str, Any]) -> dict[str, Any]:
        data = self._scoped(item)
        dead_id = _bounded_text(data.get("dead_letter_id") or _safe_id("DLQ"), 100)
        with self.pool.connection() as conn:
            row = conn.execute("INSERT INTO enterprise_dead_letters (dead_letter_id, organization_id, source, reason, payload_json, retryable, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *", (dead_id, self.context.organization_id, _bounded_text(data.get("source"), 160), _bounded_text(data.get("reason"), 1000), _payload(data.get("payload") or {}), bool(data.get("retryable", True)), utc_now())).fetchone()
        return self._row(row)

    def list_source_cursors(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_PAGE_SIZE))
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT * FROM enterprise_source_cursors WHERE organization_id=%s ORDER BY updated_at DESC LIMIT %s", (self.context.organization_id, bounded)).fetchall()
        return [self._row(row) for row in rows]

    def list_dead_letters(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_PAGE_SIZE))
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT * FROM enterprise_dead_letters WHERE organization_id=%s ORDER BY created_at DESC LIMIT %s", (self.context.organization_id, bounded)).fetchall()
        return [self._row(row) for row in rows]

    def upsert_control(self, control: dict[str, Any]) -> dict[str, Any]:
        self.context.require_governance_write()
        item = self._scoped(control)
        control_id = _bounded_text(item.get("control_id") or _safe_id("CTL"), 120)
        with self.pool.connection() as conn:
            row = conn.execute("""INSERT INTO enterprise_controls (control_id, organization_id, framework, title, status, owner, review_due_at, metadata_json, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(control_id) DO UPDATE SET status=excluded.status, owner=excluded.owner, review_due_at=excluded.review_due_at, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at WHERE enterprise_controls.organization_id=excluded.organization_id RETURNING *""", (control_id, self.context.organization_id, _bounded_text(item.get("framework"), 80), _bounded_text(item.get("title"), 300), _bounded_text(item.get("status") or "not_started", 40), _bounded_text(item.get("owner"), 200), _bounded_text(item.get("review_due_at"), 40), _payload(item.get("metadata") or {}), item["updated_at"])).fetchone()
        return self._row(row)

    def record_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        self.context.require_governance_write()
        item = self._scoped(evidence)
        evidence_id = _bounded_text(item.get("evidence_id") or _safe_id("EVD"), 120)
        body = _payload(item.get("metadata") or item.get("content") or {})
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        with self.pool.connection() as conn:
            row = conn.execute("INSERT INTO enterprise_evidence (evidence_id, organization_id, control_id, evidence_type, source, sha256, collected_at, expires_at, reviewer, status, metadata_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *", (evidence_id, self.context.organization_id, _bounded_text(item.get("control_id"), 120), _bounded_text(item.get("evidence_type") or "other", 80), _bounded_text(item.get("source"), 500), _bounded_text(item.get("sha256") or digest, 64), _bounded_text(item.get("collected_at") or utc_now(), 40), _bounded_text(item.get("expires_at"), 40), _bounded_text(item.get("reviewer"), 200), _bounded_text(item.get("status") or "pending_review", 40), body)).fetchone()
        return self._row(row)

    def _upsert_json_record(self, table: str, id_column: str, value: dict[str, Any], kind: str) -> dict[str, Any]:
        item = self._scoped(value)
        record_id = _bounded_text(item.get(id_column) or _safe_id(kind[:3].upper()), 120)
        with self.pool.connection() as conn:
            row = conn.execute(f"INSERT INTO {table} ({id_column}, organization_id, status, owner, payload_json, updated_at) VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT({id_column}) DO UPDATE SET status=excluded.status, owner=excluded.owner, payload_json=excluded.payload_json, updated_at=excluded.updated_at WHERE {table}.organization_id=excluded.organization_id RETURNING *", (record_id, self.context.organization_id, _bounded_text(item.get("status") or "draft", 40), _bounded_text(item.get("owner"), 200), _payload(item), item["updated_at"])).fetchone()
        self._record_version(kind, record_id, item)
        return self._row(row)

    def upsert_questionnaire(self, questionnaire: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_questionnaires", "questionnaire_id", questionnaire, "questionnaire")

    def upsert_threat_model(self, threat_model: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_threat_models", "threat_model_id", threat_model, "threat_model")

    def upsert_pentest_engagement(self, engagement: dict[str, Any]) -> dict[str, Any]:
        return self._upsert_json_record("enterprise_pentest_engagements", "engagement_id", engagement, "engagement")


def build_enterprise_store(*, context: EnterpriseContext | None = None, db_path: str | None = None) -> EnterpriseRepository:
    backend = os.environ.get("SECOPSAI_ENTERPRISE_DATA_STORE", "sqlite").strip().lower()
    if backend == "postgres":
        return PostgresEnterpriseStore(os.environ.get("SECOPSAI_ENTERPRISE_DATABASE_URL", ""), context=context)
    if backend != "sqlite":
        raise ValueError("SECOPSAI_ENTERPRISE_DATA_STORE must be sqlite or postgres")
    return SQLiteEnterpriseStore(db_path=db_path, context=context)
