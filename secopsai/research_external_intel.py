"""Bounded ingestion of public, source-backed package advisories.

Registry telemetry answers "what changed".  Public research feeds answer a
different question: "what has already been independently reported".  The two
signals must be joined, not substituted for one another.  This module ingests
only normalized package/version rows from an allowlisted CSV source, keeps the
source hash and provenance, and creates reviewable candidates without making
an automatic maliciousness verdict.

The initial source is the public Wiz Research IOC list for the August 2026
Keyv/Cacheable campaign.  It is deliberately treated as an external lead:
the exact artifact still requires SecOpsAI's quarantined intake and static
verification before a case can be substantiated.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import soc_store
from secopsai.research_discovery import create_candidate_alert
from secopsai.research_intake import IntakeError, SafeFetcher
from secopsai.sqlite_writer_lock import sqlite_writer_lock


SCHEMA_VERSION = "secopsai.research.external-intel.v1"
WIZ_KEYV_SOURCE_ID = "EXT-WIZ-KEYV-2026-08"
WIZ_KEYV_SOURCE_URL = (
    "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/"
    "main/reports/keyv-packages.csv"
)
WIZ_KEYV_ALLOWED_HOSTS = ("raw.githubusercontent.com",)
WIZ_KEYV_INTERVAL_SECONDS = 300
MAX_SOURCE_BYTES = 1024 * 1024
MAX_ROWS = 5000
MAX_PACKAGE_LENGTH = 512
MAX_VERSION_LENGTH = 160
PACKAGE_RE = re.compile(r"^[A-Za-z0-9@._:/+\-]+$")
VERSION_RE = re.compile(r"^[A-Za-z0-9.+:_~!*/\-]+$")


@contextmanager
def _write_transaction(connection, db_path: Optional[str]):
    """Serialize external-intel state commits with registry and Edge writes."""
    with sqlite_writer_lock(db_path):
        with connection:
            yield connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _parse_time(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _valid_package(value: Any) -> Optional[str]:
    package = str(value or "").strip()
    if not package or len(package) > MAX_PACKAGE_LENGTH or not PACKAGE_RE.fullmatch(package):
        return None
    return package


def _valid_version(value: Any) -> Optional[str]:
    version = str(value or "").strip()
    if not version or len(version) > MAX_VERSION_LENGTH or not VERSION_RE.fullmatch(version):
        return None
    return version


def _versions(value: Any) -> List[str]:
    result: List[str] = []
    for item in str(value or "").split(","):
        version = _valid_version(item)
        if version and version not in result:
            result.append(version)
    return result[:32]


def _seed_source(db_path: Optional[str]) -> None:
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            connection.execute(
                """INSERT INTO research_external_advisory_sources
                   (source_id, ecosystem, name, source_url, interval_seconds,
                    status, created_at, updated_at)
                   VALUES (?, 'npm', ?, ?, ?, 'new', ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET name=excluded.name,
                   source_url=excluded.source_url,
                   interval_seconds=excluded.interval_seconds,
                   updated_at=excluded.updated_at""",
                (
                    WIZ_KEYV_SOURCE_ID,
                    "Wiz Research Keyv/Cacheable campaign package list",
                    WIZ_KEYV_SOURCE_URL,
                    WIZ_KEYV_INTERVAL_SECONDS,
                    now,
                    now,
                ),
            )


def _source_due(db_path: Optional[str], *, force: bool) -> Tuple[bool, Optional[Dict[str, Any]]]:
    _seed_source(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM research_external_advisory_sources WHERE source_id = ?",
            (WIZ_KEYV_SOURCE_ID,),
        ).fetchone()
    current = dict(row) if row else None
    if force or not current or not current.get("last_fetch_at"):
        return True, current
    fetched = _parse_time(current.get("last_fetch_at"))
    if fetched is None:
        return True, current
    return datetime.now(timezone.utc) - fetched >= timedelta(seconds=WIZ_KEYV_INTERVAL_SECONDS), current


def _record_source_failure(db_path: Optional[str], error: str) -> None:
    now = _now()
    dedupe = f"external-advisory-source:{WIZ_KEYV_SOURCE_ID}:{now[:10]}"
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            connection.execute(
                """UPDATE research_external_advisory_sources
                   SET status='failed', last_error=?, updated_at=?
                   WHERE source_id=?""",
                (str(error)[:2000], now, WIZ_KEYV_SOURCE_ID),
            )
            connection.execute(
                """INSERT INTO research_alerts
                   (alert_id, alert_type, severity, candidate_id, campaign_id,
                    case_id, dedupe_key, reason, evidence_json, status, owner,
                    created_at, updated_at)
                   VALUES (?, 'external_advisory_feed_degraded', 'high', NULL,
                    NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
                   ON CONFLICT(dedupe_key) DO UPDATE SET reason=excluded.reason,
                    evidence_json=excluded.evidence_json, updated_at=excluded.updated_at,
                    status='open'""",
                (
                    f"RAL-{hashlib.sha256(dedupe.encode()).hexdigest()[:16].upper()}",
                    dedupe,
                    "Public advisory feed refresh failed; external campaign coverage is stale.",
                    _json({
                        "schema_version": SCHEMA_VERSION,
                        "source_id": WIZ_KEYV_SOURCE_ID,
                        "source_url": WIZ_KEYV_SOURCE_URL,
                        "error": str(error)[:1000],
                    }),
                    now,
                    now,
                ),
            )


def _parse_keyv_csv(body: bytes) -> List[Tuple[str, str]]:
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IntakeError("external advisory feed is not UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    fields = {str(field or "").strip().lower() for field in (reader.fieldnames or [])}
    if not {"package", "malicious versions"}.issubset(fields):
        raise IntakeError("external advisory feed has an unexpected schema")
    rows: List[Tuple[str, str]] = []
    for raw in reader:
        if len(rows) >= MAX_ROWS:
            raise IntakeError("external advisory feed exceeds the row limit")
        package = _valid_package(raw.get("Package") or raw.get("package"))
        if not package:
            continue
        raw_versions = raw.get("Malicious Versions") or raw.get("malicious versions") or ""
        for version in _versions(raw_versions):
            rows.append((package, version))
    if not rows:
        raise IntakeError("external advisory feed contained no valid package versions")
    return list(dict.fromkeys(rows))


def refresh_keyv_advisory(*, db_path: Optional[str] = None, fetcher: Optional[SafeFetcher] = None, force: bool = False) -> Dict[str, Any]:
    """Refresh the public Keyv/Cacheable package list and preserve provenance."""
    soc_store.init_db(db_path)
    due, source = _source_due(db_path, force=force)
    if not due:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "skipped",
            "source_id": WIZ_KEYV_SOURCE_ID,
            "last_fetch_at": (source or {}).get("last_fetch_at"),
        }
    fetcher = fetcher or SafeFetcher()
    now = _now()
    try:
        _final_url, _headers, body = fetcher.get(
            WIZ_KEYV_SOURCE_URL,
            allowed_hosts=WIZ_KEYV_ALLOWED_HOSTS,
            max_bytes=MAX_SOURCE_BYTES,
            headers={"Accept": "text/csv, text/plain"},
        )
        rows = _parse_keyv_csv(body)
    except Exception as exc:
        _record_source_failure(db_path, str(exc))
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
            "source_id": WIZ_KEYV_SOURCE_ID,
            "error": str(exc)[:1000],
        }

    source_hash = hashlib.sha256(body).hexdigest()
    seen: List[str] = []
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            for package, version in rows:
                record_id = "EXT-" + hashlib.sha256(
                    f"{WIZ_KEYV_SOURCE_ID}|npm|{package}|{version}".encode()
                ).hexdigest()[:24].upper()
                seen.append(record_id)
                evidence = {
                    "schema_version": SCHEMA_VERSION,
                    "source_id": WIZ_KEYV_SOURCE_ID,
                    "source_url": WIZ_KEYV_SOURCE_URL,
                    "source_hash": source_hash,
                    "source_name": "Wiz Research",
                    "advisory_id": "SECOPSAI-EXT-2026-08-KEYV-CACHEABLE",
                    "campaign_id": "keyv-cacheable-npm-worm-2026-08",
                    "ecosystem": "npm",
                    "package": package,
                    "version": version,
                    "validation_state": "unverified",
                    "local_exposure_required": False,
                }
                connection.execute(
                    """INSERT INTO research_external_advisory_records
                       (record_id, source_id, advisory_id, campaign_id, ecosystem,
                        package, version, severity, confidence, source_url,
                        source_hash, evidence_json, active, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, 'npm', ?, ?, 'high', 'reported',
                        ?, ?, ?, 1, ?, ?)
                       ON CONFLICT(source_id, ecosystem, package, version) DO UPDATE
                       SET source_hash=excluded.source_hash,
                           evidence_json=excluded.evidence_json,
                           active=1, last_seen=excluded.last_seen""",
                    (
                        record_id,
                        WIZ_KEYV_SOURCE_ID,
                        "SECOPSAI-EXT-2026-08-KEYV-CACHEABLE",
                        "keyv-cacheable-npm-worm-2026-08",
                        package,
                        version,
                        WIZ_KEYV_SOURCE_URL,
                        source_hash,
                        _json(evidence),
                        now,
                        now,
                    ),
                )
            if seen:
                placeholders = ",".join("?" for _ in seen)
                connection.execute(
                    f"UPDATE research_external_advisory_records SET active=0, last_seen=? WHERE source_id=? AND record_id NOT IN ({placeholders})",
                    (now, WIZ_KEYV_SOURCE_ID, *seen),
                )
            connection.execute(
                """UPDATE research_external_advisory_sources
                   SET last_fetch_at=?, source_hash=?, status='completed',
                       last_error=NULL, updated_at=? WHERE source_id=?""",
                (now, source_hash, now, WIZ_KEYV_SOURCE_ID),
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "source_id": WIZ_KEYV_SOURCE_ID,
        "source_hash": source_hash,
        "records": len(rows),
        "packages": len({package for package, _version in rows}),
        "collected_at": now,
    }


def sync_advisory_candidates(*, db_path: Optional[str] = None, limit: int = 1000) -> Dict[str, Any]:
    """Create idempotent high-priority leads from current external records."""
    from secopsai.research_discovery import _json as discovery_json  # local import avoids import cycles

    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT r.*, c.candidate_id AS existing_candidate_id,
                      a.alert_id AS existing_alert_id
               FROM research_external_advisory_records r
               LEFT JOIN research_candidates c
                 ON c.ecosystem=r.ecosystem AND c.package=r.package
                AND c.version=r.version AND c.reference_identifier=r.advisory_id
               LEFT JOIN research_alerts a
                 ON a.dedupe_key = ('external-advisory:' || r.source_id || ':' ||
                                    r.package || ':' || r.version || ':' || r.source_hash)
               WHERE r.source_id=? AND r.active=1
                 AND (c.candidate_id IS NULL OR a.alert_id IS NULL)
               ORDER BY r.package, r.version LIMIT ?""",
            (WIZ_KEYV_SOURCE_ID, max(1, min(int(limit), 5000))),
        ).fetchall()
    created = 0
    alerts = 0
    candidate_ids: List[str] = []
    for row in rows:
        record = dict(row)
        evidence = json.loads(record.get("evidence_json") or "{}")
        candidate_id = "CAN-" + hashlib.sha256(
            f"{record['advisory_id']}|{record['ecosystem']}|{record['package']}|{record['version']}".encode()
        ).hexdigest()[:24].upper()
        reason = (
            f"External advisory reports {record['package']}@{record['version']} in the active "
            "Keyv/Cacheable npm campaign. This is a source-backed lead, not a local exposure verdict; "
            "collect and verify the exact artifact before publication."
        )
        with closing(soc_store.connect(db_path)) as connection:
            now = _now()
            with _write_transaction(connection, db_path):
                if not record.get("existing_candidate_id"):
                    connection.execute(
                    """INSERT INTO research_candidates
                       (candidate_id, event_id, watchlist_id, ecosystem, package,
                        version, reference_identifier, score, score_components_json,
                        reason, status, case_id, evidence_json, first_seen, last_seen,
                        algorithm_version)
                       VALUES (?, NULL, NULL, ?, ?, ?, ?, 99, ?, ?, 'new', NULL, ?, ?, ?, ?)
                       ON CONFLICT(ecosystem, package, version, reference_identifier)
                       DO UPDATE SET score=excluded.score,
                         score_components_json=excluded.score_components_json,
                         reason=excluded.reason, evidence_json=excluded.evidence_json,
                         last_seen=excluded.last_seen""",
                    (
                        candidate_id,
                        record["ecosystem"],
                        record["package"],
                        record["version"],
                        record["advisory_id"],
                        discovery_json({
                            "source_backed": True,
                            "advisory_score": 99,
                            "local_exposure_required": False,
                            "source_hash": record["source_hash"],
                        }),
                        reason,
                        record["evidence_json"],
                        record["first_seen"],
                        now,
                        "external-advisory.v1",
                    ),
                )
                    created += 1
                candidate = connection.execute(
                    """SELECT * FROM research_candidates WHERE ecosystem=? AND package=?
                       AND version=? AND reference_identifier=?""",
                    (record["ecosystem"], record["package"], record["version"], record["advisory_id"]),
                ).fetchone()
        if not candidate:
            continue
        candidate_payload = dict(candidate)
        candidate_payload["evidence"] = evidence
        candidate_payload["campaign_id"] = record["campaign_id"]
        candidate_payload["score_components"] = {
            "source_backed": True,
            "advisory": record["advisory_id"],
            "local_exposure_required": False,
        }
        with sqlite_writer_lock(db_path):
            alert = create_candidate_alert(
                candidate_payload,
                db_path=db_path,
                alert_type="external_advisory_match",
                dedupe_key=(
                    f"external-advisory:{record['source_id']}:{record['package']}"
                    f":{record['version']}:{record['source_hash']}"
                ),
                reason_override=reason,
            )
        if alert.get("alert_id"):
            alerts += 1
        candidate_ids.append(str(candidate_payload["candidate_id"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "records_seen": len(rows),
        "candidates_created": created,
        "alerts_upserted": alerts,
        "candidate_ids": candidate_ids,
    }


def refresh_and_sync(*, db_path: Optional[str] = None, fetcher: Optional[SafeFetcher] = None, force: bool = False) -> Dict[str, Any]:
    refresh = refresh_keyv_advisory(db_path=db_path, fetcher=fetcher, force=force)
    sync = sync_advisory_candidates(db_path=db_path)
    return {"schema_version": SCHEMA_VERSION, "refresh": refresh, "sync": sync}
