"""Global registry surveillance: continuous event-feed collectors.

This module implements registry-wide ingestion as distinct from the
watchlist-scoped monitors in ``research_discovery``. Checkpoint 1 covers
the NuGet V3 Catalog: chronological cursor pages, idempotent event
persistence, coverage-gap detection, and dead-letter retry handling.

Collectors record registry metadata events only. They never download or
execute package artifacts; artifact intake remains the bounded,
quarantined path in ``research_intake``.
"""

from __future__ import annotations

import json
import random
import sqlite3
import time
import urllib.parse
import uuid
import zlib
import hashlib
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import soc_store
from secopsai.research_discovery import seed_registry_sources
from secopsai.research_intake import IntakeError, SafeFetcher

NUGET_CATALOG_INDEX_URL = "https://api.nuget.org/v3/catalog0/index.json"
NUGET_ALLOWED_HOSTS: Tuple[str, ...] = ("api.nuget.org",)
PACKAGIST_CHANGES_URL = "https://packagist.org/metadata/changes.json"
PACKAGIST_ALLOWED_HOSTS: Tuple[str, ...] = ("packagist.org",)
PYPI_SIMPLE_INDEX_URL = "https://pypi.org/simple/"
PYPI_ALLOWED_HOSTS: Tuple[str, ...] = ("pypi.org",)
PYPI_SIMPLE_JSON_ACCEPT = "application/vnd.pypi.simple.v1+json"
RUBYGEMS_TIMEFRAME_URL = "https://rubygems.org/api/v1/timeframe_versions.json"
RUBYGEMS_ALLOWED_HOSTS: Tuple[str, ...] = ("rubygems.org",)
NPM_REPLICATE_URL = "https://replicate.npmjs.com/_changes"
NPM_REPLICATE_ROOT_URL = "https://replicate.npmjs.com/"
NPM_ALLOWED_HOSTS: Tuple[str, ...] = ("replicate.npmjs.com",)
GO_INDEX_URL = "https://index.golang.org/index"
GO_ALLOWED_HOSTS: Tuple[str, ...] = ("index.golang.org",)

MAX_CATALOG_INDEX_BYTES = 8 * 1024 * 1024
MAX_CATALOG_PAGE_BYTES = 32 * 1024 * 1024
MAX_CHANGES_BYTES = 32 * 1024 * 1024
MAX_SIMPLE_INDEX_BYTES = 128 * 1024 * 1024
MAX_TIMEFRAME_PAGE_BYTES = 8 * 1024 * 1024
MAX_NPM_CHANGES_BYTES = 32 * 1024 * 1024
MAX_GO_INDEX_BYTES = 16 * 1024 * 1024
MAX_LEAF_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_PAGES = 10
DEFAULT_LOOKBACK_HOURS = 24
DEFAULT_MAX_WINDOW_HOURS = 24
DEFAULT_NPM_PAGE_LIMIT = 5000
DEFAULT_GO_PAGE_LIMIT = 2000
MAX_DEAD_LETTER_ATTEMPTS = 8
DEFAULT_MAX_DIFF_EVENTS = 10000
ALGORITHM_VERSION = "registry-surveillance.v1"
PACKAGIST_BOOTSTRAP_CURSOR = "0"

COLLECTOR_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "nuget": {
        "collector_id": "COL-NUGET-CATALOG",
        "source_id": "REG-NUGET",
        "name": "NuGet V3 Catalog",
        "feed_url": NUGET_CATALOG_INDEX_URL,
        "mode": "event_feed",
        "allowed_hosts": NUGET_ALLOWED_HOSTS,
        "coverage_mode": "catalog_chronological",
        "cursor_seed": "lookback",
        "interval_seconds": 900,
    },
    "packagist": {
        "collector_id": "COL-PACKAGIST-CHANGES",
        "source_id": "REG-PACKAGIST",
        "name": "Packagist metadata changes",
        "feed_url": PACKAGIST_CHANGES_URL,
        "mode": "event_feed",
        "allowed_hosts": PACKAGIST_ALLOWED_HOSTS,
        "coverage_mode": "changes_feed_bounded_retention",
        # Packagist keeps the metadata change log for a bounded window only;
        # the cursor must stay comfortably inside it or events are lost
        # silently. The safety window alarms well before that happens.
        "cursor_seed": "bootstrap",
        "cursor_multiplier": 10000,
        "overlap_seconds": 300,
        "retention_seconds": 86400,
        "retention_safety_seconds": 64800,
        "interval_seconds": 900,
    },
    "pypi": {
        "collector_id": "COL-PYPI-INDEX",
        "source_id": "REG-PYPI",
        "name": "PyPI Simple Index",
        "feed_url": PYPI_SIMPLE_INDEX_URL,
        "mode": "index_reconcile",
        "allowed_hosts": PYPI_ALLOWED_HOSTS,
        "coverage_mode": "simple_index_reconciliation",
        # PyPI exposes no chronological event feed; the simple index serial
        # only signals that something changed. Reconciliation diffs full
        # index snapshots, so project add/remove events are complete but
        # per-release detection needs watchlist polling or backfill.
        "cursor_seed": "zero",
        "cursor_multiplier": 1,
        # The simple index is a multi-megabyte full-document fetch; hourly
        # reconciliation is the respectful default.
        "interval_seconds": 3600,
    },
    "rubygems": {
        "collector_id": "COL-RUBYGEMS-TIMEFRAME",
        "source_id": "REG-RUBYGEMS",
        "name": "RubyGems timeframe versions",
        "feed_url": RUBYGEMS_TIMEFRAME_URL,
        "mode": "timeframe_poll",
        "allowed_hosts": RUBYGEMS_ALLOWED_HOSTS,
        "coverage_mode": "timeframe_windowed_pagination",
        # timeframe_versions returns version-created events with real
        # timestamps inside a bounded window. The cursor only advances
        # when the window drains (an empty page), so heavy publication
        # bursts cannot be skipped silently.
        "cursor_seed": "lookback",
        "overlap_seconds": 300,
        "max_window_hours": DEFAULT_MAX_WINDOW_HOURS,
        "interval_seconds": 1800,
    },
    "npm": {
        "collector_id": "COL-NPM-CHANGES",
        "source_id": "REG-NPM",
        "name": "npm replicate changes",
        "feed_url": NPM_REPLICATE_URL,
        "mode": "event_feed",
        "allowed_hosts": NPM_ALLOWED_HOSTS,
        "coverage_mode": "couchdb_changes_seq",
        # The CouchDB-style replica feed is totally ordered by sequence.
        # Cursor "0" bootstraps live from update_seq; --since backfills.
        # The feed carries no per-event timestamps, so ledger timestamps
        # are collection times and say so in event metadata.
        "cursor_seed": "zero",
        "cursor_multiplier": 1,
        "page_limit": DEFAULT_NPM_PAGE_LIMIT,
        "interval_seconds": 900,
    },
    "go": {
        "collector_id": "COL-GO-INDEX",
        "source_id": "REG-GO",
        "name": "Go module index",
        "feed_url": GO_INDEX_URL,
        "mode": "event_feed",
        "allowed_hosts": GO_ALLOWED_HOSTS,
        "coverage_mode": "module_version_index",
        # The official module index is a chronological NDJSON feed of new
        # module versions. Each batch persists with its cursor advance in
        # one transaction. Retractions and deletions are not index events;
        # the capability registry states that limitation.
        "cursor_seed": "lookback",
        "page_limit": DEFAULT_GO_PAGE_LIMIT,
        "interval_seconds": 900,
    },
}


class CollectorError(RuntimeError):
    """Raised when a collector run cannot proceed safely."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _format_ts(value: datetime) -> str:
    """Fixed-width millisecond UTC format so cursors sort lexicographically."""
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _parse_ts(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise CollectorError("registry payload is missing a timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise CollectorError(f"registry timestamp is not ISO 8601: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16].upper()}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def ensure_collectors(*, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Seed collector rows and cursors for every defined global feed."""
    seed_registry_sources(db_path=db_path)
    now = _format_ts(_utcnow())
    seeded: List[Dict[str, Any]] = []
    with closing(soc_store.connect(db_path)) as connection:
        for ecosystem, definition in COLLECTOR_DEFINITIONS.items():
            config = {
                "allowed_hosts": list(definition["allowed_hosts"]),
                "algorithm_version": ALGORITHM_VERSION,
            }
            for key in ("cursor_multiplier", "overlap_seconds", "retention_seconds", "retention_safety_seconds", "max_window_hours", "interval_seconds", "page_limit"):
                if key in definition:
                    config[key] = definition[key]
            connection.execute(
                """INSERT INTO registry_collectors
                (collector_id, source_id, ecosystem, name, feed_url, mode, enabled, config_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(collector_id) DO UPDATE SET feed_url=excluded.feed_url,
                mode=excluded.mode, config_json=excluded.config_json, updated_at=excluded.updated_at""",
                (
                    definition["collector_id"],
                    definition["source_id"],
                    ecosystem,
                    definition["name"],
                    definition["feed_url"],
                    definition["mode"],
                    _json(config),
                    now,
                    now,
                ),
            )
            if definition.get("cursor_seed") in {"bootstrap", "zero"}:
                cursor_seed = PACKAGIST_BOOTSTRAP_CURSOR
            else:
                cursor_seed = _format_ts(_utcnow() - timedelta(hours=DEFAULT_LOOKBACK_HOURS))
            connection.execute(
                """INSERT INTO registry_cursors (collector_id, cursor_value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(collector_id) DO NOTHING""",
                (
                    definition["collector_id"],
                    cursor_seed,
                    now,
                ),
            )
        connection.commit()
        rows = connection.execute(
            "SELECT * FROM registry_collectors ORDER BY ecosystem"
        ).fetchall()
        for row in rows:
            cursor = connection.execute(
                "SELECT * FROM registry_cursors WHERE collector_id = ?",
                (row["collector_id"],),
            ).fetchone()
            seeded.append(dict(row) | {"cursor": dict(cursor) if cursor else None})
    return seeded


def get_collector(collector_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    ensure_collectors(db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM registry_collectors WHERE collector_id = ?", (collector_id,)
        ).fetchone()
        if row is None:
            raise CollectorError(f"unknown collector: {collector_id}")
        cursor = connection.execute(
            "SELECT * FROM registry_cursors WHERE collector_id = ?", (collector_id,)
        ).fetchone()
    return dict(row) | {"cursor": dict(cursor) if cursor else None}


def set_collector_enabled(*, ecosystem: str, enabled: bool, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Pause or resume a collector. A paused collector keeps its cursor,
    coverage history, and dead letters; runs are refused until resumed."""
    collector = _collector_for_ecosystem(ecosystem, db_path=db_path)
    now = _format_ts(_utcnow())
    with closing(soc_store.connect(db_path)) as connection:
        with connection:
            connection.execute(
                "UPDATE registry_collectors SET enabled = ?, updated_at = ? WHERE collector_id = ?",
                (1 if enabled else 0, now, collector["collector_id"]),
            )
    updated = get_collector(collector["collector_id"], db_path=db_path)
    return {
        "collector_id": updated["collector_id"],
        "ecosystem": updated["ecosystem"],
        "enabled": bool(updated["enabled"]),
        "cursor": (updated.get("cursor") or {}).get("cursor_value"),
    }


def _collector_for_ecosystem(ecosystem: str, *, db_path: Optional[str]) -> Dict[str, Any]:
    key = str(ecosystem or "").strip().lower()
    if key not in COLLECTOR_DEFINITIONS:
        supported = ", ".join(sorted(COLLECTOR_DEFINITIONS))
        raise CollectorError(f"no global collector is defined for {ecosystem!r}; supported: {supported}")
    return get_collector(COLLECTOR_DEFINITIONS[key]["collector_id"], db_path=db_path)


def _event_type(raw_type: Any) -> str:
    values = raw_type if isinstance(raw_type, list) else [raw_type]
    lowered = [str(value).lower() for value in values if value]
    if any(value.endswith("packagedelete") for value in lowered):
        return "deleted"
    if any(value.endswith("packagedetails") for value in lowered):
        return "published"
    return "unknown"


def _idempotency_key(ecosystem: str, package: str, version: str, timestamp: str, event_type: str) -> str:
    return "|".join([ecosystem, package.strip().lower(), version.strip().lower(), timestamp, event_type])


def _fetch_json(fetcher: SafeFetcher, url: str, *, allowed_hosts: Iterable[str], max_bytes: int) -> Dict[str, Any]:
    payload, _headers = _fetch_json_response(fetcher, url, allowed_hosts=allowed_hosts, max_bytes=max_bytes)
    return payload


def _fetch_json_response(
    fetcher: SafeFetcher,
    url: str,
    *,
    allowed_hosts: Iterable[str],
    max_bytes: int,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    _final_url, response_headers, body = fetcher.get(url, allowed_hosts=allowed_hosts, max_bytes=max_bytes, headers=headers)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError("registry response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise IntakeError("registry response was not a JSON object")
    return payload, response_headers


def _fetch_json_array(
    fetcher: SafeFetcher,
    url: str,
    *,
    allowed_hosts: Iterable[str],
    max_bytes: int,
) -> List[Any]:
    _final_url, _headers, body = fetcher.get(url, allowed_hosts=allowed_hosts, max_bytes=max_bytes)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError("registry response was not valid JSON") from exc
    if not isinstance(payload, list):
        raise IntakeError("registry response was not a JSON array")
    return payload


def _fetch_ndjson(
    fetcher: SafeFetcher,
    url: str,
    *,
    allowed_hosts: Iterable[str],
    max_bytes: int,
) -> List[Dict[str, Any]]:
    """Fetch a newline-delimited JSON stream. Empty body means caught up."""
    _final_url, _headers, body = fetcher.get(url, allowed_hosts=allowed_hosts, max_bytes=max_bytes)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntakeError("registry response was not valid UTF-8") from exc
    records: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IntakeError("registry NDJSON stream contained an invalid record") from exc
        if not isinstance(record, dict):
            raise IntakeError("registry NDJSON record was not a JSON object")
        records.append(record)
    return records


def _record_dead_letter(
    connection: sqlite3.Connection,
    *,
    collector_id: str,
    run_id: str,
    url: str,
    item_kind: str,
    payload: Any,
    error: str,
) -> None:
    now = _format_ts(_utcnow())
    connection.execute(
        """INSERT INTO registry_dead_letters
        (dead_letter_id, collector_id, run_id, url, item_kind, payload_json, error_message,
         attempts, next_retry_at, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 'pending', ?, ?)""",
        (
            _id("RDL"),
            collector_id,
            run_id,
            url,
            item_kind,
            _json(payload),
            error[:500],
            _format_ts(_utcnow() + timedelta(seconds=60)),
            now,
            now,
        ),
    )


def _persist_page_events(
    connection: sqlite3.Connection,
    *,
    collector: Dict[str, Any],
    page_url: str,
    page: Dict[str, Any],
    cursor_before: str,
    fetch_leaves: bool,
    fetcher: SafeFetcher,
    run_id: str,
) -> Dict[str, int]:
    """Persist one catalog page and advance the cursor in a single transaction.

    The cursor moves to the page commit timestamp only after every event in
    the page has been written, so a crash mid-page can never skip events.
    """
    allowed_hosts = _decode(collector["config_json"], {}).get("allowed_hosts", [])
    counts = {"seen": 0, "stored": 0, "duplicate": 0, "leaf_failures": 0}
    page_commit = _format_ts(_parse_ts(str(page.get("commitTimestamp") or "")))
    now = _format_ts(_utcnow())
    items = page.get("items")
    if not isinstance(items, list):
        raise CollectorError("catalog page did not contain an items list")

    with connection:
        for item in items:
            if not isinstance(item, dict):
                continue
            item_ts_raw = str(item.get("commitTimestamp") or "")
            if not item_ts_raw:
                continue
            item_ts = _format_ts(_parse_ts(item_ts_raw))
            if item_ts <= cursor_before:
                continue
            counts["seen"] += 1
            package = str(item.get("nuget:id") or item.get("id") or "").strip()
            version = str(item.get("nuget:version") or item.get("version") or "").strip()
            leaf_url = str(item.get("@id") or "").strip()
            if not package or not version or not leaf_url:
                continue
            event_type = _event_type(item.get("@type"))
            key = _idempotency_key(collector["ecosystem"], package, version, item_ts, event_type)
            metadata: Dict[str, Any] = {"catalog_types": item.get("@type"), "algorithm_version": ALGORITHM_VERSION}
            leaf_fetched = 0
            cursor = connection.execute(
                """INSERT INTO registry_feed_events
                (feed_event_id, collector_id, ecosystem, package, version, event_type,
                 registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
                 idempotency_key, collected_at, processing_state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 'pending')
                ON CONFLICT(idempotency_key) DO NOTHING""",
                (
                    _id("RFE"),
                    collector["collector_id"],
                    collector["ecosystem"],
                    package,
                    version,
                    event_type,
                    item_ts,
                    page_url,
                    leaf_url,
                    _json(metadata),
                    key,
                    now,
                ),
            )
            if cursor.rowcount == 0:
                counts["duplicate"] += 1
                continue
            counts["stored"] += 1

            if fetch_leaves and event_type == "published":
                try:
                    leaf = _fetch_json(fetcher, leaf_url, allowed_hosts=allowed_hosts, max_bytes=MAX_LEAF_BYTES)
                    metadata.update(
                        {
                            "authors": leaf.get("authors") or leaf.get("owners") or "",
                            "description": str(leaf.get("description") or "")[:2000],
                            "listed": leaf.get("listed"),
                            "published": leaf.get("published") or "",
                            "project_url": leaf.get("projectUrl") or "",
                            "tags": leaf.get("tags") or [],
                        }
                    )
                    leaf_fetched = 1
                    connection.execute(
                        "UPDATE registry_feed_events SET leaf_fetched = 1, metadata_json = ? WHERE idempotency_key = ?",
                        (_json(metadata), key),
                    )
                except (IntakeError, CollectorError) as exc:
                    counts["leaf_failures"] += 1
                    _record_dead_letter(
                        connection,
                        collector_id=collector["collector_id"],
                        run_id=run_id,
                        url=leaf_url,
                        item_kind="leaf",
                        payload={"idempotency_key": key, "package": package, "version": version},
                        error=str(exc),
                    )

        connection.execute(
            "UPDATE registry_cursors SET cursor_value = ?, last_event_at = ?, last_run_id = ?, updated_at = ? WHERE collector_id = ?",
            (page_commit, page_commit, run_id, now, collector["collector_id"]),
        )
    return counts


def _open_run(*, collector: Dict[str, Any], cursor_before: str, db_path: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    run_id = _id("RIR")
    now = _format_ts(_utcnow())
    with closing(soc_store.connect(db_path)) as connection:
        try:
            with connection:
                connection.execute(
                    """INSERT INTO registry_ingestion_runs
                    (run_id, collector_id, status, cursor_before, cursor_after, coverage_mode, started_at)
                    VALUES (?, ?, 'running', ?, ?, ?, ?)""",
                    (run_id, collector["collector_id"], cursor_before, cursor_before, collector["mode"], now),
                )
        except sqlite3.IntegrityError:
            return None, {
                "run_id": None,
                "collector_id": collector["collector_id"],
                "status": "rejected",
                "reason": "collector already has an active run",
            }
    return run_id, None


def _close_run(
    *,
    collector: Dict[str, Any],
    run_id: str,
    cursor_before: str,
    outcome: Dict[str, Any],
    db_path: Optional[str],
) -> Dict[str, Any]:
    error_message = outcome.get("error")
    status = "failed" if error_message else "completed"
    finished = _format_ts(_utcnow())
    gap = error_message is not None and outcome["pages_processed"] < outcome["pages_selected"]
    with closing(soc_store.connect(db_path)) as connection:
        with connection:
            connection.execute(
                """UPDATE registry_ingestion_runs
                SET status = ?, cursor_after = ?, pages_processed = ?, events_seen = ?,
                    events_stored = ?, events_duplicate = ?, failures = ?, error_message = ?, completed_at = ?
                WHERE run_id = ?""",
                (
                    status,
                    outcome["cursor_after"],
                    outcome["pages_processed"],
                    outcome["events_seen"],
                    outcome["events_stored"],
                    outcome["events_duplicate"],
                    outcome["leaf_failures"] + (1 if error_message else 0),
                    error_message,
                    finished,
                    run_id,
                ),
            )
            connection.execute(
                """INSERT INTO registry_coverage_windows
                (window_id, collector_id, run_id, window_start, window_end, expected_pages,
                 processed_pages, events_stored, state, gap_reason, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    _id("RCW"),
                    collector["collector_id"],
                    run_id,
                    cursor_before,
                    outcome["cursor_after"],
                    outcome["pages_selected"],
                    outcome["pages_processed"],
                    outcome["events_stored"],
                    "gap" if gap else "complete",
                    error_message if gap else None,
                    finished,
                    finished,
                ),
            )
    return {
        "run_id": run_id,
        "collector_id": collector["collector_id"],
        "ecosystem": collector["ecosystem"],
        "status": status,
        "cursor_before": cursor_before,
        "cursor_after": outcome["cursor_after"],
        "pages_selected": outcome["pages_selected"],
        "pages_processed": outcome["pages_processed"],
        "events_seen": outcome["events_seen"],
        "events_stored": outcome["events_stored"],
        "events_duplicate": outcome["events_duplicate"],
        "leaf_failures": outcome["leaf_failures"],
        "coverage": "gap" if gap else "complete",
        "error": error_message,
        "algorithm_version": ALGORITHM_VERSION,
    }


def _empty_outcome(cursor_before: str) -> Dict[str, Any]:
    return {
        "cursor_after": cursor_before,
        "pages_selected": 0,
        "pages_processed": 0,
        "events_seen": 0,
        "events_stored": 0,
        "events_duplicate": 0,
        "leaf_failures": 0,
        "anomalies": [],
        "diff_truncated": False,
        "window_incomplete": False,
        "error": None,
    }


def _ingest_nuget_catalog(
    *,
    collector: Dict[str, Any],
    cursor_before: str,
    max_pages: int,
    fetch_leaves: bool,
    fetcher: SafeFetcher,
    run_id: str,
    db_path: Optional[str],
) -> Dict[str, Any]:
    """Walk chronological catalog pages. The first failing page stops the
    run so the durable cursor never jumps over unprocessed history."""
    allowed_hosts = _decode(collector["config_json"], {}).get("allowed_hosts", [])
    outcome = _empty_outcome(cursor_before)
    try:
        index = _fetch_json(fetcher, collector["feed_url"], allowed_hosts=allowed_hosts, max_bytes=MAX_CATALOG_INDEX_BYTES)
        pages = [
            item
            for item in index.get("items", [])
            if isinstance(item, dict) and item.get("@id") and item.get("commitTimestamp")
        ]
        pages.sort(key=lambda item: _format_ts(_parse_ts(str(item["commitTimestamp"]))))
        pending_pages = [item for item in pages if _format_ts(_parse_ts(str(item["commitTimestamp"]))) > cursor_before]
        selected = pending_pages[:max_pages]
        outcome["pages_selected"] = len(selected)

        with closing(soc_store.connect(db_path)) as connection:
            for page_ref in selected:
                page_url = str(page_ref["@id"])
                try:
                    page = _fetch_json(fetcher, page_url, allowed_hosts=allowed_hosts, max_bytes=MAX_CATALOG_PAGE_BYTES)
                except (IntakeError, CollectorError) as exc:
                    outcome["error"] = f"page fetch failed: {exc}"
                    with connection:
                        _record_dead_letter(
                            connection,
                            collector_id=collector["collector_id"],
                            run_id=run_id,
                            url=page_url,
                            item_kind="page",
                            payload={"commitTimestamp": page_ref.get("commitTimestamp")},
                            error=str(exc),
                        )
                    break
                counts = _persist_page_events(
                    connection,
                    collector=collector,
                    page_url=page_url,
                    page=page,
                    cursor_before=outcome["cursor_after"],
                    fetch_leaves=fetch_leaves,
                    fetcher=fetcher,
                    run_id=run_id,
                )
                outcome["events_seen"] += counts.get("seen", 0)
                outcome["events_stored"] += counts.get("stored", 0)
                outcome["events_duplicate"] += counts.get("duplicate", 0)
                outcome["leaf_failures"] += counts.get("leaf_failures", 0)
                outcome["pages_processed"] += 1
                outcome["cursor_after"] = _format_ts(_parse_ts(str(page.get("commitTimestamp"))))
    except (IntakeError, CollectorError) as exc:
        outcome["error"] = str(exc)
    return outcome


def _parse_packagist_since(value: str, multiplier: int) -> str:
    """Accept a raw composite cursor or an ISO datetime for convenience."""
    text = str(value).strip()
    if text.isdigit():
        return text
    return str(int(_parse_ts(text).timestamp()) * multiplier)


def _packagist_event_type(raw_type: str) -> str:
    normalized = str(raw_type or "").strip().lower()
    if normalized == "update":
        return "published"
    if normalized == "delete":
        return "deleted"
    return "unknown"


def _ingest_packagist_changes(
    *,
    collector: Dict[str, Any],
    cursor_before: str,
    fetcher: SafeFetcher,
    run_id: str,
    db_path: Optional[str],
) -> Dict[str, Any]:
    """Ingest the Packagist metadata change log in a single bounded fetch.

    The server returns every retained action after the composite cursor and
    a new authoritative cursor. Because the change log has bounded
    retention, the cursor is requested with a small overlap to tolerate
    clock skew; idempotency keys absorb the duplicated actions.
    """
    config = _decode(collector["config_json"], {})
    allowed_hosts = config.get("allowed_hosts", [])
    multiplier = int(config.get("cursor_multiplier", 10000))
    overlap = int(config.get("overlap_seconds", 300)) * multiplier
    outcome = _empty_outcome(cursor_before)
    outcome["pages_selected"] = 1

    since_value = max(0, int(cursor_before) - overlap)
    feed_url = f"{collector['feed_url']}?since={since_value}"
    try:
        payload = _fetch_json(fetcher, feed_url, allowed_hosts=allowed_hosts, max_bytes=MAX_CHANGES_BYTES)
    except (IntakeError, CollectorError) as exc:
        outcome["error"] = f"changes feed fetch failed: {exc}"
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                _record_dead_letter(
                    connection,
                    collector_id=collector["collector_id"],
                    run_id=run_id,
                    url=feed_url,
                    item_kind="feed",
                    payload={"since": since_value},
                    error=str(exc),
                )
        return outcome

    actions = payload.get("actions")
    if not isinstance(actions, list):
        outcome["error"] = "changes feed response did not contain an actions list"
        return outcome
    response_cursor = str(payload.get("timestamp") or "").strip()
    if not response_cursor.isdigit():
        outcome["error"] = "changes feed response did not contain a valid cursor"
        return outcome
    # A stale or anomalous server response must never rewind the cursor.
    new_cursor = str(max(int(response_cursor), int(cursor_before)))

    now = _format_ts(_utcnow())
    last_event_ts: Optional[str] = None
    with closing(soc_store.connect(db_path)) as connection:
        with connection:
            for action in actions:
                if not isinstance(action, dict):
                    continue
                package_raw = str(action.get("package") or "").strip()
                action_time = action.get("time")
                if not package_raw or not isinstance(action_time, (int, float)):
                    continue
                outcome["events_seen"] += 1
                channel = "release"
                package = package_raw
                if package_raw.endswith("~dev"):
                    channel = "dev"
                    package = package_raw[: -len("~dev")]
                event_type = _packagist_event_type(str(action.get("type") or ""))
                registry_ts = _format_ts(datetime.fromtimestamp(float(action_time), tz=timezone.utc))
                last_event_ts = registry_ts
                key = _idempotency_key(collector["ecosystem"], f"{package}|{channel}", "", registry_ts, event_type)
                metadata = {
                    "action_type": action.get("type"),
                    "channel": channel,
                    "raw_package": package_raw,
                    "algorithm_version": ALGORITHM_VERSION,
                }
                cursor = connection.execute(
                    """INSERT INTO registry_feed_events
                    (feed_event_id, collector_id, ecosystem, package, version, event_type,
                     registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
                     idempotency_key, collected_at, processing_state)
                    VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 0, ?, ?, ?, 'pending')
                    ON CONFLICT(idempotency_key) DO NOTHING""",
                    (
                        _id("RFE"),
                        collector["collector_id"],
                        collector["ecosystem"],
                        package,
                        event_type,
                        registry_ts,
                        feed_url,
                        f"https://repo.packagist.org/p2/{package}.json",
                        _json(metadata),
                        key,
                        now,
                    ),
                )
                if cursor.rowcount == 0:
                    outcome["events_duplicate"] += 1
                else:
                    outcome["events_stored"] += 1
            connection.execute(
                "UPDATE registry_cursors SET cursor_value = ?, last_event_at = ?, last_run_id = ?, updated_at = ? WHERE collector_id = ?",
                (new_cursor, last_event_ts, run_id, now, collector["collector_id"]),
            )
    outcome["pages_processed"] = 1
    outcome["cursor_after"] = new_cursor
    return outcome


def _latest_snapshot(connection: sqlite3.Connection, collector_id: str) -> Optional[sqlite3.Row]:
    return connection.execute(
        "SELECT * FROM registry_snapshots WHERE collector_id = ? ORDER BY created_at DESC LIMIT 1",
        (collector_id,),
    ).fetchone()


def _snapshot_names(snapshot: sqlite3.Row) -> List[str]:
    try:
        payload = json.loads(zlib.decompress(snapshot["names_blob"]).decode("utf-8"))
    except (zlib.error, UnicodeDecodeError, json.JSONDecodeError):
        return []
    return [str(name) for name in payload] if isinstance(payload, list) else []


def _insert_index_event(
    connection: sqlite3.Connection,
    *,
    collector: Dict[str, Any],
    name: str,
    event_type: str,
    serial: str,
    now: str,
) -> bool:
    key = _idempotency_key(collector["ecosystem"], name, "", serial, event_type)
    metadata = {"change": event_type, "serial": serial, "algorithm_version": ALGORITHM_VERSION}
    cursor = connection.execute(
        """INSERT INTO registry_feed_events
        (feed_event_id, collector_id, ecosystem, package, version, event_type,
         registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
         idempotency_key, collected_at, processing_state)
        VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 0, ?, ?, ?, 'pending')
        ON CONFLICT(idempotency_key) DO NOTHING""",
        (
            _id("RFE"),
            collector["collector_id"],
            collector["ecosystem"],
            name,
            event_type,
            now,
            collector["feed_url"],
            f"https://pypi.org/pypi/{name}/json",
            _json(metadata),
            key,
            now,
        ),
    )
    return cursor.rowcount > 0


def _ingest_pypi_index(
    *,
    collector: Dict[str, Any],
    cursor_before: str,
    fetcher: SafeFetcher,
    run_id: str,
    db_path: Optional[str],
    max_diff_events: int,
) -> Dict[str, Any]:
    """Reconcile the PyPI simple index against the last stored snapshot.

    PyPI exposes no chronological event feed, so coverage is honestly
    limited to project additions and removals between snapshots. The first
    run stores a baseline and emits no events.
    """
    config = _decode(collector["config_json"], {})
    allowed_hosts = config.get("allowed_hosts", [])
    outcome = _empty_outcome(cursor_before)
    outcome["pages_selected"] = 1
    try:
        payload, response_headers = _fetch_json_response(
            fetcher,
            collector["feed_url"],
            allowed_hosts=allowed_hosts,
            max_bytes=MAX_SIMPLE_INDEX_BYTES,
            headers={"Accept": PYPI_SIMPLE_JSON_ACCEPT},
        )
    except (IntakeError, CollectorError) as exc:
        outcome["error"] = f"simple index fetch failed: {exc}"
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                _record_dead_letter(
                    connection,
                    collector_id=collector["collector_id"],
                    run_id=run_id,
                    url=collector["feed_url"],
                    item_kind="feed",
                    payload={"feed": "pypi_simple_index"},
                    error=str(exc),
                )
        return outcome

    serial = str(response_headers.get("x-pypi-last-serial") or "").strip()
    if not serial:
        meta = payload.get("meta")
        if isinstance(meta, dict):
            serial = str(meta.get("_last-serial") or "").strip()
    if not serial.isdigit():
        outcome["error"] = "simple index response did not expose a valid serial"
        return outcome
    projects = payload.get("projects")
    if not isinstance(projects, list):
        outcome["error"] = "simple index response did not contain a projects list"
        return outcome
    names = sorted({str(item["name"]).strip() for item in projects if isinstance(item, dict) and item.get("name")})
    if not names:
        outcome["error"] = "simple index response contained no projects"
        return outcome

    # A serial regression is a registry-side anomaly; never overwrite newer state.
    if cursor_before.isdigit() and int(serial) < int(cursor_before):
        outcome["anomalies"] = [f"serial regressed from {cursor_before} to {serial}; snapshot skipped"]
        outcome["pages_processed"] = 1
        return outcome

    names_hash = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()
    now = _format_ts(_utcnow())
    added: List[str] = []
    removed: List[str] = []
    with closing(soc_store.connect(db_path)) as connection:
        previous = _latest_snapshot(connection, collector["collector_id"])
        if previous is not None and str(previous["serial"]) == serial and str(previous["names_hash"]) == names_hash:
            # Unchanged index: no new snapshot, no events, cursor already correct.
            with connection:
                connection.execute(
                    "UPDATE registry_cursors SET last_run_id = ?, updated_at = ? WHERE collector_id = ?",
                    (run_id, now, collector["collector_id"]),
                )
            outcome["pages_processed"] = 1
            outcome["cursor_after"] = serial
            return outcome

        if previous is not None:
            previous_names = set(_snapshot_names(previous))
            added = sorted(set(names) - previous_names)
            removed = sorted(previous_names - set(names))
        if len(added) + len(removed) > max_diff_events:
            outcome["diff_truncated"] = True
            added = added[:max_diff_events]
            removed = removed[: max(0, max_diff_events - len(added))]

        with connection:
            for name in added:
                outcome["events_seen"] += 1
                if _insert_index_event(connection, collector=collector, name=name, event_type="project_added", serial=serial, now=now):
                    outcome["events_stored"] += 1
                else:
                    outcome["events_duplicate"] += 1
            for name in removed:
                outcome["events_seen"] += 1
                if _insert_index_event(connection, collector=collector, name=name, event_type="project_removed", serial=serial, now=now):
                    outcome["events_stored"] += 1
                else:
                    outcome["events_duplicate"] += 1
            connection.execute(
                """INSERT INTO registry_snapshots
                (snapshot_id, collector_id, serial, item_count, names_hash, names_blob, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    _id("RST"),
                    collector["collector_id"],
                    serial,
                    len(names),
                    names_hash,
                    sqlite3.Binary(zlib.compress(json.dumps(names).encode("utf-8"))),
                    now,
                ),
            )
            connection.execute(
                "UPDATE registry_cursors SET cursor_value = ?, last_event_at = ?, last_run_id = ?, updated_at = ? WHERE collector_id = ?",
                (serial, now, run_id, now, collector["collector_id"]),
            )
    outcome["pages_processed"] = 1
    outcome["cursor_after"] = serial
    return outcome


def _ingest_rubygems_timeframe(
    *,
    collector: Dict[str, Any],
    cursor_before: str,
    max_pages: int,
    fetcher: SafeFetcher,
    run_id: str,
    db_path: Optional[str],
) -> Dict[str, Any]:
    """Poll the timeframe_versions feed over one bounded window.

    The window walks forward from the cursor with a small overlap. The
    cursor only advances when the window fully drains (an empty page), so
    a publication burst larger than the per-run page budget cannot be
    skipped; the next run resumes the same window and idempotency keys
    absorb the refetch.
    """
    config = _decode(collector["config_json"], {})
    allowed_hosts = config.get("allowed_hosts", [])
    overlap_seconds = int(config.get("overlap_seconds", 300))
    max_window = timedelta(hours=int(config.get("max_window_hours", DEFAULT_MAX_WINDOW_HOURS)))
    outcome = _empty_outcome(cursor_before)

    now_dt = _utcnow()
    from_dt = _parse_ts(cursor_before) - timedelta(seconds=overlap_seconds)
    to_dt = min(now_dt, from_dt + max_window)
    window_from = _format_ts(from_dt)
    window_to = _format_ts(to_dt)

    drained = False
    with closing(soc_store.connect(db_path)) as connection:
        for page_number in range(1, max(1, min(int(max_pages), 500)) + 1):
            page_url = (
                f"{collector['feed_url']}?from={urllib.parse.quote(window_from)}"
                f"&to={urllib.parse.quote(window_to)}&page={page_number}"
            )
            try:
                items = _fetch_json_array(
                    fetcher, page_url, allowed_hosts=allowed_hosts, max_bytes=MAX_TIMEFRAME_PAGE_BYTES
                )
            except (IntakeError, CollectorError) as exc:
                outcome["error"] = f"timeframe page fetch failed: {exc}"
                with connection:
                    _record_dead_letter(
                        connection,
                        collector_id=collector["collector_id"],
                        run_id=run_id,
                        url=page_url,
                        item_kind="page",
                        payload={"window_from": window_from, "window_to": window_to, "page": page_number},
                        error=str(exc),
                    )
                break
            outcome["pages_processed"] += 1
            if not items:
                drained = True
                break
            now = _format_ts(_utcnow())
            with connection:
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name") or "").strip()
                    version = str(item.get("version") or "").strip()
                    created_at = str(item.get("version_created_at") or "").strip()
                    if not name or not version or not created_at:
                        continue
                    registry_ts = _format_ts(_parse_ts(created_at))
                    outcome["events_seen"] += 1
                    platform = str(item.get("platform") or "ruby")
                    yanked = bool(item.get("yanked"))
                    event_type = "yanked" if yanked else "published"
                    key = _idempotency_key(collector["ecosystem"], name, f"{version}|{platform}", registry_ts, event_type)
                    metadata = {
                        "authors": item.get("authors") or "",
                        "licenses": item.get("licenses") or [],
                        "platform": platform,
                        "yanked": yanked,
                        "sha256": item.get("sha") or "",
                        "homepage": (item.get("metadata") or {}).get("homepage_uri") or "",
                        "algorithm_version": ALGORITHM_VERSION,
                    }
                    leaf_url = str(item.get("gem_uri") or f"https://rubygems.org/gems/{name}/versions/{version}")
                    cursor = connection.execute(
                        """INSERT INTO registry_feed_events
                        (feed_event_id, collector_id, ecosystem, package, version, event_type,
                         registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
                         idempotency_key, collected_at, processing_state)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 'pending')
                        ON CONFLICT(idempotency_key) DO NOTHING""",
                        (
                            _id("RFE"),
                            collector["collector_id"],
                            collector["ecosystem"],
                            name,
                            version,
                            event_type,
                            registry_ts,
                            page_url,
                            leaf_url,
                            _json(metadata),
                            key,
                            now,
                        ),
                    )
                    if cursor.rowcount == 0:
                        outcome["events_duplicate"] += 1
                    else:
                        outcome["events_stored"] += 1

    if outcome["error"]:
        # The failed page was expected, so the window records a gap.
        outcome["pages_selected"] = outcome["pages_processed"] + 1
        return outcome
    outcome["pages_selected"] = outcome["pages_processed"]
    if drained:
        now = _format_ts(_utcnow())
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                connection.execute(
                    "UPDATE registry_cursors SET cursor_value = ?, last_event_at = ?, last_run_id = ?, updated_at = ? WHERE collector_id = ?",
                    (window_to, now, run_id, now, collector["collector_id"]),
                )
        outcome["cursor_after"] = window_to
    else:
        # The window did not drain within the page budget; nothing was
        # skipped because the cursor stays at the window start.
        outcome["window_incomplete"] = True
        outcome["cursor_after"] = cursor_before
    return outcome


def _ingest_npm_changes(
    *,
    collector: Dict[str, Any],
    cursor_before: str,
    max_pages: int,
    fetcher: SafeFetcher,
    run_id: str,
    db_path: Optional[str],
) -> Dict[str, Any]:
    """Ingest the npm CouchDB-style replica changes feed by sequence.

    Each response batch is a contiguous sequence range, so persisting a
    batch and advancing the cursor happen in one transaction; an
    interruption can never skip sequences. The feed has no per-event
    timestamps, so ledger timestamps are collection times and the event
    metadata says so explicitly.
    """
    config = _decode(collector["config_json"], {})
    allowed_hosts = config.get("allowed_hosts", [])
    page_limit = max(1, min(int(config.get("page_limit", DEFAULT_NPM_PAGE_LIMIT)), 10000))
    outcome = _empty_outcome(cursor_before)

    if cursor_before == PACKAGIST_BOOTSTRAP_CURSOR:
        # Live-only bootstrap: adopt the registry's current sequence as
        # the baseline instead of replaying years of history.
        try:
            root = _fetch_json(fetcher, NPM_REPLICATE_ROOT_URL, allowed_hosts=allowed_hosts, max_bytes=MAX_CHANGES_BYTES)
        except (IntakeError, CollectorError) as exc:
            outcome["error"] = f"replica root fetch failed: {exc}"
            with closing(soc_store.connect(db_path)) as connection:
                with connection:
                    _record_dead_letter(
                        connection,
                        collector_id=collector["collector_id"],
                        run_id=run_id,
                        url=NPM_REPLICATE_ROOT_URL,
                        item_kind="feed",
                        payload={"bootstrap": True},
                        error=str(exc),
                    )
            return outcome
        update_seq = root.get("update_seq")
        if not isinstance(update_seq, int):
            outcome["error"] = "replica root did not expose a valid update_seq"
            return outcome
        now = _format_ts(_utcnow())
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                connection.execute(
                    "UPDATE registry_cursors SET cursor_value = ?, last_run_id = ?, updated_at = ? WHERE collector_id = ?",
                    (str(update_seq), run_id, now, collector["collector_id"]),
                )
        outcome["cursor_after"] = str(update_seq)
        outcome["pages_processed"] = 0
        outcome["pages_selected"] = 0
        outcome["anomalies"] = []
        return outcome

    since = int(cursor_before)
    with closing(soc_store.connect(db_path)) as connection:
        for page_number in range(1, max(1, min(int(max_pages), 500)) + 1):
            page_url = f"{collector['feed_url']}?since={since}&limit={page_limit}"
            outcome["pages_selected"] += 1
            try:
                payload = _fetch_json(fetcher, page_url, allowed_hosts=allowed_hosts, max_bytes=MAX_NPM_CHANGES_BYTES)
            except (IntakeError, CollectorError) as exc:
                outcome["error"] = f"changes page fetch failed: {exc}"
                with connection:
                    _record_dead_letter(
                        connection,
                        collector_id=collector["collector_id"],
                        run_id=run_id,
                        url=page_url,
                        item_kind="page",
                        payload={"since": since},
                        error=str(exc),
                    )
                break
            results = payload.get("results")
            if not isinstance(results, list):
                outcome["error"] = "changes response did not contain a results list"
                break
            last_seq = payload.get("last_seq")
            if not isinstance(last_seq, int):
                outcome["error"] = "changes response did not expose a valid last_seq"
                break
            now = _format_ts(_utcnow())
            with connection:
                for item in results:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("id") or "").strip()
                    seq = item.get("seq")
                    if not name or not isinstance(seq, int):
                        continue
                    outcome["events_seen"] += 1
                    deleted = bool(item.get("deleted"))
                    event_type = "deleted" if deleted else "published"
                    key = _idempotency_key(collector["ecosystem"], name, "", str(seq), event_type)
                    metadata = {
                        "seq": seq,
                        "rev": (item.get("changes") or [{}])[0].get("rev") if isinstance(item.get("changes"), list) and item.get("changes") else "",
                        "timestamp_source": "collector",
                        "algorithm_version": ALGORITHM_VERSION,
                    }
                    cursor = connection.execute(
                        """INSERT INTO registry_feed_events
                        (feed_event_id, collector_id, ecosystem, package, version, event_type,
                         registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
                         idempotency_key, collected_at, processing_state)
                        VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 0, ?, ?, ?, 'pending')
                        ON CONFLICT(idempotency_key) DO NOTHING""",
                        (
                            _id("RFE"),
                            collector["collector_id"],
                            collector["ecosystem"],
                            name,
                            event_type,
                            now,
                            page_url,
                            f"https://registry.npmjs.org/{name}",
                            _json(metadata),
                            key,
                            now,
                        ),
                    )
                    if cursor.rowcount == 0:
                        outcome["events_duplicate"] += 1
                    else:
                        outcome["events_stored"] += 1
                connection.execute(
                    "UPDATE registry_cursors SET cursor_value = ?, last_event_at = ?, last_run_id = ?, updated_at = ? WHERE collector_id = ?",
                    (str(last_seq), now, run_id, now, collector["collector_id"]),
                )
            outcome["pages_processed"] += 1
            outcome["cursor_after"] = str(last_seq)
            since = last_seq
            if len(results) < page_limit:
                break
    return outcome


def _ingest_go_index(
    *,
    collector: Dict[str, Any],
    cursor_before: str,
    max_pages: int,
    fetcher: SafeFetcher,
    run_id: str,
    db_path: Optional[str],
) -> Dict[str, Any]:
    """Ingest the Go module index NDJSON feed with a timestamp cursor.

    Each fetched page persists with its cursor advance in one transaction,
    so an interruption can never skip module versions. Cursors are stored
    at millisecond precision; the tiny overlap against the index's
    microsecond timestamps is absorbed by idempotency keys.
    """
    config = _decode(collector["config_json"], {})
    allowed_hosts = config.get("allowed_hosts", [])
    page_limit = max(1, min(int(config.get("page_limit", DEFAULT_GO_PAGE_LIMIT)), 2000))
    outcome = _empty_outcome(cursor_before)

    since = cursor_before
    with closing(soc_store.connect(db_path)) as connection:
        for page_number in range(1, max(1, min(int(max_pages), 500)) + 1):
            page_url = f"{collector['feed_url']}?since={urllib.parse.quote(since)}&limit={page_limit}"
            outcome["pages_selected"] += 1
            try:
                records = _fetch_ndjson(fetcher, page_url, allowed_hosts=allowed_hosts, max_bytes=MAX_GO_INDEX_BYTES)
            except (IntakeError, CollectorError) as exc:
                outcome["error"] = f"module index fetch failed: {exc}"
                with connection:
                    _record_dead_letter(
                        connection,
                        collector_id=collector["collector_id"],
                        run_id=run_id,
                        url=page_url,
                        item_kind="page",
                        payload={"since": since},
                        error=str(exc),
                    )
                break
            if not records:
                break
            last_ts: Optional[str] = None
            now = _format_ts(_utcnow())
            with connection:
                for record in records:
                    path = str(record.get("Path") or "").strip()
                    version = str(record.get("Version") or "").strip()
                    timestamp = str(record.get("Timestamp") or "").strip()
                    if not path or not version or not timestamp:
                        continue
                    registry_ts = _format_ts(_parse_ts(timestamp))
                    outcome["events_seen"] += 1
                    key = _idempotency_key(collector["ecosystem"], path, version, registry_ts, "published")
                    metadata = {
                        "module_path": path,
                        "algorithm_version": ALGORITHM_VERSION,
                    }
                    cursor = connection.execute(
                        """INSERT INTO registry_feed_events
                        (feed_event_id, collector_id, ecosystem, package, version, event_type,
                         registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
                         idempotency_key, collected_at, processing_state)
                        VALUES (?, ?, ?, ?, ?, 'published', ?, ?, ?, 0, ?, ?, ?, 'pending')
                        ON CONFLICT(idempotency_key) DO NOTHING""",
                        (
                            _id("RFE"),
                            collector["collector_id"],
                            collector["ecosystem"],
                            path,
                            version,
                            registry_ts,
                            page_url,
                            f"https://proxy.golang.org/{path}/@v/{version}.info",
                            _json(metadata),
                            key,
                            now,
                        ),
                    )
                    if cursor.rowcount == 0:
                        outcome["events_duplicate"] += 1
                    else:
                        outcome["events_stored"] += 1
                    last_ts = registry_ts
                if last_ts is not None:
                    connection.execute(
                        "UPDATE registry_cursors SET cursor_value = ?, last_event_at = ?, last_run_id = ?, updated_at = ? WHERE collector_id = ?",
                        (last_ts, last_ts, run_id, now, collector["collector_id"]),
                    )
            outcome["pages_processed"] += 1
            if last_ts is not None:
                outcome["cursor_after"] = last_ts
                since = last_ts
            if len(records) < page_limit:
                break
    return outcome


def _effective_cursor(collector: Dict[str, Any], since: Optional[str]) -> str:
    definition = COLLECTOR_DEFINITIONS[collector["ecosystem"]]
    current = str((collector.get("cursor") or {}).get("cursor_value") or "")
    if definition.get("cursor_seed") == "bootstrap":
        multiplier = int(definition.get("cursor_multiplier", 10000))
        if not current or current == PACKAGIST_BOOTSTRAP_CURSOR:
            current = str(int(time.time()) * multiplier)
        if since:
            requested = _parse_packagist_since(since, multiplier)
            if int(requested) < int(current):
                current = requested
        return current
    if definition.get("cursor_seed") == "zero":
        current = current or PACKAGIST_BOOTSTRAP_CURSOR
        if since:
            requested = _parse_packagist_since(since, int(definition.get("cursor_multiplier", 1)))
            if current == PACKAGIST_BOOTSTRAP_CURSOR or int(requested) < int(current):
                current = requested
        return current
    if not current:
        current = _format_ts(_utcnow() - timedelta(hours=DEFAULT_LOOKBACK_HOURS))
    if since:
        requested = _format_ts(_parse_ts(since))
        if requested < current:
            current = requested
    return current


def _retention_state(collector: Dict[str, Any], cursor_value: str) -> Optional[Dict[str, Any]]:
    definition = COLLECTOR_DEFINITIONS.get(collector["ecosystem"], {})
    retention = definition.get("retention_seconds")
    if not retention or not cursor_value or cursor_value == PACKAGIST_BOOTSTRAP_CURSOR:
        return None
    try:
        cursor_unix = int(cursor_value) // int(definition.get("cursor_multiplier", 10000))
    except (TypeError, ValueError):
        return None
    age = max(0.0, time.time() - cursor_unix)
    return {
        "cursor_age_seconds": round(age, 3),
        "retention_seconds": retention,
        "retention_risk": age > float(definition.get("retention_safety_seconds", retention)),
    }


def _raise_retention_alert(*, collector: Dict[str, Any], state: Dict[str, Any], db_path: Optional[str]) -> None:
    now = _format_ts(_utcnow())
    dedupe = f"retention|{collector['collector_id']}|{now[:10]}"
    reason = (
        f"{collector['name']} cursor is {int(state['cursor_age_seconds'])}s old, outside the "
        f"{int(state['retention_seconds'])}s change-log retention safety window; silent event loss is possible"
    )
    with closing(soc_store.connect(db_path)) as connection:
        with connection:
            connection.execute(
                """INSERT INTO research_alerts
                (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
                 reason, evidence_json, status, owner, created_at, updated_at)
                VALUES (?, 'collector_retention_risk', 'high', NULL, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
                ON CONFLICT(dedupe_key) DO NOTHING""",
                (_id("RAL"), dedupe, reason, _json(state | {"collector_id": collector["collector_id"]}), now, now),
            )


def run_registry_collector(
    *,
    ecosystem: str = "nuget",
    since: Optional[str] = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    fetch_leaves: bool = False,
    max_diff_events: int = DEFAULT_MAX_DIFF_EVENTS,
    db_path: Optional[str] = None,
    fetcher: Optional[SafeFetcher] = None,
) -> Dict[str, Any]:
    """Run one bounded ingestion pass for a global registry feed."""
    collector = _collector_for_ecosystem(ecosystem, db_path=db_path)
    if not int(collector["enabled"]):
        raise CollectorError(f"collector {collector['collector_id']} is paused")
    fetcher = fetcher or SafeFetcher()
    max_pages = max(1, min(int(max_pages), 500))
    cursor_before = _effective_cursor(collector, since)

    run_id, rejection = _open_run(collector=collector, cursor_before=cursor_before, db_path=db_path)
    if rejection is not None:
        return rejection

    if collector["ecosystem"] == "packagist":
        outcome = _ingest_packagist_changes(
            collector=collector,
            cursor_before=cursor_before,
            fetcher=fetcher,
            run_id=run_id,
            db_path=db_path,
        )
    elif collector["ecosystem"] == "pypi":
        outcome = _ingest_pypi_index(
            collector=collector,
            cursor_before=cursor_before,
            fetcher=fetcher,
            run_id=run_id,
            db_path=db_path,
            max_diff_events=max(1, int(max_diff_events)),
        )
    elif collector["ecosystem"] == "rubygems":
        outcome = _ingest_rubygems_timeframe(
            collector=collector,
            cursor_before=cursor_before,
            max_pages=max_pages,
            fetcher=fetcher,
            run_id=run_id,
            db_path=db_path,
        )
    elif collector["ecosystem"] == "npm":
        outcome = _ingest_npm_changes(
            collector=collector,
            cursor_before=cursor_before,
            max_pages=max_pages,
            fetcher=fetcher,
            run_id=run_id,
            db_path=db_path,
        )
    elif collector["ecosystem"] == "go":
        outcome = _ingest_go_index(
            collector=collector,
            cursor_before=cursor_before,
            max_pages=max_pages,
            fetcher=fetcher,
            run_id=run_id,
            db_path=db_path,
        )
    else:
        outcome = _ingest_nuget_catalog(
            collector=collector,
            cursor_before=cursor_before,
            max_pages=max_pages,
            fetch_leaves=fetch_leaves,
            fetcher=fetcher,
            run_id=run_id,
            db_path=db_path,
        )

    result = _close_run(collector=collector, run_id=run_id, cursor_before=cursor_before, outcome=outcome, db_path=db_path)
    if outcome.get("anomalies"):
        result["anomalies"] = outcome["anomalies"]
    if outcome.get("diff_truncated"):
        result["diff_truncated"] = True
    if outcome.get("window_incomplete"):
        result["window_incomplete"] = True
    retention = _retention_state(collector, result["cursor_after"])
    if retention is not None:
        result["retention"] = retention
        if retention["retention_risk"]:
            _raise_retention_alert(collector=collector, state=retention, db_path=db_path)
    return result


def retry_dead_letters(
    *,
    limit: int = 25,
    db_path: Optional[str] = None,
    fetcher: Optional[SafeFetcher] = None,
) -> Dict[str, Any]:
    """Retry due dead-lettered pages and leaves with exponential backoff."""
    ensure_collectors(db_path=db_path)
    fetcher = fetcher or SafeFetcher()
    now_dt = _utcnow()
    now = _format_ts(now_dt)
    results = {"retried": 0, "resolved": 0, "failed": 0, "abandoned": 0}
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT d.*, c.config_json FROM registry_dead_letters d
            JOIN registry_collectors c ON c.collector_id = d.collector_id
            WHERE d.status = 'pending' AND d.next_retry_at <= ?
            ORDER BY d.next_retry_at LIMIT ?""",
            (now, max(1, min(int(limit), 200))),
        ).fetchall()
        for row in rows:
            results["retried"] += 1
            allowed_hosts = _decode(row["config_json"], {}).get("allowed_hosts", [])
            max_bytes = MAX_CATALOG_PAGE_BYTES if row["item_kind"] == "page" else MAX_LEAF_BYTES
            attempts = int(row["attempts"]) + 1
            try:
                payload = _fetch_json(fetcher, row["url"], allowed_hosts=allowed_hosts, max_bytes=max_bytes)
            except (IntakeError, CollectorError) as exc:
                results["failed"] += 1
                backoff = min(3600, 60 * (2 ** attempts)) + random.randint(0, 30)
                new_status = "abandoned" if attempts >= MAX_DEAD_LETTER_ATTEMPTS else "pending"
                if new_status == "abandoned":
                    results["abandoned"] += 1
                with connection:
                    connection.execute(
                        """UPDATE registry_dead_letters
                        SET attempts = ?, next_retry_at = ?, status = ?, error_message = ?, updated_at = ?
                        WHERE dead_letter_id = ?""",
                        (
                            attempts,
                            _format_ts(now_dt + timedelta(seconds=backoff)),
                            new_status,
                            str(exc)[:500],
                            now,
                            row["dead_letter_id"],
                        ),
                    )
                continue
            with connection:
                if row["item_kind"] == "leaf":
                    original = _decode(row["payload_json"], {})
                    key = str(original.get("idempotency_key") or "")
                    if key:
                        metadata = {
                            "authors": payload.get("authors") or payload.get("owners") or "",
                            "description": str(payload.get("description") or "")[:2000],
                            "listed": payload.get("listed"),
                            "published": payload.get("published") or "",
                            "project_url": payload.get("projectUrl") or "",
                            "tags": payload.get("tags") or [],
                            "algorithm_version": ALGORITHM_VERSION,
                        }
                        connection.execute(
                            "UPDATE registry_feed_events SET leaf_fetched = 1, metadata_json = ? WHERE idempotency_key = ?",
                            (_json(metadata), key),
                        )
                connection.execute(
                    "UPDATE registry_dead_letters SET attempts = ?, status = 'resolved', updated_at = ? WHERE dead_letter_id = ?",
                    (attempts, now, row["dead_letter_id"]),
                )
            results["resolved"] += 1
    return results


def recover_interrupted_runs(*, max_age_seconds: int = 3600, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Mark collector runs that died without completing as interrupted."""
    ensure_collectors(db_path=db_path)
    cutoff = _format_ts(_utcnow() - timedelta(seconds=max(60, int(max_age_seconds))))
    now = _format_ts(_utcnow())
    with closing(soc_store.connect(db_path)) as connection:
        with connection:
            cursor = connection.execute(
                """UPDATE registry_ingestion_runs
                SET status = 'interrupted', completed_at = ?, error_message = 'run exceeded the liveness window'
                WHERE status = 'running' AND started_at < ?""",
                (now, cutoff),
            )
    return {"interrupted": cursor.rowcount}


def collector_status(*, ecosystem: Optional[str] = None, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Operational status per collector: cursor lag, last run, gaps, failures."""
    collectors = ensure_collectors(db_path=db_path)
    now = _utcnow()
    report: List[Dict[str, Any]] = []
    with closing(soc_store.connect(db_path)) as connection:
        for collector in collectors:
            if ecosystem and collector["ecosystem"] != ecosystem:
                continue
            collector_id = collector["collector_id"]
            cursor = connection.execute(
                "SELECT * FROM registry_cursors WHERE collector_id = ?", (collector_id,)
            ).fetchone()
            last_run = connection.execute(
                """SELECT * FROM registry_ingestion_runs WHERE collector_id = ?
                ORDER BY started_at DESC LIMIT 1""",
                (collector_id,),
            ).fetchone()
            events = connection.execute(
                "SELECT COUNT(*) AS total FROM registry_feed_events WHERE collector_id = ?",
                (collector_id,),
            ).fetchone()
            dead_letters = connection.execute(
                "SELECT COUNT(*) AS total FROM registry_dead_letters WHERE collector_id = ? AND status = 'pending'",
                (collector_id,),
            ).fetchone()
            gaps = connection.execute(
                "SELECT COUNT(*) AS total FROM registry_coverage_windows WHERE collector_id = ? AND state = 'gap'",
                (collector_id,),
            ).fetchone()
            snapshot = connection.execute(
                """SELECT snapshot_id, serial, item_count, created_at FROM registry_snapshots
                WHERE collector_id = ? ORDER BY created_at DESC LIMIT 1""",
                (collector_id,),
            ).fetchone()
            cursor_value = str(cursor["cursor_value"]) if cursor else ""
            lag_seconds: Optional[float] = None
            retention = _retention_state(collector, cursor_value)
            if retention is not None:
                lag_seconds = retention["cursor_age_seconds"]
                if retention["retention_risk"]:
                    _raise_retention_alert(collector=collector, state=retention, db_path=db_path)
            elif cursor_value and COLLECTOR_DEFINITIONS.get(collector["ecosystem"], {}).get("cursor_seed") == "lookback":
                lag_seconds = max(0.0, (now - _parse_ts(cursor_value)).total_seconds())
            report.append(
                {
                    "collector_id": collector_id,
                    "ecosystem": collector["ecosystem"],
                    "name": collector["name"],
                    "mode": collector["mode"],
                    "enabled": bool(collector["enabled"]),
                    "cursor": cursor_value,
                    "lag_seconds": lag_seconds,
                    "events_stored": int(events["total"]),
                    "pending_dead_letters": int(dead_letters["total"]),
                    "coverage_gaps": int(gaps["total"]),
                    "last_run": dict(last_run) if last_run else None,
                    "last_snapshot": dict(snapshot) if snapshot else None,
                    "retention": retention,
                    "algorithm_version": ALGORITHM_VERSION,
                }
            )
    return report


def coverage_report(*, days: int = 7, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Coverage windows from the last N days, gaps first."""
    ensure_collectors(db_path=db_path)
    cutoff = _format_ts(_utcnow() - timedelta(days=max(1, int(days))))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT * FROM registry_coverage_windows
            WHERE created_at >= ?
            ORDER BY CASE state WHEN 'gap' THEN 0 ELSE 1 END, window_start DESC""",
            (cutoff,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_feed_events(
    *,
    collector_id: Optional[str] = None,
    package: Optional[str] = None,
    limit: int = 100,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Inspect the stored feed-event ledger without terminal SQL."""
    ensure_collectors(db_path=db_path)
    clauses = []
    params: List[Any] = []
    if collector_id:
        clauses.append("collector_id = ?")
        params.append(collector_id)
    if package:
        clauses.append("package = ?")
        params.append(package)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"""SELECT * FROM registry_feed_events {where}
            ORDER BY registry_timestamp DESC LIMIT ?""",
            (*params, max(1, min(int(limit), 1000))),
        ).fetchall()
    return [dict(row) | {"metadata": _decode(row["metadata_json"], {})} for row in rows]
