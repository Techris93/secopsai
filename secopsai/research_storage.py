"""Bounded storage management for continuous research surveillance.

The registry worker writes a high-volume operational ledger. This module keeps
that ledger bounded without deleting pending work, canonical candidates,
research cases, evidence, IOCs, or active alerts. A small reserve file provides
enough emergency space for SQLite to commit cleanup work before a volume is
completely exhausted.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import soc_store


DEFAULT_RESERVE_BYTES = 1024 * 1024
DEFAULT_MIN_FREE_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_USED_PERCENT = 85.0
DEFAULT_BATCH_SIZE = 5000
RESERVE_FILENAME = ".secopsai-storage-reserve"


class ResearchStorageCapacityError(RuntimeError):
    """The worker cannot safely write until persistent capacity is restored."""


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _env_float(name: str, default: float, *, minimum: float = 0.0, maximum: float = 100.0) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _resolved_db_path(db_path: Optional[str]) -> Path:
    return Path(db_path or soc_store.default_db_path()).expanduser().resolve()


def _reserve_path(db_path: Optional[str]) -> Path:
    return _resolved_db_path(db_path).parent / RESERVE_FILENAME


def _iso_cutoff(*, hours: int = 0, days: int = 0) -> str:
    value = datetime.now(timezone.utc) - timedelta(hours=max(0, hours), days=max(0, days))
    return value.isoformat().replace("+00:00", "Z")


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def storage_status(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return database and filesystem capacity without modifying either."""
    database = _resolved_db_path(db_path)
    root = database.parent
    root.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(root)
    used_percent = round((usage.used / usage.total) * 100, 2) if usage.total else 0.0
    page_size = 0
    page_count = 0
    freelist_count = 0
    if database.exists():
        try:
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
            try:
                page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                freelist_count = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
            finally:
                connection.close()
        except sqlite3.Error:
            pass
    reserve = _reserve_path(db_path)
    min_free = _env_int("SECOPSAI_STORAGE_MIN_FREE_BYTES", DEFAULT_MIN_FREE_BYTES)
    max_used = _env_float("SECOPSAI_STORAGE_MAX_USED_PERCENT", DEFAULT_MAX_USED_PERCENT)
    pressure = usage.free < min_free or used_percent >= max_used
    return {
        "database_path": str(database),
        "storage_root": str(root),
        "database_bytes": _file_size(database),
        "journal_bytes": _file_size(Path(f"{database}-journal")),
        "wal_bytes": _file_size(Path(f"{database}-wal")),
        "reserve_bytes": _file_size(reserve),
        "filesystem_total_bytes": usage.total,
        "filesystem_used_bytes": usage.used,
        "filesystem_free_bytes": usage.free,
        "filesystem_used_percent": used_percent,
        "sqlite_page_size": page_size,
        "sqlite_page_count": page_count,
        "sqlite_freelist_pages": freelist_count,
        "sqlite_reclaimable_bytes": page_size * freelist_count,
        "pressure": pressure,
        "minimum_free_bytes": min_free,
        "maximum_used_percent": max_used,
    }


def release_storage_reserve(*, db_path: Optional[str] = None) -> int:
    """Release emergency space before cleanup or manual recovery."""
    reserve = _reserve_path(db_path)
    size = _file_size(reserve)
    try:
        reserve.unlink(missing_ok=True)
    except OSError:
        return 0
    return size


def ensure_storage_reserve(*, db_path: Optional[str] = None) -> int:
    """Allocate an owner-only, physically written emergency reserve."""
    configured = _env_int("SECOPSAI_STORAGE_RESERVE_BYTES", DEFAULT_RESERVE_BYTES)
    if configured <= 0:
        return 0
    reserve = _reserve_path(db_path)
    current = _file_size(reserve)
    if current == configured:
        return current
    status = storage_status(db_path=db_path)
    if status["filesystem_free_bytes"] <= configured + status["minimum_free_bytes"]:
        return current
    reserve.parent.mkdir(parents=True, exist_ok=True)
    temporary = reserve.with_suffix(".tmp")
    try:
        with temporary.open("wb") as handle:
            chunk = b"\0" * min(1024 * 1024, configured)
            remaining = configured
            while remaining > 0:
                piece = chunk if remaining >= len(chunk) else chunk[:remaining]
                handle.write(piece)
                remaining -= len(piece)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        temporary.replace(reserve)
    finally:
        temporary.unlink(missing_ok=True)
    return _file_size(reserve)


def _delete_batches(
    connection: sqlite3.Connection,
    *,
    table: str,
    predicate: str,
    params: Iterable[Any],
    batch_size: int,
    max_batches: int,
) -> int:
    deleted = 0
    for _ in range(max_batches):
        before = connection.total_changes
        connection.execute(
            f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {predicate} LIMIT ?)",
            (*tuple(params), batch_size),
        )
        connection.commit()
        changed = connection.total_changes - before
        deleted += changed
        if changed < batch_size:
            break
    return deleted


def _prune_rules() -> Tuple[Tuple[str, str, Tuple[Any, ...]], ...]:
    event_hours = _env_int("SECOPSAI_RESEARCH_EVENT_RETENTION_HOURS", 24, minimum=1)
    candidate_days = _env_int("SECOPSAI_RESEARCH_CANDIDATE_EVENT_RETENTION_DAYS", 90, minimum=1)
    run_days = _env_int("SECOPSAI_RESEARCH_RUN_RETENTION_DAYS", 30, minimum=1)
    gap_days = _env_int("SECOPSAI_RESEARCH_GAP_RETENTION_DAYS", 180, minimum=1)
    delivery_days = _env_int("SECOPSAI_RESEARCH_DELIVERY_RETENTION_DAYS", 90, minimum=1)
    npm_analysis_days = _env_int("SECOPSAI_RESEARCH_NPM_ANALYSIS_RETENTION_DAYS", 30, minimum=1)
    return (
        ("registry_feed_events", "processing_state IN ('scored','ignored') AND collected_at < ?", (_iso_cutoff(hours=event_hours),)),
        ("registry_feed_events", "processing_state = 'candidate' AND collected_at < ?", (_iso_cutoff(days=candidate_days),)),
        ("research_registry_events", "observed_at < ? AND NOT EXISTS (SELECT 1 FROM research_candidates c WHERE c.event_id = research_registry_events.event_id)", (_iso_cutoff(hours=event_hours),)),
        ("registry_ingestion_runs", "status != 'running' AND started_at < ?", (_iso_cutoff(days=run_days),)),
        ("research_monitor_runs", "status != 'running' AND started_at < ?", (_iso_cutoff(days=run_days),)),
        ("registry_coverage_windows", "state = 'complete' AND created_at < ?", (_iso_cutoff(days=run_days),)),
        ("registry_coverage_windows", "state != 'complete' AND created_at < ?", (_iso_cutoff(days=gap_days),)),
        ("registry_dead_letters", "status = 'resolved' AND updated_at < ?", (_iso_cutoff(days=run_days),)),
        ("research_notification_deliveries", "status IN ('sent','failed') AND updated_at < ?", (_iso_cutoff(days=delivery_days),)),
        # Clean npm analyses are reproducible from the exact event, hash, and
        # quarantine locator. Keep candidate-linked evidence and all failed or
        # pending work until its retry/triage state is no longer active.
        ("research_npm_release_analyses", "status = 'completed' AND updated_at < ? AND NOT EXISTS (SELECT 1 FROM research_candidates c WHERE c.evidence_json LIKE '%' || research_npm_release_analyses.artifact_sha256 || '%')", (_iso_cutoff(days=npm_analysis_days),)),
        ("research_npm_release_analyses", "status = 'failed' AND updated_at < ?", (_iso_cutoff(days=npm_analysis_days),)),
        ("research_npm_enrichment_runs", "status != 'running' AND completed_at IS NOT NULL AND completed_at < ?", (_iso_cutoff(days=run_days),)),
    )


def maintain_research_storage(
    *,
    db_path: Optional[str] = None,
    aggressive: bool = False,
) -> Dict[str, Any]:
    """Prune bounded operational history and make freed pages reusable."""
    before = storage_status(db_path=db_path)
    released = release_storage_reserve(db_path=db_path) if before["pressure"] or aggressive else 0
    database = _resolved_db_path(db_path)
    try:
        soc_store.init_db(str(database))
    except sqlite3.OperationalError as exc:
        if "full" in str(exc).lower():
            raise ResearchStorageCapacityError(
                "research storage is full; increase the persistent disk, then run "
                "'secopsai research storage maintain --aggressive'"
            ) from exc
        raise

    batch_size = _env_int("SECOPSAI_STORAGE_PRUNE_BATCH_SIZE", DEFAULT_BATCH_SIZE, minimum=100)
    max_batches = 200 if aggressive or before["pressure"] else 4
    deleted: Dict[str, int] = {}
    with closing(soc_store.connect(str(database))) as connection:
        for table, predicate, params in _prune_rules():
            count = _delete_batches(
                connection,
                table=table,
                predicate=predicate,
                params=params,
                batch_size=batch_size,
                max_batches=max_batches,
            )
            deleted[table] = deleted.get(table, 0) + count

        keep_snapshots = _env_int("SECOPSAI_RESEARCH_SNAPSHOTS_PER_COLLECTOR", 2, minimum=1)
        deleted["registry_snapshots"] = _delete_batches(
            connection,
            table="registry_snapshots",
            predicate="""rowid IN (
                SELECT rowid FROM (
                    SELECT rowid,
                           ROW_NUMBER() OVER (
                               PARTITION BY collector_id ORDER BY created_at DESC
                           ) AS rank
                    FROM registry_snapshots
                ) WHERE rank > ?
            )""",
            params=(keep_snapshots,),
            batch_size=batch_size,
            max_batches=max_batches,
        )
        connection.execute("PRAGMA optimize")
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass

    vacuumed = False
    mid = storage_status(db_path=str(database))
    if aggressive and mid["sqlite_reclaimable_bytes"] > 0:
        required = mid["database_bytes"] + (64 * 1024 * 1024)
        if mid["filesystem_free_bytes"] > required:
            with closing(sqlite3.connect(str(database), timeout=30)) as connection:
                connection.execute("VACUUM")
            vacuumed = True

    reserve = ensure_storage_reserve(db_path=str(database))
    after = storage_status(db_path=str(database))
    return {
        "before": before,
        "after": after,
        "deleted_rows": deleted,
        "released_reserve_bytes": released,
        "reserve_bytes": reserve,
        "vacuumed": vacuumed,
        "aggressive": aggressive,
    }
