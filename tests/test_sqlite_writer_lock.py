from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import soc_store
from secopsai.sqlite_writer_lock import lock_path, sqlite_writer_lock


_WORKER = """
import sys
import time
import soc_store
from secopsai.sqlite_writer_lock import sqlite_writer_lock

db_path, source, attempt = sys.argv[1], sys.argv[2], int(sys.argv[3])
with sqlite_writer_lock(db_path, timeout_seconds=30):
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO writer_load (source, attempt, marker) VALUES (?, ?, ?)",
            (source, attempt, f"{source}:{attempt}"),
        )
        time.sleep(0.01)
        connection.commit()
print(f"{source}:{attempt}")
"""


def test_writer_lock_is_reentrant_within_one_process(tmp_path: Path):
    db_path = str(tmp_path / "core.db")
    with sqlite_writer_lock(db_path, timeout_seconds=1):
        with sqlite_writer_lock(db_path, timeout_seconds=1):
            assert lock_path(db_path).exists()


def test_writer_lock_uses_shared_file_and_sqlite_fallbacks(tmp_path: Path, monkeypatch):
    # The application may raise this timeout for a busy local service. Keep
    # the default contract assertion independent of the operator environment.
    monkeypatch.delenv("SECOPS_BUSY_TIMEOUT_MS", raising=False)
    db_path = str(tmp_path / "core.db")
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE writer_load (source TEXT NOT NULL, attempt INTEGER NOT NULL, marker TEXT NOT NULL)"
        )
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"

    assert lock_path(db_path) == tmp_path / "core.db.writer.lock"
    attempts = [(db_path, source, index) for source in ("research", "edge") for index in range(10)]
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", _WORKER, db_path, source, str(index)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for db_path, source, index in attempts
    ]
    results = []
    errors = []
    for process in processes:
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            errors.append(f"timeout: {stderr}")
            continue
        if process.returncode != 0:
            errors.append(stderr)
        else:
            results.append(stdout.strip())
    assert errors == []

    expected = sorted(f"{source}:{index}" for _, source, index in attempts)
    assert sorted(results) == expected
    with soc_store.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT marker FROM writer_load ORDER BY source, attempt"
        ).fetchall()
    actual = [str(row[0]) for row in rows]
    assert actual == expected
    assert len(actual) == 20
    assert hashlib.sha256("|".join(actual).encode()).hexdigest() == hashlib.sha256(
        "|".join(expected).encode()
    ).hexdigest()


def test_schema_version_fast_path_does_not_rewrite_during_reader_status(tmp_path: Path):
    db_path = str(tmp_path / "core.db")
    soc_store.init_db(db_path)

    with soc_store.connect(db_path) as connection:
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == soc_store.SCHEMA_VERSION
        # A normal SQLite writer transaction may coexist with a read. Once the
        # durable schema version is present, a second init_db call must not
        # execute the schema DDL and therefore must not contend for that lock.
        connection.execute("BEGIN IMMEDIATE")
        soc_store.init_db(db_path)
        connection.rollback()


def test_wal_reader_stays_available_during_exclusive_writer_transaction(tmp_path: Path):
    db_path = str(tmp_path / "core.db")
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as writer:
        writer.execute("CREATE TABLE reader_probe (value TEXT NOT NULL)")
        writer.execute("INSERT INTO reader_probe (value) VALUES ('committed')")
        writer.commit()
        writer.execute("BEGIN EXCLUSIVE")
        writer.execute("INSERT INTO reader_probe (value) VALUES ('uncommitted')")
        started = time.monotonic()
        with soc_store.read_connect(db_path) as reader:
            rows = reader.execute("SELECT value FROM reader_probe ORDER BY value").fetchall()
        elapsed = time.monotonic() - started
        writer.rollback()

    assert [str(row[0]) for row in rows] == ["committed"]
    assert elapsed < 1.0


def test_schema_upgrade_moves_existing_rollback_database_to_wal(tmp_path: Path):
    db_path = str(tmp_path / "legacy.db")
    with sqlite3.connect(db_path) as connection:
        connection.execute("CREATE TABLE legacy_probe (value TEXT NOT NULL)")
        connection.execute("INSERT INTO legacy_probe (value) VALUES ('preserved')")
        connection.execute("PRAGMA user_version = 5")
        connection.commit()

    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == soc_store.SCHEMA_VERSION
        assert connection.execute("SELECT value FROM legacy_probe").fetchone()[0] == "preserved"
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "research_reliability_automation_runs" in tables


def test_registry_scoring_index_is_present(tmp_path: Path):
    db_path = str(tmp_path / "core.db")
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        indexes = {
            str(row[1])
            for row in connection.execute("PRAGMA index_list(registry_feed_events)").fetchall()
        }
    assert "idx_registry_feed_events_processing_state_time" in indexes
