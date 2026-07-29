from datetime import datetime, timedelta, timezone
import json

import soc_store
from secopsai import cli
from secopsai.research_storage import (
    RESERVE_FILENAME,
    ensure_storage_reserve,
    maintain_research_storage,
    release_storage_reserve,
    storage_status,
)
from secopsai.research_surveillance import ensure_collectors


def _stamp(*, days=0, hours=0):
    return (datetime.now(timezone.utc) - timedelta(days=days, hours=hours)).isoformat().replace("+00:00", "Z")


def _db(tmp_path):
    return str(tmp_path / "research-worker.db")


def test_storage_maintenance_prunes_only_bounded_operational_history(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_STORAGE_RESERVE_BYTES", "4096")
    monkeypatch.setenv("SECOPSAI_STORAGE_MIN_FREE_BYTES", "0")
    monkeypatch.setenv("SECOPSAI_STORAGE_MAX_USED_PERCENT", "100")
    monkeypatch.setenv("SECOPSAI_RESEARCH_EVENT_RETENTION_HOURS", "24")
    db_path = _db(tmp_path)
    collectors = ensure_collectors(db_path=db_path)
    collector_id = collectors[0]["collector_id"]
    source_id = collectors[0]["source_id"]
    old = _stamp(days=3)
    recent = _stamp(hours=1)

    with soc_store.connect(db_path) as connection:
        for event_id, state, collected_at in (
            ("RFE-OLD-SCORED", "scored", old),
            ("RFE-OLD-IGNORED", "ignored", old),
            ("RFE-PENDING", "pending", old),
            ("RFE-RECENT", "scored", recent),
        ):
            connection.execute(
                """INSERT INTO registry_feed_events
                   (feed_event_id, collector_id, ecosystem, package, version, event_type,
                    registry_timestamp, page_url, leaf_url, metadata_json, idempotency_key,
                    collected_at, processing_state)
                   VALUES (?, ?, 'nuget', ?, '1.0.0', 'published', ?, 'https://example.test/page',
                           'https://example.test/leaf', '{}', ?, ?, ?)""",
                (event_id, collector_id, event_id.lower(), collected_at, f"key-{event_id}", collected_at, state),
            )
        connection.execute(
            """INSERT INTO research_registry_events
               (event_id, source_id, ecosystem, package, version, publisher, source_url,
                artifact_url, artifact_sha256, observed_at, provenance_json, idempotency_key)
               VALUES ('RGE-UNREFERENCED', ?, 'nuget', 'old-package', '1', '', 'https://example.test',
                       '', '', ?, '{}', 'rge-unreferenced')""",
            (source_id, old),
        )
        connection.execute(
            """INSERT INTO research_registry_events
               (event_id, source_id, ecosystem, package, version, publisher, source_url,
                artifact_url, artifact_sha256, observed_at, provenance_json, idempotency_key)
               VALUES ('RGE-REFERENCED', ?, 'nuget', 'candidate-package', '1', '', 'https://example.test',
                       '', '', ?, '{}', 'rge-referenced')""",
            (source_id, old),
        )
        connection.execute(
            """INSERT INTO research_candidates
               (candidate_id, event_id, ecosystem, package, version, reference_identifier,
                score, score_components_json, reason, status, evidence_json, first_seen,
                last_seen, algorithm_version)
               VALUES ('RCD-TEST', 'RGE-REFERENCED', 'nuget', 'candidate-package', '1',
                       'legitimate-package', 90, '{}', 'test', 'new', '{}', ?, ?, 'test-v1')""",
            (old, old),
        )
        for index in range(4):
            connection.execute(
                """INSERT INTO registry_snapshots
                   (snapshot_id, collector_id, serial, item_count, names_hash, names_blob, created_at)
                   VALUES (?, ?, ?, 1, ?, X'789C030000000001', ?)""",
                (f"RSS-{index}", collector_id, str(index), f"hash-{index}", _stamp(days=4-index)),
            )
        connection.commit()

    result = maintain_research_storage(db_path=db_path, aggressive=True)
    assert result["deleted_rows"]["registry_feed_events"] == 2
    assert result["deleted_rows"]["research_registry_events"] == 1
    assert result["deleted_rows"]["registry_snapshots"] == 2

    with soc_store.connect(db_path) as connection:
        feed_ids = {row["feed_event_id"] for row in connection.execute("SELECT feed_event_id FROM registry_feed_events")}
        registry_ids = {row["event_id"] for row in connection.execute("SELECT event_id FROM research_registry_events")}
        snapshot_count = connection.execute("SELECT COUNT(*) AS total FROM registry_snapshots").fetchone()["total"]
    assert feed_ids == {"RFE-PENDING", "RFE-RECENT"}
    assert registry_ids == {"RGE-REFERENCED"}
    assert snapshot_count == 2


def test_storage_reserve_is_real_and_releasable(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_STORAGE_RESERVE_BYTES", "8192")
    monkeypatch.setenv("SECOPSAI_STORAGE_MIN_FREE_BYTES", "0")
    monkeypatch.setenv("SECOPSAI_STORAGE_MAX_USED_PERCENT", "100")
    db_path = _db(tmp_path)
    soc_store.init_db(db_path)

    assert ensure_storage_reserve(db_path=db_path) == 8192
    reserve = tmp_path / RESERVE_FILENAME
    assert reserve.exists()
    assert reserve.stat().st_mode & 0o777 == 0o600
    status = storage_status(db_path=db_path)
    assert status["reserve_bytes"] == 8192
    assert status["database_bytes"] > 0
    assert release_storage_reserve(db_path=db_path) == 8192
    assert not reserve.exists()


def test_storage_cli_dispatches_status_and_maintenance(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SECOPSAI_STORAGE_RESERVE_BYTES", "0")
    db_path = _db(tmp_path)

    status_code = cli.main(
        ["--json", "research", "storage", "status", "--db-path", db_path]
    )
    status = json.loads(capsys.readouterr().out)
    assert status_code == 0
    assert status["database_path"].endswith("research-worker.db")

    maintain_code = cli.main(
        ["--json", "research", "storage", "maintain", "--db-path", db_path]
    )
    maintenance = json.loads(capsys.readouterr().out)
    assert maintain_code == 0
    assert maintenance["after"]["pressure"] is False
