from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

import soc_store
from secopsai import cli
from secopsai.research_storage import (
    RESERVE_FILENAME,
    archive_and_prune_history,
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


def test_storage_retention_predicates_have_supporting_indexes(tmp_path):
    db_path = _db(tmp_path)
    soc_store.init_db(db_path)

    required = {
        "idx_registry_feed_events_retention",
        "idx_registry_feed_events_ecosystem_state_time",
        "idx_research_registry_events_retention",
        "idx_registry_ingestion_runs_retention",
        "idx_research_monitor_runs_retention",
        "idx_registry_coverage_retention",
        "idx_registry_dead_letters_retention",
        "idx_research_notification_deliveries_retention",
        "idx_research_npm_release_analyses_status",
        "idx_research_npm_enrichment_runs_retention",
        "idx_registry_snapshots_collector",
        "idx_research_candidates_event",
        "idx_research_case_findings_finding",
        "idx_research_pipeline_steps_intelligence_job",
    }
    with soc_store.connect(db_path) as connection:
        present = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }

    assert required <= present


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


def test_storage_status_can_skip_large_page_statistics(tmp_path):
    db_path = _db(tmp_path)
    soc_store.init_db(db_path)

    fast = storage_status(db_path=db_path, include_page_stats=False)
    assert fast["sqlite_page_count"] == 0
    assert fast["sqlite_freelist_pages"] == 0

    detailed = storage_status(db_path=db_path, include_freelist=True)
    assert detailed["sqlite_page_count"] > 0


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


def test_history_archive_writes_before_pruning_terminal_rows(tmp_path):
    db_path = _db(tmp_path)
    soc_store.init_db(db_path)
    old = _stamp(days=120)
    with soc_store.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO findings
               (finding_id, title, summary, severity, severity_score, status, disposition,
                source, first_seen, last_seen, created_at, updated_at, payload_json)
               VALUES ('FND-OLD', 'Old finding', 'Archived', 'low', 25, 'closed',
                       'false_positive', 'test', ?, ?, ?, ?, ?)""",
            (old, old, old, old, json.dumps({"finding_id": "FND-OLD", "evidence": ["fixture"]})),
        )
        connection.execute(
            """INSERT INTO intelligence_jobs
               (job_id, action, target_id, status, requested_by, idempotency_key, attempt,
                provider, queued_at, started_at, completed_at, updated_at, error_code,
                error_message, input_json, result_json)
               VALUES ('AIJ-OLD', 'triage_finding', 'FND-OLD', 'failed', 'test', 'old-job',
                       1, 'test', ?, ?, ?, ?, 'bridge_failed', 'old failure', '{}', '{}')""",
            (old, old, old, old),
        )
        connection.commit()

    result = archive_and_prune_history(
        db_path=db_path,
        archive_dir=str(tmp_path / "archive"),
        resolved_days=90,
        failed_job_days=30,
    )
    assert result["status"] == "archived"
    assert result["findings_archived"] == 1
    assert result["intelligence_jobs_archived"] == 1
    archive_path = tmp_path / "archive" / Path(result["archive_path"]).name
    assert archive_path.exists()
    assert archive_path.stat().st_mode & 0o777 == 0o600

    import gzip
    with gzip.open(archive_path, "rt", encoding="utf-8") as handle:
        archived = json.load(handle)
    assert archived["counts"] == {"findings": 1, "intelligence_jobs": 1}
    with soc_store.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) AS n FROM findings WHERE finding_id='FND-OLD'").fetchone()["n"] == 0
        assert connection.execute("SELECT COUNT(*) AS n FROM intelligence_jobs WHERE job_id='AIJ-OLD'").fetchone()["n"] == 0


def test_history_archive_keeps_active_case_and_supports_dry_run(tmp_path):
    db_path = _db(tmp_path)
    soc_store.init_db(db_path)
    old = _stamp(days=120)
    with soc_store.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO research_cases
               (case_id, title, summary, status, severity, confidence, case_type,
                owner, disclosure_status, created_at, updated_at, payload_json)
               VALUES ('RSC-ACTIVE', 'Active case', '', 'in_review', 'high', 50,
                       'supply_chain', 'operator', 'not_started', ?, ?, '{}')""",
            (old, old),
        )
        connection.execute(
            """INSERT INTO findings
               (finding_id, title, summary, severity, severity_score, status, disposition,
                source, first_seen, last_seen, created_at, updated_at, payload_json)
               VALUES ('FND-LINKED', 'Linked finding', 'Retain', 'high', 80, 'closed',
                       'needs_review', 'test', ?, ?, ?, ?, '{}')""",
            (old, old, old, old),
        )
        connection.execute(
            """INSERT INTO research_case_findings (case_id, finding_id, relationship, created_at)
               VALUES ('RSC-ACTIVE', 'FND-LINKED', 'subject', ?)""",
            (old,),
        )
        connection.commit()
    result = archive_and_prune_history(db_path=db_path, resolved_days=90, dry_run=True)
    assert result["status"] == "dry_run"
    assert result["findings_selected"] == 0
    with soc_store.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) AS n FROM findings WHERE finding_id='FND-LINKED'").fetchone()["n"] == 1


def test_history_archive_does_not_delete_when_archive_write_fails(tmp_path, monkeypatch):
    db_path = _db(tmp_path)
    soc_store.init_db(db_path)
    old = _stamp(days=120)
    with soc_store.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO findings
               (finding_id, title, summary, severity, severity_score, status, disposition,
                source, first_seen, last_seen, created_at, updated_at, payload_json)
               VALUES ('FND-UNARCHIVED', 'Unarchived finding', 'Keep', 'low', 25, 'closed',
                       'false_positive', 'test', ?, ?, ?, ?, '{}')""",
            (old, old, old, old),
        )
        connection.commit()

    def fail_archive(**_kwargs):
        raise OSError("archive volume unavailable")

    monkeypatch.setattr("secopsai.research_storage._archive_rows", fail_archive)
    with pytest.raises(OSError, match="archive volume unavailable"):
        archive_and_prune_history(db_path=db_path, resolved_days=90)
    with soc_store.connect(db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) AS n FROM findings WHERE finding_id='FND-UNARCHIVED'"
        ).fetchone()["n"] == 1
