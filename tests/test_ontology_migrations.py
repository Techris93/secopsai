from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import soc_store


def test_local_ontology_schema_is_additive_idempotent_and_bounded(tmp_path: Path):
    db_path = str(tmp_path / "ontology-schema.db")
    soc_store.init_db(db_path)
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert {
            "ontology_entities", "ontology_aliases", "ontology_relationships",
            "ontology_evidence_refs", "ontology_events", "ontology_entity_merges",
            "ontology_metadata", "ontology_change_log", "ontology_conflicts",
            "ontology_ingest_receipts", "coordinator_commands", "runner_heartbeats",
            "ontology_sync_outbox",
        } <= tables
        assert "trg_intelligence_jobs_json_bounds_insert" in triggers
        assert "trg_agent_triage_json_bounds_insert" in triggers
        assert "trg_ontology_ingest_receipts_response_bound" in triggers
        assert "trg_ontology_sync_outbox_json_bounds_insert" in triggers
        assert "workspace_id" in {row[1] for row in connection.execute("PRAGMA table_info(ontology_evidence_refs)").fetchall()}
        assert {"valid_from", "valid_to"} <= {row[1] for row in connection.execute("PRAGMA table_info(ontology_entities)").fetchall()}
        now = soc_store.utc_now()
        valid = ("ATR-MIGRATION-1", "finding", "finding:test:1", "fingerprint", "queued", None, "model", "provider", "{}", "{}", "{}", "", 1, "{}", None, None, now, None, now)
        connection.execute(
            "INSERT INTO agent_triage_runs (run_id,target_type,target_id,target_fingerprint,status,intelligence_job_id,selected_model,provider,deterministic_json,recommendation_json,decision_json,final_action,reversible,rollback_json,error_code,error_message,queued_at,completed_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            valid,
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO agent_triage_runs (run_id,target_type,target_id,target_fingerprint,status,intelligence_job_id,selected_model,provider,deterministic_json,recommendation_json,decision_json,final_action,reversible,rollback_json,error_code,error_message,queued_at,completed_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("ATR-MIGRATION-2", "finding", "finding:test:2", "fingerprint", "queued", None, "model", "provider", json.dumps({"x": "y" * 40000}), "{}", "{}", "", 1, "{}", None, None, now, None, now),
            )
        connection.commit()


def test_cloudflare_migrations_are_additive_and_cover_control_plane_contract():
    root = Path(__file__).parents[1] / "cloudflare" / "secopsai-core-edge" / "migrations"
    migration_text = "\n".join((root / name).read_text(encoding="utf-8") for name in ("0003_ontology.sql", "0004_control_plane_bounds.sql", "0005_ontology_ingest_receipts.sql", "0006_ontology_evidence_scope.sql", "0007_ontology_entity_validity.sql"))
    for table in (
        "ontology_entities", "ontology_aliases", "ontology_relationships", "ontology_evidence_refs",
        "ontology_events", "ontology_entity_merges", "ontology_metadata", "ontology_change_log",
        "ontology_conflicts", "ontology_ingest_receipts",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in migration_text
    for index in ("idx_ontology_entities_type_key", "idx_ontology_relationships_from", "idx_ontology_relationships_to"):
        assert index in migration_text
    assert "trg_intelligence_jobs_json_bounds_insert" in migration_text
    assert "trg_ontology_entities_json_bounds_insert" in migration_text
    assert "trg_ontology_relationships_json_bounds_insert" in migration_text
    assert "trg_ontology_ingest_receipts_response_bound" in migration_text
    assert "workspace_id" in migration_text
    assert "valid_from" in migration_text and "valid_to" in migration_text
