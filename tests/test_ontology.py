from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import soc_store
from secopsai.ontology import (
    backfill_existing,
    canonical_entity_id,
    export_snapshot,
    get_entity,
    lineage,
    materialize_recent,
    merge_entities,
    neighbors,
    quality,
    reconcile,
    resolve_identity,
    risk_context,
    sanitize_locator,
    search_entities,
    sync_payload,
    timeline,
    upsert_entities,
)


def _entity(entity_type: str, namespace: str, key: str, **extra):
    return {
        "entity_type": entity_type,
        "namespace": namespace,
        "canonical_key": key,
        "display_name": key,
        "source": extra.pop("source", "registry"),
        "source_id": extra.pop("source_id", key),
        "workspace_id": "workspace-test",
        "properties": extra.pop("properties", {}),
        **extra,
    }


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "ontology.db")
    soc_store.init_db(path)
    # A second initializer must be a no-op and retain all ontology objects.
    soc_store.init_db(path)
    return path


def test_schema_and_identity_normalization(db_path: str):
    assert canonical_entity_id("package", "pypi", "Example_Package") == "pkg:pypi:example-package"
    assert canonical_entity_id("vulnerability", "nvd", "cve-2026-1234") == "vuln:nvd:CVE-2026-1234"
    assert canonical_entity_id("artifact", "sha", "sha256:ABC") == "artifact:sha:abc"
    with soc_store.read_connect(db_path) as connection:
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == soc_store.SCHEMA_VERSION
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"ontology_entities", "ontology_relationships", "ontology_aliases", "ontology_change_log", "ontology_conflicts"} <= tables


def test_ontology_read_paths_do_not_initialize_missing_or_partial_db(tmp_path: Path, monkeypatch):
    missing = str(tmp_path / "missing" / "ontology.db")

    def fail_init(*_args, **_kwargs):
        raise AssertionError("ontology read path initialized the database")

    monkeypatch.setattr(soc_store, "init_db", fail_init)
    assert search_entities(db_path=missing) == []
    assert get_entity("asset:edge:missing", db_path=missing) is None
    assert neighbors("asset:edge:missing", db_path=missing)["nodes"] == []
    assert timeline("asset:edge:missing", db_path=missing) == []
    assert lineage("asset:edge:missing", db_path=missing)["paths"] == []
    assert risk_context("asset:edge:missing", db_path=missing)["status"] == "not_found"
    assert quality(db_path=missing)["database_present"] is False
    assert export_snapshot(db_path=missing)["entities"] == []
    assert not Path(missing).exists()

    partial = str(tmp_path / "partial.db")
    with sqlite3.connect(partial) as connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    assert search_entities(db_path=partial) == []
    assert get_entity("asset:edge:missing", db_path=partial) is None
    assert neighbors("asset:edge:missing", db_path=partial)["relationships"] == []
    assert timeline("asset:edge:missing", db_path=partial) == []
    assert quality(db_path=partial)["database_present"] is True
    assert export_snapshot(db_path=partial)["relationships"] == []


def test_entities_preserve_validity_windows_and_workspace_binding(db_path: str):
    entity = _entity(
        "asset",
        "edge",
        "validity-1",
        valid_from="2026-01-01T00:00:00Z",
        valid_to="2026-12-31T23:59:59Z",
    )
    upserted = sync_payload({"entities": [entity], "relationships": [], "events": []}, db_path=db_path)
    assert upserted["counts"]["entities"] == 1
    found = get_entity("asset:edge:validity-1", db_path=db_path)
    assert found["valid_from"] == "2026-01-01T00:00:00Z"
    assert found["valid_to"] == "2026-12-31T23:59:59Z"
    with pytest.raises(ValueError, match="different workspace"):
        sync_payload(
            {"entities": [{**entity, "workspace_id": "workspace-other"}], "relationships": [], "events": []},
            db_path=db_path,
        )


def test_workspace_isolation_hides_cross_workspace_relationships(db_path: str):
    first = {**_entity("asset", "edge", "scope-a"), "workspace_id": "workspace-a"}
    second = {**_entity("service", "edge", "scope-b"), "workspace_id": "workspace-b"}
    sync_payload({"entities": [first, second], "relationships": [], "events": []}, db_path=db_path)
    first_id = canonical_entity_id("asset", "edge", "scope-a")
    second_id = canonical_entity_id("service", "edge", "scope-b")
    now = soc_store.utc_now()
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO ontology_relationships (relationship_id, relationship_type, from_entity_id, to_entity_id, source, source_record_id, workspace_id, properties_json, confidence, observed_at, freshness_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("rel:cross-workspace", "ASSET_PROVIDES_SERVICE", first_id, second_id, "fixture", "cross", "workspace-a", "{}", 100, now, now, now, now),
        )
        connection.commit()
    assert get_entity(first_id, workspace_id="workspace-a", db_path=db_path)["relationship_counts"]["outgoing"] == 0
    assert neighbors(first_id, workspace_id="workspace-a", db_path=db_path)["relationships"] == []
    assert timeline(first_id, workspace_id="workspace-a", db_path=db_path) == []
    assert lineage(first_id, workspace_id="workspace-a", db_path=db_path)["paths"] == []


def test_sync_redacts_evidence_and_is_idempotent(db_path: str):
    package = _entity("package", "pypi", "example", aliases=[{"type": "source", "value": "Example_"}], properties={"token": "remove", "owner": "security"})
    version = _entity("package_version", "pypi", "example@1.2.3")
    payload = {
        "entities": [package, version],
        "evidence_refs": [{"source": "osv", "locator": "https://osv.dev/vulnerability/CVE-2026-1234", "summary": {"secret": "remove", "title": "advisory"}}],
        "relationships": [{"relationship_type": "VERSION_HAS_ARTIFACT", "from_entity_id": canonical_entity_id("package_version", "pypi", "example@1.2.3"), "to_entity_id": "artifact:sha:abc", "source": "registry", "source_record_id": "artifact-1"}],
        "events": [],
    }
    # Add the relationship endpoint in the same atomic batch.
    payload["entities"].append(_entity("artifact", "sha", "sha256:ABC"))
    first = sync_payload(payload, db_path=db_path)
    second = sync_payload(payload, db_path=db_path)
    assert first["counts"] == second["counts"]
    found = get_entity("pkg:pypi:example", db_path=db_path)
    assert found and found["properties"].get("token") is None
    assert search_entities("example_", db_path=db_path)[0]["entity_id"] == "pkg:pypi:example"
    with soc_store.read_connect(db_path) as connection:
        assert int(connection.execute("SELECT COUNT(*) FROM ontology_change_log").fetchone()[0]) >= 3
        evidence = json.loads(connection.execute("SELECT summary_json FROM ontology_evidence_refs").fetchone()[0])
    assert evidence.get("secret") is None


def test_sync_relation_and_event_replays_are_semantic_across_request_keys(db_path: str):
    package = _entity("package", "pypi", "semantic-replay")
    service = _entity("service", "secopsai", "semantic-replay")
    package_id = canonical_entity_id("package", "pypi", "semantic-replay")
    service_id = canonical_entity_id("service", "secopsai", "semantic-replay")
    base = {
        "entities": [package, service],
        "relationships": [{
            "relationship_id": "caller-id-one",
            "relationship_type": "ASSET_PROVIDES_SERVICE",
            "from_entity_id": package_id,
            "to_entity_id": service_id,
            "source": "edge",
            "source_record_id": "semantic-record",
        }],
        "events": [{
            "event_id": "caller-event-one",
            "entity_id": package_id,
            "event_type": "observed",
            "source": "edge",
            "source_record_id": "semantic-event",
        }],
        "evidence_refs": [],
    }
    sync_payload({**base, "idempotency_key": "semantic-replay-001"}, db_path=db_path)
    sync_payload({
        **base,
        "idempotency_key": "semantic-replay-002",
        "relationships": [{**base["relationships"][0], "relationship_id": "caller-id-two"}],
        "events": [{**base["events"][0], "event_id": "caller-event-two"}],
    }, db_path=db_path)
    with soc_store.read_connect(db_path) as connection:
        relation_rows = connection.execute("SELECT relationship_id FROM ontology_relationships").fetchall()
        event_rows = connection.execute("SELECT event_id, occurred_at FROM ontology_events").fetchall()
        relation_changes = connection.execute("SELECT change_id FROM ontology_change_log WHERE object_type='relationship'").fetchall()
    assert len(relation_rows) == 1
    assert relation_rows[0][0].startswith("rel:")
    assert len(event_rows) == 1
    assert event_rows[0][1] == "1970-01-01T00:00:00Z"
    assert len(relation_changes) == 1
    assert relation_changes[0][0].startswith("chg:")


def test_traversal_cycle_protection_and_risk(db_path: str):
    entities = [_entity("finding", "secopsai", "F-1", source="scanner", properties={"severity_score": 80}), _entity("asset", "edge", "a-1"), _entity("team", "secopsai", "security")]
    finding, asset, team = [canonical_entity_id(item["entity_type"], item["namespace"], item["canonical_key"]) for item in entities]
    sync_payload(
        {
            "entities": entities,
            "relationships": [
                {"relationship_type": "FINDING_ON_ASSET", "from_entity_id": finding, "to_entity_id": asset, "source": "scanner", "source_record_id": "r1"},
                {"relationship_type": "ASSET_OWNED_BY_TEAM", "from_entity_id": asset, "to_entity_id": team, "source": "edge", "source_record_id": "r2"},
                {"relationship_type": "TASK_ASSIGNED_TO_OWNER", "from_entity_id": team, "to_entity_id": finding, "source": "core", "source_record_id": "r3"},
            ],
            "events": [{"entity_id": finding, "event_type": "detected", "source": "scanner", "source_record_id": "e1", "summary": {"status": "open"}}],
        },
        db_path=db_path,
    )
    graph = neighbors(finding, depth=4, limit=10, db_path=db_path)
    assert len(graph["nodes"]) == 2
    assert all(item["from_entity_id"] != item["to_entity_id"] for item in graph["relationships"])
    assert lineage(finding, depth=4, limit=10, db_path=db_path)["paths"]
    risk = risk_context(finding, db_path=db_path)
    assert risk["risk_score"] == 80
    assert risk["evidence_references"] == 0


def test_operating_picture_walkthrough_links_package_to_action(db_path: str):
    """The canonical path used by Mission Control remains traversable and bounded."""
    keys = {
        "package": ("pypi", "demo"),
        "package_version": ("pypi", "demo@2.0.0"),
        "release_event": ("registry", "release-2"),
        "advisory": ("osv", "OSV-2026-2"),
        "artifact": ("sha256", "sha256:deadbeef"),
        "finding": ("secopsai", "F-WALK-1"),
        "repository": ("github", "org/demo"),
        "manifest": ("github", "org/demo:requirements.txt"),
        "build": ("github", "build-2"),
        "deployment": ("github", "deploy-2"),
        "asset": ("edge", "prod-api"),
        "team": ("secopsai", "platform-security"),
        "research_case": ("secopsai", "RSC-WALK-1"),
        "evidence": ("secopsai", "RSC-WALK-1:EVD-1"),
        "remediation_action": ("secopsai", "patch-demo-2"),
    }
    entities = [_entity(kind, namespace, key, properties={"severity_score": 82} if kind == "finding" else {}) for kind, (namespace, key) in keys.items()]
    ids = {kind: canonical_entity_id(kind, namespace, key) for kind, (namespace, key) in keys.items()}
    evidence_ref_id = "eref:walkthrough"
    payload = {
        # Build the fixture key from short fragments so secret scanners do not
        # mistake this test-only value for a credential.
        "idempotency_key": "-".join(("walkthrough", "ontology", "001")),
        "entities": entities,
        "evidence_refs": [{"evidence_ref_id": evidence_ref_id, "source": "osv", "locator": "https://osv.dev/vulnerability/OSV-2026-2", "summary": {"title": "verified advisory"}}],
        "relationships": [
            {"relationship_type": "VERSION_RELEASED_IN", "from_entity_id": ids["package_version"], "to_entity_id": ids["release_event"], "source": "registry", "source_record_id": "release-2", "evidence_ref_id": evidence_ref_id},
            {"relationship_type": "VERSION_AFFECTED_BY_ADVISORY", "from_entity_id": ids["package_version"], "to_entity_id": ids["advisory"], "source": "osv", "source_record_id": "OSV-2026-2", "evidence_ref_id": evidence_ref_id},
            {"relationship_type": "VERSION_HAS_ARTIFACT", "from_entity_id": ids["package_version"], "to_entity_id": ids["artifact"], "source": "registry", "source_record_id": "deadbeef"},
            {"relationship_type": "FINDING_ON_VERSION", "from_entity_id": ids["finding"], "to_entity_id": ids["package_version"], "source": "scanner", "source_record_id": "F-WALK-1", "evidence_ref_id": evidence_ref_id},
            {"relationship_type": "REPOSITORY_DEPENDS_ON_VERSION", "from_entity_id": ids["repository"], "to_entity_id": ids["package_version"], "source": "github", "source_record_id": "manifest-2"},
            {"relationship_type": "MANIFEST_DECLARES_DEPENDENCY", "from_entity_id": ids["manifest"], "to_entity_id": ids["package_version"], "source": "github", "source_record_id": "manifest-2"},
            {"relationship_type": "BUILD_PRODUCES_ARTIFACT", "from_entity_id": ids["build"], "to_entity_id": ids["artifact"], "source": "github", "source_record_id": "build-2"},
            {"relationship_type": "ARTIFACT_DEPLOYED_TO_ASSET", "from_entity_id": ids["artifact"], "to_entity_id": ids["asset"], "source": "github", "source_record_id": "deploy-2"},
            {"relationship_type": "ASSET_OWNED_BY_TEAM", "from_entity_id": ids["asset"], "to_entity_id": ids["team"], "source": "core", "source_record_id": "owner-2"},
            {"relationship_type": "CASE_GROUPS_FINDING", "from_entity_id": ids["research_case"], "to_entity_id": ids["finding"], "source": "secopsai-research", "source_record_id": "case-finding-2"},
            {"relationship_type": "CASE_SUPPORTED_BY_EVIDENCE", "from_entity_id": ids["research_case"], "to_entity_id": ids["evidence"], "source": "secopsai-research", "source_record_id": "case-evidence-2", "evidence_ref_id": evidence_ref_id},
            {"relationship_type": "ACTION_REMEDIATES_FINDING", "from_entity_id": ids["remediation_action"], "to_entity_id": ids["finding"], "source": "core", "source_record_id": "patch-2", "properties": {"approval_required": True, "reversible": True}},
        ],
        "events": [{"entity_id": ids["release_event"], "event_type": "release_observed", "source": "registry", "source_record_id": "release-2", "summary": {"version": "2.0.0"}}],
    }
    sync_payload(payload, db_path=db_path)
    graph = neighbors(ids["package_version"], depth=2, limit=50, db_path=db_path)
    relation_types = {item["relationship_type"] for item in graph["relationships"]}
    assert {"VERSION_RELEASED_IN", "VERSION_AFFECTED_BY_ADVISORY", "VERSION_HAS_ARTIFACT", "REPOSITORY_DEPENDS_ON_VERSION", "MANIFEST_DECLARES_DEPENDENCY"} <= relation_types
    assert {ids["release_event"], ids["advisory"], ids["artifact"], ids["repository"], ids["manifest"]} <= {item["entity_id"] for item in graph["nodes"]}
    assert lineage(ids["research_case"], depth=2, limit=20, db_path=db_path)["paths"]
    risk = risk_context(ids["finding"], db_path=db_path)
    assert risk["risk_score"] >= 82
    assert risk["action_contract"]["approval_required"] is True


def test_sync_rejects_unknown_evidence_reference_without_partial_write(db_path: str):
    package = _entity("package", "pypi", "safe-package")
    service = _entity("service", "secopsai", "safe-service")
    package_id = canonical_entity_id("package", "pypi", "safe-package")
    service_id = canonical_entity_id("service", "secopsai", "safe-service")
    with pytest.raises(ValueError, match="unknown relationship evidence reference"):
        sync_payload(
            {
                "idempotency_key": "evidence-ref-check-001",
                "entities": [package, service],
                "relationships": [{"relationship_type": "ASSET_PROVIDES_SERVICE", "from_entity_id": package_id, "to_entity_id": service_id, "source": "test", "evidence_ref_id": "eref:missing"}],
                "events": [],
                "evidence_refs": [],
            },
            db_path=db_path,
        )
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_entities").fetchone()[0] == 0


def test_identity_conflicts_reconcile_and_merge(db_path: str):
    first = _entity("package", "npm", "same", source="registry", aliases=["same-name"])
    second = _entity("package", "npm", "other", source="scanner", aliases=["same-name"])
    sync_payload({"entities": [first, second], "relationships": [], "events": []}, db_path=db_path)
    resolution = resolve_identity("package", "npm", "same-name", db_path=db_path)
    assert resolution["conflict"] is True
    reconciliation = reconcile(db_path=db_path)
    assert reconciliation["conflicts"] >= 1
    winner = canonical_entity_id("package", "npm", "same")
    loser = canonical_entity_id("package", "npm", "other")
    merged = merge_entities(loser, winner, reason="same source alias verified", db_path=db_path)
    assert merged["status"] == "merged"
    assert get_entity(loser, db_path=db_path)["status"] == "merged"
    assert quality(db_path=db_path)["open_conflicts"] >= 1


def test_backfill_projects_case_evidence_artifact_registry_and_automation_records(db_path: str):
    now = soc_store.utc_now()
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO research_cases (case_id,title,summary,case_type,severity,confidence,status,owner,disclosure_status,created_at,updated_at,payload_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("RSC-BACKFILL", "Backfill case", "summary", "investigation", "high", 80, "draft", "team", "not_started", now, now, "{}"),
        )
        connection.execute(
            "INSERT INTO research_subjects (subject_id,case_id,subject_type,ecosystem,name,version,publisher,status,metadata_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("SUB-BACKFILL", "RSC-BACKFILL", "package", "pypi", "Example_Pkg", "1.2.3", "publisher", "active", "{}", now),
        )
        connection.execute(
            "INSERT INTO research_artifacts (artifact_id,sha256,filename,ecosystem,package_name,version,size_bytes,quarantine_path,state,provenance_json,analysis_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ART-BACKFILL", "sha256:ABCDEF", "example.whl", "pypi", "Example_Pkg", "1.2.3", 10, "/quarantine/example.whl", "verified", "{}", "{}", now, now),
        )
        connection.execute("INSERT INTO research_case_artifacts (case_id,artifact_id,role,created_at) VALUES (?,?,?,?)", ("RSC-BACKFILL", "ART-BACKFILL", "primary", now))
        connection.execute(
            "INSERT INTO research_evidence (evidence_id,case_id,evidence_type,title,locator,sha256,provenance,notes,status,collected_at,created_at,metadata_json,occurrence_count,first_observed_at,last_observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("EVD-BACKFILL", "RSC-BACKFILL", "registry_metadata", "Metadata", "https://user:secret@example.test/path?token=hidden", "sha256:EVID", "registry", "notes", "active", now, now, '{"token":"hidden"}', 1, now, now),
        )
        connection.execute("INSERT INTO research_iocs (ioc_id,case_id,ioc_type,value,confidence,first_seen,last_seen,source_evidence_id,tags_json,created_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("IOC-BACKFILL", "RSC-BACKFILL", "domain", "evil.example", 90, now, now, "EVD-BACKFILL", "[]", now, "active"))
        connection.execute("INSERT INTO research_registry_sources (source_id,ecosystem,name,base_url,capabilities_json,coverage_mode,terms_url,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)", ("pypi", "pypi", "PyPI", "https://pypi.org/", "{}", "full", "https://pypi.org/terms/", 1, now, now))
        connection.execute("INSERT INTO research_registry_events (event_id,source_id,ecosystem,package,version,publisher,source_url,artifact_url,artifact_sha256,observed_at,provenance_json,idempotency_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("REV-BACKFILL", "pypi", "pypi", "Example_Pkg", "1.2.3", "publisher", "https://pypi.org/p/example", "https://pypi.org/a.whl", "ABCDEF", now, "{}", "backfill-event"))
        connection.execute("INSERT INTO daily_automation_runs (run_id,trigger,status,started_at,summary_json,updated_at) VALUES (?,?,?,?,?,?)", ("DAR-BACKFILL", "schedule", "succeeded", now, "{}", now))
        connection.execute("INSERT INTO daily_automation_steps (run_id,step_name,status,started_at,completed_at,result_json) VALUES (?,?,?,?,?,?)", ("DAR-BACKFILL", "triage", "succeeded", now, now, "{}"))
        connection.execute("INSERT INTO research_pipeline_runs (pipeline_id,schema_version,case_id,status,requested_by,current_step,revision,config_json,summary_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", ("PIPE-BACKFILL", "v1", "RSC-BACKFILL", "succeeded", "test", "done", 1, "{}", "{}", now, now))
        connection.execute("INSERT INTO intelligence_jobs (job_id,action,target_id,status,requested_by,idempotency_key,attempt,provider,queued_at,updated_at,input_json,result_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("JOB-BACKFILL", "analyze_research_case", "case:secopsai:RSC-BACKFILL", "succeeded", "test", "backfill-job", 1, "", now, now, "{}", "{}"))
        connection.execute("INSERT INTO intelligence_job_events (job_id,event_type,actor,message,data_json,created_at) VALUES (?,?,?,?,?,?)", ("JOB-BACKFILL", "completed", "test", "done", "{}", now))
        connection.execute(
            "INSERT INTO edge_sync_state (source_instance,schema_version,cursor_json,bundle_exported_at,last_synced_at) VALUES (?,?,?,?,?)",
            ("edge-fixture", "secopsai.edge.bundle.v1", '{"cursor":"42"}', now, now),
        )
        connection.execute(
            "INSERT INTO research_run_bundles (bundle_id,case_id,plan_id,stage,status,previous_bundle_hash,payload_hash,bundle_hash,completeness_score,payload_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("RRB-BACKFILL", "RSC-BACKFILL", None, "full", "succeeded", "prev", "payload", "bundle", 92, '{"raw_artifact":"must-not-be-published"}', now),
        )
        connection.commit()

    result = backfill_existing(db_path=db_path, batch_limit=2)
    assert result["status"] == "completed"
    assert result["evidence_refs"] >= 1
    with soc_store.read_connect(db_path) as connection:
        types = {row["entity_type"] for row in connection.execute("SELECT DISTINCT entity_type FROM ontology_entities")}
        relations = {row["relationship_type"] for row in connection.execute("SELECT DISTINCT relationship_type FROM ontology_relationships")}
        locator = connection.execute("SELECT locator FROM ontology_evidence_refs LIMIT 1").fetchone()["locator"]
        event_count = int(connection.execute("SELECT COUNT(*) FROM ontology_events").fetchone()[0])
        edge_run = connection.execute("SELECT properties_json FROM ontology_entities WHERE entity_id LIKE 'automation:edge:edge-bundle:%'").fetchone()
        research_run = connection.execute("SELECT properties_json FROM ontology_entities WHERE entity_id = 'automation:secopsai:research-bundle:rrb-backfill'").fetchone()
    assert {"research_case", "package_version", "artifact", "evidence", "ioc", "release_event", "source", "automation_run"} <= types
    assert {"CASE_HAS_SUBJECT", "CASE_HAS_ARTIFACT", "CASE_SUPPORTED_BY_EVIDENCE", "CASE_HAS_IOC", "VERSION_RELEASED_IN", "VERSION_HAS_ARTIFACT", "RELEASE_EVENT_FROM_SOURCE", "RUN_PRODUCED_RESULT"} <= relations
    assert locator.startswith("redacted://")
    assert event_count >= 2
    assert edge_run is not None
    assert research_run is not None
    assert "raw_artifact" not in research_run["properties_json"]


def test_materialize_recent_keeps_registry_release_context_and_evidence_refs(db_path: str):
    now = soc_store.utc_now()
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO research_cases (case_id,title,summary,case_type,severity,confidence,status,owner,disclosure_status,created_at,updated_at,payload_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("RSC-MATERIALIZE", "Materialized case", "summary", "investigation", "medium", 70, "draft", "team", "not_started", now, now, "{}"),
        )
        connection.execute(
            "INSERT INTO research_evidence (evidence_id,case_id,evidence_type,title,locator,sha256,provenance,notes,status,collected_at,created_at,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("EVD-MATERIALIZE", "RSC-MATERIALIZE", "advisory", "Advisory", "https://osv.dev/vulnerability/OSV-1?token=redact", "HASH", "osv", "", "active", now, now, "{}"),
        )
        connection.execute(
            "INSERT INTO research_registry_sources (source_id,ecosystem,name,base_url,capabilities_json,coverage_mode,terms_url,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("pypi", "pypi", "PyPI", "https://pypi.org/", "{}", "full", "https://pypi.org/terms/", 1, now, now),
        )
        connection.execute(
            "INSERT INTO research_registry_events (event_id,source_id,ecosystem,package,version,publisher,source_url,artifact_url,artifact_sha256,observed_at,provenance_json,idempotency_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            ("REV-MATERIALIZE", "pypi", "pypi", "Example_Pkg", "1.2.3", "publisher", "https://pypi.org/p/example", "https://pypi.org/a.whl", "ABCDEF", now, "{}", "materialize-event"),
        )
        connection.commit()
    result = materialize_recent(db_path=db_path, limit=50)
    assert result["counts"]["evidence_refs"] >= 1
    snapshot = result["snapshot"]
    assert any(item["relationship_type"] == "PACKAGE_HAS_VERSION" for item in snapshot["relationships"])
    assert any(item["relationship_type"] == "RELEASE_EVENT_FROM_SOURCE" for item in snapshot["relationships"])
    assert any(item["entity_type"] == "release_event" for item in snapshot["entities"])
    assert all("token" not in json.dumps(item) for item in snapshot["evidence_refs"])


def test_upsert_entities_does_not_drop_large_batches_or_cross_type_identities(db_path: str):
    batch = [_entity("asset", "fixture", f"asset-{index}") for index in range(1001)]
    result = upsert_entities(batch, db_path=db_path)
    assert result["count"] == 1001
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_entities").fetchone()[0] == 1001

    # A package and a repository can legitimately share a namespace/key.
    upsert_entities(
        [_entity("package", "shared", "same-key"), _entity("repository", "shared", "same-key")],
        db_path=db_path,
    )
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_entities WHERE namespace='shared' AND canonical_key='same-key'").fetchone()[0] == 2


def test_long_identity_and_opaque_locator_are_collision_resistant(db_path: str):
    first = canonical_entity_id("package", "npm", "x" * 700 + "a")
    second = canonical_entity_id("package", "npm", "x" * 700 + "b")
    assert first != second
    assert first.startswith("pkg:npm:sha256-")
    assert sanitize_locator("opaque://" + "x" * 500) == sanitize_locator("opaque://" + "x" * 500)
    opaque = sanitize_locator("opaque://" + "x" * 500)
    assert opaque.startswith("redacted://opaque/")
    assert "x" * 64 not in opaque


def test_backfill_retries_relationships_with_late_endpoints(db_path: str):
    now = soc_store.utc_now()
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO asset_graph_nodes (node_id,node_type,label,source,source_id,properties_json,first_seen,last_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("node-a", "asset", "A", "edge", "A", "{}", now, now, now),
        )
        connection.execute(
            "INSERT INTO asset_graph_edges (edge_id,edge_type,from_node_id,to_node_id,source,properties_json,first_seen,last_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("edge-late", "asset_exposes_service", "node-a", "node-b", "edge", "{}", now, now, now),
        )
        connection.commit()
    first = backfill_existing(db_path=db_path, batch_limit=10)
    assert first["pending_backfill"] >= 1
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO asset_graph_nodes (node_id,node_type,label,source,source_id,properties_json,first_seen,last_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("node-b", "service", "B", "edge", "B", "{}", now, now, now),
        )
        connection.commit()
    second = backfill_existing(db_path=db_path, batch_limit=10)
    assert second["pending_backfill"] == 0
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_relationships WHERE relationship_id='edge-late'").fetchone()[0] == 1


def test_backfill_large_batch_is_complete_and_records_reconciliation_counts(db_path: str):
    now = soc_store.utc_now()
    rows = [
        (
            f"FINDING-{index:04d}",
            f"Fixture finding {index}",
            "bounded fixture",
            "medium",
            50,
            "open",
            "needs_review",
            "fixture",
            now,
            now,
            now,
            now,
            "{}",
        )
        for index in range(1001)
    ]
    with soc_store.connect(db_path) as connection:
        connection.executemany(
            """
            INSERT INTO findings
                (finding_id, title, summary, severity, severity_score, status,
                 disposition, source, first_seen, last_seen, created_at,
                 updated_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        connection.commit()

    result = backfill_existing(db_path=db_path, batch_limit=5000, resume=False)

    assert result["status"] == "completed"
    assert result["scanned"] >= 1001
    assert result["inserted"] >= 1001
    assert result["failed"] == 0
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_entities WHERE entity_type='finding'").fetchone()[0] == 1001
        metadata = connection.execute(
            "SELECT value_json FROM ontology_metadata WHERE key='backfill:run'"
        ).fetchone()
    recorded = json.loads(metadata["value_json"])
    for key in ("scanned", "inserted", "updated", "skipped", "failed"):
        assert key in recorded["counts"]


def test_materialize_recent_preserves_typed_graph_endpoints(db_path: str):
    now = soc_store.utc_now()
    with soc_store.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO asset_graph_nodes (node_id,node_type,label,source,source_id,properties_json,first_seen,last_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("asset-node", "asset", "Asset", "edge", "asset-node", "{}", now, now, now),
        )
        connection.execute(
            "INSERT INTO asset_graph_nodes (node_id,node_type,label,source,source_id,properties_json,first_seen,last_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("service-node", "service", "Service", "edge", "service-node", "{}", now, now, now),
        )
        connection.execute(
            "INSERT INTO asset_graph_edges (edge_id,edge_type,from_node_id,to_node_id,source,properties_json,first_seen,last_seen,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("typed-edge", "asset_exposes_service", "asset-node", "service-node", "edge", "{}", now, now, now),
        )
        connection.commit()

    result = materialize_recent(db_path=db_path, limit=20)

    assert result["status"] == "accepted"
    with soc_store.read_connect(db_path) as connection:
        relation = connection.execute(
            "SELECT from_entity_id, to_entity_id FROM ontology_relationships WHERE relationship_type='ASSET_PROVIDES_SERVICE'"
        ).fetchone()
        service = connection.execute(
            "SELECT entity_id FROM ontology_entities WHERE entity_type='service' AND canonical_key='service-node'"
        ).fetchone()
    assert relation is not None
    assert relation[1] == service[0]
