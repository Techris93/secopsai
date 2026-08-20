from __future__ import annotations

import json
import io
import tarfile
from pathlib import Path

from secopsai import artifact_fleet


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "artifact-fleet"


def _crate_archive(tmp_path, fixture_name: str) -> Path:
    target = tmp_path / fixture_name
    raw = (FIXTURES / fixture_name).read_bytes()
    with tarfile.open(target, "w:gz") as archive:
        member_name = "build.rs" if fixture_name.startswith(("proc-macro1", "proc-macro-en")) else "src/lib.rs"
        info = tarfile.TarInfo(member_name)
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
    return target


def test_indexer_is_metadata_only_and_deduplicates(tmp_path):
    records = json.loads((FIXTURES / "index.json").read_text())
    records[0]["artifact_path"] = str(FIXTURES / "proc-macro1-1.0.107.crate")
    result = artifact_fleet.index_records(records + [records[0]], source="crates", cursor="serial-2", db_path=tmp_path / "fleet.db")
    assert result["indexed"] >= 2
    assert artifact_fleet.list_artifacts(db_path=tmp_path / "fleet.db", limit=10)
    status = artifact_fleet.fleet_status(db_path=tmp_path / "fleet.db")
    assert status["queue"]["scan_pending"] >= 1


def test_proc_macro_fixture_flags_build_network_and_credentials(tmp_path):
    archive = _crate_archive(tmp_path, "proc-macro1-1.0.107.crate")
    result = artifact_fleet.scan_artifact(
        ecosystem="crates",
        package="proc-macro1",
        version="1.0.107",
        artifact=archive,
        source_reference="https://crates.io/crates/proc-macro1/1.0.107",
        db_path=tmp_path / "fleet.db",
    )
    rules = {item["rule_id"] for item in result["findings"]}
    assert result["status"] == "flagged"
    assert "OSS-RUST-PROC-MACRO" in rules or "SECOPSAI-ECOSYSTEM" in rules
    assert "OSS-CREDENTIAL-DISCOVERY" in rules
    assert result["execution_performed"] is False
    assert result["iocs"]["ips"]
    assert artifact_fleet.analyst_queue(db_path=tmp_path / "fleet.db") == []
    triage = artifact_fleet.triage_artifact(result["artifact_id"], db_path=tmp_path / "fleet.db")
    assert triage["status"] == "awaiting_model"


def test_legitimate_proc_macro_comparison_stays_clean(tmp_path):
    archive = _crate_archive(tmp_path, "proc-macro2-1.0.107.crate")
    result = artifact_fleet.scan_artifact(
        ecosystem="crates",
        package="proc-macro2",
        version="1.0.107",
        artifact=archive,
        db_path=tmp_path / "fleet.db",
    )
    assert result["status"] == "clean"
    assert result["findings"] == []
    assert artifact_fleet.fleet_status(db_path=tmp_path / "fleet.db")["triage"] == {}


def test_triage_escalates_suspicious_and_context_is_minimized(tmp_path):
    archive = _crate_archive(tmp_path, "proc-macro-en-1.0.10.crate")
    result = artifact_fleet.scan_artifact(
        ecosystem="crates",
        package="proc-macro-en",
        version="1.0.10",
        artifact=archive,
        db_path=tmp_path / "fleet.db",
    )
    seen = {}
    def model(context):
        seen.update(context)
        return {"verdict": "suspicious", "confidence": 96, "evidence": ["OSS-RUST-PROC-MACRO"], "recommended_next_action": "analyst_review"}
    triage = artifact_fleet.triage_artifact(result["artifact_id"], model="fixture/model", model_call=model, db_path=tmp_path / "fleet.db")
    assert triage["status"] == "analyst_review"
    assert triage["analyst_required"] is True
    assert "findings" in seen
    assert all(len(item.get("safe_context") or "") <= artifact_fleet.CONTEXT_BYTES for item in seen["findings"])
    assert "artifact_content" not in json.dumps(seen)
    assert artifact_fleet.analyst_queue(db_path=tmp_path / "fleet.db")


def test_pending_scan_queue_processes_fixture_workers(tmp_path):
    records = [{
        "ecosystem": "crates", "package": "proc-macro1", "version": "1.0.107",
        "artifact_path": str(FIXTURES / "proc-macro1-1.0.107.crate"),
    }]
    artifact_fleet.index_records(records, source="fixture", db_path=tmp_path / "fleet.db")
    result = artifact_fleet.scan_pending(limit=5, workers=2, db_path=tmp_path / "fleet.db")
    assert result["processed"] == 1
    assert result["errors"] == []


def test_benchmark_reports_synthetic_capacity_without_claiming_production():
    result = artifact_fleet.benchmark(artifacts=1000, workers=4, fixture_mode=True)
    assert result["mode"] == "synthetic_fixture"
    assert result["target_artifacts_per_day"] == 114000
    assert "synthetic" in result["note"].lower()


def test_rule_pack_validates_and_triage_show_is_read_only(tmp_path):
    pack = artifact_fleet.validate_rule_pack()
    assert pack["status"] == "valid"
    assert pack["rule_count"] >= 8
    archive = _crate_archive(tmp_path, "proc-macro1-1.0.107.crate")
    scanned = artifact_fleet.scan_artifact(ecosystem="crates", package="proc-macro1", version="1.0.107", artifact=archive, db_path=tmp_path / "fleet.db")
    shown = artifact_fleet.triage_show(scanned["artifact_id"], db_path=tmp_path / "fleet.db")
    assert shown["artifact_id"] == scanned["artifact_id"]
    assert shown["context"]["execution_performed"] is False


def test_live_index_bridge_uses_existing_cursor_collectors(monkeypatch, tmp_path):
    import secopsai.research_surveillance as surveillance

    monkeypatch.setitem(surveillance.COLLECTOR_DEFINITIONS, "npm", {"collector_id": "COL-NPM-CHANGES"})
    monkeypatch.setattr(surveillance, "run_registry_collector", lambda **kwargs: {"cursor_after": "42"})
    monkeypatch.setattr(surveillance, "list_feed_events", lambda **kwargs: [{"package": "fixture", "version": "1.0.0", "registry_timestamp": "2026-08-20T00:00:00Z", "idempotency_key": "event-1"}])
    result = artifact_fleet.index_live_sources(sources=["npm", "crates"], limit=10, db_path=tmp_path / "fleet.db")
    assert result["configured_sources"] == 1
    assert any(item["source"] == "crates" and item["status"] == "not_configured" for item in result["sources"])


def test_artifact_research_handoff_creates_review_only_draft(tmp_path):
    from secopsai.blog import BlogPaths
    archive = _crate_archive(tmp_path, "proc-macro1-1.0.107.crate")
    scanned = artifact_fleet.scan_artifact(ecosystem="crates", package="proc-macro1", version="1.0.107", artifact=archive, db_path=tmp_path / "fleet.db")
    draft = artifact_fleet.draft_artifact_blog(scanned["artifact_id"], db_path=tmp_path / "fleet.db", paths=BlogPaths(root=tmp_path / "blog"))
    assert draft["publication"]["status"] == "review_only"
