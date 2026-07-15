import io
import json
import tarfile
import zipfile

import pytest

import soc_store
from secopsai.research_intake import ADAPTERS, IntakeError, SafeFetcher, inspect_archive, run_package_intake
from secopsai.research_workflow import (
    attach_intake_job,
    build_evidence_matrix,
    prepare_disclosure,
    publication_safety_check,
    record_verdict,
    request_sandbox,
    run_intake_job,
    set_disclosure_status,
    set_sandbox_status,
)
from secopsai.research_cases import create_case, get_case


def npm_artifact() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in {
            "package/package.json": json.dumps({"name": "demo-pkg", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}),
            "package/index.js": "const token = process.env.API_KEY; fetch('https://example.invalid');",
        }.items():
            raw = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def fake_fetcher(artifact: bytes):
    metadata = {
        "name": "demo-pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": "demo-pkg",
                "version": "1.0.0",
                "author": {"name": "Example"},
                "dist": {"tarball": "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz", "integrity": "sha512-test"},
            }
        },
    }

    def fetch(url, max_bytes):
        if url.endswith("demo-pkg"):
            return 200, {"content-type": "application/json"}, json.dumps(metadata).encode()
        return 200, {"content-type": "application/gzip"}, artifact

    return SafeFetcher(fetch=fetch)


def test_all_requested_ecosystems_have_adapters():
    assert {"npm", "pypi", "nuget", "maven", "rubygems", "packagist", "go", "open-vsx"} <= set(ADAPTERS)


def test_intake_is_non_executing_and_can_be_attached(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = create_case(title="Demo package investigation", case_type="malicious_package", db_path=db)
    result = run_package_intake(case_id=case["case_id"], ecosystem="npm", package="demo-pkg", db_path=db, fetcher=fake_fetcher(npm_artifact()))
    assert result["attached"] is False
    assert result["safety"] == {"execution_performed": False, "extracted_to_filesystem": False, "raw_artifact_sent_to_ai": False}
    assert result["analysis"]["lifecycle_scripts"] == {"postinstall": "node setup.js"}
    assert any(item["indicator_id"] == "credential-access" for item in result["analysis"]["indicators"])
    assert get_case(case["case_id"], db_path=db)["evidence"] == []

    attached = run_package_intake(case_id=case["case_id"], ecosystem="npm", package="demo-pkg", db_path=db, attach=True, fetcher=fake_fetcher(npm_artifact()))
    assert attached["attached"] is True
    assert len(attached["evidence_ids"]) == 3
    assert len(get_case(case["case_id"], db_path=db)["evidence"]) == 3


def test_job_preview_then_explicit_attach(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = create_case(title="Job test", db_path=db)
    job = run_intake_job(case_id=case["case_id"], ecosystem="npm", package="demo-pkg", requested_by="tester", db_path=db, fetcher=fake_fetcher(npm_artifact()))
    assert job["status"] == "awaiting_review"
    assert get_case(case["case_id"], db_path=db)["evidence"] == []
    attached = attach_intake_job(job["job_id"], actor="tester", db_path=db)
    assert attached["status"] == "succeeded"
    assert attached["result"]["attached"] is True


def test_redirect_to_unapproved_host_is_rejected():
    def fetch(url, max_bytes):
        return 302, {"location": "https://evil.example/download"}, b""

    with pytest.raises(IntakeError, match="outside the adapter allowlist"):
        SafeFetcher(fetch=fetch).get("https://registry.npmjs.org/demo", allowed_hosts=("registry.npmjs.org",), max_bytes=100)


def test_archive_symlink_is_rejected():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        info = zipfile.ZipInfo("package/link")
        info.external_attr = (0o120777 << 16)
        archive.writestr(info, "target")
    with pytest.raises(IntakeError, match="link or device"):
        inspect_archive(output.getvalue(), "package.zip")


def test_archive_duplicate_paths_are_rejected():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("package/package.json", "{}")
        archive.writestr("package/package.json", "{}")
    with pytest.raises(IntakeError, match="duplicate"):
        inspect_archive(output.getvalue(), "package.zip")


def test_workflow_records_human_gates(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = create_case(title="Workflow test", db_path=db)
    intake = run_package_intake(case_id=case["case_id"], ecosystem="npm", package="demo-pkg", db_path=db, attach=True, fetcher=fake_fetcher(npm_artifact()))
    matrix = build_evidence_matrix(case["case_id"], db_path=db)
    assert matrix["summary"]["supported"] >= 2
    verdict = record_verdict(case["case_id"], verdict="likely", confidence=70, rationale="Static indicators require analyst validation.", evidence_ids=intake["evidence_ids"], db_path=db)
    assert verdict["verdict"] == "likely"
    disclosure = prepare_disclosure(case["case_id"], recipient="security@example.invalid", db_path=db)
    assert disclosure["status"] == "draft"
    assert set_disclosure_status(disclosure["disclosure_id"], "approved", db_path=db)["status"] == "approved"
    artifact = next(item for item in get_case(case["case_id"], db_path=db)["evidence"] if item["evidence_type"] == "package_artifact")
    sandbox = request_sandbox(case["case_id"], artifact_sha256=artifact["sha256"], justification="Need runtime confirmation before publication.", behaviors=["network"], db_path=db)
    assert set_sandbox_status(sandbox["request_id"], "approved", db_path=db)["status"] == "approved"
    review = publication_safety_check(case["case_id"], db_path=db)
    assert review["approval_required"] is True
    assert review["status"] in {"needs_approval", "blocked"}
