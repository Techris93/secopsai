import json
import zipfile

import soc_store
from secopsai.research_artifact_analysis import compare_artifacts, extract_ioc_candidates, inspect_artifact, review_ioc_candidate
from secopsai.research_artifacts import attach_to_case, import_artifact
from secopsai.research_cases import add_subject, create_case, update_subject_state
from secopsai.research_acquisition import create_partner_request, update_partner_request


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
    left = import_artifact(str(left_path), ecosystem="nuget", package_name="Demo", version="1.0", db_path=db)
    right = import_artifact(str(right_path), ecosystem="nuget", package_name="Demo", version="2.0", db_path=db)
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
        import_artifact(str(path), ecosystem="nuget", db_path=db)
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
