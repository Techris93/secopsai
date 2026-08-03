import io
import hashlib
import json
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

import soc_store
from secopsai.research_intake import ADAPTERS, IntakeError, SafeFetcher, inspect_archive, run_package_intake
from secopsai.research_workflow import (
    attach_intake_job,
    build_evidence_matrix,
    prepare_disclosure,
    suggest_disclosure_draft,
    publication_safety_check,
    record_verdict,
    request_sandbox,
    run_intake_job,
    set_disclosure_status,
    set_sandbox_status,
    approve_sandbox_submission,
)
from secopsai.research_cases import create_case, get_case
from secopsai.research_artifacts import attach_to_case, import_artifact
from secopsai.research_sandbox import SandboxProviderError, normalize_result, prepare_manual_submission
from secopsai.research_workflow import get_sandbox_request


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
                "author": {"name": "Example Maintainer", "email": "maintainer@example.com"},
                "maintainers": [{"name": "Example Maintainer", "email": "maintainer@example.com"}],
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


def test_rubygems_adapter_uses_current_metadata_api():
    payload = {
        "name": "stripe",
        "version": "18.2.0",
        "authors": "Stripe",
        "version_created_at": "2026-07-01T00:00:00Z",
        "sha": "abc123",
        "dependencies": {"runtime": []},
    }

    def fetch(url, max_bytes):
        assert url == "https://rubygems.org/api/v1/gems/stripe.json"
        return 200, {"content-type": "application/json"}, json.dumps(payload).encode()

    metadata = ADAPTERS["rubygems"].resolve("stripe", "", SafeFetcher(fetch=fetch))
    assert metadata.version == "18.2.0"
    assert metadata.artifact_url.endswith("/stripe-18.2.0.gem")
    assert metadata.integrity == {"sha": "abc123"}


def test_packagist_adapter_accepts_p2_version_lists_and_selects_latest():
    payload = {
        "packages": {
            "stripe/stripe-php": [
                {"version": "v17.4.0", "time": "2026-07-01T00:00:00Z", "dist": {"url": "https://api.github.com/repos/stripe/stripe-php/zipball/current", "shasum": "new"}},
                {"version": "v17.3.0", "time": "2026-06-01T00:00:00Z", "dist": {"url": "https://api.github.com/repos/stripe/stripe-php/zipball/previous", "shasum": "old"}},
            ]
        }
    }

    def fetch(url, max_bytes):
        assert url == "https://repo.packagist.org/p2/stripe/stripe-php.json"
        return 200, {"content-type": "application/json"}, json.dumps(payload).encode()

    metadata = ADAPTERS["packagist"].resolve("stripe/stripe-php", "", SafeFetcher(fetch=fetch))
    assert metadata.version == "v17.4.0"
    assert metadata.artifact_url.endswith("/current")
    assert metadata.integrity == {"shasum": "new"}


def test_packagist_adapter_skips_prerelease_by_default():
    payload = {
        "packages": {
            "stripe/stripe-php": [
                {"version": "v21.1.0-alpha.1", "dist": {"url": "https://api.github.com/repos/stripe/stripe-php/zipball/alpha"}},
                {"version": "v21.0.0", "dist": {"url": "https://api.github.com/repos/stripe/stripe-php/zipball/stable"}},
            ]
        }
    }

    def fetch(url, max_bytes):
        return 200, {"content-type": "application/json"}, json.dumps(payload).encode()

    metadata = ADAPTERS["packagist"].resolve("stripe/stripe-php", "", SafeFetcher(fetch=fetch))
    assert metadata.version == "v21.0.0"
    explicit = ADAPTERS["packagist"].resolve("stripe/stripe-php", "v21.1.0-alpha.1", SafeFetcher(fetch=fetch))
    assert explicit.version == "v21.1.0-alpha.1"


def test_maven_adapter_ignores_prerelease_release_marker_by_default():
    payload = b"""<metadata><versioning><release>33.2.0-beta.1</release><versions><version>33.1.0</version><version>33.2.0-beta.1</version></versions></versioning></metadata>"""

    def fetch(url, max_bytes):
        return 200, {"content-type": "application/xml"}, payload

    metadata = ADAPTERS["maven"].resolve("com.stripe:stripe-java", "", SafeFetcher(fetch=fetch))
    assert metadata.version == "33.1.0"
    explicit = ADAPTERS["maven"].resolve("com.stripe:stripe-java", "33.2.0-beta.1", SafeFetcher(fetch=fetch))
    assert explicit.version == "33.2.0-beta.1"


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
    with pytest.raises(ValueError, match="acknowledgment"):
        approve_sandbox_submission(sandbox["request_id"], db_path=db)
    assert approve_sandbox_submission(sandbox["request_id"], public_submission_acknowledged=True, db_path=db)["status"] == "approved"
    review = publication_safety_check(case["case_id"], db_path=db)
    assert review["approval_required"] is True
    assert review["status"] in {"needs_approval", "blocked"}


def test_manual_sandbox_handoff_requires_approval_and_preserves_exact_hash(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    quarantine = tmp_path / "quarantine"
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(quarantine))
    case = create_case(title="Manual sandbox handoff", db_path=db)
    source = tmp_path / "candidate.nupkg"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("candidate.nuspec", "<package><metadata><id>Candidate</id></metadata></package>")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    artifact = import_artifact(
        str(source),
        ecosystem="nuget",
        package_name="Candidate",
        version="1.0.0",
        provenance={"source": "authorized test fixture"},
        db_path=db,
    )
    attach_to_case(case["case_id"], artifact["artifact_id"], db_path=db)
    request = request_sandbox(
        case["case_id"],
        artifact_sha256=digest,
        justification="Confirm runtime behavior in an isolated public sandbox.",
        behaviors=["network", "process"],
        db_path=db,
    )
    with pytest.raises(SandboxProviderError, match="approved"):
        prepare_manual_submission(
            request["request_id"],
            output_dir=str(tmp_path / "handoff"),
            public_acknowledged=True,
            db_path=db,
        )
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    prepared = prepare_manual_submission(
        request["request_id"],
        output_dir=str(tmp_path / "handoff"),
        public_acknowledged=True,
        actor="test-operator",
        db_path=db,
    )
    output = Path(prepared["output_path"])
    assert output.is_file()
    assert hashlib.sha256(output.read_bytes()).hexdigest() == digest
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    durable = get_sandbox_request(request["request_id"], db_path=db)
    assert durable["status"] == "approved"
    assert durable["result"]["manual_exports"][0]["sha256"] == digest
    assert "output_path" not in durable["result"]["manual_exports"][0]


def test_manual_sandbox_handoff_rejects_tampered_quarantine(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    quarantine = tmp_path / "quarantine"
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(quarantine))
    case = create_case(title="Tampered sandbox handoff", db_path=db)
    source = tmp_path / "candidate.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("candidate.txt", "original")
    artifact = import_artifact(str(source), provenance={"source": "authorized test fixture"}, db_path=db)
    attach_to_case(case["case_id"], artifact["artifact_id"], db_path=db)
    request = request_sandbox(case["case_id"], artifact_sha256=artifact["sha256"], justification="Test hash enforcement.", behaviors=["filesystem"], db_path=db)
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    quarantined = next(quarantine.glob(f"{artifact['sha256']}.*"))
    quarantined.write_bytes(b"tampered")
    with pytest.raises(SandboxProviderError, match="hash"):
        prepare_manual_submission(request["request_id"], output_dir=str(tmp_path / "handoff"), public_acknowledged=True, db_path=db)


def test_manual_sandbox_handoff_rejects_catalog_path_outside_quarantine(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    quarantine = tmp_path / "quarantine"
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(quarantine))
    case = create_case(title="Out-of-quarantine handoff", db_path=db)
    source = tmp_path / "outside.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("candidate.txt", "original")
    artifact = import_artifact(str(source), provenance={"source": "authorized test fixture"}, db_path=db)
    attach_to_case(case["case_id"], artifact["artifact_id"], db_path=db)
    request = request_sandbox(case["case_id"], artifact_sha256=artifact["sha256"], justification="Test quarantine boundary.", behaviors=["filesystem"], db_path=db)
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    with soc_store.connect(db) as connection:
        connection.execute("UPDATE research_artifacts SET quarantine_path = ? WHERE artifact_id = ?", (str(source), artifact["artifact_id"]))
        connection.commit()
    with pytest.raises(SandboxProviderError, match="outside local quarantine"):
        prepare_manual_submission(request["request_id"], output_dir=str(tmp_path / "handoff"), public_acknowledged=True, db_path=db)


def test_manual_sandbox_result_is_sanitized_and_tria_ge_scoped():
    result = normalize_result(
        {
            "id": "260803-example123",
            "status": "reported",
            "score": 8.5,
            "summary": "Observed process and network behavior.",
            "secret": "must-not-survive",
        },
        report_url="https://tria.ge/260803-example123",
    )
    assert result["score"] == 8.5
    assert result["behavior"] == "Observed process and network behavior."
    assert "secret" not in result
    with pytest.raises(SandboxProviderError, match="approved Tria.ge"):
        normalize_result({"id": "260803-example123"}, report_url="https://example.invalid/report")



def test_disclosure_prefills_from_case_metadata(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = create_case(title="Disclosure prefill test", db_path=db)
    run_package_intake(
        case_id=case["case_id"],
        ecosystem="npm",
        package="demo-pkg",
        db_path=db,
        attach=True,
        fetcher=fake_fetcher(npm_artifact()),
    )
    suggestion = suggest_disclosure_draft(case["case_id"], db_path=db)
    assert suggestion["recipient"] == "maintainer@example.com"
    assert "demo-pkg" in suggestion["subject"]
    assert "demo-pkg" in suggestion["body"]
    assert any(value == "maintainer@example.com" for value in suggestion["recipient_candidates"])
    disclosure = prepare_disclosure(case["case_id"], db_path=db)
    assert disclosure["status"] == "draft"
    assert disclosure["recipient"] == "maintainer@example.com"
    assert "demo-pkg" in disclosure["subject"]
    assert disclosure["body"]
