import io
import hashlib
import json
import stat
import tarfile
import zipfile
from pathlib import Path
from unittest import mock

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
    materialize_completed_sandbox_evidence,
)
from secopsai.research_cases import add_evidence, add_subject, create_case, get_case
from secopsai.research_artifacts import attach_to_case, import_artifact
from secopsai.research_sandbox import (
    SandboxProviderError,
    list_sandbox_recommendations,
    normalize_result,
    prepare_manual_submission,
    provider_status,
    recommend_dynamic_analysis,
    submit_sandbox_request,
)
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


def test_completed_sandbox_result_materializes_linked_evidence_and_subject_state(tmp_path):
    db = str(tmp_path / "research.db")
    digest = "c" * 64
    case = create_case(title="Automatic sandbox evidence", db_path=db)
    add_subject(
        case["case_id"],
        subject_type="package",
        ecosystem="npm",
        name="demo-pkg",
        version="1.0.0",
        artifact_state="collected",
        metadata={"artifact_sha256": digest},
        db_path=db,
    )
    request = request_sandbox(
        case["case_id"],
        artifact_sha256=digest,
        justification="Confirm the bounded runtime behavior in an isolated provider.",
        behaviors=["network", "process"],
        provider="tria.ge",
        db_path=db,
    )
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    result = normalize_result(
        {
            "id": "260829-auto-evidence",
            "status": "reported",
            "score": 8.2,
            "summary": "Observed a child process and outbound request.",
            "network": [{"domain": "c2.example", "ip": "203.0.113.8", "port": 443}],
        },
        report_url="https://tria.ge/260829-auto-evidence",
    )

    completed = set_sandbox_status(
        request["request_id"],
        "completed",
        result=result,
        actor="sandbox-worker",
        db_path=db,
    )
    assert completed["sandbox_evidence_attached"] is True
    assert completed["sandbox_evidence_id"].startswith("EVD-")

    stored = get_case(case["case_id"], db_path=db)
    sandbox_evidence = [item for item in stored["evidence"] if item["evidence_type"] == "sandbox_analysis"]
    assert len(sandbox_evidence) == 1
    assert sandbox_evidence[0]["sha256"] == digest
    assert sandbox_evidence[0]["locator"] == "https://tria.ge/260829-auto-evidence"
    assert sandbox_evidence[0]["metadata"]["sandbox_request_id"] == request["request_id"]
    assert sandbox_evidence[0]["metadata"]["raw_result_retained"] is False
    subject = next(item for item in stored["subjects"] if item["name"] == "demo-pkg")
    assert subject["validation_state"] == "sandbox_confirmed"
    matrix = build_evidence_matrix(case["case_id"], db_path=db)
    assert matrix["summary"]["sandbox_evidence"] == 1
    assert any("sanitized external sandbox report" in item["statement"] for item in matrix["claims"])


def test_repeated_completed_sandbox_result_is_idempotent(tmp_path):
    db = str(tmp_path / "research.db")
    digest = "d" * 64
    case = create_case(title="Idempotent sandbox evidence", db_path=db)
    request = request_sandbox(
        case["case_id"],
        artifact_sha256=digest,
        justification="Verify that repeated provider polling does not duplicate evidence.",
        behaviors=["network"],
        provider="tria.ge",
        db_path=db,
    )
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    result = normalize_result(
        {"id": "260829-idempotent", "status": "completed", "summary": "No additional behavior was observed."},
        report_url="https://tria.ge/260829-idempotent",
    )
    first = set_sandbox_status(request["request_id"], "completed", result=result, db_path=db)
    second = set_sandbox_status(request["request_id"], "completed", result=result, db_path=db)
    assert first["sandbox_evidence_id"] == second["sandbox_evidence_id"]
    with soc_store.connect(db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM research_evidence WHERE case_id = ? AND evidence_type = 'sandbox_analysis' AND status = 'active'",
            (case["case_id"],),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM research_case_events WHERE case_id = ? AND event_type = 'sandbox_evidence_materialized'",
            (case["case_id"],),
        ).fetchone()[0] == 1


def test_failed_or_unlinkable_sandbox_result_does_not_create_evidence(tmp_path):
    db = str(tmp_path / "research.db")
    case = create_case(title="Sandbox result validation", db_path=db)
    request = request_sandbox(
        case["case_id"],
        artifact_sha256="e" * 64,
        justification="Keep failed provider results retryable.",
        behaviors=["network"],
        provider="tria.ge",
        db_path=db,
    )
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    set_sandbox_status(
        request["request_id"],
        "failed",
        result={"status": "failed", "summary": "Provider error"},
        db_path=db,
    )
    assert get_case(case["case_id"], db_path=db)["evidence"] == []

    retry = request_sandbox(
        case["case_id"],
        artifact_sha256="f" * 64,
        justification="Reject an untrusted report URL without creating evidence.",
        behaviors=["network"],
        provider="tria.ge",
        db_path=db,
    )
    approve_sandbox_submission(retry["request_id"], public_submission_acknowledged=True, db_path=db)
    completed = set_sandbox_status(
        retry["request_id"],
        "completed",
        result={
            "id": "260829-invalid-url",
            "status": "completed",
            "report_url": "https://example.invalid/report",
            "summary": "This must not become durable evidence.",
        },
        db_path=db,
    )
    assert completed["sandbox_evidence_attached"] is False
    stored = get_case(case["case_id"], db_path=db)
    assert stored["evidence"] == []
    assert stored["sandbox_recommendation"]["status"] == "completed_unlinked"


def test_sandbox_evidence_repair_backfills_legacy_completed_request(tmp_path):
    db = str(tmp_path / "research.db")
    case = create_case(title="Legacy sandbox repair", db_path=db)
    request = request_sandbox(
        case["case_id"],
        artifact_sha256="a" * 64,
        justification="Repair a completed request created before automatic evidence linking.",
        behaviors=["network"],
        provider="tria.ge",
        db_path=db,
    )
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    legacy_result = normalize_result(
        {"id": "260829-legacy", "status": "reported", "summary": "Observed a bounded external request."},
        report_url="https://tria.ge/260829-legacy",
    )
    # Simulate a pre-fix row: the request is terminal, but no evidence row exists.
    with soc_store.connect(db) as connection:
        connection.execute(
            "UPDATE research_sandbox_requests SET status = 'completed', result_json = ? WHERE request_id = ?",
            (json.dumps(legacy_result), request["request_id"]),
        )
        connection.commit()

    repaired = materialize_completed_sandbox_evidence(case_id=case["case_id"], db_path=db)
    assert repaired["processed"] == 1
    assert repaired["attached"] == 1
    assert repaired["unlinked"] == 0
    assert get_case(case["case_id"], db_path=db)["sandbox_recommendation"]["status"] == "completed"

    repeated = materialize_completed_sandbox_evidence(case_id=case["case_id"], db_path=db)
    assert repeated["already_linked"] == 1
    assert len([item for item in get_case(case["case_id"], db_path=db)["evidence"] if item["evidence_type"] == "sandbox_analysis"]) == 1


def test_empty_terminal_sandbox_result_remains_unlinked(tmp_path):
    db = str(tmp_path / "research.db")
    case = create_case(title="Empty sandbox result", db_path=db)
    request = request_sandbox(
        case["case_id"],
        artifact_sha256="b" * 64,
        justification="Require a reviewed summary before accepting runtime evidence.",
        behaviors=["network"],
        provider="tria.ge",
        db_path=db,
    )
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)
    completed = set_sandbox_status(
        request["request_id"],
        "completed",
        result={
            "id": "260829-empty",
            "status": "completed",
            "report_url": "https://tria.ge/260829-empty",
            "score": 9.0,
        },
        db_path=db,
    )
    assert completed["sandbox_evidence_attached"] is False
    assert completed["sandbox_evidence"]["reason"] == "sandbox result is missing a sanitized behavior summary"
    assert get_case(case["case_id"], db_path=db)["sandbox_recommendation"]["status"] == "completed_unlinked"


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


def test_tria_ge_submission_uses_documented_file_multipart_contract(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(quarantine))
    monkeypatch.setenv("TRIAGE_API_TOKEN", "test-token")

    sample = b"safe, inert fixture bytes"
    digest = hashlib.sha256(sample).hexdigest()
    (quarantine / f"{digest}.tgz").write_bytes(sample)
    case = create_case(title="Tria.ge submission contract", db_path=db)
    request = request_sandbox(
        case["case_id"],
        artifact_sha256=digest,
        justification="Validate the multipart submission contract without executing a sample.",
        behaviors=["network"],
        provider="tria.ge",
        db_path=db,
    )
    approve_sandbox_submission(request["request_id"], public_submission_acknowledged=True, db_path=db)

    captured = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, _limit):
            return json.dumps({"id": "260829-contract123", "status": "running"}).encode()

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    with mock.patch("secopsai.research_sandbox.urllib.request.urlopen", side_effect=fake_urlopen):
        submitted = submit_sandbox_request(
            request["request_id"],
            public_acknowledged=True,
            db_path=db,
        )

    body = captured["request"].data
    assert b'name="kind"' in body
    assert b"\r\n\r\nfile\r\n" in body
    assert b'name="file"; filename="' in body
    assert b"sample" not in body.split(b'filename=', 1)[0]
    assert captured["request"].get_header("Authorization") == "Bearer test-token"
    assert submitted["status"] == "submitted"
    assert submitted["result"]["submission_id"] == "260829-contract123"
    assert submitted["result"]["report_url"] == "https://tria.ge/260829-contract123"


def test_dynamic_sandbox_recommendation_requires_high_signal_and_exact_artifact():
    observations = [
        {
            "rule_id": "process-execution",
            "category": "execution",
            "confidence": 95,
            "severity": "high",
            "context_classification": "executable_source",
            "contributes_to_score": True,
        },
        {
            "rule_id": "outbound-network",
            "category": "network",
            "confidence": 90,
            "severity": "high",
            "context_classification": "executable_source",
            "contributes_to_score": True,
        },
    ]
    base = {
        "case_id": "RSC-AAAAAAAAAAAA",
        "evidence": [{"evidence_type": "static_analysis", "metadata": {"observations": observations}}],
        "claims": [{"statement": "Runtime behavior requires confirmation.", "missing_evidence": ["dynamic sandbox result"]}],
        "artifacts": [],
        "sandbox_requests": [],
        "verdicts": [],
    }
    blocked = recommend_dynamic_analysis(base)
    assert blocked["recommended"] is True
    assert blocked["status"] == "blocked"
    assert "hash-verified artifact" in blocked["blockers"][0]

    base["artifacts"] = [{
        "artifact_id": "ART-AAAAAAAAAAAAAAAA",
        "sha256": "a" * 64,
        "state": "collected",
        "role": "subject",
    }]
    recommended = recommend_dynamic_analysis(base)
    assert recommended["status"] == "recommended"
    assert recommended["artifact_sha256"] == "a" * 64
    assert recommended["allowed_actions"] == ["request_sandbox_approval"]
    assert "process behavior" in recommended["requested_behaviors"]
    assert "network behavior" in recommended["requested_behaviors"]


def test_dynamic_sandbox_recommendation_ignores_documentation_and_avoids_duplicates():
    case = {
        "case_id": "RSC-BBBBBBBBBBBB",
        "evidence": [{
            "evidence_type": "static_analysis",
            "metadata": {"observations": [{
                "rule_id": "documentation-example",
                "category": "execution",
                "confidence": 99,
                "severity": "high",
                "context_classification": "documentation",
                "contributes_to_score": True,
            }]},
        }],
        "claims": [],
        "artifacts": [{"sha256": "b" * 64, "state": "collected", "role": "subject"}],
        "sandbox_requests": [],
        "verdicts": [],
    }
    result = recommend_dynamic_analysis(case)
    assert result["status"] == "not_recommended"
    assert result["recommended"] is False

    case["sandbox_requests"] = [{"status": "pending_approval"}]
    duplicate = recommend_dynamic_analysis(case)
    assert duplicate["status"] == "already_requested"
    assert "request_sandbox_approval" in duplicate["blocked_actions"]


def test_sandbox_recommendation_queue_reads_cases_without_side_effects(tmp_path):
    db = str(tmp_path / "research.db")
    case = create_case(title="Queue recommendation", db_path=db)
    add_evidence(
        case["case_id"],
        evidence_type="static_analysis",
        title="High signal fixture",
        metadata={"observations": [{
            "rule_id": "process-execution",
            "category": "execution",
            "confidence": 95,
            "severity": "high",
            "context_classification": "executable_source",
            "contributes_to_score": True,
        }]},
        db_path=db,
    )
    queued = list_sandbox_recommendations(db_path=db, limit=10)
    assert queued["summary"]["scanned"] >= 1
    assert queued["summary"]["blocked"] == 1
    assert queued["recommendations"][0]["case_id"] == case["case_id"]


def test_tria_ge_provider_status_verifies_read_only_resources_without_exposing_token(monkeypatch):
    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"resources": [{"name": "fixture"}, {"name": "fixture-2"}]}'

    monkeypatch.setenv("TRIAGE_API_TOKEN", "fixture-token")
    with mock.patch("secopsai.research_sandbox.urllib.request.urlopen", return_value=FakeResponse()) as opener:
        result = provider_status(verify=True)
    assert result["configured"] is True
    assert result["verified"] is True
    assert result["health"] == "ready"
    assert result["resource_count"] == 2
    assert "token" not in json.dumps(result).lower()
    opener.assert_called_once()



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
