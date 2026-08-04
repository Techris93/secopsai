from __future__ import annotations

import io
import json
import tarfile

from secopsai import cli as cli_module
from secopsai.intelligence import bridge_output_schema, prepare_bridge_request
from secopsai.intelligence_jobs import claim_next_job, complete_job, fail_job
from secopsai.research_cases import add_evidence, add_subject, create_case, get_case
from secopsai.research_intake import SafeFetcher
from secopsai.research_intake import IntakeError
from secopsai.research_pipeline import (
    agent_complete_pipeline,
    get_pipeline,
    pipeline_intelligence_context,
    resume_investigation_pipeline,
    review_pipeline_item,
    auto_review_pipeline,
    start_investigation_pipeline,
)


def _artifact(package: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        files = {
            "package/package.json": json.dumps(
                {
                    "name": package,
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node setup.js"} if "suspicious" in package else {},
                }
            ),
            "package/index.js": "fetch('https://telemetry.example'); const key = process.env.API_KEY;"
            if "suspicious" in package
            else "module.exports = value => String(value);",
        }
        for name, content in files.items():
            raw = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def _fetcher() -> SafeFetcher:
    artifacts = {
        "suspicious-pkg": _artifact("suspicious-pkg"),
        "legitimate-pkg": _artifact("legitimate-pkg"),
    }

    def fetch(url: str, max_bytes: int):
        for package, artifact in artifacts.items():
            if url == f"https://registry.npmjs.org/{package}":
                metadata = {
                    "name": package,
                    "dist-tags": {"latest": "1.0.0"},
                    "versions": {
                        "1.0.0": {
                            "name": package,
                            "version": "1.0.0",
                            "author": {"name": "Expected Publisher" if package == "legitimate-pkg" else "Unknown"},
                            "dist": {"tarball": f"https://registry.npmjs.org/{package}/-/{package}-1.0.0.tgz"},
                        }
                    },
                }
                return 200, {"content-type": "application/json"}, json.dumps(metadata).encode()
            if f"/{package}/-/" in url:
                return 200, {"content-type": "application/gzip"}, artifact
        raise AssertionError(f"unexpected test URL: {url}")

    return SafeFetcher(fetch=fetch)


def _case(db: str) -> dict:
    case = create_case(
        title="Suspicious package investigation",
        summary="A registry-monitoring lead requires static comparison and evidence-led analyst review before any verdict.",
        case_type="malicious_package",
        db_path=db,
    )
    return add_subject(
        case["case_id"],
        subject_type="package",
        ecosystem="npm",
        name="suspicious-pkg",
        version="1.0.0",
        publisher="Unknown",
        db_path=db,
    )


def _bridge_result(action: str) -> dict:
    data = {
        "summary": f"Review-only {action} result.",
        "risk_assessment": "Static evidence warrants analyst review but does not prove maliciousness.",
        "evidence": ["The package was collected and hash identified without execution."],
        "recommended_actions": ["Verify publisher ownership."],
        "limitations": ["No runtime behavior was observed."],
        "verdict_recommendation": "inconclusive",
        "verdict_confidence": 50,
        "verdict_rationale": "Evidence remains incomplete.",
        "verdict_evidence_refs": [],
    }
    if action == "analyze_research_case":
        data.update(
            {
                "confirmed_facts": ["The collected artifact has a recorded SHA-256."],
                "inferences": ["The lifecycle script may deserve isolated runtime analysis."],
                "unsupported_claims": ["Victim impact has not been established."],
                "contradictions": [],
                "missing_evidence": ["Publisher confirmation is missing."],
                "verdict_recommendation": "likely",
                "verdict_confidence": 78,
                "verdict_rationale": "Static package and comparison evidence supports a likely verdict while runtime behavior remains unobserved.",
                "verdict_evidence_refs": ["collect_subject", "compare_packages"],
            }
        )
    elif action == "generate_analyst_brief":
        data["article_outline"] = ["Summary", "Technical comparison", "Defensive guidance"]
    else:
        data["publication_risks"] = ["Do not describe static indicators as observed runtime behavior."]
        data["disclosure_draft"] = "Review-only disclosure draft."
    return {"schema_version": "secopsai.intelligence.v1", "action": action, "data": data}


def _complete_bridge_queue(db: str) -> None:
    while True:
        job = claim_next_job(provider="test-codex", worker_id="test-worker", db_path=db)
        if job is None:
            return
        complete_job(job["job_id"], result=_bridge_result(job["action"]), actor="test-worker", db_path=db)


def test_pipeline_collects_compares_and_queues_minimized_codex_analysis(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)

    pipeline = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        actor="tester",
        db_path=db,
        fetcher=_fetcher(),
    )

    assert pipeline["status"] == "awaiting_ai"
    assert pipeline["summary"]["comparison_complete"] is True
    assert len([step for step in pipeline["steps"] if step["status"] == "queued"]) == 3
    case_detail = get_case(case["case_id"], db_path=db)
    assert case_detail["evidence"] == []
    assert "quarantine://" not in json.dumps(case_detail)
    case_steps = {step["step_key"]: step for step in case_detail["pipelines"][0]["steps"]}
    assert case_steps["collect_subject"]["result"]["indicator_count"] >= 1
    assert "indicators" not in case_steps["collect_subject"]["result"]
    assert start_investigation_pipeline(case["case_id"], db_path=db, fetcher=_fetcher())["pipeline_id"] == pipeline["pipeline_id"]

    context = pipeline_intelligence_context(pipeline["pipeline_id"], db_path=db)
    encoded = json.dumps(context)
    assert context["safety"]["raw_artifact_included"] is False
    assert "quarantine://" not in encoded
    assert "artifact_content" not in encoded
    assert context["comparison"]["safety"]["execution_performed"] is False

    _complete_bridge_queue(db)
    ready = get_pipeline(pipeline["pipeline_id"], db_path=db)
    assert ready["status"] == "awaiting_review"
    assert ready["review_summary"]["pending"] >= 10
    assert ready["review_summary"]["pending"] <= 20
    assert any(item["item_type"] == "unsupported_claim" for item in ready["review_items"])
    assert any(item["item_type"] == "disclosure_draft" for item in ready["review_items"])
    grouped = next(item for item in ready["review_items"] if item["item_type"] == "proposed_fact")
    assert grouped["content"].startswith("- ")
    assert grouped["metadata"]["grouped_items"] == 1
    assert get_case(case["case_id"], db_path=db)["verdicts"] == []
    assert get_case(case["case_id"], db_path=db)["disclosures"] == []


def test_review_accepts_evidence_and_rejects_advice_without_automatic_verdict(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=_fetcher(),
    )
    _complete_bridge_queue(db)

    current = get_pipeline(pipeline["pipeline_id"], db_path=db)
    for item in current["review_items"]:
        decision = "accepted" if item["item_type"] in {"intake_evidence", "comparison_evidence"} else "rejected"
        review_pipeline_item(
            pipeline["pipeline_id"],
            item["item_id"],
            decision=decision,
            review_note="Reviewed in deterministic test.",
            actor="human-reviewer",
            db_path=db,
        )

    completed = get_pipeline(pipeline["pipeline_id"], db_path=db)
    stored_case = get_case(case["case_id"], db_path=db)
    assert completed["status"] == "succeeded"
    assert completed["review_summary"]["pending"] == 0
    assert len(stored_case["evidence"]) == 7
    assert all((item.get("metadata") or {}).get("review_state") == "accepted" for item in stored_case["evidence"])
    assert stored_case["verdicts"] == []
    assert stored_case["disclosures"] == []
    assert stored_case["status"] != "published"
    assert completed["summary"]["published"] is False


def test_auto_review_pipeline(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=_fetcher(),
    )
    _complete_bridge_queue(db)

    completed = auto_review_pipeline(
        pipeline["pipeline_id"],
        actor="auto-ai-analyst",
        db_path=db,
    )
    assert completed["status"] == "succeeded"
    assert completed["review_summary"]["pending"] == 0
    assert completed["review_summary"]["accepted"] > 0
    assert completed["review_summary"]["rejected"] == 0


def test_agent_complete_records_bounded_verdict_without_external_actions(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=_fetcher(),
    )
    _complete_bridge_queue(db)

    completed = agent_complete_pipeline(pipeline["pipeline_id"], db_path=db)
    stored = get_case(case["case_id"], db_path=db)

    assert completed["status"] == "succeeded"
    assert completed["summary"]["autonomy_mode"] == "agent_review"
    assert completed["summary"]["verdict_recorded"] is True
    assert completed["summary"]["agent_verdict"] == "likely"
    assert completed["summary"]["disclosure_sent"] is False
    assert completed["summary"]["sandbox_submitted"] is False
    assert completed["summary"]["published"] is False
    assert stored["verdicts"][0]["verdict"] == "likely"
    assert stored["verdicts"][0]["actor"].startswith("secopsai-agent-autonomy:")
    assert stored["verdicts"][0]["evidence_ids"]
    accepted_ids = {
        item["evidence_id"]
        for item in stored["evidence"]
        if (item.get("metadata") or {}).get("pipeline_id") == pipeline["pipeline_id"]
    }
    assert set(stored["verdicts"][0]["evidence_ids"]) <= accepted_ids


def test_agent_completion_cannot_treat_local_absence_as_benign(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(case["case_id"], db_path=db, fetcher=_fetcher())

    while True:
        job = claim_next_job(provider="test-codex", worker_id="test-worker", db_path=db)
        if job is None:
            break
        result = _bridge_result(job["action"])
        if job["action"] == "analyze_research_case":
            result["data"].update(
                {
                    "verdict_recommendation": "benign",
                    "verdict_confidence": 99,
                    "verdict_rationale": "The package is not found in the local repository and no matching dependency exists.",
                }
            )
        complete_job(job["job_id"], result=result, actor="test-worker", db_path=db)

    completed = agent_complete_pipeline(pipeline["pipeline_id"], db_path=db)
    stored = get_case(case["case_id"], db_path=db)
    assert completed["summary"]["agent_verdict"] == "inconclusive"
    assert stored["verdicts"][0]["verdict"] == "inconclusive"
    assert "local absence cannot establish package benignness" in stored["verdicts"][0]["rationale"]


def test_agent_review_mode_completes_pipeline_when_last_job_finishes(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SECOPSAI_RESEARCH_AUTONOMY_MODE", "agent_review")
    case = _case(db)
    pipeline = start_investigation_pipeline(case["case_id"], db_path=db, fetcher=_fetcher())
    _complete_bridge_queue(db)

    completed = get_pipeline(pipeline["pipeline_id"], db_path=db)
    assert completed["status"] == "succeeded"
    assert completed["current_step"] == "agent_review_complete"
    assert completed["summary"]["agent_verdict"] == "likely"
    assert completed["review_summary"]["pending"] == 0


def test_retracted_package_reuses_exact_hash_verified_quarantine(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    first = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=_fetcher(),
    )
    _complete_bridge_queue(db)
    auto_review_pipeline(first["pipeline_id"], actor="test-reviewer", db_path=db)

    def unavailable(_url, _max_bytes):
        raise IntakeError("registry returned HTTP 404")

    second = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=SafeFetcher(fetch=unavailable),
    )
    steps = {step["step_key"]: step for step in second["steps"]}
    assert second["pipeline_id"] != first["pipeline_id"]
    assert second["status"] == "awaiting_ai"
    assert steps["collect_subject"]["result"]["reuse"]["mode"] == "verified_quarantine"
    assert steps["collect_reference"]["result"]["reuse"]["hash_verified"] is True
    assert steps["collect_subject"]["result"]["safety"]["execution_performed"] is False
    assert second["summary"]["quarantine_reuse_count"] == 2
    assert second["summary"]["registry_collection_degraded"] is True
    assert "verified a previously quarantined" in steps["evidence_matrix"]["result"]["claims"][0]["statement"]


def test_pipeline_does_not_guess_a_legitimate_reference(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(case["case_id"], db_path=db, fetcher=_fetcher())
    steps = {step["step_key"]: step for step in pipeline["steps"]}
    assert pipeline["summary"]["comparison_input_required"] is True
    assert steps["collect_reference"]["status"] == "awaiting_input"
    assert "will not guess" in steps["collect_reference"]["result"]["message"]
    unchanged = resume_investigation_pipeline(pipeline["pipeline_id"], db_path=db, fetcher=_fetcher())
    assert unchanged["revision"] == 1
    assert unchanged["pipeline_id"] == pipeline["pipeline_id"]

    resumed = resume_investigation_pipeline(
        pipeline["pipeline_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=_fetcher(),
    )
    assert resumed["revision"] == 2
    assert resumed["summary"]["comparison_complete"] is True


def test_bridge_schema_accepts_structured_research_review_fields():
    schema = bridge_output_schema()
    properties = schema["properties"]
    for key in (
        "confirmed_facts",
        "inferences",
        "unsupported_claims",
        "contradictions",
        "missing_evidence",
        "publication_risks",
        "article_outline",
        "disclosure_draft",
    ):
        assert key in properties
    assert set(schema["required"]) == set(properties)


def test_bridge_schema_uses_strict_object_rules_for_tuning_values():
    schema = bridge_output_schema()
    proposed_value = schema["properties"]["rule_tuning_proposals"]["items"]["properties"]["proposed_value"]
    object_variant = next(item for item in proposed_value["anyOf"] if item.get("type") == "object")
    assert object_variant["additionalProperties"] is False
    assert set(object_variant["properties"]) == {"value", "enabled", "threshold", "weight"}
    assert object_variant["required"] == ["value", "enabled", "threshold", "weight"]


def test_pipeline_cli_dispatches_to_the_pipeline_service(monkeypatch, capsys):
    called = {}

    def fake_start(case_id: str, **kwargs):
        called.update({"case_id": case_id, **kwargs})
        return {"pipeline_id": "RPL-AAAAAAAAAAAAAAAA", "status": "awaiting_ai"}

    monkeypatch.setattr(cli_module, "start_investigation_pipeline", fake_start)
    status = cli_module.main(
        [
            "--json",
            "research",
            "pipeline",
            "start",
            "RSC-AAAAAAAAAAAA",
            "--actor",
            "cli-test",
            "--db-path",
            "/tmp/research-cli-test.db",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["pipeline_id"] == "RPL-AAAAAAAAAAAAAAAA"
    assert called["case_id"] == "RSC-AAAAAAAAAAAA"
    assert called["actor"] == "cli-test"


def test_pipeline_cli_dispatches_agent_completion(monkeypatch, capsys):
    called = {}

    def fake_complete(pipeline_id: str, **kwargs):
        called.update({"pipeline_id": pipeline_id, **kwargs})
        return {"pipeline_id": pipeline_id, "status": "succeeded"}

    monkeypatch.setattr(cli_module, "agent_complete_pipeline", fake_complete)
    status = cli_module.main(
        [
            "--json",
            "research",
            "pipeline",
            "agent-complete",
            "RPL-AAAAAAAAAAAAAAAA",
            "--actor",
            "agent-test",
            "--db-path",
            "/tmp/research-agent-test.db",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["status"] == "succeeded"
    assert called["pipeline_id"] == "RPL-AAAAAAAAAAAAAAAA"
    assert called["actor"] == "agent-test"


def test_bridge_request_contains_only_normalized_pipeline_context(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    add_evidence(
        case["case_id"],
        evidence_type="package_artifact",
        title="Legacy quarantined artifact record",
        locator=f"quarantine://{tmp_path}/artifact.tgz",
        provenance="Legacy local intake",
        metadata={
            "quarantine_locator": f"quarantine://{tmp_path}/artifact.tgz",
            "raw_output": "must-not-enter-model-context",
        },
        db_path=db,
    )
    pipeline = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=_fetcher(),
    )
    job = claim_next_job(provider="test-codex", worker_id="test-worker", db_path=db)
    assert job is not None

    request = prepare_bridge_request(job["action"], job["input"], db_path=db)
    encoded = json.dumps(request)
    context = request["context"]["investigation_pipeline"]
    assert context["pipeline_id"] == pipeline["pipeline_id"]
    assert "raw_artifact_included" not in context["safety"]
    assert request["safety"]["artifact_content_included"] is False
    assert "quarantine://" not in encoded
    assert str(tmp_path) not in encoded
    assert "must-not-enter-model-context" not in encoded
    assert "postinstall" in encoded


def test_pipeline_review_is_blocked_until_all_bridge_analysis_is_ready(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(case["case_id"], db_path=db, fetcher=_fetcher())
    pending = next(item for item in pipeline["review_items"] if item["status"] == "pending")

    try:
        review_pipeline_item(
            pipeline["pipeline_id"],
            pending["item_id"],
            decision="accepted",
            actor="human-reviewer",
            db_path=db,
        )
    except ValueError as exc:
        assert "only after all analysis is ready" in str(exc)
    else:
        raise AssertionError("pipeline proposal was accepted before bridge analysis completed")


def test_failed_bridge_analysis_can_resume_without_reusing_stale_review_items(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(
        case["case_id"],
        reference_ecosystem="npm",
        reference_package="legitimate-pkg",
        reference_version="1.0.0",
        db_path=db,
        fetcher=_fetcher(),
    )

    first = claim_next_job(provider="test-codex", worker_id="test-worker", db_path=db)
    assert first is not None
    fail_job(
        first["job_id"],
        error_code="bridge_test_failure",
        error_message="Deterministic bridge failure.",
        actor="test-worker",
        db_path=db,
    )
    _complete_bridge_queue(db)
    failed = get_pipeline(pipeline["pipeline_id"], db_path=db)
    assert failed["status"] == "failed"
    assert failed["summary"]["retry_available"] is True

    resumed = resume_investigation_pipeline(
        pipeline["pipeline_id"],
        actor="human-reviewer",
        db_path=db,
        fetcher=_fetcher(),
    )
    assert resumed["revision"] == 2
    assert resumed["status"] == "awaiting_ai"
    assert all(
        item["status"] == "superseded"
        for item in resumed["review_items"]
        if item["source_key"].startswith("r1:")
    )
    assert any(
        item["status"] == "pending" and item["source_key"].startswith("r2:")
        for item in resumed["review_items"]
    )

    _complete_bridge_queue(db)
    ready = get_pipeline(pipeline["pipeline_id"], db_path=db)
    assert ready["status"] == "awaiting_review"
    assert any(
        item["status"] == "pending" and item["source_key"].startswith("r2:ai:")
        for item in ready["review_items"]
    )
