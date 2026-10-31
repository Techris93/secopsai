"""Regressions for the hosted artifact failures inventoried on 2026-10-18."""
import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from secopsai import codex_bridge
from secopsai.decision_contracts import DecisionError
from secopsai.decision_evidence import artifact_decision_choices
from secopsai.intelligence import bridge_output_schema


def artifact_context():
    return {"artifact_triage": {
        "findings": [{"rule_id": "BEHAVIOUR:R1", "file_path": "package/install.js"}],
        "flagged_files": [{"path": "package/install.js", "content": "require('./payload.js')"}],
        "missing_files": ["package/install.js", "package/payload.js"],
    }}


def structured_result():
    return {
        "summary": "A static lead requiring review.", "risk_assessment": "No execution observed.",
        "evidence": ["package/install.js:1 loads a separate file."], "recommended_actions": ["Review payload."],
        "limitations": ["Static analysis only."], "confirmed_facts": [], "inferences": [],
        "unsupported_claims": [], "contradictions": [], "missing_evidence": [], "publication_risks": [],
        "article_outline": [], "disclosure_draft": "", "verdict_recommendation": "inconclusive",
        "verdict_confidence": 0, "verdict_rationale": "Verdict not assessed by this action",
        "verdict_evidence_refs": [], "finding_verdict": "true_positive", "finding_confidence": 90,
        "malicious_probability": 80, "decision_contract_version": "artifact-choices-v3",
        "decision_evidence_refs": ["package/install.js"], "exposure_assessment": "unknown",
        "automation_recommendation": "escalate", "counterarguments": [], "rule_tuning_proposals": [],
        "finding_priorities": [], "publication_checks": {},
    }


@pytest.mark.parametrize("action", ["", "triage_artifact", "review_publication_safety", "analyze_research_case"])
def test_every_structured_output_object_satisfies_provider_strict_requirements(action):
    schema = bridge_output_schema(action, artifact_context())
    Draft202012Validator.check_schema(schema)

    def inspect(value):
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
                assert set(value.get("required", [])) == set(value.get("properties", {}))
            for child in value.values():
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)
    inspect(schema)


def test_artifact_schema_accepts_exact_refs_and_rejects_line_qualified_or_invented_citations():
    validator = Draft202012Validator(bridge_output_schema("triage_artifact", artifact_context()))
    raw = structured_result()
    validator.validate(raw)
    for ref in ("package/install.js:1", "R1", "package/invented.js"):
        with pytest.raises(ValidationError):
            validator.validate({**raw, "decision_evidence_refs": [ref]})
    with pytest.raises(ValidationError):
        validator.validate({**raw, "missing_evidence": ["package/install.js"]})
    validator.validate({**raw, "finding_verdict": "needs_more_evidence", "missing_evidence": ["package/payload.js"]})


def test_artifact_without_missing_files_cannot_request_an_invented_file():
    context = artifact_context()
    context["artifact_triage"]["missing_files"] = []
    validator = Draft202012Validator(bridge_output_schema("triage_artifact", context))
    with pytest.raises(ValidationError):
        validator.validate({**structured_result(), "finding_verdict": "needs_more_evidence"})
    with pytest.raises(ValidationError):
        validator.validate({**structured_result(), "missing_evidence": ["package/payload.js"]})


@pytest.mark.parametrize("loopback", [False, True])
def test_native_and_loopback_inference_receive_the_same_bounded_choices(monkeypatch, loopback):
    request = {"action": {"name": "triage_artifact"}, "context": artifact_context(), "instructions": "Review supplied evidence."}
    seen = []

    def check(prompt, schema):
        body = json.loads(prompt.split("\n\n", 1)[1])
        choices = artifact_decision_choices(request["context"]["artifact_triage"])
        assert body["decision_choices"] == choices
        assert schema["properties"]["decision_evidence_refs"]["items"]["enum"] == choices["decision_evidence_refs"]
        seen.append(True)

    def runner(command, prompt, environment, timeout):
        check(prompt, json.loads(Path(command[command.index("--output-schema") + 1]).read_text()))
        Path(command[command.index("--output-last-message") + 1]).write_text(json.dumps(structured_result()))
        return subprocess.CompletedProcess(command, 0, "", "")

    def post(model, prompt, *, schema, timeout):
        check(prompt, schema)
        return {"output": [{"content": [{"type": "output_text", "text": json.dumps(structured_result())}]}]}

    monkeypatch.setattr(codex_bridge, "_opencodex_responses_endpoint", lambda: "http://127.0.0.1:53886/v1/responses")
    monkeypatch.setattr(codex_bridge, "_post_opencodex_response", post)
    raw = codex_bridge._invoke_codex(request, codex_bridge.BridgeSettings(), codex_bridge._run if loopback else runner,
                                    model="provider/model" if loopback else "native-model")
    assert raw["decision_evidence_refs"] == ["package/install.js"] and seen == [True]
    assert raw["disposition_recommendation"] == "true_positive"


def test_policy_disposition_is_derived_only_for_versioned_provider_output():
    from secopsai.decision_contracts import validate_action_result
    raw = structured_result()
    normalized = codex_bridge._normalize_bridge_result(raw, action_name="triage_artifact")
    validate_action_result("triage_artifact", normalized)
    contradictory = codex_bridge._normalize_bridge_result({**raw, "disposition_recommendation": "false_positive"}, action_name="triage_artifact")
    with pytest.raises(DecisionError, match="contradicts"):
        validate_action_result("triage_artifact", contradictory)
    legacy = {key: value for key, value in raw.items() if key != "decision_contract_version"}
    with pytest.raises(DecisionError):
        validate_action_result("triage_artifact", codex_bridge._normalize_bridge_result(legacy, action_name="triage_artifact"))


def test_invalid_schema_is_not_misclassified_as_websocket_availability_failure():
    error = codex_bridge.provider_error_from_process("native-model", returncode=1,
        output='failed to connect to websocket: HTTP error: 426 Upgrade Required\n{"error":{"type":"invalid_request_error","code":"invalid_json_schema"}}')
    assert error.category == "invalid_request"
    assert not codex_bridge.provider_failure_allows_fallback("any_provider", error)


def test_unsupported_artifact_without_identifiers_fails_before_provider_call():
    with pytest.raises(DecisionError, match="no supplied evidence"):
        codex_bridge._invoke_codex({"action": "triage_artifact", "context": {}}, codex_bridge.BridgeSettings(),
                                   lambda *a: pytest.fail("provider called with impossible evidence contract"), model="native-model")


def test_bridge_restarts_between_jobs_when_loaded_source_changes(monkeypatch):
    monkeypatch.setattr(codex_bridge, "_bridge_source_fingerprint", lambda: "new-installed-build")
    monkeypatch.setattr(codex_bridge, "run_once", lambda **kw: pytest.fail("stale runtime claimed a job"))
    result = codex_bridge.run_loop(settings=codex_bridge.BridgeSettings(), max_iterations=1)
    assert result["status"] == "restart_required" and result["processed"] == 0


def test_recovered_research_result_advances_only_its_exact_failed_revision(tmp_path, monkeypatch):
    import soc_store
    from secopsai import research_ai_triage
    db = str(tmp_path / "ledger.db")
    soc_store.init_db(db)
    monkeypatch.setenv("SECOPSAI_DECISION_MODE", "observe")
    context = {"findings": [{"rule_id": "R1", "file_path": "install.js"}]}
    result = {"summary": "Suspicious code", "risk_assessment": "Review required", "evidence": ["R1"],
              "recommended_actions": ["Review"], "limitations": [], "finding_verdict": "true_positive",
              "finding_confidence": 99, "malicious_probability": 95, "disposition_recommendation": "true_positive",
              "decision_evidence_refs": ["R1"]}
    with soc_store.connect(db) as connection:
        research_ai_triage._ensure(connection)
        connection.execute("INSERT INTO research_ai_triage (artifact_key,ecosystem,package,version,status,score,context_json,job_id,created_at,updated_at) VALUES ('npm:fixture@1','npm','fixture','1','failed',80,?,'AIJ-ORIGINAL','t','t')", (json.dumps(context),))
        item = {"artifact_id": "npm:fixture@1", "job_id": "AIJ-RECOVERY", "status": "succeeded", "result": result,
                "recovery_of_job_id": "AIJ-DIFFERENT", "recovery_contract_version": "artifact-choices-v3"}
        assert research_ai_triage._apply_result(connection, item, "t2") is None
        assert connection.execute("SELECT job_id FROM research_ai_triage").fetchone()[0] == "AIJ-ORIGINAL"
        item["recovery_of_job_id"] = "AIJ-ORIGINAL"
        assert research_ai_triage._apply_result(connection, item, "t3") == "escalated"
        stored = connection.execute("SELECT job_id,status,verdict,confidence FROM research_ai_triage").fetchone()
        assert tuple(stored) == ("AIJ-RECOVERY", "triaged", "suspicious", 99)
        assert research_ai_triage._apply_result(connection, {**item, "job_id": "AIJ-LATE", "recovery_of_job_id": "AIJ-RECOVERY"}, "t4") is None


@pytest.mark.parametrize("category", ["availability", "rate_limit", "timeout", "bridge_timeout"])
def test_structured_transient_recovery_preserves_unknown_historical_causes(tmp_path, category):
    from secopsai.intelligence_jobs import enqueue_job, claim_next_job, fail_job, recover_transient_jobs, get_job
    db = str(tmp_path / "ledger.db")
    jobs = []
    for message in ("Connection reset", "DecisionError: decision: all configured bridge models failed"):
        job = enqueue_job(action="explain_finding", target_id="FND-" + str(len(jobs)), db_path=db)
        claim_next_job(provider="fixture", worker_id="fixture", db_path=db)
        fail_job(job["job_id"], actor="fixture", error_code=category, error_message=message, db_path=db)
        jobs.append(job["job_id"])
    recovered = recover_transient_jobs(db_path=db, min_age_seconds=0)
    assert recovered["job_ids"] == jobs[:1]
    assert get_job(jobs[1], db_path=db)["status"] == "failed"


@pytest.mark.parametrize("message,category", [
    ("You've hit your usage limit. Try again at 4:41 AM.", "rate_limit"),
    ("Authentication failed: not logged in", "authentication"),
])
def test_terminal_provider_rejection_outranks_abandoned_websocket_warning(message, category):
    failure = codex_bridge.provider_error_from_process("gpt-6-luna", returncode=1,
        output="failed to connect to websocket: HTTP error: 426 Upgrade Required\nERROR: " + message)
    assert failure.category == category
    assert codex_bridge.provider_failure_allows_fallback("quota_auth", failure)
    assert not codex_bridge.provider_failure_allows_fallback("disabled", failure)


@pytest.mark.parametrize("action", ["explain_finding", "analyze_research_case", "generate_analyst_brief", "review_publication_safety", "prioritize_findings"])
def test_actions_do_not_compile_decision_fields_they_never_return(action):
    props = bridge_output_schema(action, artifact_context())["properties"]

    for key in ("finding_verdict", "finding_confidence", "malicious_probability", "disposition_recommendation"):
        assert props[key] == {"type": "null"}
    assert props["rule_tuning_proposals"] == {"type": "array", "maxItems": 0, "items": {"type": "string"}}
    assert props["decision_evidence_refs"] == {"type": "array", "maxItems": 0, "items": {"type": "string"}}
    if action != "prioritize_findings":
        assert props["finding_priorities"] == {"type": "array", "maxItems": 0, "items": {"type": "string"}}


def test_triage_keeps_the_fields_it_decides_with():
    finding = bridge_output_schema("triage_finding", artifact_context())["properties"]
    assert finding["finding_verdict"]["enum"]
    assert finding["rule_tuning_proposals"]["items"]["type"] == "object"
    artifact = bridge_output_schema("triage_artifact", artifact_context())["properties"]
    assert artifact["decision_evidence_refs"]["minItems"] == 1
    assert bridge_output_schema("prioritize_findings", artifact_context())["properties"]["finding_priorities"]["items"]["type"] == "object"
