from __future__ import annotations

import json
import plistlib
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import soc_store
from secopsai.codex_bridge import BridgeSettings, doctor, run_once
from secopsai.codex_bridge_service import install_service
from secopsai.intelligence import list_actions, minimize, prepare_bridge_request, run_read_action, validate_bridge_result
from secopsai.intelligence_jobs import (
    cancel_job,
    claim_next_job,
    complete_job,
    enqueue_job,
    get_job,
    list_jobs,
)


ROOT = Path(__file__).resolve().parents[1]


def _finding() -> dict:
    return {
        "finding_id": "FND-INTEL-1",
        "title": "Risky service exposed",
        "summary": "A database service was observed on an internal asset.",
        "severity": "high",
        "severity_score": 80,
        "status": "open",
        "disposition": "unreviewed",
        "source": "secopsai_edge",
        "first_seen": "2026-07-22T10:00:00Z",
        "last_seen": "2026-07-22T10:00:00Z",
        "event_ids": [],
        "rule_ids": ["EDGE-RISKY-SERVICE"],
        "evidence": {"port": 3306, "mac_address": "aa:bb:cc:dd:ee:ff", "raw_nmap_output": "forbidden"},
    }


def test_action_registry_and_read_queries_are_bounded_and_redacted(tmp_path: Path):
    db = str(tmp_path / "core.db")
    soc_store.persist_findings([_finding()], source="secopsai_edge", db_path=db)
    registry = list_actions()
    assert registry["schema_version"] == "secopsai.intelligence.v1"
    assert any(item["name"] == "explain_finding" and item["requires_bridge"] for item in registry["actions"])

    result = run_read_action("get_finding", {"finding_id": "FND-INTEL-1"}, db_path=db)
    encoded = json.dumps(result)
    assert result["read_only"] is True
    assert "3306" in encoded
    assert "aa:bb" not in encoded
    assert "forbidden" not in encoded

    with pytest.raises(ValueError, match="requires the local Codex bridge"):
        run_read_action("explain_finding", {"finding_id": "FND-INTEL-1"}, db_path=db)


def test_versioned_intelligence_fixture_validates_against_contract():
    schema = json.loads((ROOT / "contracts" / "secopsai.intelligence.v1.schema.json").read_text(encoding="utf-8"))
    fixture = json.loads((ROOT / "contracts" / "fixtures" / "secopsai.intelligence.workspace-summary.v1.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(fixture)


def test_bridge_request_treats_records_as_minimized_context(tmp_path: Path):
    db = str(tmp_path / "core.db")
    soc_store.persist_findings([_finding()], source="secopsai_edge", db_path=db)
    request = prepare_bridge_request("explain_finding", {"finding_id": "FND-INTEL-1"}, db_path=db)
    encoded = json.dumps(request)
    assert request["safety"]["raw_telemetry_included"] is False
    assert "raw_nmap_output" not in encoded
    assert "mac_address" not in encoded
    assert "Do not execute commands" in request["instructions"]
    assert minimize({"token": "secret", "safe": "value"}) == {"safe": "value"}


def test_job_lifecycle_is_idempotent_and_audited(tmp_path: Path):
    db = str(tmp_path / "core.db")
    first = enqueue_job(action="explain_finding", target_id="FND-1", requested_by="tester", idempotency_key="same", db_path=db)
    second = enqueue_job(action="explain_finding", target_id="FND-1", requested_by="tester", idempotency_key="same", db_path=db)
    assert first["job_id"] == second["job_id"]
    assert len(list_jobs(db_path=db)) == 1

    claimed = claim_next_job(provider="fake", worker_id="worker-1", db_path=db)
    assert claimed and claimed["status"] == "running"
    completed = complete_job(claimed["job_id"], result={"ok": True}, actor="worker-1", db_path=db)
    assert completed["status"] == "succeeded"
    assert [event["event_type"] for event in completed["events"]] == ["queued", "claimed", "succeeded"]

    canceled_source = enqueue_job(action="prioritize_findings", requested_by="tester", idempotency_key="cancel", db_path=db)
    canceled = cancel_job(canceled_source["job_id"], actor="tester", db_path=db)
    assert canceled["status"] == "canceled"

    running_source = enqueue_job(action="prioritize_findings", requested_by="tester", idempotency_key="running", db_path=db)
    claimed_running = claim_next_job(provider="fake", worker_id="worker-1", db_path=db)
    assert claimed_running and claimed_running["job_id"] == running_source["job_id"]
    with pytest.raises(ValueError, match="cannot be canceled safely"):
        cancel_job(running_source["job_id"], actor="tester", db_path=db)


def test_local_bridge_doctor_recognizes_chatgpt_login(monkeypatch):
    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: "/usr/local/bin/codex")

    def runner(command, stdin, environment, timeout):
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, "codex-cli 1.0\n", "")
        return subprocess.CompletedProcess(command, 0, "Logged in using ChatGPT\n", "")

    status = doctor(BridgeSettings(), runner=runner)
    assert status["status"] == "ready"
    assert status["authentication_method"] in {"chatgpt_subscription", "opencodex_proxy", "api_key"}


def test_local_bridge_doctor_rejects_partial_hosted_queue_configuration(monkeypatch):
    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: "/usr/local/bin/codex")

    def runner(command, stdin, environment, timeout):
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, "codex-cli 1.0\n", "")
        return subprocess.CompletedProcess(command, 0, "Logged in using ChatGPT\n", "")

    status = doctor(BridgeSettings(core_api_url="https://core.example.test"), runner=runner)
    assert status["status"] == "blocked"
    assert "SECOPSAI_CODEX_BRIDGE_TOKEN" in status["message"]


def test_local_bridge_processes_job_with_injected_runner(tmp_path: Path):
    db = str(tmp_path / "core.db")
    soc_store.persist_findings([_finding()], source="secopsai_edge", db_path=db)
    job = enqueue_job(action="explain_finding", target_id="FND-INTEL-1", requested_by="tester", db_path=db)

    def runner(command, stdin, environment, timeout):
        # doctor/model discovery probes should be ignored by the assertion path
        if "--version" in command or "login" in command or "models" in command or "health" in command or "status" in command:
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, "codex-cli 1.0\n", "")
            if "login" in command:
                return subprocess.CompletedProcess(command, 0, "Logged in using ChatGPT\n", "")
            if "health" in command:
                return subprocess.CompletedProcess(command, 0, json.dumps({"ok": True}), "")
            if "models" in command:
                return subprocess.CompletedProcess(command, 0, json.dumps({"openai": ["gpt-5.4"]}), "")
            return subprocess.CompletedProcess(command, 0, "Proxy: running\n", "")
        assert "--sandbox" in command and "read-only" in command
        assert "--ephemeral" in command
        assert "raw_nmap_output" not in stdin
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "summary": "The finding identifies an internally exposed database service.",
                    "risk_assessment": "High priority for ownership and exposure review.",
                    "evidence": ["Port 3306 was observed."],
                    "recommended_actions": ["Confirm service ownership."],
                    "limitations": ["No runtime behavior was observed."],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = run_once(
        db_path=db,
        settings=BridgeSettings(codex_binary="codex", worker_id="test-worker"),
        runner=runner,
        require_subscription_login=False,
    )
    assert result["status"] == "succeeded"
    stored = get_job(job["job_id"], db_path=db)
    assert stored["status"] == "succeeded"
    assert stored["provider"] == "codex_chatgpt_subscription" or str(stored["provider"]).startswith("opencodex")
    assert stored["result"]["data"]["summary"].startswith("The finding")


def test_local_bridge_failure_keeps_diagnostic_and_drops_echoed_context(tmp_path: Path):
    db = str(tmp_path / "core.db")
    soc_store.persist_findings([_finding()], source="secopsai_edge", db_path=db)
    job = enqueue_job(action="explain_finding", target_id="FND-INTEL-1", requested_by="tester", db_path=db)

    def runner(command, stdin, environment, timeout):
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            'user\n{"context":{"finding":"private-normalized-context"}}\nERROR: invalid output schema\n',
        )

    result = run_once(
        db_path=db,
        settings=BridgeSettings(codex_binary="codex", worker_id="test-worker"),
        runner=runner,
        require_subscription_login=False,
    )
    assert result["status"] == "failed"
    stored = get_job(job["job_id"], db_path=db)
    assert "invalid output schema" in stored["error_message"]
    assert "private-normalized-context" not in stored["error_message"]


def test_launchd_service_contains_no_credentials(tmp_path: Path):
    calls = []

    def runner(command):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, "", "")

    result = install_service(
        db_path=str(tmp_path / "core.db"),
        start=True,
        home=tmp_path,
        platform_name="darwin",
        runner=runner,
    )
    plist_path = Path(result["path"])
    with plist_path.open("rb") as handle:
        payload = plistlib.load(handle)
    encoded = json.dumps(payload)
    assert payload["Label"] == "ai.secopsai.codex-bridge"
    assert "SECOPSAI_CORE_READ_TOKEN" not in encoded
    assert "OPENAI_API_KEY" not in encoded
    assert result["credentials_persisted"] is False
    assert any(command[1] == "bootstrap" for command in calls)


def test_bridge_lists_opencodex_models(monkeypatch):
    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: f"/usr/local/bin/{value}")

    def runner(command, stdin, environment, timeout):
        joined = " ".join(command)
        if "models --json" in joined or (len(command) >= 2 and command[1] == "models" and "--json" in command):
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({
                    "kimi": ["kimi-k2.7-code", "kimi-k2.7-code-highspeed"],
                    "xai": ["grok-4.5"],
                    "google-antigravity": ["gemini-3.5-flash-low"],
                }),
                "",
            )
        if command[-1] == "models":
            return subprocess.CompletedProcess(command, 0, "kimi:\n  kimi-k2.7-code *\n", "")
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, "opencodex 2.7.28\n", "")
        if "health" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps({"ok": True}), "")
        if "status" in command:
            return subprocess.CompletedProcess(command, 0, "Proxy: running\nkimi logged in\n", "")
        if "login" in command:
            return subprocess.CompletedProcess(command, 0, "Logged in using ChatGPT\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    from secopsai.codex_bridge import list_models

    payload = list_models(BridgeSettings(), runner=runner)
    ids = {item["id"] for item in payload["models"]}
    assert "kimi/kimi-k2.7-code" in ids
    assert "xai/grok-4.5" in ids
    assert "google-antigravity/gemini-3.5-flash-low" in ids


def test_local_bridge_uses_selected_model_and_falls_back(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    soc_store.persist_findings([_finding()], source="secopsai_edge", db_path=db)
    job = enqueue_job(action="explain_finding", target_id="FND-INTEL-1", requested_by="tester", db_path=db)

    calls = []

    def runner(command, stdin, environment, timeout):
        calls.append(list(command))
        # doctor helpers
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, "codex-cli 1.0\n", "")
        if "login" in command and "status" in command:
            return subprocess.CompletedProcess(command, 0, "Logged in using ChatGPT\n", "")
        if "health" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps({"ok": True}), "")
        if "models" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({"kimi": ["kimi-k2.7-code"], "xai": ["grok-4.5"]}),
                "",
            )
        if "status" in command:
            return subprocess.CompletedProcess(command, 0, "Proxy: running\n", "")
        # first model hits quota, second succeeds
        model = ""
        if "--model" in command:
            model = command[command.index("--model") + 1]
        if model == "kimi/kimi-k2.7-code":
            return subprocess.CompletedProcess(command, 1, "", "ERROR: You've hit your usage limit.")
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "summary": "Fallback model completed the analysis.",
                    "risk_assessment": "Medium pending human review.",
                    "evidence": ["Static package indicators were available."],
                    "recommended_actions": ["Review the evidence matrix."],
                    "limitations": ["No runtime execution was performed."],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: f"/usr/local/bin/{value}")
    result = run_once(
        db_path=db,
        settings=BridgeSettings(
            codex_binary="codex",
            opencodex_binary="opencodex",
            model="kimi/kimi-k2.7-code",
            fallback_models=("xai/grok-4.5",),
            worker_id="test-worker",
        ),
        runner=runner,
        require_ready_provider=False,
    )
    assert result["status"] == "succeeded"
    assert result["model"] == "xai/grok-4.5"
    stored = get_job(job["job_id"], db_path=db)
    assert stored["status"] == "succeeded"
    assert "opencodex:xai" in stored["provider"]


def test_requeue_failed_intelligence_job(tmp_path: Path):
    from secopsai.intelligence_jobs import fail_job, requeue_job

    db = str(tmp_path / "core.db")
    job = enqueue_job(action="explain_finding", target_id="FND-INTEL-1", requested_by="tester", db_path=db)
    claimed = claim_next_job(provider="opencodex_proxy", worker_id="worker-1", db_path=db)
    assert claimed and claimed["job_id"] == job["job_id"]
    failed = fail_job(
        job["job_id"],
        error_code="bridge_failed",
        error_message="usage limit",
        actor="worker-1",
        db_path=db,
    )
    assert failed["status"] == "failed"
    requeued = requeue_job(job["job_id"], actor="tester", db_path=db)
    assert requeued["status"] == "queued"
    assert requeued["provider"] == ""


def test_bridge_normalizes_kimi_style_structured_result():
    from secopsai.codex_bridge import _normalize_bridge_result, _parse_structured_result

    fenced_kimi_output = """```json
{
  "analysis_id": "ANL-1",
  "case_id": "RSC-TEST",
  "human_review_required": true,
  "confirmed_facts": [
    {
      "statement": "SecOpsAI collected nuget:Example@1.0 from its allowlisted registry source.",
      "evidence_refs": ["collect_subject", "artifact.sha256"]
    }
  ],
  "unsupported_claims": [],
  "contradictions": [],
  "missing_evidence": ["Runtime behavior was not observed."]
}
```"""
    parsed = _parse_structured_result(fenced_kimi_output)
    normalized = _normalize_bridge_result(parsed)
    assert normalized["summary"].startswith("SecOpsAI collected nuget:Example@1.0")
    assert "risk_assessment" in normalized
    assert normalized["evidence"][0].startswith("SecOpsAI collected nuget:Example@1.0")
    assert "(evidence: collect_subject" in normalized["evidence"][0]
    assert normalized["limitations"] == ["Runtime behavior was not observed."]
    validated = validate_bridge_result("analyze_research_case", normalized, provider="opencodex:kimi")
    assert validated["provider"] == "opencodex:kimi"
