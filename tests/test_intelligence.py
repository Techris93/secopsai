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
from secopsai.intelligence import list_actions, minimize, prepare_bridge_request, run_read_action
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
    assert status["authentication_method"] == "chatgpt_subscription"


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
    assert stored["provider"] == "codex_chatgpt_subscription"
    assert stored["result"]["data"]["summary"].startswith("The finding")


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
