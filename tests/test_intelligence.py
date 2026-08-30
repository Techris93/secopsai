from __future__ import annotations

import json
import plistlib
import subprocess
import time
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import soc_store
from secopsai.codex_bridge import (
    DEFAULT_FALLBACK_MODELS,
    PRIMARY_MODEL,
    BridgeSettings,
    clear_provider_health_cache,
    doctor,
    load_model_routing,
    persist_model_routing,
    probe_provider_health,
    resolve_model_routing,
    run_loop,
    run_once,
    _invoke_codex,
    _model_chain,
    _run,
)
from secopsai.codex_bridge_service import install_service
from secopsai.intelligence import list_actions, minimize, prepare_bridge_request, run_read_action, validate_bridge_result
from secopsai.intelligence_jobs import (
    cancel_job,
    claim_next_job,
    complete_job,
    enqueue_job,
    get_job,
    list_jobs,
    mark_job_awaiting_provider,
    release_job_from_provider_wait,
    recover_running_jobs,
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


def test_intelligence_status_job_list_is_compact_but_show_keeps_full_result(tmp_path: Path):
    db = str(tmp_path / "core.db")
    queued = enqueue_job(action="prioritize_findings", requested_by="tester", db_path=db)
    claimed = claim_next_job(provider="fake", worker_id="worker-1", db_path=db)
    assert claimed and claimed["job_id"] == queued["job_id"]
    complete_job(claimed["job_id"], result={"summary": "x" * 1000}, actor="worker-1", db_path=db)

    compact = list_jobs(db_path=db, include_result=False)
    assert compact[0]["result"] == {}
    assert compact[0]["result_available"] is True
    assert compact[0]["result_bytes"] > 1000
    assert compact[0]["input"] == {}
    assert compact[0]["input_available"] is False
    assert get_job(claimed["job_id"], db_path=db)["result"]["summary"] == "x" * 1000


def test_bridge_service_recovery_requeues_interrupted_running_jobs(tmp_path: Path):
    db = str(tmp_path / "core.db")
    job = enqueue_job(action="prioritize_findings", requested_by="tester", db_path=db)
    claimed = claim_next_job(provider="opencodex_proxy", worker_id="old-worker", db_path=db)
    assert claimed and claimed["job_id"] == job["job_id"]
    recovered = recover_running_jobs(actor="service-restart", db_path=db)
    assert recovered["job_ids"] == [job["job_id"]]
    stored = get_job(job["job_id"], db_path=db)
    assert stored["status"] == "queued"
    assert stored["events"][-1]["event_type"] == "service_recovered"


def test_local_bridge_doctor_recognizes_chatgpt_login(monkeypatch):
    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: "/usr/local/bin/codex")
    monkeypatch.setenv("SECOPSAI_BRIDGE_DEEP_DOCTOR", "true")

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


def test_bridge_health_probe_reports_each_upstream_failure(monkeypatch):
    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: f"/usr/local/bin/{value}")
    clear_provider_health_cache()
    settings = BridgeSettings(
        codex_binary="codex",
        opencodex_binary="opencodex",
        model=PRIMARY_MODEL,
        fallback_models=DEFAULT_FALLBACK_MODELS,
    )

    def runner(command, stdin, environment, timeout):
        model = command[command.index("--model") + 1]
        if model == PRIMARY_MODEL:
            return subprocess.CompletedProcess(command, 0, "OK", "")
        if model.startswith("google-antigravity/"):
            return subprocess.CompletedProcess(command, 1, "", "HTTP error: 429 Too Many Requests")
        if model.startswith("kimi/"):
            return subprocess.CompletedProcess(command, 1, "", "HTTP error: 403 usage limit reached")
        return subprocess.CompletedProcess(command, 1, "", "HTTP error: 403 no credits")

    health = probe_provider_health(
        settings,
        [PRIMARY_MODEL, *DEFAULT_FALLBACK_MODELS],
        runner=runner,
        force=True,
    )
    assert health[PRIMARY_MODEL]["status"] == "ready"
    assert health["google-antigravity/gemini-3.5-flash-low"]["status"] == "unavailable"
    assert health["google-antigravity/gemini-3.5-flash-low"]["http_status"] == 429
    assert "Too Many Requests" in health["google-antigravity/gemini-3.5-flash-low"]["error"]
    assert health["kimi/kimi-k2.7-code"]["http_status"] == 403
    assert health["xai/grok-4.5"]["http_status"] == 403


def test_bridge_health_probes_selected_model_before_fallbacks(monkeypatch):
    calls = []

    def probe(model, settings, runner, *, force):
        calls.append(model)
        return {"model": model, "status": "ready", "http_status": 200, "probe_method": "test", "error": ""}

    monkeypatch.setattr("secopsai.codex_bridge._probe_provider", probe)
    settings = BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS)
    health = probe_provider_health(settings, [PRIMARY_MODEL, *DEFAULT_FALLBACK_MODELS], runner=lambda *args: None, force=True)
    assert health[PRIMARY_MODEL]["status"] == "ready"
    assert calls[0] == PRIMARY_MODEL
    assert set(calls) == {PRIMARY_MODEL, *DEFAULT_FALLBACK_MODELS}


def test_background_probe_skips_fallbacks_when_selected_model_is_ready(tmp_path: Path, monkeypatch):
    calls = []

    def probe(model, settings, runner, *, force):
        calls.append(model)
        return {"model": model, "status": "ready", "http_status": 200, "probe_method": "test", "error": ""}

    monkeypatch.setattr("secopsai.codex_bridge._probe_provider", probe)
    settings = BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS)
    health = doctor(
        settings,
        runner=lambda *args: None,
        probe_fallbacks=False,
        db_path=str(tmp_path / "bridge.db"),
    )
    assert calls == [PRIMARY_MODEL]
    assert health["live_ready"] is True
    assert health["probe_fallbacks"] is False


def test_background_probe_stops_at_first_healthy_fallback(tmp_path: Path, monkeypatch):
    calls = []

    def probe(model, settings, runner, *, force):
        calls.append(model)
        status = "unavailable" if model == PRIMARY_MODEL else "ready"
        return {"model": model, "status": status, "http_status": 200 if status == "ready" else 429, "probe_method": "test", "error": "at capacity" if status != "ready" else ""}

    monkeypatch.setattr("secopsai.codex_bridge._probe_provider", probe)
    settings = BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS)
    health = doctor(
        settings,
        runner=lambda *args: None,
        probe_fallbacks=True,
        db_path=str(tmp_path / "bridge.db"),
    )
    assert calls == [PRIMARY_MODEL, DEFAULT_FALLBACK_MODELS[0]]
    assert health["live_ready"] is True
    assert health["selected_model_ready"] is False
    assert health["providers"][DEFAULT_FALLBACK_MODELS[0]]["status"] == "ready"


def test_model_chain_keeps_configured_fallbacks_when_catalog_is_stale():
    settings = BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS)
    chain = _model_chain(settings, model=PRIMARY_MODEL, available={"models": [{"id": PRIMARY_MODEL}]})
    assert chain == [PRIMARY_MODEL, *DEFAULT_FALLBACK_MODELS]


def test_bridge_probe_accepts_successful_http_fallback_diagnostic(monkeypatch):
    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: f"/usr/local/bin/{value}")
    clear_provider_health_cache()
    settings = BridgeSettings(model=PRIMARY_MODEL, fallback_models=())

    def runner(command, stdin, environment, timeout):
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text("OK", encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "ERROR: failed to connect to websocket: HTTP error: 426 Upgrade Required",
        )

    health = probe_provider_health(settings, [PRIMARY_MODEL], runner=runner, force=True)
    assert health[PRIMARY_MODEL]["status"] == "ready"
    assert health[PRIMARY_MODEL]["http_status"] == 200
    assert health[PRIMARY_MODEL]["transport_diagnostic_status"] == 426
    assert "fallback transport" in health[PRIMARY_MODEL]["transport_diagnostic"]


def test_provider_model_uses_tool_free_loopback_responses(monkeypatch):
    captured = []
    monkeypatch.setenv("SECOPSAI_OPENCODEX_RESPONSES_URL", "http://127.0.0.1:53886/v1/responses")
    clear_provider_health_cache()

    canonical = {
        "summary": "Bounded local model review completed.",
        "risk_assessment": "Evidence needs analyst review.",
        "evidence": ["Static evidence was supplied."],
        "recommended_actions": ["Review the evidence."],
        "limitations": ["No package code was executed."],
    }

    class FakeResponse:
        ok = True
        status_code = 200
        text = ""

        def __init__(self, payload):
            self._payload = payload
            self.content = json.dumps(payload).encode()

        def json(self):
            return self._payload

    class FakeSession:
        def __init__(self):
            self.trust_env = True

        def post(self, endpoint, **kwargs):
            assert self.trust_env is False
            captured.append({"endpoint": endpoint, **kwargs})
            body = kwargs["json"]
            output = "OK" if "text" not in body else json.dumps(canonical)
            return FakeResponse({"output": [{"content": [{"type": "output_text", "text": output}]}]})

    monkeypatch.setattr("secopsai.codex_bridge.requests.Session", FakeSession)
    settings = BridgeSettings(model="xai/grok-4.6", fallback_models=())
    health = probe_provider_health(settings, ["xai/grok-4.6"], runner=_run, force=True)
    assert health["xai/grok-4.6"]["status"] == "ready"
    assert health["xai/grok-4.6"]["probe_method"] == "opencodex_responses_loopback"

    result = _invoke_codex(
        {"action": "analyze_research_case", "instructions": "Review bounded evidence.", "context": {}},
        settings,
        _run,
        model="xai/grok-4.6",
    )
    assert result["summary"] == canonical["summary"]
    assert all(call["endpoint"] == "http://127.0.0.1:53886/v1/responses" for call in captured)
    assert all("tools" not in call["json"] for call in captured)
    assert captured[-1]["json"]["text"]["format"]["type"] == "json_schema"
    assert captured[-1]["allow_redirects"] is False


def test_bridge_drains_queued_work_before_autopilot_discovery(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    enqueue_job(action="prioritize_findings", requested_by="tester", db_path=db)
    monkeypatch.setattr(
        "secopsai.codex_bridge.run_once",
        lambda **kwargs: {"status": "succeeded", "job": {"job_id": "AIJ-QUEUED"}},
    )
    monkeypatch.setattr(
        "secopsai.investigation_autopilot.run_due",
        lambda **kwargs: pytest.fail("autopilot discovery must wait until the bridge queue is empty"),
    )

    result = run_loop(db_path=db, settings=BridgeSettings(worker_id="queue-first-test"), max_iterations=1)
    assert result["status"] == "stopped"
    assert result["processed"] == 1


def test_bridge_does_not_hold_writer_lock_during_autopilot_discovery(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    from secopsai.sqlite_writer_lock import sqlite_writer_lock

    def discovery(**kwargs):
        # Evidence collection may perform registry and static-analysis work.
        # A separate writer must be able to acquire the lock while that work
        # is running.
        with sqlite_writer_lock(db, timeout_seconds=0.5):
            return {"status": "completed", "processed": 0, "runs": []}

    monkeypatch.setattr("secopsai.investigation_autopilot.run_due", discovery)
    monkeypatch.setattr("secopsai.agent_triage.enqueue_due_findings", lambda **kwargs: {"queued": []})
    monkeypatch.setattr("secopsai.codex_bridge.run_once", lambda **kwargs: {"status": "idle", "job": None})

    result = run_loop(db_path=db, settings=BridgeSettings(worker_id="lock-scope-test"), max_iterations=1)
    assert result["status"] == "stopped"


def test_bridge_runner_kills_the_process_group_on_timeout(monkeypatch):
    captured = {}
    killed = []

    class FakeProcess:
        pid = 4242
        returncode = -9

        def communicate(self, *, input=None, timeout=None):
            if timeout is not None:
                raise subprocess.TimeoutExpired(["codex"], timeout)
            return "", ""

        def kill(self):
            captured["fallback_kill"] = True

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr("secopsai.codex_bridge.subprocess.Popen", fake_popen)
    monkeypatch.setattr("secopsai.codex_bridge.os.killpg", lambda pid, sig: killed.append((pid, sig)))

    with pytest.raises(subprocess.TimeoutExpired):
        _run(["codex", "exec"], "Return OK.", {"PATH": "/usr/bin"}, 1)

    assert captured["kwargs"]["start_new_session"] is True
    assert killed and killed[0][0] == 4242


def test_bridge_uses_luna_first_when_live_probe_is_healthy(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    job = enqueue_job(action="prioritize_findings", requested_by="tester", db_path=db)
    monkeypatch.setattr(
        "secopsai.codex_bridge.doctor",
        lambda settings, runner=None, **kwargs: {
            "status": "ready",
            "live_ready": True,
            "provider": "opencodex_proxy",
            "opencodex": {"status": "ready"},
            "models": {"default_model": PRIMARY_MODEL, "models": [{"id": PRIMARY_MODEL}]},
        },
    )

    def runner(command, stdin, environment, timeout):
        assert command[command.index("--model") + 1] == PRIMARY_MODEL
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text(json.dumps({"summary": "Luna completed the bounded review."}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = run_once(
        db_path=db,
        settings=BridgeSettings(model=PRIMARY_MODEL, worker_id="luna-test"),
        runner=runner,
    )
    assert result["status"] == "succeeded"
    assert result["model"] == PRIMARY_MODEL
    assert get_job(job["job_id"], db_path=db)["status"] == "succeeded"


def test_bridge_falls_back_after_luna_upstream_rate_limit(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    job = enqueue_job(action="prioritize_findings", requested_by="tester", db_path=db)
    models = [PRIMARY_MODEL, *DEFAULT_FALLBACK_MODELS]
    monkeypatch.setattr(
        "secopsai.codex_bridge.doctor",
        lambda settings, runner=None, **kwargs: {
            "status": "degraded",
            "live_ready": True,
            "provider": "opencodex_proxy",
            "opencodex": {"status": "ready"},
            "models": {"default_model": PRIMARY_MODEL, "models": [{"id": item} for item in models]},
        },
    )
    attempted = []

    def runner(command, stdin, environment, timeout):
        model = command[command.index("--model") + 1]
        attempted.append(model)
        if model == PRIMARY_MODEL:
            return subprocess.CompletedProcess(command, 1, "", "HTTP error: 429 Too Many Requests")
        if model == DEFAULT_FALLBACK_MODELS[0]:
            output_path = Path(command[command.index("--output-last-message") + 1])
            output_path.write_text(json.dumps({"summary": "Gemini fallback completed the bounded review."}), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 1, "", "fallback should not be needed")

    result = run_once(
        db_path=db,
        settings=BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS, worker_id="fallback-test"),
        runner=runner,
        require_ready_provider=False,
    )
    assert result["status"] == "succeeded"
    assert result["model"] == DEFAULT_FALLBACK_MODELS[0]
    assert attempted[:2] == [PRIMARY_MODEL, DEFAULT_FALLBACK_MODELS[0]]


def test_bridge_moves_triage_job_to_awaiting_provider_when_all_providers_down(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    job = enqueue_job(
        action="triage_finding",
        target_id="FND-DOWN",
        requested_by="tester",
        db_path=db,
    )
    monkeypatch.setattr(
        "secopsai.codex_bridge.doctor",
        lambda settings, runner=None, **kwargs: {
            "status": "blocked",
            "live_ready": False,
            "configured_provider_count": 4,
            "message": "Provider health: Luna=unavailable: 429; Gemini=unavailable: 429; Kimi=unavailable: 403; Grok=unavailable: 403.",
            "providers": {},
        },
    )
    result = run_once(
        db_path=db,
        settings=BridgeSettings(model=PRIMARY_MODEL, worker_id="blocked-test"),
        runner=lambda *args: pytest.fail("no provider command should run"),
    )
    assert result["status"] == "awaiting_provider"
    stored = get_job(job["job_id"], db_path=db)
    assert stored["status"] == "awaiting_provider"
    assert stored["error_code"] == "provider_unavailable"


def test_provider_recovery_releases_only_the_captured_job(tmp_path: Path):
    db = str(tmp_path / "core.db")
    first = enqueue_job(action="triage_finding", target_id="FND-ONE", requested_by="tester", db_path=db)
    second = enqueue_job(action="triage_finding", target_id="FND-TWO", requested_by="tester", db_path=db)
    mark_job_awaiting_provider(first["job_id"], reason="selected model unavailable", db_path=db)
    mark_job_awaiting_provider(second["job_id"], reason="different captured model unavailable", db_path=db)

    released = release_job_from_provider_wait(
        first["job_id"],
        provider="opencodex:xai",
        db_path=db,
    )

    assert released["status"] == "queued"
    assert released["error_code"] is None
    assert get_job(second["job_id"], db_path=db)["status"] == "awaiting_provider"


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
        autonomy_mode="agent_review",
        model="kimi/kimi-k2.7-code-highspeed",
    )
    plist_path = Path(result["path"])
    with plist_path.open("rb") as handle:
        payload = plistlib.load(handle)
    encoded = json.dumps(payload)
    assert payload["Label"] == "ai.secopsai.codex-bridge"
    assert "SECOPSAI_CORE_READ_TOKEN" not in encoded
    assert "OPENAI_API_KEY" not in encoded
    assert payload["EnvironmentVariables"]["SECOPSAI_RESEARCH_AUTONOMY_MODE"] == "agent_review"
    assert "--model" not in payload["ProgramArguments"]
    from secopsai.codex_bridge import load_selected_model
    assert load_selected_model(db_path=str(tmp_path / "core.db")) == "kimi/kimi-k2.7-code-highspeed"
    assert result["autonomy_mode"] == "agent_review"
    assert result["model"] == "kimi/kimi-k2.7-code-highspeed"
    assert result["credentials_persisted"] is False
    assert any(command[1] == "bootstrap" for command in calls)


def test_bridge_service_rejects_unknown_autonomy_mode(tmp_path: Path):
    with pytest.raises(ValueError, match="supervised or agent_review"):
        install_service(
            db_path=str(tmp_path / "core.db"),
            start=False,
            home=tmp_path,
            platform_name="darwin",
            autonomy_mode="publish_everything",
        )


def test_bridge_service_rejects_unsafe_model_id(tmp_path: Path):
    with pytest.raises(ValueError, match="unsupported characters"):
        install_service(
            db_path=str(tmp_path / "core.db"),
            start=False,
            home=tmp_path,
            platform_name="darwin",
            model="kimi/model;curl example.invalid",
        )


def test_bridge_lists_opencodex_models(monkeypatch):
    monkeypatch.setattr("secopsai.codex_bridge.shutil.which", lambda value: f"/usr/local/bin/{value}")
    monkeypatch.setenv("SECOPSAI_BRIDGE_LIVE_MODELS", "true")

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
            assert environment.get("OCX_SHIM_BYPASS") == "1"
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


def test_opencodex_catalog_pins_survive_transient_model_list_rewrites(tmp_path: Path, monkeypatch):
    config_dir = tmp_path / ".opencodex"
    config_dir.mkdir()
    (config_dir / "config.json").write_text(
        json.dumps(
            {
                "providers": {
                    "google-antigravity": {
                        "defaultModel": "gemini-3.6-flash",
                        "models": ["gemini-3.6-flash"],
                        "modelCatalogPins": [
                            "gemini-3.5-flash-extra-low",
                            "gemini-3.5-flash-low",
                            "gemini-3.5-flash-mid",
                            "gemini-3.5-flash-high",
                            "gemini-3-flash-agent",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    from secopsai.codex_bridge import _models_from_opencodex_config

    ids = {item["id"] for item in _models_from_opencodex_config()}
    assert ids >= {
        "google-antigravity/gemini-3.5-flash-extra-low",
        "google-antigravity/gemini-3.5-flash-low",
        "google-antigravity/gemini-3.5-flash-mid",
        "google-antigravity/gemini-3.5-flash-high",
        "google-antigravity/gemini-3-flash-agent",
    }


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


def test_bridge_promotes_nested_analyst_brief_fields():
    from secopsai.codex_bridge import _normalize_bridge_result

    normalized = _normalize_bridge_result(
        {
            "analyst_brief": {
                "executive_summary": "A detailed evidence-led executive summary.",
                "facts": ["Fact one", "Fact two"],
                "inferences": ["Inference one"],
                "limitations": ["Runtime behavior was not observed."],
                "next_steps": ["Run approved isolated analysis."],
            },
            "missing_evidence": ["Sandbox telemetry"],
        }
    )
    assert normalized["summary"] == "A detailed evidence-led executive summary."
    assert normalized["confirmed_facts"] == ["Fact one", "Fact two"]
    assert normalized["inferences"] == ["Inference one"]
    assert normalized["limitations"] == ["Runtime behavior was not observed."]
    assert normalized["recommended_actions"] == ["Run approved isolated analysis."]


def test_bridge_promotes_schema_adjacent_triage_depth():
    from secopsai.codex_bridge import _normalize_bridge_result

    normalized = _normalize_bridge_result(
        {
            "finding_verdict": "needs_more_evidence",
            "finding_confidence": 55,
            "disposition_recommendation": "needs_review",
            "automation_note": "Keep the finding in review and collect the exact artifacts.",
            "triage_analysis": {
                "facts": ["The scanner score exceeded the configured threshold."],
                "inferences": ["Report-text matches may have inflated the score."],
                "limitations": ["Artifact bytes were not available."],
            },
            "handling_proposal": {
                "immediate_reversible_steps": ["Collect and hash both artifacts."],
                "escalation_path": "Open a Research Case if static comparison corroborates the signal.",
            },
        }
    )
    assert normalized["summary"].startswith("Keep the finding in review")
    assert normalized["risk_assessment"].startswith("Model verdict: needs more evidence")
    assert normalized["confirmed_facts"] == ["The scanner score exceeded the configured threshold."]
    assert normalized["inferences"] == ["Report-text matches may have inflated the score."]
    assert normalized["limitations"] == ["Artifact bytes were not available."]
    assert normalized["recommended_actions"] == [
        "Collect and hash both artifacts.",
        "Open a Research Case if static comparison corroborates the signal.",
    ]


def test_research_bridge_prompt_requests_evidence_led_depth():
    from secopsai.intelligence import ACTIONS, _bridge_instructions

    action = ACTIONS["analyze_research_case"]
    prompt = _bridge_instructions(action)
    assert "comprehensive defensive research assessment" in prompt
    assert "5-12 confirmed_facts" in prompt
    assert "prioritized recommended_actions" in prompt
    assert "Use the available output limits fully" in prompt

def test_operator_selected_model_is_persisted_and_not_overwritten_by_service_flag(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    monkeypatch.delenv("SECOPSAI_BRIDGE_MODEL", raising=False)
    monkeypatch.delenv("SECOPSAI_BRIDGE_FALLBACK_MODELS", raising=False)
    from secopsai.codex_bridge import persist_selected_model, resolve_selected_model, doctor
    persist_selected_model("xai/grok-4.6", db_path=db, actor="operator")
    settings = BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS, worker_id="persist-test")
    assert resolve_selected_model(settings, model=PRIMARY_MODEL, db_path=db) == "xai/grok-4.6"
    calls = []
    def probe(model, settings, runner, *, force):
        calls.append(model)
        return {"model": model, "status": "ready", "http_status": 200, "probe_method": "test", "error": ""}
    monkeypatch.setattr("secopsai.codex_bridge._probe_provider", probe)
    health = doctor(settings, runner=lambda *args: None, probe_fallbacks=True, db_path=db, model=PRIMARY_MODEL)
    assert health["selected_model"] == "xai/grok-4.6"
    assert calls == ["xai/grok-4.6"]
    assert set(health["providers"]) == {"xai/grok-4.6"}


def test_unconfigured_fallbacks_do_not_probe_exhausted_codex_siblings(tmp_path: Path, monkeypatch):
    calls = []
    def probe(model, settings, runner, *, force):
        calls.append(model)
        return {"model": model, "status": "unavailable", "http_status": 429, "probe_method": "test", "error": "usage limit"}
    monkeypatch.setattr("secopsai.codex_bridge._probe_provider", probe)
    settings = BridgeSettings(model="xai/grok-4.6", fallback_models=(), worker_id="exclusive-test")
    health = doctor(settings, runner=lambda *args: None, probe_fallbacks=True, db_path=str(tmp_path / "bridge.db"))
    assert calls == ["xai/grok-4.6"]
    assert health["selected_model"] == "xai/grok-4.6"
    assert health["effective_model_chain"] == ["xai/grok-4.6"]


def test_model_routing_persists_primary_ordered_fallbacks_and_mode(tmp_path: Path):
    db = str(tmp_path / "core.db")
    saved = persist_model_routing(
        "xai/grok-4.6",
        fallback_models=["google-antigravity/gemini-3.5-flash-low", "gpt-5.6-sol"],
        fallback_mode="quota_auth",
        db_path=db,
        actor="dashboard",
    )
    assert saved["fallback_models"] == ["google-antigravity/gemini-3.5-flash-low", "gpt-5.6-sol"]
    assert load_model_routing(db)["fallback_mode"] == "quota_auth"
    resolved = resolve_model_routing(BridgeSettings(model=PRIMARY_MODEL), db_path=db)
    assert resolved == {
        "primary_model": "xai/grok-4.6",
        "fallback_models": ["google-antigravity/gemini-3.5-flash-low", "gpt-5.6-sol"],
        "fallback_mode": "quota_auth",
        "source": "persisted",
    }


def test_disabled_model_routing_keeps_only_operator_primary(tmp_path: Path):
    db = str(tmp_path / "core.db")
    saved = persist_model_routing(
        "xai/grok-4.6",
        fallback_models=["gpt-5.6-sol"],
        fallback_mode="disabled",
        db_path=db,
    )
    assert saved["fallback_models"] == []
    resolved = resolve_model_routing(BridgeSettings(model=PRIMARY_MODEL), db_path=db)
    assert resolved["primary_model"] == "xai/grok-4.6"
    assert resolved["fallback_models"] == []
    assert resolved["fallback_mode"] == "disabled"


def test_any_provider_routing_falls_back_on_provider_timeout(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    enqueue_job(action="prioritize_findings", requested_by="tester", db_path=db)
    models = ["xai/grok-4.6", "google-antigravity/gemini-3.5-flash-low"]
    monkeypatch.setattr(
        "secopsai.codex_bridge.doctor",
        lambda settings, runner=None, **kwargs: {
            "status": "degraded",
            "live_ready": True,
            "provider": "opencodex_proxy",
            "opencodex": {"status": "ready"},
            "models": {"default_model": models[0], "models": [{"id": item} for item in models]},
        },
    )
    attempted = []

    def runner(command, stdin, environment, timeout):
        model = command[command.index("--model") + 1]
        attempted.append(model)
        if model == models[0]:
            return subprocess.CompletedProcess(command, 1, "", "provider unavailable: gateway timeout")
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text(json.dumps({"summary": "Fallback completed."}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = run_once(
        db_path=db,
        settings=BridgeSettings(
            model=models[0],
            fallback_models=(models[1],),
            fallback_mode="any_provider",
            worker_id="routing-test",
        ),
        runner=runner,
        require_ready_provider=False,
    )
    assert result["status"] == "succeeded"
    assert result["model"] == models[1]
    assert attempted == models


def test_persisted_selection_survives_service_restart_without_model_flag(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    monkeypatch.delenv("SECOPSAI_BRIDGE_MODEL", raising=False)
    monkeypatch.delenv("SECOPSAI_BRIDGE_FALLBACK_MODELS", raising=False)
    from secopsai.codex_bridge import load_selected_model, persist_selected_model, resolve_selected_model

    persist_selected_model("xai/grok-4.6", db_path=db, actor="operator")

    def runner(command):
        return subprocess.CompletedProcess(command, 0, "", "")

    result = install_service(
        db_path=db,
        start=True,
        home=tmp_path,
        platform_name="darwin",
        runner=runner,
    )
    with Path(result["path"]).open("rb") as handle:
        payload = plistlib.load(handle)
    assert "--model" not in payload["ProgramArguments"]
    assert load_selected_model(db_path=db) == "xai/grok-4.6"
    settings = BridgeSettings.from_environment()
    assert resolve_selected_model(settings, model="", db_path=db) == "xai/grok-4.6"
    assert resolve_selected_model(settings, model=None, db_path=db) == "xai/grok-4.6"
    assert resolve_selected_model(
        BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS),
        model=PRIMARY_MODEL,
        db_path=db,
    ) == "xai/grok-4.6"


def test_healthy_selected_model_is_the_only_health_probe(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    monkeypatch.delenv("SECOPSAI_BRIDGE_MODEL", raising=False)
    monkeypatch.delenv("SECOPSAI_BRIDGE_FALLBACK_MODELS", raising=False)
    from secopsai.codex_bridge import persist_selected_model

    persist_selected_model("xai/grok-4.6", db_path=db, actor="operator")
    calls = []

    def probe(model, settings, runner, *, force):
        calls.append(model)
        return {"model": model, "status": "ready", "http_status": 200, "probe_method": "test", "error": ""}

    monkeypatch.setattr("secopsai.codex_bridge._probe_provider", probe)
    settings = BridgeSettings(model=PRIMARY_MODEL, fallback_models=DEFAULT_FALLBACK_MODELS, worker_id="probe-scope-test")
    health = doctor(settings, runner=lambda *args: None, probe_fallbacks=True, db_path=db)
    assert health["selected_model"] == "xai/grok-4.6"
    assert calls == ["xai/grok-4.6"]
    assert set(health["providers"]) == {"xai/grok-4.6"}
    assert all(item not in calls for item in DEFAULT_FALLBACK_MODELS)


def test_queued_job_probes_and_runs_its_captured_model_not_global_selection(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    captured_model = "google-antigravity/gemini-3.7-flash"
    enqueue_job(
        action="prioritize_findings",
        requested_by="tester",
        inputs={
            "selected_model": captured_model,
            "fallback_mode": "disabled",
            "fallback_models": [],
        },
        db_path=db,
    )
    probed = []

    def fake_doctor(settings, runner=None, **kwargs):
        probed.append((settings.model, kwargs.get("model"), tuple(settings.fallback_models)))
        return {
            "status": "ready",
            "live_ready": True,
            "configured_provider_count": 1,
            "provider": "opencodex_proxy",
            "opencodex": {"status": "ready"},
            "models": {"models": [{"id": captured_model}]},
            "providers": {captured_model: {"status": "ready"}},
        }

    monkeypatch.setattr("secopsai.codex_bridge.doctor", fake_doctor)

    def runner(command, stdin, environment, timeout):
        assert command[command.index("--model") + 1] == captured_model
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text(json.dumps({"summary": "Captured model completed."}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = run_once(
        db_path=db,
        settings=BridgeSettings(model="xai/grok-4.6", worker_id="captured-model-test"),
        runner=runner,
    )
    assert result["status"] == "succeeded"
    assert result["model"] == captured_model
    assert probed == [(captured_model, captured_model, ())]


def test_long_running_job_renews_lease_and_publishes_busy_health(tmp_path: Path, monkeypatch):
    db = str(tmp_path / "core.db")
    model = "xai/grok-4.6"
    enqueue_job(
        action="prioritize_findings",
        requested_by="tester",
        inputs={"selected_model": model, "fallback_mode": "disabled", "fallback_models": []},
        db_path=db,
    )
    health = {
        "status": "ready",
        "live_ready": True,
        "configured_provider_count": 1,
        "provider": "opencodex_proxy",
        "opencodex": {"status": "ready"},
        "models": {"models": [{"id": model}]},
        "providers": {model: {"status": "ready"}},
    }
    monkeypatch.setattr("secopsai.codex_bridge.doctor", lambda *args, **kwargs: dict(health))
    monkeypatch.setattr("secopsai.codex_bridge.JOB_HEARTBEAT_INTERVAL_SECONDS", 0.02)
    snapshots = []
    from secopsai import codex_bridge as bridge_module

    real_write = bridge_module._write_health_snapshot

    def capture_snapshot(payload, path=None):
        snapshots.append(dict(payload))
        real_write(payload, path)

    monkeypatch.setattr("secopsai.codex_bridge._write_health_snapshot", capture_snapshot)

    def runner(command, stdin, environment, timeout):
        time.sleep(0.08)
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text(json.dumps({"summary": "Long review completed."}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    result = run_once(
        db_path=db,
        settings=BridgeSettings(model=model, worker_id="heartbeat-test"),
        runner=runner,
    )
    assert result["status"] == "succeeded"
    assert sum(1 for item in snapshots if item.get("busy")) >= 2
    assert snapshots[-1]["busy"] is False
    stored = get_job(result["job"]["job_id"], db_path=db)
    assert sum(1 for event in stored["events"] if event["event_type"] == "heartbeat") >= 2
