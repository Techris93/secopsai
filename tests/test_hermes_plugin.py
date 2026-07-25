from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from integrations import hermes as plugin
from integrations.hermes import runner


EXPECTED_TOOLS = {
    "secopsai_hermes_status",
    "secopsai_hermes_findings",
    "secopsai_list_findings",
    "secopsai_show_finding",
    "secopsai_triage_summary",
    "secopsai_session_list",
    "secopsai_session_show",
    "secopsai_asset_summary",
}


class FakeContext:
    def __init__(self) -> None:
        self.tools: dict[str, dict[str, Any]] = {}

    def register_tool(self, **kwargs: Any) -> None:
        self.tools[str(kwargs["name"])] = kwargs


def _registered() -> FakeContext:
    context = FakeContext()
    plugin.register(context)
    return context


def test_manifest_and_registration_expose_only_the_documented_read_only_tools() -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "integrations" / "hermes" / "plugin.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    context = _registered()

    assert set(manifest["provides_tools"]) == EXPECTED_TOOLS
    assert set(context.tools) == EXPECTED_TOOLS
    assert all(item["toolset"] == "secopsai" for item in context.tools.values())
    assert all(item["schema"]["parameters"].get("additionalProperties") is False for item in context.tools.values())


def test_handlers_use_fixed_core_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> dict[str, Any]:
        commands.append(command)
        return {"command": command}

    monkeypatch.setattr(plugin, "run", fake_run)
    context = _registered()

    cases = [
        ("secopsai_hermes_status", {}, ["hermes", "doctor"]),
        ("secopsai_hermes_findings", {"limit": 500}, ["list", "--platform", "hermes", "--no-refresh", "--limit", "100"]),
        ("secopsai_show_finding", {"finding_id": "EDGE-1234"}, ["intelligence", "query", "get_finding", "--target-id", "EDGE-1234"]),
        ("secopsai_triage_summary", {}, ["intelligence", "query", "workspace_summary"]),
        ("secopsai_session_show", {"session_id": "SES-123456"}, ["session", "show", "SES-123456"]),
    ]
    for name, args, expected in cases:
        payload = json.loads(context.tools[name]["handler"](args))
        assert payload["success"] is True
        assert commands[-1] == expected


def test_invalid_identifiers_and_choices_never_reach_the_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugin, "run", lambda command: pytest.fail(f"unexpected command: {command}"))
    context = _registered()

    invalid_finding = json.loads(context.tools["secopsai_show_finding"]["handler"]({"finding_id": "ABC; rm -rf /"}))
    invalid_session = json.loads(context.tools["secopsai_session_show"]["handler"]({"session_id": "../../auth.json"}))
    invalid_severity = json.loads(context.tools["secopsai_list_findings"]["handler"]({"severity": "urgent"}))

    assert invalid_finding["success"] is False
    assert invalid_session["success"] is False
    assert invalid_severity["success"] is False


def test_runner_uses_no_shell_and_strips_inherited_and_response_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    core = tmp_path / "core"
    python = core / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    python.chmod(0o700)
    monkeypatch.setenv("SECOPSAI_HOME", str(core))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-forwarded")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))

    def fake_subprocess(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert command[:5] == [str(python), "-m", "secopsai.cli", "--json", "hermes"]
        assert "shell" not in kwargs
        assert "OPENAI_API_KEY" not in kwargs["env"]
        assert kwargs["env"]["HERMES_HOME"] == str(tmp_path / ".hermes")
        output = json.dumps({"status": "ok", "token": "secret", "nested": {"password": "secret", "value": 1}})
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_subprocess)
    result = runner.run(["hermes", "doctor"])

    assert result == {"status": "ok", "nested": {"value": 1}}
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("mode", ["malformed", "oversized", "failed", "timeout"])
def test_runner_fails_closed_for_invalid_process_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    core = tmp_path / "core"
    python = core / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    python.chmod(0o700)
    monkeypatch.setenv("SECOPSAI_HOME", str(core))

    def fake_subprocess(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if mode == "malformed":
            return subprocess.CompletedProcess(command, 0, stdout="not-json", stderr="")
        if mode == "oversized":
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"value": "x" * (runner.MAX_OUTPUT_BYTES + 1)}), stderr="")
        if mode == "failed":
            return subprocess.CompletedProcess(command, 1, stdout=json.dumps({"error": "not available"}), stderr="")
        raise subprocess.TimeoutExpired(command, timeout=30)

    monkeypatch.setattr(runner.subprocess, "run", fake_subprocess)
    with pytest.raises(runner.SecOpsAIRunnerError):
        runner.run(["hermes", "doctor"])

