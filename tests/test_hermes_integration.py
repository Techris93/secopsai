from __future__ import annotations

import json
import plistlib
import subprocess
from pathlib import Path

import pytest

from secopsai.hermes_integration import doctor, read_state, refresh
from secopsai.hermes_service import install_service, refresh_interval, service_action


def _hermes_fixture(root: Path) -> Path:
    home = root / ".hermes"
    (home / "logs").mkdir(parents=True)
    (home / "sessions").mkdir()
    (home / ".hermes_history").write_text(
        "# 2026-07-25 10:00:00.000000\n+echo healthy\n",
        encoding="utf-8",
    )
    (home / "logs" / "agent.log").write_text(
        "2026-07-25 10:00:01,000 INFO hermes: ready\n",
        encoding="utf-8",
    )
    (home / "sessions" / "sessions.json").write_text("{}", encoding="utf-8")
    (home / "auth.json").write_text('{"token":"must-not-leak"}', encoding="utf-8")
    (home / ".env").write_text("API_KEY=must-not-leak\n", encoding="utf-8")
    return home


def _completed(command: list[str], *, stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


def test_hermes_refresh_persists_normalized_findings_and_safe_state(tmp_path: Path) -> None:
    hermes = _hermes_fixture(tmp_path)
    db_path = tmp_path / "findings.db"
    state_home = tmp_path / "operator"

    result = refresh(configured_home=str(hermes), db_path=str(db_path), home=state_home)

    assert result["status"] == "healthy"
    assert result["raw_events"] >= 2
    assert result["normalized_events"] == result["raw_events"]
    assert db_path.exists()
    serialized = json.dumps(read_state(state_home))
    assert "must-not-leak" not in serialized
    assert "auth.json" not in serialized


def test_hermes_doctor_reports_supported_version_and_excluded_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hermes = _hermes_fixture(tmp_path)
    monkeypatch.setattr("secopsai.hermes_integration.shutil.which", lambda name: "/usr/local/bin/hermes" if name == "hermes" else None)

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[-1] == "--version":
            return _completed(command, stdout="Hermes Agent v0.18.2 (2026.7.7.2)\n")
        if command[-4:] == ["plugins", "list", "--plain", "--no-bundled"]:
            return _completed(command, stdout="secopsai | enabled\n")
        raise AssertionError(command)

    result = doctor(configured_home=str(hermes), home=tmp_path, runner=runner, include_service=False)

    assert result["status"] == "healthy"
    assert result["hermes"]["version_supported"] is True
    assert result["plugin"]["installed"] is True
    assert result["plugin"]["enabled"] is True
    assert {item["name"] for item in result["telemetry"]["excluded_credentials"]} == {"auth.json", ".env"}
    assert all(item["collection_policy"] == "excluded" for item in result["telemetry"]["excluded_credentials"])
    assert "must-not-leak" not in json.dumps(result)


def test_hermes_doctor_rejects_old_or_unparseable_versions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hermes = _hermes_fixture(tmp_path)
    monkeypatch.setattr("secopsai.hermes_integration.shutil.which", lambda name: "/usr/bin/hermes")

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[-1] == "--version":
            return _completed(command, stdout="Hermes Agent v0.17.9\n")
        return _completed(command)

    result = doctor(configured_home=str(hermes), home=tmp_path, runner=runner, include_service=False)
    assert result["status"] == "degraded"
    assert result["hermes"]["version_supported"] is False


def test_invalid_or_too_short_refresh_intervals_are_rejected() -> None:
    with pytest.raises(ValueError, match="integer"):
        refresh_interval("five")
    with pytest.raises(ValueError, match="at least 60"):
        refresh_interval(59)
    assert refresh_interval(300) == 300


def test_launchd_service_install_is_private_idempotent_and_retains_data(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(command))
        return _completed(command)

    first = install_service(home=tmp_path, platform_name="darwin", runner=runner, start=True, interval=300)
    second = install_service(home=tmp_path, platform_name="darwin", runner=runner, start=True, interval=300)
    plist_path = Path(first["path"])
    with plist_path.open("rb") as handle:
        payload = plistlib.load(handle)

    assert first["manager"] == second["manager"] == "launchd"
    assert payload["Label"] == "ai.secopsai.hermes-monitor"
    assert payload["StartInterval"] == 300
    assert payload["ProgramArguments"][-2:] == ["hermes", "refresh"]
    assert plist_path.stat().st_mode & 0o777 == 0o600
    assert any(command[:2] == ["launchctl", "bootstrap"] for command in calls)

    result = service_action("uninstall", home=tmp_path, platform_name="darwin", runner=runner)
    assert result["data_retained"] is True
    assert not plist_path.exists()


def test_systemd_service_and_timer_are_hardened_and_controllable(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(command))
        return _completed(command, stdout="active\n")

    result = install_service(home=tmp_path, platform_name="linux", runner=runner, start=True, interval=600)
    service_text = Path(result["service_path"]).read_text(encoding="utf-8")
    timer_text = Path(result["path"]).read_text(encoding="utf-8")

    assert "NoNewPrivileges=true" in service_text
    assert "ProtectHome=read-only" in service_text
    assert "OnUnitActiveSec=600" in timer_text
    assert ["systemctl", "--user", "enable", "--now", "secopsai-hermes-monitor.timer"] in calls

    status = service_action("status", home=tmp_path, platform_name="linux", runner=runner)
    assert status["status"] == "running"
