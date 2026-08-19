from __future__ import annotations

import os
import platform
import plistlib
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

import soc_store
from secopsai.codex_bridge import persist_selected_model
from secopsai.intelligence_jobs import recover_running_jobs


LABEL = "ai.secopsai.codex-bridge"
SYSTEMD_UNIT = "secopsai-codex-bridge.service"
RunCommand = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")


def install_service(
    *,
    db_path: str | None = None,
    start: bool = True,
    home: Path | None = None,
    platform_name: str | None = None,
    runner: RunCommand | None = None,
    autonomy_mode: str = "supervised",
    model: str = "",
) -> dict[str, Any]:
    resolved_home = (home or Path.home()).expanduser().resolve()
    system = (platform_name or platform.system()).lower()
    run = runner or _run
    autonomy_mode = str(autonomy_mode or "supervised").strip().lower()
    if autonomy_mode not in {"supervised", "agent_review"}:
        raise ValueError("autonomy mode must be supervised or agent_review")
    model = str(model or "").strip()
    if model and not MODEL_ID_RE.fullmatch(model):
        raise ValueError("bridge model id contains unsupported characters")
    if model:
        persist_selected_model(model, db_path=db_path, actor="bridge-service-install")
    if system == "darwin":
        result = _install_launchd(resolved_home, db_path, run, start, autonomy_mode, model)
    elif system == "linux":
        result = _install_systemd(resolved_home, db_path, run, start, autonomy_mode, model)
    else:
        raise ValueError("automatic Codex bridge service installation supports macOS and Linux")
    return {"status": "installed", "service": LABEL, **result}


def service_action(
    action: str,
    *,
    home: Path | None = None,
    platform_name: str | None = None,
    runner: RunCommand | None = None,
    tail: int = 80,
    db_path: str | None = None,
) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    if action not in {"start", "stop", "status", "logs", "uninstall"}:
        raise ValueError(f"unsupported bridge service action: {action}")
    resolved_home = (home or Path.home()).expanduser().resolve()
    system = (platform_name or platform.system()).lower()
    run = runner or _run
    if action == "logs":
        return _logs(resolved_home, system, run, tail)
    if system == "darwin":
        return _launchd_action(action, resolved_home, run, db_path=db_path)
    if system == "linux":
        return _systemd_action(action, resolved_home, run, db_path=db_path)
    raise ValueError("Codex bridge service controls support macOS and Linux")


def _install_launchd(home: Path, db_path: str | None, run: RunCommand, start: bool, autonomy_mode: str, model: str) -> dict[str, Any]:
    launch_agents = home / "Library" / "LaunchAgents"
    logs = home / "Library" / "Logs" / "SecOpsAI"
    launch_agents.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    path = launch_agents / f"{LABEL}.plist"
    working_directory = Path(__file__).resolve().parents[1]
    args = [
        sys.executable,
        "-m",
        "secopsai.cli",
        "intelligence",
        "bridge",
        "run",
        "--db-path",
        str(Path(db_path or soc_store.default_db_path()).expanduser().resolve()),
    ]
    environment = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
        "SECOPSAI_RESEARCH_AUTONOMY_MODE": autonomy_mode,
    }
    if os.environ.get("CODEX_HOME"):
        environment["CODEX_HOME"] = os.environ["CODEX_HOME"]
    payload = {
        "Label": LABEL,
        "ProgramArguments": args,
        "WorkingDirectory": str(working_directory),
        "EnvironmentVariables": environment,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 15,
        "ProcessType": "Background",
        "StandardOutPath": str(logs / "codex-bridge.out.log"),
        "StandardErrorPath": str(logs / "codex-bridge.err.log"),
    }
    with path.open("wb") as handle:
        plistlib.dump(payload, handle, sort_keys=True)
    os.chmod(path, 0o600)
    domain = f"gui/{os.getuid()}"
    run(["launchctl", "bootout", f"{domain}/{LABEL}"])
    recover_running_jobs(
        actor="bridge-service-install",
        reason="The previous local bridge process was replaced during service installation.",
        db_path=db_path,
    )
    if start:
        completed = run(["launchctl", "bootstrap", domain, str(path)])
        _require_success(completed, "launchd bootstrap")
    return {
        "manager": "launchd",
        "path": str(path),
        "started": start,
        "logs": [str(logs / "codex-bridge.out.log"), str(logs / "codex-bridge.err.log")],
        "credentials_persisted": False,
        "autonomy_mode": autonomy_mode,
        "model": model or "provider default",
    }


def _install_systemd(home: Path, db_path: str | None, run: RunCommand, start: bool, autonomy_mode: str, model: str) -> dict[str, Any]:
    unit_dir = home / ".config" / "systemd" / "user"
    logs = home / ".local" / "state" / "secopsai"
    unit_dir.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    path = unit_dir / SYSTEMD_UNIT
    working_directory = Path(__file__).resolve().parents[1]
    command = [
        sys.executable,
        "-m",
        "secopsai.cli",
        "intelligence",
        "bridge",
        "run",
        "--db-path",
        str(Path(db_path or soc_store.default_db_path()).expanduser().resolve()),
    ]
    lines = [
        "[Unit]",
        "Description=SecOpsAI local Codex intelligence bridge",
        "After=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"WorkingDirectory={working_directory}",
        f"ExecStart={shlex.join(command)}",
        f"Environment=SECOPSAI_RESEARCH_AUTONOMY_MODE={autonomy_mode}",
        "Restart=on-failure",
        "RestartSec=15",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        f"ReadWritePaths={logs} {Path(db_path or soc_store.default_db_path()).expanduser().resolve().parent}",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(path, 0o600)
    _require_success(run(["systemctl", "--user", "daemon-reload"]), "systemd reload")
    if start:
        _require_success(run(["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT]), "systemd enable")
    return {
        "manager": "systemd",
        "path": str(path),
        "started": start,
        "logs": [f"journalctl --user -u {SYSTEMD_UNIT}"],
        "credentials_persisted": False,
        "autonomy_mode": autonomy_mode,
        "model": model or "provider default",
    }


def _launchd_action(action: str, home: Path, run: RunCommand, *, db_path: str | None = None) -> dict[str, Any]:
    domain = f"gui/{os.getuid()}"
    service = f"{domain}/{LABEL}"
    path = home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    if action == "start":
        if not path.exists():
            raise ValueError("bridge service is not installed")
        completed = run(["launchctl", "bootstrap", domain, str(path)])
        if completed.returncode != 0:
            completed = run(["launchctl", "kickstart", "-k", service])
        _require_success(completed, "launchd start")
    elif action == "stop":
        _require_success(run(["launchctl", "bootout", service]), "launchd stop", allow_not_loaded=True)
        recover_running_jobs(db_path=db_path)
    elif action == "uninstall":
        run(["launchctl", "bootout", service])
        path.unlink(missing_ok=True)
        return {"status": "uninstalled", "manager": "launchd", "path": str(path)}
    elif action == "status":
        completed = run(["launchctl", "print", service])
        return {
            "status": "running" if completed.returncode == 0 else ("installed" if path.exists() else "not_installed"),
            "manager": "launchd",
            "path": str(path),
            "details": _bounded(completed.stdout or completed.stderr),
        }
    return {"status": "started" if action == "start" else "stopped", "manager": "launchd", "path": str(path)}


def _systemd_action(action: str, home: Path, run: RunCommand, *, db_path: str | None = None) -> dict[str, Any]:
    path = home / ".config" / "systemd" / "user" / SYSTEMD_UNIT
    if action == "start":
        _require_success(run(["systemctl", "--user", "start", SYSTEMD_UNIT]), "systemd start")
    elif action == "stop":
        _require_success(run(["systemctl", "--user", "stop", SYSTEMD_UNIT]), "systemd stop", allow_not_loaded=True)
        recover_running_jobs(db_path=db_path)
    elif action == "uninstall":
        run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT])
        path.unlink(missing_ok=True)
        run(["systemctl", "--user", "daemon-reload"])
        return {"status": "uninstalled", "manager": "systemd", "path": str(path)}
    elif action == "status":
        completed = run(["systemctl", "--user", "status", SYSTEMD_UNIT, "--no-pager"])
        return {
            "status": "running" if completed.returncode == 0 else ("installed" if path.exists() else "not_installed"),
            "manager": "systemd",
            "path": str(path),
            "details": _bounded(completed.stdout or completed.stderr),
        }
    return {"status": "started" if action == "start" else "stopped", "manager": "systemd", "path": str(path)}


def _logs(home: Path, system: str, run: RunCommand, tail: int) -> dict[str, Any]:
    tail = max(1, min(int(tail), 500))
    if system == "darwin":
        directory = home / "Library" / "Logs" / "SecOpsAI"
        entries = []
        for name in ("codex-bridge.out.log", "codex-bridge.err.log"):
            path = directory / name
            text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
            entries.append({"path": str(path), "lines": text.splitlines()[-tail:]})
        return {"status": "ok", "manager": "launchd", "logs": entries}
    if system == "linux":
        completed = run(["journalctl", "--user", "-u", SYSTEMD_UNIT, "-n", str(tail), "--no-pager"])
        return {"status": "ok" if completed.returncode == 0 else "unavailable", "manager": "systemd", "logs": _bounded(completed.stdout or completed.stderr, 16000)}
    raise ValueError("Codex bridge logs support macOS and Linux")


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), text=True, capture_output=True, check=False, timeout=30)


def _require_success(completed: subprocess.CompletedProcess[str], label: str, *, allow_not_loaded: bool = False) -> None:
    if completed.returncode == 0:
        return
    message = _bounded(completed.stderr or completed.stdout)
    if allow_not_loaded and any(value in message.lower() for value in ("could not find", "not loaded", "not found")):
        return
    raise RuntimeError(f"{label} failed: {message or 'unknown error'}")


def _bounded(value: str, limit: int = 4000) -> str:
    return str(value or "")[:limit]
