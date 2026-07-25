from __future__ import annotations

import os
import platform
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from secopsai.hermes_integration import DEFAULT_REFRESH_SECONDS, MIN_REFRESH_SECONDS, state_dir


LABEL = "ai.secopsai.hermes-monitor"
SYSTEMD_SERVICE = "secopsai-hermes-monitor.service"
SYSTEMD_TIMER = "secopsai-hermes-monitor.timer"
RunCommand = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def refresh_interval(value: int | str | None = None) -> int:
    raw = value if value is not None else os.environ.get("SECOPSAI_HERMES_REFRESH_SECONDS", DEFAULT_REFRESH_SECONDS)
    try:
        interval = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("SECOPSAI_HERMES_REFRESH_SECONDS must be an integer") from exc
    if interval < MIN_REFRESH_SECONDS:
        raise ValueError(f"Hermes refresh interval must be at least {MIN_REFRESH_SECONDS} seconds")
    return interval


def install_service(
    *,
    interval: int | str | None = None,
    configured_home: str | None = None,
    db_path: str | None = None,
    start: bool = True,
    home: Path | None = None,
    platform_name: str | None = None,
    runner: RunCommand | None = None,
) -> dict[str, Any]:
    resolved_home = (home or Path.home()).expanduser().resolve()
    system = (platform_name or platform.system()).lower()
    run = runner or _run
    seconds = refresh_interval(interval)
    if system == "darwin":
        result = _install_launchd(resolved_home, seconds, configured_home, db_path, start, run)
    elif system == "linux":
        result = _install_systemd(resolved_home, seconds, configured_home, db_path, start, run)
    else:
        raise ValueError("Hermes service installation supports macOS, Linux, and Windows through WSL2")
    return {"status": "installed", "service": LABEL, "interval_seconds": seconds, **result}


def service_action(
    action: str,
    *,
    home: Path | None = None,
    platform_name: str | None = None,
    runner: RunCommand | None = None,
    tail: int = 80,
) -> dict[str, Any]:
    normalized = str(action or "").strip().lower()
    if normalized not in {"start", "stop", "status", "run-now", "logs", "uninstall"}:
        raise ValueError(f"unsupported Hermes service action: {action}")
    resolved_home = (home or Path.home()).expanduser().resolve()
    system = (platform_name or platform.system()).lower()
    run = runner or _run
    if normalized == "logs":
        return _logs(resolved_home, system, run, tail)
    if system == "darwin":
        return _launchd_action(normalized, resolved_home, run)
    if system == "linux":
        return _systemd_action(normalized, resolved_home, run)
    raise ValueError("Hermes service controls support macOS, Linux, and Windows through WSL2")


def _refresh_command(configured_home: str | None, db_path: str | None) -> list[str]:
    command = [sys.executable, "-m", "secopsai.cli", "--json", "hermes", "refresh"]
    if configured_home:
        command.extend(["--hermes-home", str(Path(configured_home).expanduser().resolve())])
    if db_path:
        command.extend(["--db-path", str(Path(db_path).expanduser().resolve())])
    return command


def _install_launchd(
    home: Path,
    interval: int,
    configured_home: str | None,
    db_path: str | None,
    start: bool,
    run: RunCommand,
) -> dict[str, Any]:
    launch_agents = home / "Library" / "LaunchAgents"
    logs = home / "Library" / "Logs" / "SecOpsAI"
    launch_agents.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    os.chmod(logs, 0o700)
    path = launch_agents / f"{LABEL}.plist"
    payload = {
        "Label": LABEL,
        "ProgramArguments": _refresh_command(configured_home, db_path),
        "WorkingDirectory": str(Path(__file__).resolve().parents[1]),
        "EnvironmentVariables": {
            "HOME": str(home),
            "PATH": os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
        },
        "RunAtLoad": True,
        "StartInterval": interval,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "ThrottleInterval": 30,
        "Umask": 0o077,
        "StandardOutPath": str(logs / "hermes-monitor.out.log"),
        "StandardErrorPath": str(logs / "hermes-monitor.err.log"),
    }
    with path.open("wb") as handle:
        plistlib.dump(payload, handle, sort_keys=True)
    os.chmod(path, 0o600)
    domain = f"gui/{os.getuid()}"
    run(["launchctl", "bootout", f"{domain}/{LABEL}"])
    if start:
        _require_success(run(["launchctl", "bootstrap", domain, str(path)]), "launchd bootstrap")
    return {
        "manager": "launchd",
        "path": str(path),
        "started": start,
        "logs": [str(logs / "hermes-monitor.out.log"), str(logs / "hermes-monitor.err.log")],
    }


def _install_systemd(
    home: Path,
    interval: int,
    configured_home: str | None,
    db_path: str | None,
    start: bool,
    run: RunCommand,
) -> dict[str, Any]:
    units = home / ".config" / "systemd" / "user"
    state = state_dir(home)
    units.mkdir(parents=True, exist_ok=True)
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    service_path = units / SYSTEMD_SERVICE
    timer_path = units / SYSTEMD_TIMER
    root = Path(__file__).resolve().parents[1]
    command = _refresh_command(configured_home, db_path)
    writable_db = Path(db_path).expanduser().resolve().parent if db_path else root / "data" / "openclaw" / "findings"
    service_lines = [
        "[Unit]",
        "Description=SecOpsAI Hermes telemetry refresh",
        "After=default.target",
        "",
        "[Service]",
        "Type=oneshot",
        f"WorkingDirectory={root}",
        f"ExecStart={shlex.join(command)}",
        f"Environment=HOME={home}",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        f"ReadWritePaths={state} {writable_db}",
        "",
    ]
    timer_lines = [
        "[Unit]",
        "Description=Run SecOpsAI Hermes telemetry refresh on schedule",
        "",
        "[Timer]",
        "OnBootSec=60",
        f"OnUnitActiveSec={interval}",
        "Persistent=true",
        f"Unit={SYSTEMD_SERVICE}",
        "",
        "[Install]",
        "WantedBy=timers.target",
        "",
    ]
    service_path.write_text("\n".join(service_lines), encoding="utf-8")
    timer_path.write_text("\n".join(timer_lines), encoding="utf-8")
    os.chmod(service_path, 0o600)
    os.chmod(timer_path, 0o600)
    _require_success(run(["systemctl", "--user", "daemon-reload"]), "systemd reload")
    if start:
        _require_success(run(["systemctl", "--user", "enable", "--now", SYSTEMD_TIMER]), "systemd enable")
    return {
        "manager": "systemd",
        "path": str(timer_path),
        "service_path": str(service_path),
        "started": start,
        "logs": [f"journalctl --user -u {SYSTEMD_SERVICE}"],
    }


def _launchd_action(action: str, home: Path, run: RunCommand) -> dict[str, Any]:
    domain = f"gui/{os.getuid()}"
    service = f"{domain}/{LABEL}"
    path = home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    if action == "start":
        if not path.exists():
            raise ValueError("Hermes monitor service is not installed")
        completed = run(["launchctl", "bootstrap", domain, str(path)])
        if completed.returncode != 0:
            completed = run(["launchctl", "kickstart", "-k", service])
        _require_success(completed, "launchd start")
    elif action == "stop":
        _require_success(run(["launchctl", "bootout", service]), "launchd stop", allow_not_loaded=True)
    elif action == "run-now":
        _require_success(run(["launchctl", "kickstart", "-k", service]), "launchd run-now")
    elif action == "uninstall":
        run(["launchctl", "bootout", service])
        path.unlink(missing_ok=True)
        return {"status": "uninstalled", "manager": "launchd", "path": str(path), "data_retained": True}
    elif action == "status":
        completed = run(["launchctl", "print", service])
        return {
            "status": "running" if completed.returncode == 0 else ("installed" if path.exists() else "not_installed"),
            "manager": "launchd",
            "path": str(path),
            "details": _bounded(completed.stdout or completed.stderr),
        }
    return {"status": "started" if action in {"start", "run-now"} else "stopped", "manager": "launchd", "path": str(path)}


def _systemd_action(action: str, home: Path, run: RunCommand) -> dict[str, Any]:
    units = home / ".config" / "systemd" / "user"
    service_path = units / SYSTEMD_SERVICE
    timer_path = units / SYSTEMD_TIMER
    if action == "start":
        _require_success(run(["systemctl", "--user", "enable", "--now", SYSTEMD_TIMER]), "systemd start")
    elif action == "stop":
        _require_success(run(["systemctl", "--user", "disable", "--now", SYSTEMD_TIMER]), "systemd stop", allow_not_loaded=True)
    elif action == "run-now":
        _require_success(run(["systemctl", "--user", "start", SYSTEMD_SERVICE]), "systemd run-now")
    elif action == "uninstall":
        run(["systemctl", "--user", "disable", "--now", SYSTEMD_TIMER])
        service_path.unlink(missing_ok=True)
        timer_path.unlink(missing_ok=True)
        run(["systemctl", "--user", "daemon-reload"])
        return {"status": "uninstalled", "manager": "systemd", "path": str(timer_path), "data_retained": True}
    elif action == "status":
        completed = run(["systemctl", "--user", "is-active", SYSTEMD_TIMER])
        return {
            "status": "running" if completed.returncode == 0 else ("installed" if timer_path.exists() else "not_installed"),
            "manager": "systemd",
            "path": str(timer_path),
            "details": _bounded(completed.stdout or completed.stderr),
        }
    return {"status": "started" if action in {"start", "run-now"} else "stopped", "manager": "systemd", "path": str(timer_path)}


def _logs(home: Path, system: str, run: RunCommand, tail: int) -> dict[str, Any]:
    lines = max(1, min(int(tail), 500))
    if system == "darwin":
        directory = home / "Library" / "Logs" / "SecOpsAI"
        entries = []
        for name in ("hermes-monitor.out.log", "hermes-monitor.err.log"):
            path = directory / name
            content = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
            entries.append({"path": str(path), "lines": content.splitlines()[-lines:]})
        return {"status": "ok", "manager": "launchd", "logs": entries}
    if system == "linux":
        completed = run(["journalctl", "--user", "-u", SYSTEMD_SERVICE, "-n", str(lines), "--no-pager"])
        return {"status": "ok" if completed.returncode == 0 else "unavailable", "manager": "systemd", "logs": _bounded(completed.stdout or completed.stderr, 16000)}
    raise ValueError("Hermes monitor logs support macOS, Linux, and Windows through WSL2")


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), text=True, capture_output=True, check=False, timeout=30)


def _require_success(completed: subprocess.CompletedProcess[str], label: str, *, allow_not_loaded: bool = False) -> None:
    if completed.returncode == 0:
        return
    message = _bounded(completed.stderr or completed.stdout)
    if allow_not_loaded and any(value in message.lower() for value in ("not loaded", "not found", "could not find", "not enabled")):
        return
    raise RuntimeError(f"{label} failed: {message or f'exit {completed.returncode}'}")


def _bounded(value: str, limit: int = 4000) -> str:
    return str(value or "")[:limit]

