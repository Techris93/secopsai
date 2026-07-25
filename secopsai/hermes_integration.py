from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

import soc_store
from adapters.hermes.adapter import HermesAdapter
from detect import run_detection

try:
    import fcntl
except ImportError:  # pragma: no cover - Hermes background monitoring targets POSIX hosts
    fcntl = None  # type: ignore[assignment]


MIN_HERMES_VERSION = (0, 18, 2)
STATE_SCHEMA = "secopsai.hermes.monitor-state.v1"
DEFAULT_REFRESH_SECONDS = 300
MIN_REFRESH_SECONDS = 60
RunCommand = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]

TELEMETRY_SOURCES = (
    ("history", ".hermes_history"),
    ("agent_log", "logs/agent.log"),
    ("error_log", "logs/errors.log"),
    ("gateway_log", "logs/gateway.log"),
    ("sessions", "sessions/sessions.json"),
    ("gateway_state", "gateway_state.json"),
)
EXCLUDED_CREDENTIAL_PATHS = ("auth.json", ".env")


def hermes_home(value: str | None = None) -> Path:
    configured = value or os.environ.get("HERMES_HOME")
    return Path(configured).expanduser().resolve() if configured else (Path.home() / ".hermes").resolve()


def state_dir(home: Path | None = None) -> Path:
    configured = os.environ.get("SECOPSAI_STATE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    resolved_home = (home or Path.home()).expanduser().resolve()
    return resolved_home / ".local" / "state" / "secopsai"


def state_path(home: Path | None = None) -> Path:
    return state_dir(home) / "hermes-monitor-state.json"


def lock_path(home: Path | None = None) -> Path:
    return state_dir(home) / "hermes-monitor.lock"


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def read_state(home: Path | None = None) -> dict[str, Any]:
    path = state_path(home)
    if not path.exists():
        return {"schema_version": STATE_SCHEMA, "status": "never_run", "path": str(path)}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema_version": STATE_SCHEMA,
            "status": "invalid",
            "path": str(path),
            "error": f"{type(exc).__name__}: {exc}",
        }
    return payload if isinstance(payload, dict) else {"schema_version": STATE_SCHEMA, "status": "invalid"}


@contextmanager
def _exclusive_refresh(home: Path | None = None) -> Iterator[bool]:
    path = lock_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    handle = path.open("a+", encoding="utf-8")
    os.chmod(path, 0o600)
    if fcntl is None:  # pragma: no cover - protected by supported platform checks
        handle.close()
        raise RuntimeError("Hermes monitor locking is unavailable on this platform")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        yield True
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def refresh(
    *,
    configured_home: str | None = None,
    db_path: str | None = None,
    max_lines: int = 5000,
    home: Path | None = None,
) -> dict[str, Any]:
    resolved_home = hermes_home(configured_home)
    started_at = _utc_now()
    with _exclusive_refresh(home) as acquired:
        if not acquired:
            return {
                "schema_version": STATE_SCHEMA,
                "status": "skipped_overlap",
                "started_at": started_at,
                "hermes_home": str(resolved_home),
            }

        running = {
            "schema_version": STATE_SCHEMA,
            "status": "running",
            "started_at": started_at,
            "hermes_home": str(resolved_home),
        }
        _safe_write_json(state_path(home), running)
        try:
            adapter = HermesAdapter({"hermes_home": str(resolved_home)})
            raw_events = list(adapter.collect(max_lines=max(1, min(int(max_lines), 20000))))
            normalized = [event for item in raw_events if (event := adapter.normalize(item))]
            detection = run_detection(normalized)
            findings = list(detection.get("findings") or [])
            resolved_db = soc_store.persist_findings(findings, source="secopsai_hermes", db_path=db_path)
            completed = {
                "schema_version": STATE_SCHEMA,
                "status": "healthy",
                "started_at": started_at,
                "completed_at": _utc_now(),
                "hermes_home": str(resolved_home),
                "raw_events": len(raw_events),
                "normalized_events": len(normalized),
                "findings": len(findings),
                "findings_db": resolved_db,
            }
            _safe_write_json(state_path(home), completed)
            return completed
        except Exception as exc:
            failed = {
                "schema_version": STATE_SCHEMA,
                "status": "degraded",
                "started_at": started_at,
                "completed_at": _utc_now(),
                "hermes_home": str(resolved_home),
                "error": f"{type(exc).__name__}: {exc}",
            }
            _safe_write_json(state_path(home), failed)
            raise


def _parse_version(output: str) -> tuple[int, int, int] | None:
    match = re.search(r"Hermes Agent v(\d+)\.(\d+)\.(\d+)", output)
    if not match:
        return None
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), text=True, capture_output=True, check=False, timeout=15)


def doctor(
    *,
    configured_home: str | None = None,
    home: Path | None = None,
    runner: RunCommand | None = None,
    include_service: bool = True,
) -> dict[str, Any]:
    resolved_home = hermes_home(configured_home)
    run = runner or _run
    executable = shutil.which("hermes")
    version_output = ""
    version: tuple[int, int, int] | None = None
    if executable:
        completed = run([executable, "--version"])
        version_output = (completed.stdout or completed.stderr or "").strip()
        if completed.returncode == 0:
            version = _parse_version(version_output)

    sources = []
    for name, relative in TELEMETRY_SOURCES:
        path = resolved_home / relative
        sources.append(
            {
                "name": name,
                "path": str(path),
                "exists": path.exists(),
                "readable": path.is_file() and os.access(path, os.R_OK),
            }
        )
    request_dump_count = len(list((resolved_home / "sessions").glob("request_dump_*.json")))

    plugin = {"status": "unavailable", "installed": False, "enabled": False}
    if executable:
        completed = run([executable, "plugins", "list", "--plain", "--no-bundled"])
        output = (completed.stdout or completed.stderr or "")[:16000]
        lowered = output.lower()
        installed = completed.returncode == 0 and "secopsai" in lowered
        plugin = {
            "status": "installed" if installed else "not_installed",
            "installed": installed,
            "enabled": installed and not any(marker in lowered for marker in ("secopsai (disabled)", "secopsai | disabled")),
        }

    service: dict[str, Any] = {"status": "not_checked"}
    if include_service:
        try:
            from secopsai.hermes_service import service_action

            service = service_action("status", home=home)
        except Exception as exc:
            service = {"status": "unavailable", "error": f"{type(exc).__name__}: {exc}"}

    readable_sources = sum(1 for item in sources if item["readable"])
    version_supported = version is not None and version >= MIN_HERMES_VERSION
    healthy = bool(executable and version_supported and resolved_home.is_dir() and readable_sources > 0)
    return {
        "schema_version": "secopsai.hermes.doctor.v1",
        "status": "healthy" if healthy else "degraded",
        "generated_at": _utc_now(),
        "hermes": {
            "executable": executable or "",
            "version": ".".join(str(value) for value in version) if version else "unknown",
            "version_output": version_output[:500],
            "minimum_version": ".".join(str(value) for value in MIN_HERMES_VERSION),
            "version_supported": version_supported,
            "home": str(resolved_home),
            "home_exists": resolved_home.is_dir(),
        },
        "telemetry": {
            "sources": sources,
            "readable_sources": readable_sources,
            "request_dump_count": request_dump_count,
            "excluded_credentials": [
                {"name": relative, "exists": (resolved_home / relative).exists(), "collection_policy": "excluded"}
                for relative in EXCLUDED_CREDENTIAL_PATHS
            ],
        },
        "plugin": plugin,
        "service": service,
        "last_refresh": read_state(home),
    }
