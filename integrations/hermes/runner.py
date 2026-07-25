from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Sequence


MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 30
FINDING_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SESSION_ID = re.compile(r"^SES-[A-Za-z0-9]{6,64}$")
SEVERITIES = {"info", "low", "medium", "high", "critical"}
STATUSES = {"open", "in_review", "closed", "acknowledged", "resolved", "false_positive"}
FORBIDDEN_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "headers",
    "password",
    "private_key",
    "raw_output",
    "request_body",
    "request_headers",
    "secret",
    "token",
}


class SecOpsAIRunnerError(RuntimeError):
    pass


def core_root() -> Path:
    configured = str(os.environ.get("SECOPSAI_HOME") or "").strip()
    root = Path(configured).expanduser() if configured else Path.home() / "secopsai"
    resolved = root.resolve()
    if not resolved.is_dir():
        raise SecOpsAIRunnerError(
            f"SecOpsAI Core was not found at {resolved}. Run the Hermes installer from https://secopsai.dev/install-hermes.sh."
        )
    return resolved


def _python(root: Path) -> Path:
    candidates = (root / ".venv" / "bin" / "python", root / ".venv" / "Scripts" / "python.exe")
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise SecOpsAIRunnerError(f"SecOpsAI virtual environment is unavailable under {root}")


def _timeout() -> int:
    try:
        value = int(os.environ.get("SECOPSAI_HERMES_TOOL_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    except ValueError:
        value = DEFAULT_TIMEOUT_SECONDS
    return max(5, min(value, 60))


def _environment(root: Path) -> dict[str, str]:
    allowed = {
        "HOME",
        "HERMES_HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SECOPS_FINDINGS_DIR",
        "SECOPSAI_SESSION_DIR",
        "SECOPSAI_STATE_DIR",
        "TZ",
    }
    env = {name: value for name, value in os.environ.items() if name in allowed and value}
    env["SECOPSAI_HOME"] = str(root)
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    return env


def _clean(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "[depth limit]"
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in list(value.items())[:100]:
            normalized = str(key).strip().lower()
            if normalized in FORBIDDEN_KEYS or any(part in normalized for part in ("password", "secret", "token", "private_key", "raw_")):
                continue
            output[str(key)[:120]] = _clean(item, depth=depth + 1)
        return output
    if isinstance(value, list):
        return [_clean(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:4000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:4000]


def run(command: Sequence[str]) -> dict[str, Any]:
    root = core_root()
    invocation = [str(_python(root)), "-m", "secopsai.cli", "--json", *[str(item) for item in command]]
    try:
        completed = subprocess.run(
            invocation,
            cwd=root,
            env=_environment(root),
            text=True,
            capture_output=True,
            check=False,
            timeout=_timeout(),
        )
    except subprocess.TimeoutExpired as exc:
        raise SecOpsAIRunnerError(f"SecOpsAI command timed out after {_timeout()} seconds") from exc
    output = completed.stdout or completed.stderr or ""
    if len(output.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise SecOpsAIRunnerError("SecOpsAI response exceeded the 64 KiB plugin limit")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SecOpsAIRunnerError("SecOpsAI returned an invalid JSON response") from exc
    cleaned = _clean(payload)
    if completed.returncode != 0:
        message = cleaned.get("error") if isinstance(cleaned, dict) else None
        raise SecOpsAIRunnerError(str(message or f"SecOpsAI exited with status {completed.returncode}"))
    if not isinstance(cleaned, dict):
        raise SecOpsAIRunnerError("SecOpsAI returned an unexpected response")
    return cleaned


def bounded_limit(value: Any, *, default: int = 20, maximum: int = 100) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


def identifier(value: Any, *, kind: str) -> str:
    normalized = str(value or "").strip()
    pattern = SESSION_ID if kind == "session" else FINDING_ID
    if not pattern.fullmatch(normalized):
        raise SecOpsAIRunnerError(f"Invalid {kind} identifier")
    return normalized


def optional_choice(value: Any, *, choices: set[str], label: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized and normalized not in choices:
        raise SecOpsAIRunnerError(f"Unsupported {label}: {normalized}")
    return normalized


def result(handler) -> Any:
    def wrapped(args: dict[str, Any] | None = None, **_: Any) -> str:
        try:
            return json.dumps({"success": True, "data": handler(args or {})}, separators=(",", ":"))
        except Exception as exc:
            message = str(exc) if isinstance(exc, SecOpsAIRunnerError) else f"SecOpsAI tool failed: {type(exc).__name__}"
            return json.dumps({"success": False, "error": message[:1000]}, separators=(",", ":"))

    return wrapped

