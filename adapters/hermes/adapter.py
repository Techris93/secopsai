"""Hermes Agent adapter.

Collects local Hermes Agent telemetry without executing Hermes, package scripts,
or external tooling. The adapter reads only local history, log, and session
metadata files, redacts sensitive values, and normalizes them into SecOpsAI's
shared event shape.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from adapters.base import BaseAdapter, AdapterRegistry


LOG_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+"
    r"(?P<level>[A-Z]+)\s+(?P<logger>[^:]+):\s*(?P<message>.*)$"
)
HISTORY_TS = re.compile(r"^#\s*(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
SECRET_VALUE = re.compile(
    r"(?i)\b("
    r"authorization|bearer|api[_-]?key|token|secret|password|passwd|cookie|credential"
    r")\b\s*[:=]\s*['\"]?[^'\"\s,}]+"
)
TOKEN_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{12,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b[A-Za-z0-9_-]{24,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}\b"),
]
SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "token",
    "secret",
    "password",
    "cookie",
    "credential",
    "session_key",
    "auth",
    "headers",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> str:
    if not value:
        return _utc_now()
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text.rstrip("Z"), fmt).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            continue
    return text if text.endswith("Z") else f"{text}Z"


def _is_after(timestamp: str, start_time: Optional[datetime]) -> bool:
    if start_time is None:
        return True
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    threshold = start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
    return parsed >= threshold


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except Exception:
        return str(path)


def redact_text(value: str, *, max_length: int = 800) -> str:
    redacted = SECRET_VALUE.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    for pattern in TOKEN_PATTERNS:
        redacted = pattern.sub("[REDACTED_TOKEN]", redacted)
    return redacted[:max_length]


def redact_obj(value: Any) -> Any:
    if isinstance(value, dict):
        safe: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS or any(part in key_text.lower() for part in ("token", "secret", "password", "auth", "cookie")):
                safe[key_text] = "[REDACTED]"
            else:
                safe[key_text] = redact_obj(item)
        return safe
    if isinstance(value, list):
        return [redact_obj(item) for item in value[:25]]
    if isinstance(value, str):
        return redact_text(value)
    return value


class HermesAdapter(BaseAdapter):
    """Adapter for Hermes Agent local telemetry."""

    @property
    def name(self) -> str:
        return "hermes"

    @property
    def version(self) -> str:
        return "1.0.0"

    def hermes_home(self) -> Path:
        configured = self.config.get("hermes_home") or os.environ.get("HERMES_HOME")
        return Path(configured).expanduser() if configured else Path.home() / ".hermes"

    def collect(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        hermes_home: Optional[str] = None,
        max_lines: int = 5000,
        **kwargs: Any,
    ) -> Iterable[Dict[str, Any]]:
        """Collect Hermes history, logs, session state, and request-dump metadata."""
        _ = end_time, kwargs
        home = Path(hermes_home).expanduser() if hermes_home else self.hermes_home()
        if not home.exists():
            raise FileNotFoundError(f"Hermes home not found: {home}")

        yield from self._collect_history(home / ".hermes_history", start_time)
        for log_name in ("agent.log", "errors.log", "gateway.log", "gateway.error.log", "gateway-exit-diag.log"):
            yield from self._collect_log(home / "logs" / log_name, start_time, max_lines=max_lines)
        yield from self._collect_sessions(home / "sessions" / "sessions.json", start_time)
        for dump_path in sorted((home / "sessions").glob("request_dump_*.json")):
            yield from self._collect_request_dump(dump_path, start_time)
        yield from self._collect_gateway_state(home / "gateway_state.json", start_time)

    def stream(self, **kwargs: Any) -> Iterable[Dict[str, Any]]:
        raise NotImplementedError("Hermes streaming uses SecOpsAI live poll mode")

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        source = str(raw_event.get("source") or "unknown")
        raw = raw_event.get("raw") if isinstance(raw_event.get("raw"), dict) else {}
        timestamp = str(raw.get("timestamp") or raw_event.get("timestamp") or _utc_now())
        message = str(raw.get("message") or raw.get("command") or raw.get("error_message") or source)
        tool_name = raw.get("tool_name") or ("terminal" if source in {"history", "log"} else raw.get("platform"))
        event_type = self._event_type(source, raw)

        normalized = {
            "timestamp": timestamp,
            "event_type": event_type,
            "platform": "hermes",
            "source": f"hermes_{source}",
            "sourcetype": f"hermes_{source}",
            "host": self.hostname,
            "event_id": self.generate_event_id({"source": source, "raw": raw}),
            "actor": {
                "user": raw.get("user"),
                "process": tool_name or raw.get("logger") or "hermes",
                "command_line": raw.get("command"),
            },
            "target": {
                "file": raw.get("path"),
                "domain": raw.get("request_domain"),
                "url": raw.get("request_url"),
            },
            "outcome": raw.get("outcome") or ("failure" if str(raw.get("level", "")).upper() in {"ERROR", "WARNING"} else "unknown"),
            "severity": raw.get("severity", "info"),
            "message": message,
            "command": raw.get("command"),
            "tool_name": tool_name,
            "session_key": raw.get("session_id") or raw.get("session_key"),
            "status": raw.get("status"),
            "metadata": {
                "hermes_source": source,
                "hermes_path": raw.get("path"),
                "hermes_level": raw.get("level"),
                "hermes_logger": raw.get("logger"),
                "hermes_message": message,
                "hermes_platform": raw.get("platform"),
                "hermes_chat_type": raw.get("chat_type"),
                "hermes_error_type": raw.get("error_type"),
                "hermes_request_method": raw.get("request_method"),
                "hermes_request_url": raw.get("request_url"),
                "hermes_model": raw.get("model"),
            },
        }
        return self.enrich_event({key: value for key, value in normalized.items() if value is not None})

    def _event_type(self, source: str, raw: Dict[str, Any]) -> str:
        if source == "history":
            return "tool_invocation"
        if source == "request_dump":
            return "agent_api_error"
        if source == "session":
            return "session_state"
        if source == "gateway_state":
            return "agent_state"
        logger = str(raw.get("logger") or "")
        message = str(raw.get("message") or "")
        if "tool_executor" in logger or re.search(r"(?i)\btool\b.*\b(returned|failed|error|start)", message):
            return "tool_invocation"
        if str(raw.get("level") or "").upper() in {"ERROR", "WARNING"}:
            return "agent_error"
        return "agent_log"

    def _collect_history(self, path: Path, start_time: Optional[datetime]) -> Iterable[Dict[str, Any]]:
        if not path.exists():
            return
        current_ts = _utc_now()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = HISTORY_TS.match(line.strip())
            if match:
                current_ts = _parse_timestamp(match.group("ts"))
                continue
            if not line.startswith("+"):
                continue
            timestamp = current_ts
            if not _is_after(timestamp, start_time):
                continue
            command = redact_text(line[1:].strip(), max_length=1200)
            if command:
                yield {
                    "source": "history",
                    "raw": {
                        "timestamp": timestamp,
                        "command": command,
                        "message": command,
                        "tool_name": "terminal",
                        "path": _display_path(path),
                    },
                }

    def _collect_log(self, path: Path, start_time: Optional[datetime], *, max_lines: int) -> Iterable[Dict[str, Any]]:
        if not path.exists():
            return
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-max_lines:]:
            match = LOG_LINE.match(line)
            if match:
                timestamp = _parse_timestamp(match.group("ts"))
                level = match.group("level")
                logger = match.group("logger")
                message = redact_text(match.group("message"), max_length=1200)
            else:
                timestamp = _utc_now()
                level = "INFO"
                logger = path.stem
                message = redact_text(line, max_length=1200)
            if not _is_after(timestamp, start_time):
                continue
            yield {
                "source": "log",
                "raw": {
                    "timestamp": timestamp,
                    "level": level,
                    "logger": logger,
                    "message": message,
                    "path": _display_path(path),
                    "status": "error" if level in {"ERROR", "WARNING"} else "ok",
                },
            }

    def _collect_sessions(self, path: Path, start_time: Optional[datetime]) -> Iterable[Dict[str, Any]]:
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        for key, row in payload.items():
            if not isinstance(row, dict):
                continue
            timestamp = _parse_timestamp(row.get("updated_at") or row.get("created_at"))
            if not _is_after(timestamp, start_time):
                continue
            yield {
                "source": "session",
                "raw": {
                    "timestamp": timestamp,
                    "session_id": row.get("session_id"),
                    "session_key": key,
                    "platform": row.get("platform"),
                    "chat_type": row.get("chat_type"),
                    "message": f"Hermes session {row.get('session_id') or key} on {row.get('platform') or 'unknown'}",
                    "path": _display_path(path),
                },
            }

    def _collect_request_dump(self, path: Path, start_time: Optional[datetime]) -> Iterable[Dict[str, Any]]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        safe = redact_obj(payload)
        request = safe.get("request") if isinstance(safe.get("request"), dict) else {}
        body = request.get("body") if isinstance(request.get("body"), dict) else {}
        error = safe.get("error") if isinstance(safe.get("error"), dict) else {}
        timestamp = _parse_timestamp(safe.get("timestamp"))
        if not _is_after(timestamp, start_time):
            return
        yield {
            "source": "request_dump",
            "raw": {
                "timestamp": timestamp,
                "session_id": safe.get("session_id"),
                "reason": safe.get("reason"),
                "request_method": request.get("method"),
                "request_url": request.get("url"),
                "request_domain": _domain_from_url(str(request.get("url") or "")),
                "model": body.get("model"),
                "error_type": error.get("type"),
                "error_message": str(error.get("message") or "")[:800],
                "message": f"Hermes request dump: {safe.get('reason') or error.get('type') or 'api error'}",
                "path": _display_path(path),
                "status": "error",
            },
        }

    def _collect_gateway_state(self, path: Path, start_time: Optional[datetime]) -> Iterable[Dict[str, Any]]:
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        timestamp = _utc_now()
        if not _is_after(timestamp, start_time):
            return
        yield {
            "source": "gateway_state",
            "raw": {
                "timestamp": timestamp,
                "status": payload.get("gateway_state"),
                "message": f"Hermes gateway state: {payload.get('gateway_state') or 'unknown'}",
                "path": _display_path(path),
            },
        }


def _domain_from_url(url: str) -> str:
    match = re.match(r"^[a-z]+://([^/]+)", url, flags=re.IGNORECASE)
    return match.group(1).lower() if match else ""


AdapterRegistry.register("hermes", HermesAdapter)
