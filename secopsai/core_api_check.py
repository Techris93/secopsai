"""Secret-safe liveness, readiness, and authenticated Core API check."""

from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse


SCHEMA_VERSION = "secopsai.core.hosted-check.v1"
REDACTED_KEYS = {
    "bssid",
    "mac",
    "mac_address",
    "nmap_xml",
    "packet_capture",
    "pcap",
    "raw_nmap_output",
    "raw_output",
    "raw_packet_data",
    "raw_scan_log",
    "raw_scan_logs",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _safe_origin(raw: str) -> str:
    parsed = urlparse(raw.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Core API URL must be an HTTPS origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Core API URL must not contain credentials, query parameters, or fragments")
    if parsed.path not in ("", "/"):
        raise ValueError("Core API URL must be an origin without a path")
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _contains_redacted_key(value: Any) -> bool:
    if isinstance(value, dict):
        if any(str(key).lower() in REDACTED_KEYS for key in value):
            return True
        return any(_contains_redacted_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_redacted_key(item) for item in value)
    return False


def _request_json(origin: str, path: str, token: str | None, timeout: float) -> tuple[int, Any | None, str | None]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"{origin}{path}", headers=headers, method="GET")
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read(2 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        return int(exc.code), None, "http_error"
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, socket.gaierror):
            return 0, None, "dns_resolution_failed"
        return 0, None, "network_error"
    except TimeoutError:
        return 0, None, "timeout"
    except OSError:
        return 0, None, "network_error"
    if len(body) > 2 * 1024 * 1024:
        return status, None, "response_too_large"
    try:
        return status, json.loads(body.decode("utf-8")), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return status, None, "invalid_json"


def _result(name: str, status: int, payload: Any | None, error: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "ok": False}
    if status:
        result["status"] = status
    if error:
        result["error"] = error
        return result
    if not isinstance(payload, dict):
        result["error"] = "invalid_json"
        return result
    result["ok"] = True
    result["status"] = status
    result["status_value"] = payload.get("status")
    result["version"] = payload.get("version")
    return result


def run_check(origin: str, token: str, timeout: float = 12.0) -> dict[str, Any]:
    """Return non-secret check evidence for a hosted Core API."""

    checks: list[dict[str, Any]] = []
    health_status, health_payload, health_error = _request_json(origin, "/healthz", None, timeout)
    health = _result("healthz", health_status, health_payload, health_error)
    if health.get("ok") and health.get("status_value") != "ok":
        health["ok"] = False
        health["error"] = "schema_mismatch"
    checks.append(health)

    ready_status, ready_payload, ready_error = _request_json(origin, "/readyz", None, timeout)
    ready = _result("readyz", ready_status, ready_payload, ready_error)
    if ready.get("ok") and ready.get("status_value") != "ready":
        ready["ok"] = False
        ready["error"] = "schema_mismatch"
    checks.append(ready)

    workspace_status, workspace_payload, workspace_error = _request_json(
        origin,
        "/api/v1/workspace?limit=1",
        token,
        timeout,
    )
    workspace: dict[str, Any] = {"name": "workspace", "ok": False}
    if workspace_status:
        workspace["status"] = workspace_status
    if workspace_error:
        workspace["error"] = workspace_error
    elif not isinstance(workspace_payload, dict):
        workspace["error"] = "invalid_json"
    elif workspace_payload.get("schema_version") != "secopsai.core.workspace.v1":
        workspace["error"] = "schema_mismatch"
    elif _contains_redacted_key(workspace_payload):
        workspace["error"] = "raw_telemetry_exposed"
    else:
        workspace["ok"] = True
        workspace["status"] = workspace_status
        workspace["schema_version"] = workspace_payload.get("schema_version")
        summary = workspace_payload.get("summary")
        if isinstance(summary, dict):
            workspace["summary_keys"] = sorted(str(key) for key in summary)[:30]
    checks.append(workspace)

    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "origin": origin,
        "ok": all(bool(item.get("ok")) for item in checks),
        "checks": checks,
    }


def main() -> int:
    try:
        origin = _safe_origin(os.environ.get("SECOPSAI_CORE_API_URL", ""))
        token = os.environ.get("SECOPSAI_CORE_READ_TOKEN", "").strip()
        if not token:
            raise ValueError("SECOPSAI_CORE_READ_TOKEN is required")
        timeout = float(os.environ.get("SECOPSAI_CORE_CHECK_TIMEOUT", "12"))
        if timeout <= 0 or timeout > 60:
            raise ValueError("SECOPSAI_CORE_CHECK_TIMEOUT must be between 0 and 60 seconds")
        evidence = run_check(origin, token, timeout)
    except ValueError as exc:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "ok": False, "error": str(exc)}))
        return 2
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
