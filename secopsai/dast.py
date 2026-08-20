"""Authorization-gated DAST target and SARIF workflows."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from typing import Any, Callable, Sequence
from urllib.parse import urlparse


SAFE_TARGET_RE = re.compile(r"^https://[^\s<>\"']{3,500}$", re.IGNORECASE)
MAX_SARIF_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class DastTarget:
    target_id: str
    url: str
    owner: str
    authorized_by: str
    scope: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    active_scan_approved: bool = False

    def validate(self) -> None:
        parsed = urlparse(self.url)
        if not SAFE_TARGET_RE.fullmatch(self.url) or parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("DAST targets must be explicit HTTPS URLs")
        if not self.target_id or not self.owner or not self.authorized_by:
            raise ValueError("DAST target ownership and authorization are required")
        if self.active_scan_approved and not self.authorized_by:
            raise ValueError("active DAST requires authorization evidence")


def build_zap_command(target: DastTarget, *, mode: str = "passive", zap_binary: str = "zaproxy") -> list[str]:
    target.validate()
    normalized = mode.strip().lower()
    if normalized not in {"passive", "active"}:
        raise ValueError("DAST mode must be passive or active")
    if normalized == "active" and not target.active_scan_approved:
        raise PermissionError("active DAST requires explicit approval")
    # This is an argv array, never a shell string. The caller still decides
    # whether and when to execute it through an allowlisted runner.
    command = [zap_binary, "-quickurl", target.url, "-quickout", "-quickprogress"]
    if normalized == "passive":
        command.extend(["-scantime", "1"])
    return command


def parse_sarif(payload: str | bytes, *, target_id: str, source: str = "dast") -> list[dict[str, Any]]:
    raw = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
    if len(raw.encode("utf-8")) > MAX_SARIF_BYTES:
        raise ValueError("DAST SARIF exceeds the safety limit")
    document = json.loads(raw)
    findings: list[dict[str, Any]] = []
    for run in document.get("runs") or []:
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name") or source
        rules = {str(rule.get("id")): rule for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []}
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "DAST-UNKNOWN")[:160]
            rule = rules.get(rule_id) or {}
            level = str(result.get("level") or "warning").lower()
            severity = "critical" if level == "error" else "medium" if level == "warning" else "low"
            locations = result.get("locations") or []
            digest = hashlib.sha256(f"{target_id}|{rule_id}|{json.dumps(locations, sort_keys=True)}".encode("utf-8")).hexdigest()[:16].upper()
            findings.append({
                "finding_id": f"DAST-{digest}",
                "target_id": target_id,
                "source": source,
                "tool": str(tool)[:120],
                "rule_id": rule_id,
                "title": str(rule.get("name") or result.get("message", {}).get("text") or rule_id)[:300],
                "severity": severity,
                "message": str((result.get("message") or {}).get("text") or "")[:2000],
                "locations": locations[:20],
                "remediation": str(rule.get("help", {}).get("text") if isinstance(rule.get("help"), dict) else "Review the authorized target and remediate the reported issue.")[:2000],
            })
    return findings


def validate_scope(target: DastTarget, requested_url: str) -> bool:
    target.validate()
    requested = urlparse(requested_url)
    base = urlparse(target.url)
    if requested.scheme != "https" or requested.hostname != base.hostname:
        return False
    if not target.scope:
        return requested.path == base.path or requested.path.startswith(base.path.rstrip("/") + "/")
    return any(requested.path.startswith(prefix) for prefix in target.scope)
