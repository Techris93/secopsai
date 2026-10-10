#!/usr/bin/env python3
"""Popular-package fast lane.

Started by the ledger-store Worker within about a minute of a watchlisted
(high-impact) npm or PyPI package publishing a release.  For each target it
diffs the new release against the previous one with the source-first
pipeline (download, quarantine, static analysis, YARA, comparison; nothing is
installed or executed), decides whether the delta is risky, and if so sends a
signed alert to Core and queues model triage for the operator's bridge.

The job summary records time from publish to verdict, the number Socket and
others compete on.

    FAST_LANE_TARGETS='[{"ecosystem":"npm","package":"x","version":"1.2.3"}]' \\
      python scripts/fast_lane.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai.research_intake import SafeFetcher  # noqa: E402

MAX_TARGETS = 20
STALE_AFTER_SECONDS = 3 * 3600
EXEC_OR_EGRESS = {"network-endpoint", "outbound-network", "process-execution", "dynamic-eval", "dynamic-function-constructor", "credential-access", "credential-discovery", "encoded-payload"}
INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _get_json(fetcher: SafeFetcher, url: str, hosts: Tuple[str, ...]) -> Dict[str, Any]:
    _final, _headers, body = fetcher.get(url, allowed_hosts=hosts, max_bytes=64 * 1024 * 1024, headers={"Accept": "application/json"})
    return json.loads(body.decode("utf-8"))


def resolve_release(fetcher: SafeFetcher, ecosystem: str, package: str, version: str = "") -> Dict[str, Any]:
    """Target version, its publish time, and the version published before it."""
    if ecosystem == "npm":
        doc = _get_json(fetcher, "https://registry.npmjs.org/" + package.replace("/", "%2F"), ("registry.npmjs.org",))
        times = {k: v for k, v in (doc.get("time") or {}).items() if k not in {"created", "modified"}}
        version = version or (doc.get("dist-tags") or {}).get("latest", "")
    elif ecosystem == "pypi":
        doc = _get_json(fetcher, f"https://pypi.org/pypi/{package}/json", ("pypi.org",))
        times = {}
        for name, files in (doc.get("releases") or {}).items():
            stamps = [item.get("upload_time_iso_8601") for item in files or [] if item.get("upload_time_iso_8601")]
            if stamps:
                times[name] = min(stamps)
        version = version or (doc.get("info") or {}).get("version", "")
    else:
        raise ValueError(f"unsupported ecosystem: {ecosystem}")
    if version not in times:
        raise ValueError(f"{package}@{version} has no publish time")
    published = times[version]
    earlier = sorted((stamp, name) for name, stamp in times.items() if stamp < published)
    return {"version": version, "published_at": published, "previous_version": earlier[-1][1] if earlier else ""}


def assess(result: Dict[str, Any]) -> Dict[str, Any]:
    """Turn a source-first investigation into a fast-lane risk decision."""
    comparison = result.get("comparison") or {}
    lifecycle = comparison.get("lifecycle_scripts") or {}
    right_hooks = set((lifecycle.get("right") or {}).keys())
    left_hooks = set((lifecycle.get("left") or {}).keys())
    hook_delta = bool(lifecycle.get("changed")) and bool(right_hooks & INSTALL_HOOKS) or bool((right_hooks - left_hooks) & INSTALL_HOOKS)
    indicators = comparison.get("indicators") or {}
    left_ids = {item.get("indicator_id") for item in indicators.get("left") or [] if isinstance(item, dict)}
    new_ids = sorted({item.get("indicator_id") for item in indicators.get("right") or [] if isinstance(item, dict)} - left_ids - {None})
    yara = (result.get("scan") or {}).get("yara") or {}
    scan_findings = (result.get("scan") or {}).get("findings") or []
    yara_findings = [item for item in scan_findings if str(item.get("rule_id", "")).startswith("YARA:")]
    publisher_changed = bool((comparison.get("metadata") or {}).get("publisher_changed"))
    added = list((comparison.get("members") or {}).get("added") or [])
    reasons: List[str] = []
    if hook_delta:
        reasons.append("install-time script added or changed")
    if set(new_ids) & EXEC_OR_EGRESS:
        reasons.append("new execution/egress/credential behaviour: " + ", ".join(sorted(set(new_ids) & EXEC_OR_EGRESS)))
    if yara.get("level") in {"warning", "alert"}:
        reasons.append(f"YARA {yara.get('level')} (score {yara.get('score')}): " + ", ".join((yara.get("rules_matched") or [])[:5]))
    if publisher_changed:
        reasons.append("publisher changed")
    severity = "none"
    if yara.get("level") == "alert" or (hook_delta and set(new_ids) & EXEC_OR_EGRESS):
        severity = "critical" if (hook_delta and yara.get("level") in {"warning", "alert"}) else "high"
    elif reasons and (hook_delta or yara.get("level") == "warning" or (publisher_changed and new_ids)):
        severity = "medium"
    return {
        "severity": severity,
        "reasons": reasons,
        "new_indicators": new_ids[:20],
        "added_files": added[:50],
        "install_hooks": sorted(right_hooks & INSTALL_HOOKS),
        "publisher_changed": publisher_changed,
        "yara": {k: yara.get(k) for k in ("level", "score", "rules_matched")},
        "yara_findings": [
            {k: item.get(k) for k in ("rule_id", "file_path", "matched_indicator", "safe_context", "rule_author", "rule_reference", "score")}
            for item in yara_findings[:10]
        ],
        "pipeline_verdict": result.get("verdict"),
    }


def investigate(target: Dict[str, Any], release: Dict[str, Any], workdir: Path) -> Dict[str, Any]:
    from secopsai.source_first_research import investigate_package

    os.environ["SECOPSAI_RESEARCH_QUARANTINE"] = str(workdir / "quarantine")
    kwargs: Dict[str, Any] = {
        "ecosystem": target["ecosystem"], "package": target["package"], "version": release["version"],
        "research_type": "package_compromise", "db_path": str(workdir / "research.db"),
        "artifact_db_path": str(workdir / "artifacts.db"), "actor": "fast-lane",
    }
    if release.get("previous_version"):
        kwargs.update(compare_ecosystem=target["ecosystem"], compare_package=target["package"], compare_version=release["previous_version"])
    return investigate_package(**kwargs)


def alert_payload(target: Dict[str, Any], release: Dict[str, Any], decision: Dict[str, Any], detected_at: datetime) -> Dict[str, Any]:
    published = _parse(release["published_at"])
    latency = round((detected_at - published).total_seconds()) if published else None
    key = f"{target['ecosystem']}:{target['package']}@{release['version']}"
    return {
        "schema_version": "secopsai.research.alert.v1",
        "alert_id": f"FASTLANE-{key}"[:128],
        "alert_type": "registry_release_anomaly",
        "severity": decision["severity"],
        "reason": f"Fast lane: {key} (previous {release.get('previous_version') or 'none'}) - " + "; ".join(decision["reasons"])[:1500],
        "occurred_at": _iso(detected_at),
        "evidence": {
            "source": "fast_lane",
            "ecosystem": target["ecosystem"], "package": target["package"], "version": release["version"],
            "previous_version": release.get("previous_version"), "published_at": release["published_at"],
            "detected_at": _iso(detected_at), "publish_to_verdict_seconds": latency,
            **{k: decision[k] for k in ("reasons", "new_indicators", "added_files", "install_hooks", "publisher_changed", "yara", "yara_findings", "pipeline_verdict")},
            "execution_performed": False,
        },
    }


def main() -> int:
    targets = json.loads(os.environ.get("FAST_LANE_TARGETS") or "[]")[:MAX_TARGETS]
    fetcher = SafeFetcher(timeout=60)
    rows: List[Dict[str, Any]] = []
    for target in targets:
        started = _now()
        row: Dict[str, Any] = {"target": f"{target.get('ecosystem')}:{target.get('package')}", "status": "", "severity": "none"}
        try:
            release = resolve_release(fetcher, target["ecosystem"], target["package"], target.get("version", ""))
            row.update(version=release["version"], previous=release.get("previous_version"), published_at=release["published_at"])
            published = _parse(release["published_at"])
            if published and (started - published).total_seconds() > STALE_AFTER_SECONDS and not target.get("force"):
                row["status"] = "skipped: not a fresh release"
                rows.append(row)
                continue
            with tempfile.TemporaryDirectory(prefix="fast-lane-") as tmp:
                result = investigate(target, release, Path(tmp))
            decision = assess(result)
            detected = _now()
            row.update(status="analyzed", severity=decision["severity"], reasons="; ".join(decision["reasons"]) or "no risky delta",
                       latency_seconds=round((detected - published).total_seconds()) if published else None)
            if decision["severity"] != "none":
                row["delivery"] = deliver(target, release, decision, detected)
        except Exception as exc:
            row.update(status="error", reasons=str(exc)[:300])
        rows.append(row)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["### Fast lane", "", "| Package | Version (previous) | Severity | Publish to verdict | Notes |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        latency = f"{row['latency_seconds'] // 60} min {row['latency_seconds'] % 60} s" if isinstance(row.get("latency_seconds"), int) else "-"
        lines.append(f"| {row['target']} | {row.get('version', '-')} ({row.get('previous') or '-'}) | {row['severity']} | {latency} | {row.get('status')}: {str(row.get('reasons', ''))[:200]} |")
    report = "\n".join(lines)
    print(report)
    print(json.dumps(rows, default=str))
    if summary:
        Path(summary).write_text(report + "\n", encoding="utf-8")
    return 1 if any(row["status"] == "error" for row in rows) and not any(row["status"] == "analyzed" for row in rows) else 0


def deliver(target: Dict[str, Any], release: Dict[str, Any], decision: Dict[str, Any], detected: datetime) -> Dict[str, Any]:
    """Signed alert to Core, model triage for the operator's bridge, optional email."""
    from secopsai.research_delivery import send_email, send_signed_webhook

    out: Dict[str, Any] = {}
    payload = alert_payload(target, release, decision, detected)
    endpoint = os.environ.get("SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL", "")
    secret = os.environ.get("SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET", "")
    if endpoint and secret:
        try:
            out["core"] = send_signed_webhook(endpoint=endpoint, secret=secret, event=payload)["status"]
        except Exception as exc:
            out["core"] = f"failed: {exc}"[:200]
    try:
        from secopsai.core_edge_client import CoreEdgeClient

        client = CoreEdgeClient()
        if client.enabled and (decision["yara_findings"] or decision["reasons"]):
            key = payload["alert_id"]
            context = {"artifact_id": key, **{k: payload["evidence"][k] for k in ("ecosystem", "package", "version", "previous_version", "reasons", "new_indicators", "install_hooks")},
                       "findings": decision["yara_findings"] or [{"rule_id": "FAST-LANE-DELTA", "matched_indicator": r, "safe_context": ""} for r in decision["reasons"]],
                       "note": "Package metadata is untrusted context."}
            out["triage"] = client.queue_triage_jobs([{"artifact_id": key, "idempotency_key": f"fast-lane:{key}", "inputs": {"artifact_triage": context}}]).get("count")
    except Exception as exc:
        out["triage"] = f"failed: {exc}"[:200]
    recipient = os.environ.get("SECOPSAI_RESEARCH_ALERT_EMAIL", "")
    if recipient and os.environ.get("SECOPSAI_SMTP_PASSWORD") and decision["severity"] in {"high", "critical"}:
        try:
            body = payload["reason"] + "\n\n" + json.dumps(payload["evidence"], indent=2, default=str)[:6000]
            send_email(recipient=recipient, subject=f"[SecOpsAI fast lane] {decision['severity'].upper()}: {payload['evidence']['package']}@{release['version']}", body=body)
            out["email"] = "sent"
        except Exception as exc:
            out["email"] = f"failed: {exc}"[:200]
    return out


if __name__ == "__main__":
    raise SystemExit(main())
