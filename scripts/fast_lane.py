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
import re
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai.research_intake import SafeFetcher  # noqa: E402

MAX_TARGETS = 20
STALE_AFTER_SECONDS = 3 * 3600
EXEC_OR_EGRESS = {"network-endpoint", "outbound-network", "process-execution", "dynamic-eval", "dynamic-function-constructor", "credential-access", "credential-discovery", "encoded-payload"}
INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare"}
# Behaviour rules (secopsai/package_features.py) that mark code which runs
# without any install step or a hijacked release: always critical here.
CRITICAL_BEHAVIOUR = {"BEH_PTH_STARTUP_INLINE", "BEH_PTH_STARTUP_HARVEST", "BEH_DIFF_NEW_PTH_STARTUP"}
PTH_FLAGS = {"pth_startup_code", "pth_startup_inline", "pth_chain_secrets", "pth_chain_network"}


def established_start_up_hook(behaviour: Dict[str, Any], publisher_changed: bool) -> bool:
    """True when the previous release was read in full and already had every
    start-up hook flag this one has, from the same publisher. That is the
    package's design (2026-11-18: pirateface patches Hugging Face downloads
    from a .pth on every release), not a takeover; it stays a high alert for
    triage but no longer sends the urgent email on each release. A first
    release, an unreadable previous release or any new hook flag stays
    critical (agent-framework 1.26.1 added its hook)."""
    diff = behaviour.get("diff") or {}
    if publisher_changed or not diff.get("previous_version") or "new_flags" not in diff:
        return False
    return not (set(diff.get("new_flags") or []) & PTH_FLAGS)
NOT_FOUND_RETRIES = 3
NOT_FOUND_DELAY_SECONDS = 20


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


class PublishTimePending(RuntimeError):
    """The registry lists a release but not yet its publish time."""

    failure_category = "publish_time_pending"


def resolve_release(fetcher: SafeFetcher, ecosystem: str, package: str, version: str = "") -> Dict[str, Any]:
    """Target version, its publish time, and the version published before it."""
    if ecosystem == "npm":
        doc = _get_json(fetcher, "https://registry.npmjs.org/" + package.replace("/", "%2F"), ("registry.npmjs.org",))
        # npm keeps "time" entries for unpublished versions; only versions with a tarball in "versions" are releases.
        published_versions = doc.get("versions") or {}
        times = {k: v for k, v in (doc.get("time") or {}).items() if k not in {"created", "modified"} and k in published_versions}
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
    if version not in times and ecosystem == "pypi" and version:
        # The project document is CDN-cached and can lag a fresh release by
        # minutes; the per-version document is published with the release.
        release_doc = _get_json(fetcher, f"https://pypi.org/pypi/{package}/{version}/json", ("pypi.org",))
        stamps = [item.get("upload_time_iso_8601") for item in release_doc.get("urls") or [] if item.get("upload_time_iso_8601")]
        if stamps:
            times[version] = min(stamps)
    if not version:
        raise ValueError(f"{package} has no current version")
    if version not in times:
        # npm's document can lag a fresh release; failed Fast Lane twice (2026-10-28, 2026-10-30).
        raise PublishTimePending(f"{package}@{version} has no publish time yet")
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
    # The worker's behaviour rules over the same release (sdist and wheel for
    # PyPI, with the version diff), so both paths judge a release alike.
    behaviour = [item for item in ((result.get("behaviour") or {}).get("findings") or [])
                 if str(item.get("rule_id", "")).startswith("BEHAVIOUR:")]
    behaviour_ids = {str(item["rule_id"]).split(":", 1)[1] for item in behaviour}
    behaviour_top = max((int(item.get("score") or 0) for item in behaviour), default=0)
    reasons: List[str] = []
    if hook_delta:
        reasons.append("install-time script added or changed")
    if set(new_ids) & EXEC_OR_EGRESS:
        reasons.append("new execution/egress/credential behaviour: " + ", ".join(sorted(set(new_ids) & EXEC_OR_EGRESS)))
    if yara.get("level") in {"warning", "alert"}:
        reasons.append(f"YARA {yara.get('level')} (score {yara.get('score')}): " + ", ".join((yara.get("rules_matched") or [])[:5]))
    if publisher_changed:
        reasons.append("publisher changed")
    if behaviour:
        reasons.append("behaviour rules: " + ", ".join(sorted(behaviour_ids)))
    severity = "none"
    if yara.get("level") == "alert" or (hook_delta and set(new_ids) & EXEC_OR_EGRESS):
        severity = "critical" if (hook_delta and yara.get("level") in {"warning", "alert"}) else "high"
    elif reasons and (hook_delta or (publisher_changed and new_ids)):
        severity = "medium"
    elif yara.get("level") == "warning":
        # A YARA warning with nothing else new: 81% judged benign by model
        # triage, 1 of 824 at 70% or more (2026-11-15..18). Still triaged and
        # shown; the urgent email still fires if the model is sure.
        severity = "medium" if (set(new_ids) & EXEC_OR_EGRESS) or publisher_changed else "low"
    order = ["none", "low", "medium", "high", "critical"]
    critical_ids = behaviour_ids & CRITICAL_BEHAVIOUR
    if established_start_up_hook(result.get("behaviour") or {}, publisher_changed):
        critical_ids -= {"BEH_PTH_STARTUP_INLINE", "BEH_PTH_STARTUP_HARVEST"}
    floor = "critical" if critical_ids else "high" if behaviour_top >= 70 else "medium" if behaviour_top >= 60 else "none"
    severity = max(severity, floor, key=order.index)
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
        "behaviour_findings": [
            {k: item.get(k) for k in ("rule_id", "file_path", "matched_indicator", "safe_context", "score")}
            for item in behaviour[:10]
        ],
        "pipeline_verdict": result.get("verdict"),
        # The whole behaviour scan (start-up files, flagged files, version
        # diff) for model triage; never written to the report or the alert.
        "triage_prescan": result.get("behaviour") or {},
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
    result = investigate_package(**kwargs)
    result["behaviour"] = behaviour_scan(target, release)
    return result


def behaviour_scan(target: Dict[str, Any], release: Dict[str, Any]) -> Dict[str, Any]:
    """The content funnel's scan (YARA + behaviour rules + version diff) of
    this release. Extra signal: a failure here never fails the target."""
    from secopsai.research_content_funnel import scan_release

    try:
        scan = scan_release(SafeFetcher(timeout=60), target["ecosystem"], target["package"], release["version"])
    except Exception as exc:
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"[:200], "findings": []}
    return scan


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
            **{k: decision[k] for k in ("reasons", "new_indicators", "added_files", "install_hooks", "publisher_changed", "yara", "yara_findings", "behaviour_findings", "pipeline_verdict") if k in decision},
            **({"source_match": source_summary(decision["source_match"])} if decision.get("source_match") else {}),
            "execution_performed": False,
        },
    }


def main() -> int:
    targets = json.loads(os.environ.get("FAST_LANE_TARGETS") or "[]")
    if not isinstance(targets, list) or len(targets) > MAX_TARGETS:
        raise ValueError(f"FAST_LANE_TARGETS must contain at most {MAX_TARGETS} targets")
    fetcher = SafeFetcher(timeout=60)
    rows: List[Dict[str, Any]] = []
    from secopsai.research_intake import (
        ArtifactResourceLimitError,
        IntakeResponseLimitError,
        RegistryHTTPError,
        TransientTransportError,
    )

    for target in targets:
        started = _now()
        row: Dict[str, Any] = {"target": f"{target.get('ecosystem')}:{target.get('package')}", "queue_id": target.get("_queue_id"),
                               "version": target.get("version"), "status": "", "severity": "none"}
        try:
            for attempt in range(NOT_FOUND_RETRIES + 1):
                try:
                    release = resolve_release(fetcher, target["ecosystem"], target["package"], target.get("version", ""))
                    break
                except PublishTimePending:
                    if attempt == NOT_FOUND_RETRIES:
                        raise
                    time.sleep(NOT_FOUND_DELAY_SECONDS)
            row.update(version=release["version"], previous=release.get("previous_version"), published_at=release["published_at"])
            published = _parse(release["published_at"])
            if published and (started - published).total_seconds() > STALE_AFTER_SECONDS and not target.get("force"):
                row["status"] = "skipped: not a fresh release"
                rows.append(row)
                continue
            result = None
            # Registries can answer 404 for a tarball for a short while after
            # publish (the CDN has not caught up); retry before giving up.
            for attempt in range(NOT_FOUND_RETRIES + 1):
                try:
                    with tempfile.TemporaryDirectory(prefix="fast-lane-") as tmp:
                        result = investigate(target, release, Path(tmp))
                    break
                except Exception as exc:
                    if not isinstance(exc, RegistryHTTPError) or exc.status != 404 or attempt == NOT_FOUND_RETRIES:
                        raise
                    time.sleep(NOT_FOUND_DELAY_SECONDS)
            decision = assess(result)
            detected = _now()
            row.update(status="analyzed", severity=decision["severity"], reasons="; ".join(decision["reasons"]) or "no risky delta",
                       latency_seconds=round((detected - published).total_seconds()) if published else None)
            coverage = (result.get("scan") or {}).get("coverage") or {}
            if coverage.get("partial"):
                # Large archives are read within a budget (install-time and
                # manifest files first).  The verdict covers only what was
                # read and must never be presented as a complete clean scan.
                row.update(coverage="partial", coverage_detail={key: coverage.get(key) for key in (
                    "reason", "members_total", "members_read", "members_skipped", "bytes_declared", "bytes_read")})
                row["reasons"] = (f"partial scan ({coverage.get('members_read')} of {coverage.get('members_total')} files read; "
                                  f"{coverage.get('reason')}); " + row["reasons"])
            else:
                row["coverage"] = "complete"
            if decision["severity"] != "none":
                row["delivery"] = deliver(target, release, decision, detected)
        except Exception as exc:
            if isinstance(exc, ArtifactResourceLimitError):
                row.update(status="incomplete", failure_category=exc.failure_category,
                           reasons="Configured archive resource limit reached; no clean verdict was produced.")
            elif isinstance(exc, IntakeResponseLimitError):
                row.update(status="incomplete", failure_category=exc.failure_category,
                           reasons="Registry response exceeded a configured size limit; no clean verdict was produced.")
            elif isinstance(exc, RegistryHTTPError) and (exc.retryable or exc.status == 404):
                row.update(status="retryable_failure", failure_category=exc.failure_category,
                           http_status=exc.status, retryable=True,
                           reasons=f"Registry request returned HTTP {exc.status}; target remains unresolved.")
            elif isinstance(exc, RegistryHTTPError):
                row.update(status="incomplete", failure_category=exc.failure_category,
                           http_status=exc.status, retryable=False,
                           reasons=f"Registry request returned permanent HTTP {exc.status}; no clean verdict was produced.")
            elif isinstance(exc, TransientTransportError):
                row.update(status="retryable_failure", failure_category=exc.failure_category,
                           retryable=True, reasons=exc.diagnostic)
            elif isinstance(exc, PublishTimePending):
                row.update(status="retryable_failure", failure_category=exc.failure_category,
                           retryable=True, reasons=f"{exc}; target remains unresolved.")
            else:
                # Our own exception messages name the failing check; keep a
                # short, control-character-free copy so the cause is visible
                # in the run log without reproducing it.
                detail = re.sub(r"[\x00-\x1f\x7f]", " ", str(exc))[:200]
                row.update(status="error", failure_category=type(exc).__name__, failure_detail=detail,
                           reasons=f"Target could not be analyzed: {type(exc).__name__}: {detail}")
        rows.append(row)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["### Fast lane", "", "| Package | Version (previous) | Severity | Publish to verdict | Notes |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        latency = f"{row['latency_seconds'] // 60} min {row['latency_seconds'] % 60} s" if isinstance(row.get("latency_seconds"), int) else "-"
        lines.append(f"| {row['target']} | {row.get('version', '-')} ({row.get('previous') or '-'}) | {row['severity']} | {latency} | {row.get('status')}: {str(row.get('reasons', ''))[:200]} |")
    report = "\n".join(lines)
    print(report)
    print(json.dumps(rows, default=str))
    report_path = Path(os.environ.get("FAST_LANE_REPORT_PATH", "reports/fast-lane-results.json"))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({"schema_version": "secopsai.fast-lane.results.v1", "completed_at": _iso(_now()), "results": rows}, indent=2), encoding="utf-8")
    if summary:
        Path(summary).write_text(report + "\n", encoding="utf-8")
    # A bounded but incomplete artifact is a recorded outcome, not an analyzer
    # crash. Retryable registry failures are green only when a durable queue
    # receipt can reschedule that target; otherwise the report needs operator
    # attention and the workflow must remain red.
    unhandled = any(
        row["status"] == "error"
        or (row["status"] == "retryable_failure" and not row.get("queue_id"))
        for row in rows
    )
    return 1 if unhandled else 0


def triage_context(key: str, evidence: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
    """The worker's triage context for this release (start-up and install
    files, flagged code, the comparison with the previous release) plus the
    Fast Lane's own delta. Falls back to the delta alone if the scan failed."""
    from secopsai import research_ai_triage

    fast = {k: evidence[k] for k in ("ecosystem", "package", "version", "previous_version", "reasons", "new_indicators", "install_hooks")}
    fast["publisher_changed"] = bool(decision.get("publisher_changed"))
    findings = (decision["yara_findings"] + decision.get("behaviour_findings", [])) or [
        {"rule_id": "FAST-LANE-DELTA", "matched_indicator": r, "safe_context": ""} for r in decision["reasons"]]
    prescan = decision.get("triage_prescan") or {}
    if prescan.get("status") in {"hit", "clean"}:
        context = research_ai_triage.triage_context(ecosystem=evidence["ecosystem"], package=evidence["package"], version=evidence["version"],
                                                    prescan=prescan, previous_version=evidence.get("previous_version") or "")
        context.update(fast)
        seen = {item.get("rule_id") for item in context.get("findings") or []}
        context["findings"] = [item for item in decision["yara_findings"] if item.get("rule_id") not in seen] + list(context.get("findings") or [])
    else:
        context = {**fast, "findings": findings, "note": "Package metadata is untrusted context."}
    context["artifact_id"] = key
    return context


# The urgent email waits this long, per run, for the model's verdict so the
# reader sees it at once; it is sent without it when the time runs out.
URGENT_VERDICT_WAIT_SECONDS = max(0, min(int(os.environ.get("SECOPSAI_URGENT_VERDICT_WAIT_SECONDS", "300") or 0), 600))
VERDICT_POLL_SECONDS = 15
BENIGN_VERDICTS = {"false_positive", "benign_expected", "policy_noise"}
_verdict_budget = {"until": None}


def release_status(fetcher: SafeFetcher, ecosystem: str, package: str, version: str) -> str:
    """Is the release still downloadable? listed, yanked/deprecated, removed
    (registry 404) or unknown. A removal usually means someone reported it."""
    try:
        if ecosystem == "pypi":
            doc = _get_json(fetcher, f"https://pypi.org/pypi/{package}/{version}/json", ("pypi.org",))
            files = doc.get("urls") or []
            return "yanked" if files and all(item.get("yanked") for item in files) else "listed"
        if ecosystem == "npm":
            doc = _get_json(fetcher, "https://registry.npmjs.org/" + package.replace("/", "%2F"), ("registry.npmjs.org",))
            entry = (doc.get("versions") or {}).get(version)
            if entry is None:
                return "removed"
            return "deprecated" if entry.get("deprecated") else "listed"
    except Exception as exc:
        from secopsai.research_intake import RegistryHTTPError

        if isinstance(exc, RegistryHTTPError) and exc.status == 404:
            return "removed"
    return "unknown"


def wait_for_verdict(client: Any, key: str, since: str, seconds: float) -> Dict[str, Any]:
    """The model's schema-valid verdict on ``key``, polling Core for at most
    ``seconds``. {} when none arrived in time or it was not valid."""
    from secopsai.decision_contracts import DecisionError, validate_action_result

    deadline = time.monotonic() + max(0.0, seconds)
    while True:
        items: List[Dict[str, Any]] = []
        cursor = since
        for _page in range(10):
            try:
                response = client.triage_results(since=cursor, limit=200) or {}
            except Exception:
                break
            page = response.get("results") or []
            items += page
            if not page or not (response.get("truncated") or len(page) >= 200) or response.get("next_since") in {None, "", cursor}:
                break
            cursor = response["next_since"]
        for item in items:
            if str(item.get("artifact_id") or "") != key:
                continue
            result = item.get("result") if isinstance(item.get("result"), dict) else {}
            if item.get("status") != "succeeded":
                return {"status": "failed"}
            try:
                validate_action_result("triage_artifact", result)
            except (DecisionError, TypeError, ValueError, KeyError):
                return {"status": "invalid"}
            return {"status": "ready", "verdict": result["finding_verdict"], "probability": result.get("malicious_probability"),
                    "confidence": result.get("finding_confidence"), "summary": str(result.get("summary") or "")[:600]}
        if time.monotonic() + VERDICT_POLL_SECONDS > deadline:
            return {}
        time.sleep(VERDICT_POLL_SECONDS)


def source_check(target: Dict[str, Any], release: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
    """Compare the release's start-up/install and flagged files with its
    GitHub repository at the release tag (secopsai/source_match.py)."""
    from secopsai import source_match

    scan = decision.get("triage_prescan") or {}
    if scan.get("status") != "hit":
        return {"result": "unknown", "reason": "no scan to compare"}
    ecosystem, package, version = target["ecosystem"], target["package"], release["version"]
    fetcher = SafeFetcher(timeout=20)
    try:
        if ecosystem == "pypi":
            metadata = _get_json(fetcher, f"https://pypi.org/pypi/{package}/{version}/json", ("pypi.org",))
        elif ecosystem == "npm":
            metadata = _get_json(fetcher, "https://registry.npmjs.org/" + package.replace("/", "%2F") + "/" + version, ("registry.npmjs.org",))
        else:
            return {"result": "unknown", "reason": f"not compared for {ecosystem}"}
        return source_match.compare(fetcher, ecosystem, package, version, metadata, scan)
    except Exception as exc:
        return {"result": "unknown", "reason": f"comparison failed: {type(exc).__name__}"}


def source_summary(match: Dict[str, Any]) -> Dict[str, Any]:
    """The comparison as the model and the alert see it (bounded)."""
    return {k: match[k] for k in ("result", "repository", "tag", "reason", "note") if match.get(k)} | (
        {"files": [{k: item[k] for k in ("path", "outcome", "install_time")} for item in (match.get("files") or [])[:8]]} if match.get("files") else {})


def auto_check(decision: Dict[str, Any], status: str, verdict: Dict[str, Any]) -> Dict[str, Any]:
    """The checks an analyst runs first on an urgent alert, as a checklist and
    a one-line reading. Advice only: nothing is closed or suppressed."""
    diff = (decision.get("triage_prescan") or {}).get("diff") or {}
    checks = []
    checks.append(("registry", {"listed": "ok", "removed": "bad", "yanked": "bad", "deprecated": "bad"}.get(status, "unknown"),
                   {"listed": "still on the registry", "removed": "removed from the registry (often: already reported)",
                    "yanked": "yanked on PyPI", "deprecated": "deprecated on npm"}.get(status, "registry status unknown")))
    if "new_flags" in diff:
        new = list(diff.get("new_flags") or [])
        checks.append(("new", "bad" if new else "ok", (f"new since {diff.get('previous_version')}: " + ", ".join(new[:6])) if new
                       else f"nothing risky is new since {diff.get('previous_version')}"))
    else:
        checks.append(("new", "unknown", "no comparison with a previous release" + (f" ({diff.get('note')})" if diff.get("note") else "")))
    checks.append(("publisher", "bad" if decision.get("publisher_changed") else "ok",
                   "publisher changed" if decision.get("publisher_changed") else "same publisher"))
    source = decision.get("source_match") or {}
    if source.get("result") == "matches":
        checks.append(("source", "ok", f"start-up/flagged files match {source.get('repository')} at {source.get('tag')}"))
    elif source.get("result") == "differs":
        odd = [item["path"].rsplit("/", 1)[-1] + " " + item["outcome"] for item in source.get("files") or []
               if item["outcome"] == "differs" or (item["outcome"] == "missing" and item.get("install_time"))]
        checks.append(("source", "bad", f"not as in {source.get('repository')} at {source.get('tag')}: " + ", ".join(odd[:4])))
    else:
        checks.append(("source", "unknown", "source repository not compared" + (f" ({source.get('reason')})" if source.get("reason") else "")))
    if verdict.get("status") == "ready":
        label = str(verdict["verdict"]).replace("_", " ")
        mark = "ok" if verdict["verdict"] in BENIGN_VERDICTS else "bad" if verdict["verdict"] == "true_positive" else "unknown"
        checks.append(("model", mark, f"model: {label}, {verdict.get('probability')}% likely malicious (confidence {verdict.get('confidence')}%)"))
    else:
        checks.append(("model", "unknown", {"failed": "model triage failed", "invalid": "model answer failed validation"}.get(
            verdict.get("status"), "model verdict not ready yet (see the dashboard)")))
    marks = {name: mark for name, mark, _ in checks}
    benign_model = verdict.get("status") == "ready" and verdict["verdict"] in BENIGN_VERDICTS and int(verdict.get("probability") or 0) <= 20
    if marks["model"] == "bad" or (marks["new"] == "bad" and "bad" in {marks["publisher"], marks["source"]}):
        reading = "likely malicious: review now"
    elif benign_model and marks["new"] == "ok" and marks["publisher"] == "ok" and marks["source"] != "bad":
        reading = "likely benign: confirm and close"
    else:
        reading = "needs review"
    return {"reading": reading, "checks": [{"check": name, "result": mark, "detail": detail} for name, mark, detail in checks],
            "model_summary": verdict.get("summary", "")}


def auto_check_text(check: Dict[str, Any]) -> str:
    symbol = {"ok": "[ok]", "bad": "[!!]", "unknown": "[??]"}
    lines = [f"Auto-check: {check['reading']}", ""]
    lines += [f"  {symbol[item['result']]} {item['detail']}" for item in check["checks"]]
    if check.get("model_summary"):
        lines += ["", "Model: " + check["model_summary"]]
    lines += ["", "Nothing was closed automatically; closing stays your decision."]
    return "\n".join(lines)


def deliver(target: Dict[str, Any], release: Dict[str, Any], decision: Dict[str, Any], detected: datetime) -> Dict[str, Any]:
    """Signed alert to Core, model triage for the operator's bridge, optional email."""
    from secopsai.research_delivery import send_email, send_signed_webhook

    out: Dict[str, Any] = {}
    decision = {**decision, "source_match": source_check(target, release, decision)}
    out["source_match"] = source_summary(decision["source_match"])
    triage_client: Any = None
    queued_since = ""
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
        if client.enabled and (decision["yara_findings"] or decision.get("behaviour_findings") or decision["reasons"]):
            key = payload["alert_id"]
            context = triage_context(key, payload["evidence"], decision)
            if decision.get("source_match"):
                context["source_repository_match"] = source_summary(decision["source_match"])
            queued_since = _iso(_now() - timedelta(minutes=1))
            out["triage"] = client.queue_triage_jobs([{"artifact_id": key, "idempotency_key": f"fast-lane:{key}", "inputs": {"artifact_triage": context}}]).get("count")
            triage_client = client
    except Exception as exc:
        out["triage"] = f"failed: {exc}"[:200]
    from secopsai import notification_policy

    # Only critical alerts are emailed now; every alert also goes into the daily
    # digest (marked when it was already emailed). SECOPSAI_EMAIL_PAUSED stops both.
    recipient = os.environ.get("SECOPSAI_RESEARCH_ALERT_EMAIL", "")
    emailed = False
    urgent = notification_policy.urgent_fast_lane(decision["severity"])
    if recipient and os.environ.get("SECOPSAI_SMTP_PASSWORD") and notification_policy.email_now(decision["severity"], urgent=urgent):
        try:
            check_block = ""
            if urgent:
                if _verdict_budget["until"] is None:
                    _verdict_budget["until"] = time.monotonic() + URGENT_VERDICT_WAIT_SECONDS
                wait = max(0.0, _verdict_budget["until"] - time.monotonic())
                verdict = wait_for_verdict(triage_client, payload["alert_id"], queued_since, wait) if triage_client else {}
                check = auto_check(decision, release_status(SafeFetcher(timeout=30), target["ecosystem"], target["package"], release["version"]), verdict)
                out["auto_check"] = check
                check_block = auto_check_text(check) + "\n\n"
            body = (check_block + payload["reason"] + "\n\nDashboard: " + notification_policy.DASHBOARD_INBOX + "\n\n"
                    + json.dumps(payload["evidence"], indent=2, default=str)[:6000])
            label = "URGENT " if urgent else ""
            reading = (out.get("auto_check") or {}).get("reading", "")
            label += f"({reading.split(':', 1)[0]}) " if reading else ""
            send_email(recipient=recipient, subject=f"[SecOpsAI fast lane] {label}{decision['severity'].upper()}: {payload['evidence']['package']}@{release['version']}", body=body)
            out["email"] = "sent"
            emailed = True
        except Exception as exc:
            out["email"] = f"failed: {exc}"[:200]
    else:
        out["email"] = "paused" if notification_policy.email_paused() else "digest"
    evidence = payload["evidence"]
    out["digest"] = notification_policy.digest_entry(
        source="fast_lane", alert_id=payload["alert_id"], dashboard_id=notification_policy.core_alert_id(payload["alert_id"]),
        severity=decision["severity"], title=f"{evidence['package']}@{evidence['version']}", reason="; ".join(decision["reasons"]),
        occurred_at=payload["occurred_at"], ecosystem=evidence["ecosystem"], package=evidence["package"],
        version=evidence["version"], emailed=emailed)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
