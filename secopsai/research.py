from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import quote_plus

import soc_store

from scripts.secopsai_report_snapshot import build_snapshot
from secopsai.supply_chain import explain_policy, load_recent_results
from secopsai.triage.engine import infer_category


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_DIR = ROOT / "reports" / "research"
DEFAULT_WORKSPACE_LOGS = Path.home() / ".openclaw" / "workspace" / "logs"
DEFAULT_OPENCLAW_HOME = Path.home() / ".openclaw"
MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
}
SEARCHABLE_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".js", ".ts", ".tsx"}
SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "site-packages",
    "uploads",
}


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned or "research"


def _normalize_terms(values: Iterable[str]) -> List[str]:
    terms: List[str] = []
    seen: set[str] = set()
    for value in values:
        term = str(value or "").strip().lower()
        if not term or len(term) < 2:
            continue
        if term in seen:
            continue
        terms.append(term)
        seen.add(term)
    return terms


def _preview(text: str, index: int, *, radius: int = 140) -> str:
    start = max(0, index - radius)
    end = min(len(text), index + radius)
    snippet = " ".join(text[start:end].split())
    return snippet[:320].rstrip()


def _should_scan(path: Path, *, manifest_only: bool) -> bool:
    parts = {part.lower() for part in path.parts}
    if parts.intersection(SKIP_DIRS):
        return False
    if manifest_only:
        return path.name in MANIFEST_FILES
    return path.name in MANIFEST_FILES or path.suffix.lower() in SEARCHABLE_SUFFIXES


def _scan_root(
    root: Path,
    terms: Sequence[str],
    *,
    manifest_only: bool = False,
    limit: int = 8,
) -> List[Dict[str, Any]]:
    if not root.exists():
        return []

    results: List[Dict[str, Any]] = []
    lowered_terms = [term.lower() for term in terms]

    for path in root.rglob("*"):
        if len(results) >= limit:
            break
        if not path.is_file() or not _should_scan(path, manifest_only=manifest_only):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lowered = content.lower()
        matched = [term for term in lowered_terms if term in lowered]
        if not matched:
            continue
        index = min(lowered.find(term) for term in matched if lowered.find(term) >= 0)
        results.append(
            {
                "path": str(path.resolve()),
                "matched_terms": matched[:4],
                "excerpt": _preview(content, index),
            }
        )
    return results


def _search_urls(query: str) -> List[Dict[str, Any]]:
    encoded = quote_plus(query)
    return [
        {
            "label": "CVE search",
            "type": "external_search",
            "url": f"https://www.cve.org/CVERecord/SearchResults?query={encoded}",
        },
        {
            "label": "GitHub Security Advisories",
            "type": "external_search",
            "url": f"https://github.com/advisories?query={encoded}",
        },
        {
            "label": "CISA KEV catalog",
            "type": "external_reference",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        },
        {
            "label": "SigmaHQ rules search",
            "type": "external_search",
            "url": f"https://github.com/SigmaHQ/sigma/search?q={encoded}",
        },
        {
            "label": "YARA code search",
            "type": "external_search",
            "url": f"https://github.com/search?q={encoded}+extension%3Ayara&type=code",
        },
    ]


def _finding_query(finding: Dict[str, Any]) -> str:
    package = str(finding.get("package") or "").strip()
    ecosystem = str(finding.get("ecosystem") or "").strip()
    title = str(finding.get("title") or "").strip()
    if package and ecosystem:
        return f"{ecosystem} {package}"
    return title or str(finding.get("finding_id") or "finding")


def _package_observations(
    *,
    ecosystem: str,
    package: str,
    version: Optional[str],
    policy: Dict[str, Any],
    manifest_matches: Sequence[Dict[str, Any]],
    recent_results: Sequence[Dict[str, Any]],
) -> List[str]:
    observations: List[str] = []
    if manifest_matches:
        observations.append(
            f"{package} appears in {len(manifest_matches)} local manifest or source file(s), so this alert is inside the current code boundary."
        )
    else:
        observations.append(
            f"{package} was not found in common dependency manifests under the scanned local roots."
        )
    if policy.get("allow_matches"):
        observations.append(
            f"Local supply-chain policy already allowlists this target via {policy['allow_matches']}."
        )
    if recent_results:
        latest = recent_results[0]
        verdict = str(latest.get("verdict") or "unknown")
        version_hint = str(latest.get("new_version") or version or "")
        observations.append(
            f"Latest stored supply-chain result for {ecosystem}:{package}{('@' + version_hint) if version_hint else ''} is {verdict}."
        )
    return observations


def build_preflight_report(
    *,
    repo: Optional[str] = None,
    workspace_logs: Optional[str] = None,
    openclaw_home: Optional[str] = None,
) -> Dict[str, Any]:
    repo_path = Path(repo).expanduser().resolve() if repo else ROOT
    workspace_logs_path = (
        Path(workspace_logs).expanduser().resolve() if workspace_logs else DEFAULT_WORKSPACE_LOGS
    )
    openclaw_home_path = (
        Path(openclaw_home).expanduser().resolve() if openclaw_home else DEFAULT_OPENCLAW_HOME
    )
    snapshot = build_snapshot(repo_path, workspace_logs_path, openclaw_home_path)

    intel = snapshot.get("intel") or {}
    telemetry = snapshot.get("telemetry") or {}
    labeled_replay = telemetry.get("labeled_replay") or {}
    replay_bundle = telemetry.get("openclaw_latest_bundle") or {}
    source = telemetry.get("openclaw_source") or {}
    correlation = snapshot.get("correlation") or {}

    issues: List[Dict[str, str]] = []
    recommendations: List[str] = []

    replay_age = labeled_replay.get("age_hours_since_latest_event")
    bundle_age = replay_bundle.get("age_hours")
    intel_age = intel.get("age_hours")
    source_age = source.get("age_hours_since_latest_activity")
    total_events = int(labeled_replay.get("total_events") or 0)
    status_counts = labeled_replay.get("status_counts") or {}
    failed = int(status_counts.get("failed") or 0)
    errors = int(status_counts.get("error") or 0)

    if not labeled_replay.get("exists") or total_events <= 0:
        issues.append(
            {
                "code": "replay_missing",
                "severity": "critical",
                "message": "Replay telemetry is missing or empty, so correlation and triage are operating without fresh runtime evidence.",
            }
        )
        recommendations.append("Run secopsai refresh to rebuild replay telemetry before relying on triage output.")

    if isinstance(replay_age, (int, float)) and replay_age > 24:
        issues.append(
            {
                "code": "telemetry_stale",
                "severity": "critical",
                "message": f"Latest replay event is {float(replay_age):.2f}h old, so telemetry-backed triage context is stale.",
            }
        )
        recommendations.append("Refresh or ingest newer OpenClaw replay telemetry first.")

    if isinstance(source_age, (int, float)) and source_age <= 24 and isinstance(replay_age, (int, float)) and replay_age > 24:
        issues.append(
            {
                "code": "export_bridge_stale",
                "severity": "critical",
                "message": "OpenClaw source logs are fresher than the replay export, which points to an export bridge problem rather than idle source activity.",
            }
        )
        recommendations.append("Repair the replay export bridge or rerun secopsai refresh against the fresh OpenClaw source logs.")

    if isinstance(bundle_age, (int, float)) and bundle_age > 24:
        issues.append(
            {
                "code": "bundle_stale",
                "severity": "warning",
                "message": f"Latest replay findings bundle is {float(bundle_age):.2f}h old.",
            }
        )

    if isinstance(intel_age, (int, float)) and intel_age > 24:
        issues.append(
            {
                "code": "intel_stale",
                "severity": "warning",
                "message": f"Threat intel snapshot is {float(intel_age):.2f}h old.",
            }
        )
        recommendations.append("Refresh threat intel so IOC matching uses a current corpus.")

    if total_events and (failed + errors) >= max(25, int(total_events * 0.05)):
        issues.append(
            {
                "code": "replay_error_mix",
                "severity": "warning",
                "message": f"Replay contains {failed} failed and {errors} error events, which may hide real coverage gaps.",
            }
        )

    if correlation.get("error"):
        issues.append(
            {
                "code": "correlation_unavailable",
                "severity": "warning",
                "message": f"Correlation summary failed to build: {correlation['error']}",
            }
        )

    critical = any(issue["severity"] == "critical" for issue in issues)
    status = "block" if critical else ("warn" if issues else "pass")
    if not recommendations and not issues:
        recommendations.append("Telemetry, findings, and intel look fresh enough for native triage and correlation.")

    summary = (
        "Preflight checks found critical freshness issues."
        if status == "block"
        else "Preflight checks found non-blocking warnings."
        if status == "warn"
        else "Preflight checks passed."
    )
    return {
        "generated_at": _utc_now(),
        "status": status,
        "summary": summary,
        "issues": issues,
        "recommendations": recommendations[:5],
        "staleness_flags": snapshot.get("staleness_flags") or [],
        "metrics": {
            "intel_age_hours": intel_age,
            "ioc_total": intel.get("total_iocs"),
            "replay_age_hours": replay_age,
            "replay_total_events": total_events,
            "findings_bundle_age_hours": bundle_age,
            "openclaw_source_age_hours": source_age,
            "replay_failed_events": failed,
            "replay_error_events": errors,
        },
    }


def _write_report(
    *,
    stem: str,
    payload: Dict[str, Any],
    markdown: str,
    report_dir: Optional[str] = None,
) -> Dict[str, Any]:
    target_dir = Path(report_dir).expanduser().resolve() if report_dir else DEFAULT_REPORT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    json_path = target_dir / f"{stamp}-{stem}.json"
    markdown_path = target_dir / f"{stamp}-{stem}.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(markdown, encoding="utf-8")
    return {
        "json_report": str(json_path),
        "markdown_report": str(markdown_path),
    }


def _format_source_item(item: Dict[str, Any]) -> str:
    label = str(item.get("label") or item.get("type") or "Source")
    target = item.get("url") or item.get("path") or item.get("reference")
    if target:
        return f"- {label}: {target}"
    return f"- {label}"


def _package_markdown(payload: Dict[str, Any]) -> str:
    lines = [
        f"# Supply-Chain Research: {payload['ecosystem']}:{payload['package']}",
        "",
        f"- Generated at: {payload['generated_at']}",
        f"- Version: {payload.get('version') or 'latest-seen'}",
        f"- Summary: {payload['summary']}",
        "",
        "## Observations",
        "",
    ]
    for item in payload.get("observations") or []:
        lines.append(f"- {item}")
    lines.extend(["", "## Local Manifest Matches", ""])
    manifest_matches = payload.get("local_presence", {}).get("manifest_matches") or []
    if manifest_matches:
        for item in manifest_matches:
            lines.append(f"- {item['path']}: {item['excerpt']}")
    else:
        lines.append("- No manifest matches found.")
    lines.extend(["", "## Local Repo Matches", ""])
    repo_matches = payload.get("local_presence", {}).get("repo_matches") or []
    if repo_matches:
        for item in repo_matches:
            lines.append(f"- {item['path']}: {item['excerpt']}")
    else:
        lines.append("- No additional local repo matches found.")
    lines.extend(["", "## External Sources", ""])
    for item in payload.get("sources") or []:
        lines.append(_format_source_item(item))
    return "\n".join(lines) + "\n"


def _finding_markdown(payload: Dict[str, Any]) -> str:
    finding = payload.get("finding") or {}
    lines = [
        f"# Finding Research: {finding.get('finding_id')}",
        "",
        f"- Generated at: {payload['generated_at']}",
        f"- Category: {payload['category']}",
        f"- Title: {finding.get('title')}",
        f"- Summary: {payload['summary']}",
        "",
        "## Observations",
        "",
    ]
    for item in payload.get("observations") or []:
        lines.append(f"- {item}")
    lines.extend(["", "## Local Matches", ""])
    local_matches = payload.get("local_matches") or []
    if local_matches:
        for item in local_matches:
            lines.append(f"- {item['path']}: {item['excerpt']}")
    else:
        lines.append("- No relevant local matches found.")
    lines.extend(["", "## External Sources", ""])
    for item in payload.get("sources") or []:
        lines.append(_format_source_item(item))
    return "\n".join(lines) + "\n"


def _build_package_payload(
    *,
    ecosystem: str,
    package: str,
    version: Optional[str],
    search_root: Optional[str],
) -> Dict[str, Any]:
    repo_root = ROOT
    roots = [repo_root]
    if search_root:
        roots.insert(0, Path(search_root).expanduser().resolve())
    terms = _normalize_terms([package, f"{ecosystem} {package}", f"{package}@{version or ''}"])
    manifest_matches: List[Dict[str, Any]] = []
    repo_matches: List[Dict[str, Any]] = []
    for root in roots:
        manifest_matches.extend(_scan_root(root, terms, manifest_only=True, limit=max(0, 6 - len(manifest_matches))))
        repo_matches.extend(_scan_root(root, terms, manifest_only=False, limit=max(0, 6 - len(repo_matches))))
        if len(manifest_matches) >= 6 and len(repo_matches) >= 6:
            break

    recent_results = [
        row
        for row in load_recent_results(limit=500)
        if str(row.get("ecosystem") or "") == ecosystem
        and str(row.get("package") or "") == package
        and (not version or str(row.get("new_version") or "") == version)
    ][:5]
    policy = explain_policy(ecosystem, package)
    observations = _package_observations(
        ecosystem=ecosystem,
        package=package,
        version=version,
        policy=policy,
        manifest_matches=manifest_matches,
        recent_results=recent_results,
    )
    summary = observations[0]
    payload: Dict[str, Any] = {
        "generated_at": _utc_now(),
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "summary": summary,
        "observations": observations,
        "policy": {
            "effective_threshold": policy.get("effective_threshold"),
            "allow_matches": policy.get("allow_matches"),
            "deny_matches": policy.get("deny_matches"),
            "precedence": policy.get("precedence"),
        },
        "local_presence": {
            "manifest_matches": manifest_matches,
            "repo_matches": repo_matches[:6],
            "present": bool(manifest_matches),
        },
        "recent_results": recent_results,
        "sources": _search_urls(f"{ecosystem} {package}"),
    }
    if recent_results and recent_results[0].get("report_path"):
        payload["sources"].insert(
            0,
            {
                "label": "Latest stored supply-chain diff report",
                "type": "local_report",
                "path": str(Path(str(recent_results[0]["report_path"])).expanduser().resolve()),
            },
        )
    return payload


def research_package(
    *,
    ecosystem: str,
    package: str,
    version: Optional[str] = None,
    search_root: Optional[str] = None,
    report_dir: Optional[str] = None,
) -> Dict[str, Any]:
    payload = _build_package_payload(
        ecosystem=ecosystem,
        package=package,
        version=version,
        search_root=search_root,
    )
    payload.update(
        _write_report(
            stem=f"{ecosystem}-{_slug(package)}",
            payload=payload,
            markdown=_package_markdown(payload),
            report_dir=report_dir,
        )
    )
    return payload


def research_finding(
    *,
    finding_id: str,
    db_path: Optional[str] = None,
    search_root: Optional[str] = None,
    report_dir: Optional[str] = None,
) -> Dict[str, Any]:
    finding = soc_store.get_finding(finding_id, db_path)
    if not finding:
        raise ValueError(f"finding not found: {finding_id}")

    category = infer_category(finding)
    if category == "supply_chain" and finding.get("package") and finding.get("ecosystem"):
        package_payload = _build_package_payload(
            ecosystem=str(finding["ecosystem"]),
            package=str(finding["package"]),
            version=str(finding.get("new_version") or "") or None,
            search_root=search_root,
        )
        payload: Dict[str, Any] = {
            "generated_at": _utc_now(),
            "finding": finding,
            "category": category,
            "summary": package_payload["summary"],
            "observations": package_payload["observations"],
            "local_matches": package_payload["local_presence"]["manifest_matches"] + package_payload["local_presence"]["repo_matches"],
            "sources": package_payload["sources"],
            "package_research": package_payload,
        }
    else:
        query = _finding_query(finding)
        terms = _normalize_terms(
            [query, finding.get("finding_id"), *(finding.get("rule_ids") or [])]
        )
        roots = [ROOT]
        if search_root:
            roots.insert(0, Path(search_root).expanduser().resolve())
        local_matches: List[Dict[str, Any]] = []
        for root in roots:
            local_matches.extend(_scan_root(root, terms, manifest_only=False, limit=max(0, 8 - len(local_matches))))
            if len(local_matches) >= 8:
                break
        observations = []
        if local_matches:
            observations.append("Local repo or docs contain matching terms that can help explain this finding in current project context.")
        else:
            observations.append("No matching local repo evidence was found, so this finding should be explained mainly through external detection references.")
        if finding.get("events"):
            observations.append(f"Finding includes {len(finding.get('events') or [])} embedded event record(s) for local review.")
        payload = {
            "generated_at": _utc_now(),
            "finding": finding,
            "category": category,
            "summary": observations[0],
            "observations": observations,
            "local_matches": local_matches,
            "sources": _search_urls(query),
        }

    payload.update(
        _write_report(
            stem=_slug(finding_id),
            payload=payload,
            markdown=_finding_markdown(payload),
            report_dir=report_dir,
        )
    )
    return payload
