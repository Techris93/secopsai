"""Exact-version npm enrichment and bounded proactive release inspection.

The npm replica changes feed identifies package documents, not release
versions.  This module resolves those documents through the official npm
registry, keeps a compact per-package baseline, creates exact-version ledger
events, and statically inspects a bounded queue of exact releases. Explainable
metadata and artifact signals decide which releases become review candidates.

The artifact path is deliberately non-executing.  It uses the existing
quarantined ``collect_package_intake`` implementation and never installs,
imports, or runs package code.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import soc_store
from secopsai.research_discovery import create_candidate_alert
from secopsai.research_intake import IntakeError, SafeFetcher, collect_package_intake
from secopsai.sqlite_writer_lock import sqlite_writer_lock


SCHEMA_VERSION = "secopsai.research.npm-enrichment.v1"
NPM_METADATA_HOSTS = ("registry.npmjs.org",)
NPM_METADATA_BASE = "https://registry.npmjs.org/"
NPM_COLLECTOR_ID = "COL-NPM-CHANGES"
MAX_PACKUMENT_BYTES = 2 * 1024 * 1024
MAX_PACKUMENT_VERSIONS = 5000
MAX_SNAPSHOT_SUMMARIES = 256
MAX_SNAPSHOT_VERSION_NAMES = 2000
MAX_PACKAGE_EVENTS_PER_CYCLE = 100
MAX_STATIC_ANALYSES_PER_CYCLE = 10
MAX_RETRY_SECONDS = 300
MAX_ATTEMPTS = 8
PACKAGE_RE = re.compile(r"^[A-Za-z0-9@._:/+\-]+$")
LIFECYCLE_NAMES = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishonly",
}
SUSPICIOUS_SCRIPT_TOKENS = {
    "child_process",
    "execsync",
    "spawnsync",
    "curl",
    "wget",
    "http",
    "https",
    "bun",
    "base64",
    "atob",
    "fromcharcode",
    "eval",
    "token",
    "password",
    "secret",
    "credential",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, default: Any) -> Any:
    try:
        result = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return result


def _bounded_limit(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


@contextmanager
def _write_transaction(connection: Any, db_path: Optional[str]):
    """Serialize short NPM-enrichment writes with every other Core writer."""
    with sqlite_writer_lock(db_path):
        with connection:
            yield connection


def _valid_package(value: Any) -> Optional[str]:
    package = str(value or "").strip()
    if not package or len(package) > 512 or not PACKAGE_RE.fullmatch(package):
        return None
    return package


def _parse_time(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _hash_text(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", "ignore")).hexdigest()


def _bounded_mapping(value: Any, *, limit: int = 200) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key)[:200]: str(item)[:500]
        for key, item in list(value.items())[:limit]
        if str(key).strip()
    }


def _repository(value: Any) -> str:
    if isinstance(value, str):
        return value[:500]
    if isinstance(value, dict):
        return str(value.get("url") or value.get("directory") or "")[:500]
    return ""


def _version_summary(version: str, item: Dict[str, Any], times: Dict[str, Any]) -> Dict[str, Any]:
    scripts = item.get("scripts") if isinstance(item.get("scripts"), dict) else {}
    lifecycle = {
        str(key): _hash_text(value)
        for key, value in scripts.items()
        if str(key).lower() in LIFECYCLE_NAMES
    }
    script_text = " ".join(str(value)[:1000].lower() for value in scripts.values())
    script_risk_tokens = sorted(
        token for token in SUSPICIOUS_SCRIPT_TOKENS if token in script_text
    )[:20]
    all_script_names = [str(key)[:120] for key in list(scripts)[:100]]
    dist = item.get("dist") if isinstance(item.get("dist"), dict) else {}
    author = item.get("author")
    if isinstance(author, dict):
        author = author.get("name") or author.get("email") or ""
    maintainers: List[str] = []
    for maintainer in item.get("maintainers") if isinstance(item.get("maintainers"), list) else []:
        if isinstance(maintainer, dict):
            name = maintainer.get("name") or maintainer.get("username") or ""
            if name:
                maintainers.append(str(name)[:160])
        elif maintainer:
            maintainers.append(str(maintainer)[:160])
    return {
        "version": version,
        "published_at": str(
            times.get(version)
            or (item.get("_npmUser", {}).get("date") if isinstance(item.get("_npmUser"), dict) else "")
            or ""
        )[:80],
        "lifecycle_scripts": lifecycle,
        "script_names": all_script_names,
        "script_risk_tokens": script_risk_tokens,
        "dependencies": sorted(str(key) for key in (item.get("dependencies") or {}).keys())[:300],
        "optional_dependencies": sorted(str(key) for key in (item.get("optionalDependencies") or {}).keys())[:100],
        "peer_dependencies": sorted(str(key) for key in (item.get("peerDependencies") or {}).keys())[:100],
        "author": str(author or "")[:240],
        "maintainers": maintainers[:20],
        "repository": _repository(item.get("repository")),
        "homepage": str(item.get("homepage") or "")[:500],
        "has_bin": bool(item.get("bin")),
        "tarball": str(dist.get("tarball") or "")[:1000],
        "integrity": str(dist.get("integrity") or "")[:240],
        "shasum": str(dist.get("shasum") or "")[:128],
        "description_hash": _hash_text(item.get("description")),
    }


def _packument_summary(payload: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], str]:
    versions = payload.get("versions") if isinstance(payload.get("versions"), dict) else {}
    times = payload.get("time") if isinstance(payload.get("time"), dict) else {}
    result: Dict[str, Dict[str, Any]] = {}
    for version, item in list(versions.items())[:MAX_PACKUMENT_VERSIONS]:
        if isinstance(item, dict) and str(version).strip():
            result[str(version)] = _version_summary(str(version), item, times)
    dist_tags = payload.get("dist-tags") if isinstance(payload.get("dist-tags"), dict) else {}
    latest = str(dist_tags.get("latest") or "")
    if latest not in result and result:
        latest = next(reversed(result))
    return result, latest


def _summary_time(summary: Dict[str, Any]) -> Optional[datetime]:
    return _parse_time(summary.get("published_at"))


def _compact_snapshot_versions(versions: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Keep a bounded recent baseline; the event ledger remains authoritative."""
    ordered = sorted(
        versions.items(),
        key=lambda item: (_summary_time(item[1]) or datetime.min.replace(tzinfo=timezone.utc), item[0]),
        reverse=True,
    )
    return dict(ordered[:MAX_SNAPSHOT_SUMMARIES])


def _known_version_names(versions: Dict[str, Dict[str, Any]]) -> List[str]:
    ordered = sorted(
        versions.items(),
        key=lambda item: (_summary_time(item[1]) or datetime.min.replace(tzinfo=timezone.utc), item[0]),
        reverse=True,
    )
    return [name for name, _summary in ordered[:MAX_SNAPSHOT_VERSION_NAMES]]


def _new_versions(
    current_versions: Dict[str, Dict[str, Any]],
    *,
    prior: Optional[Dict[str, Any]],
    prior_versions: Dict[str, Dict[str, Any]],
    latest: str,
) -> List[str]:
    """Resolve releases not present at the previous packument observation.

    Release timestamps are preferred because a compact snapshot intentionally
    does not retain every historical version.  The latest-version fallback
    still catches registries that omit timestamps or mutate a same-timestamp
    release without replaying the entire package history.
    """
    if not prior:
        return [latest] if latest else []
    known = set(_decode(prior.get("known_versions_json"), []))
    known.update(prior_versions)
    cutoff = _parse_time(prior.get("last_published_at"))
    candidates: List[Tuple[Optional[datetime], str]] = []
    for version, summary in current_versions.items():
        published = _summary_time(summary)
        newer_than_cutoff = (
            cutoff is None and published is None and version == latest
        ) or (
            published is not None and (cutoff is None or published > cutoff)
        )
        if version not in known and newer_than_cutoff:
            candidates.append((published, version))
    if latest and latest not in known and latest not in {version for _published, version in candidates}:
        candidates.append((_summary_time(current_versions.get(latest, {})), latest))
    candidates.sort(key=lambda item: (item[0] or datetime.min.replace(tzinfo=timezone.utc), item[1]))
    return [version for _published, version in candidates]


def _fetch_packument(package: str, fetcher: SafeFetcher) -> Tuple[str, Dict[str, Any], str]:
    url = NPM_METADATA_BASE + quote(package, safe="@/")
    final_url, _headers, body = fetcher.get(
        url,
        allowed_hosts=NPM_METADATA_HOSTS,
        max_bytes=MAX_PACKUMENT_BYTES,
        headers={"Accept": "application/json"},
    )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError("npm packument was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise IntakeError("npm packument was not an object")
    return final_url, payload, hashlib.sha256(body).hexdigest()


def _event_metadata(row: Dict[str, Any]) -> Dict[str, Any]:
    metadata = _decode(row.get("metadata_json"), {})
    return metadata if isinstance(metadata, dict) else {}


def _retry_allowed(metadata: Dict[str, Any]) -> bool:
    attempts = int(metadata.get("npm_enrichment_attempts") or 0)
    if attempts >= MAX_ATTEMPTS:
        return False
    last = _parse_time(metadata.get("npm_enrichment_last_attempt"))
    if last is None:
        return True
    return datetime.now(timezone.utc) - last >= timedelta(seconds=MAX_RETRY_SECONDS)


def _insert_exact_event(
    connection: Any,
    *,
    parent: Dict[str, Any],
    package: str,
    version: str,
    summary: Dict[str, Any],
    metadata_url: str,
    previous_version: str,
    baseline_only: bool,
) -> bool:
    published_at = str(summary.get("published_at") or parent.get("registry_timestamp") or _now())[:80]
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "source": "npm_packument",
        "parent_feed_event_id": parent.get("feed_event_id"),
        "metadata_url": metadata_url,
        "artifact_url": summary.get("tarball") or "",
        "publisher": summary.get("author") or (summary.get("maintainers") or [""])[0],
        "integrity": {
            "integrity": summary.get("integrity") or "",
            "shasum": summary.get("shasum") or "",
        },
        "version_summary": summary,
        "previous_version": previous_version,
        "baseline_only": bool(baseline_only),
        "timestamp_source": "npm_packument",
    }
    key = hashlib.sha256(
        f"npm-enriched|{parent.get('feed_event_id')}|{package}|{version}".encode()
    ).hexdigest()
    event_type = "version_observed" if baseline_only else "version_updated"
    cursor = connection.execute(
        """INSERT INTO registry_feed_events
           (feed_event_id, collector_id, ecosystem, package, version, event_type,
            registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
            idempotency_key, collected_at, processing_state)
           VALUES (?, ?, 'npm', ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 'pending')
           ON CONFLICT(idempotency_key) DO NOTHING""",
        (
            _id("RFE"),
            NPM_COLLECTOR_ID,
            package,
            version,
            event_type,
            published_at,
            metadata_url,
            summary.get("tarball") or "",
            _json(metadata),
            key,
            _now(),
        ),
    )
    return cursor.rowcount == 1


def _suspicion_score(summary: Dict[str, Any], *, previous: Optional[Dict[str, Any]], baseline_only: bool) -> Tuple[int, List[Dict[str, Any]]]:
    score = 0
    signals: List[Dict[str, Any]] = []
    lifecycle = summary.get("lifecycle_scripts") if isinstance(summary.get("lifecycle_scripts"), dict) else {}
    previous_lifecycle = previous.get("lifecycle_scripts") if isinstance(previous, dict) and isinstance(previous.get("lifecycle_scripts"), dict) else {}
    new_lifecycle = sorted(set(lifecycle) - set(previous_lifecycle))
    lifecycle_changed = bool(previous and lifecycle and any(lifecycle.get(name) != previous_lifecycle.get(name) for name in lifecycle))
    if lifecycle_changed:
        score += 50
        signals.append({"id": "lifecycle_script_changed", "points": 50, "hooks": sorted(lifecycle)})
    elif new_lifecycle:
        points = 45 if any(name in {"preinstall", "install", "postinstall"} for name in new_lifecycle) else 30
        score += points
        signals.append({"id": "new_lifecycle_hook", "points": points, "hooks": new_lifecycle})
    elif lifecycle:
        points = 40 if baseline_only or not previous else 20
        score += points
        signals.append({"id": "lifecycle_hook", "points": points, "hooks": sorted(lifecycle)})
    tokens = sorted(str(token) for token in summary.get("script_risk_tokens") or [])
    if tokens:
        score += min(35, 10 * len(tokens))
        signals.append({"id": "suspicious_lifecycle_name", "points": min(35, 10 * len(tokens)), "tokens": tokens})
    if summary.get("has_bin") and lifecycle:
        score += 15
        signals.append({"id": "binary_with_lifecycle", "points": 15})
    previous_author = str((previous or {}).get("author") or "")
    if previous and previous_author and summary.get("author") and summary.get("author") != previous_author:
        score += 25
        signals.append({"id": "publisher_changed", "points": 25})
    previous_dependencies = set((previous or {}).get("dependencies") or [])
    dependency_delta = sorted(set(summary.get("dependencies") or []) - previous_dependencies)
    if dependency_delta:
        points = min(20, 5 + len(dependency_delta))
        score += points
        signals.append({"id": "new_dependencies", "points": points, "count": len(dependency_delta)})
    if baseline_only:
        signals.append({"id": "first_observed_version", "points": 0})
    return min(100, score), signals


def _artifact_score(analysis: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    """Convert bounded static indicators into a conservative triage score."""
    weights = {
        "credential-access": 40,
        "browser-payment-access": 40,
        "persistence": 35,
        "process-execution": 20,
        "dynamic-eval": 20,
        "encoded-payload": 20,
        "install-hook": 15,
        "network-endpoint": 5,
    }
    indicators = analysis.get("indicators") if isinstance(analysis.get("indicators"), list) else []
    signals: List[Dict[str, Any]] = []
    seen: set[str] = set()
    score = 0
    for indicator in indicators:
        if not isinstance(indicator, dict):
            continue
        indicator_id = str(indicator.get("indicator_id") or "")
        if not indicator_id or indicator_id in seen:
            continue
        seen.add(indicator_id)
        points = weights.get(indicator_id, 0)
        if points:
            score += points
            signals.append({"id": f"artifact_{indicator_id}", "points": points, "indicator_id": indicator_id})
    return min(100, score), signals


def _analysis_evidence(intake: Dict[str, Any]) -> Dict[str, Any]:
    metadata = intake.get("metadata") if isinstance(intake.get("metadata"), dict) else {}
    analysis = intake.get("analysis") if isinstance(intake.get("analysis"), dict) else {}
    return {
        "artifact_sha256": metadata.get("artifact_sha256"),
        "artifact_bytes": metadata.get("artifact_bytes"),
        "artifact_url_final": metadata.get("artifact_url_final"),
        "filename": analysis.get("filename"),
        "archive_type": analysis.get("archive_type"),
        "member_count": analysis.get("member_count"),
        "expanded_bytes": analysis.get("expanded_bytes"),
        "text_files_inspected": analysis.get("text_files_inspected"),
        "lifecycle_script_names": sorted((analysis.get("lifecycle_scripts") or {}).keys()) if isinstance(analysis.get("lifecycle_scripts"), dict) else [],
        "manifest_summary": analysis.get("manifest_summary") or {},
        "indicators": analysis.get("indicators") or [],
        "execution_performed": bool(analysis.get("execution_performed")),
        "extracted_to_filesystem": bool(analysis.get("extracted_to_filesystem")),
    }


def _store_analysis(
    *,
    db_path: Optional[str],
    event: Dict[str, Any],
    score: int,
    signals: List[Dict[str, Any]],
    intake: Optional[Dict[str, Any]],
    error: str = "",
) -> Dict[str, Any]:
    package = str(event.get("package") or "")
    version = str(event.get("version") or "")
    evidence = _analysis_evidence(intake or {}) if intake else {}
    if intake:
        artifact_score, artifact_signals = _artifact_score(
            intake.get("analysis") if isinstance(intake.get("analysis"), dict) else {}
        )
        if artifact_signals:
            score = max(score, artifact_score)
            signals = [*signals, *artifact_signals]
    artifact_sha256 = str(evidence.get("artifact_sha256") or "")
    status = "completed" if intake else "failed"
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            connection.execute(
                """INSERT INTO research_npm_release_analyses
               (analysis_id, source_event_id, package, version, artifact_sha256,
                status, score, indicators_json, intake_json, error_message, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(package, version, artifact_sha256) DO UPDATE SET
                 status=excluded.status, score=excluded.score,
                 indicators_json=excluded.indicators_json, intake_json=excluded.intake_json,
                 error_message=excluded.error_message, updated_at=excluded.updated_at""",
            (
                _id("NAN"),
                event.get("feed_event_id"),
                package,
                version,
                artifact_sha256,
                status,
                int(score),
                _json(signals),
                _json(evidence),
                str(error)[:2000],
                now,
                now,
            ),
            )
            event_metadata = _event_metadata(event)
            static_attempts = int(event_metadata.get("npm_static_attempts") or 0) + 1
            event_metadata.update({
                "npm_static_analysis": evidence,
                "npm_signals": signals,
                "npm_analysis_status": status,
                "npm_static_attempts": static_attempts,
                "npm_static_last_attempt": now,
                "npm_static_error": str(error)[:1000],
            })
            processing_state = "candidate" if score >= 40 else "analyzed"
            if not intake:
                processing_state = "analysis_failed"
            connection.execute(
                "UPDATE registry_feed_events SET processing_state = ?, metadata_json = ? WHERE feed_event_id = ?",
                (processing_state, _json(event_metadata), event.get("feed_event_id")),
            )
    return {"status": status, "score": score, "signals": signals, "evidence": evidence, "error": error}


def _promote_static_candidate(*, db_path: Optional[str], event: Dict[str, Any], result: Dict[str, Any]) -> Optional[str]:
    if int(result.get("score") or 0) < 40:
        return None
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "source": "npm_registry_proactive_static",
        "source_event_id": event.get("feed_event_id"),
        "metadata_url": _event_metadata(event).get("metadata_url") or event.get("page_url"),
        "artifact_url": _event_metadata(event).get("artifact_url") or event.get("leaf_url"),
        "ecosystem": "npm",
        "package": event.get("package"),
        "version": event.get("version"),
        "previous_version": _event_metadata(event).get("previous_version") or "",
        "score": int(result.get("score") or 0),
        "signals": result.get("signals") or [],
        "analysis": result.get("evidence") or {},
        "validation_state": "static_confirmed" if result.get("status") == "completed" else "unverified",
        "local_exposure_required": False,
        "execution_performed": False,
        "raw_artifact_sent_to_ai": False,
    }
    candidate_id = "CAN-" + hashlib.sha256(
        f"npm-proactive|{event.get('package')}|{event.get('version')}|{evidence.get('analysis', {}).get('artifact_sha256') or event.get('feed_event_id')}".encode()
    ).hexdigest()[:24].upper()
    reason = (
        f"New npm release {event.get('package')}@{event.get('version')} triggered explainable static-risk signals. "
        "SecOpsAI collected the exact artifact without executing it; this is a proactive lead, not a maliciousness verdict."
    )
    score = max(40, min(99, int(result.get("score") or 0) + (25 if result.get("status") == "completed" else 0)))
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            connection.execute(
                """INSERT INTO research_candidates
               (candidate_id, event_id, watchlist_id, ecosystem, package, version,
                reference_identifier, score, score_components_json, reason, status,
                case_id, evidence_json, first_seen, last_seen, algorithm_version)
               VALUES (?, NULL, NULL, 'npm', ?, ?, 'npm-proactive-static.v1', ?, ?, ?, 'new', NULL, ?, ?, ?, ?)
               ON CONFLICT(ecosystem, package, version, reference_identifier)
               DO UPDATE SET score=excluded.score, score_components_json=excluded.score_components_json,
                 reason=excluded.reason, evidence_json=excluded.evidence_json, last_seen=excluded.last_seen""",
            (
                candidate_id,
                event.get("package"),
                event.get("version"),
                score,
                _json({"signals": result.get("signals") or [], "proactive": True, "analysis_status": result.get("status")}),
                reason,
                _json(evidence),
                event.get("registry_timestamp") or _now(),
                _now(),
                "npm-proactive-static.v1",
            ),
            )
            candidate = connection.execute(
                "SELECT * FROM research_candidates WHERE ecosystem='npm' AND package=? AND version=? AND reference_identifier='npm-proactive-static.v1'",
                (event.get("package"), event.get("version")),
            ).fetchone()
    if not candidate:
        return None
    payload = dict(candidate)
    payload["campaign_id"] = ""
    payload["evidence"] = evidence
    payload["score_components"] = result.get("signals") or []
    severity = "critical" if score >= 90 else "high" if score >= 70 else "medium"
    alert = create_candidate_alert(
        payload,
        db_path=db_path,
        alert_type="npm_proactive_anomaly",
        severity_override=severity,
        dedupe_key=f"npm-proactive:{event.get('package')}:{event.get('version')}:{evidence.get('analysis', {}).get('artifact_sha256') or event.get('feed_event_id')}",
        reason_override=reason,
    )
    return str(alert.get("alert_id") or "")


def _enrich_package(
    *,
    package: str,
    rows: List[Dict[str, Any]],
    db_path: Optional[str],
    fetcher: SafeFetcher,
) -> Dict[str, Any]:
    now = _now()
    final_url, payload, source_hash = _fetch_packument(package, fetcher)
    current_versions, latest = _packument_summary(payload)
    if not current_versions:
        raise IntakeError("npm packument contained no versions")
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            prior_row = connection.execute(
                "SELECT * FROM research_npm_package_snapshots WHERE package=?", (package,)
            ).fetchone()
            prior = dict(prior_row) if prior_row else None
            previous_versions = _decode((prior or {}).get("versions_json"), {})
            if not isinstance(previous_versions, dict):
                previous_versions = {}
            new_versions = _new_versions(current_versions, prior=prior, prior_versions=previous_versions, latest=latest)
            baseline_only = not prior
            previous_version = str((prior or {}).get("latest_version") or "")
            for row in rows:
                metadata = _event_metadata(row)
                metadata.update({
                    "npm_enrichment_status": "completed",
                    "npm_enrichment_last_attempt": now,
                    "npm_enrichment_attempts": int(metadata.get("npm_enrichment_attempts") or 0) + 1,
                    "npm_exact_versions": new_versions[:100],
                    "npm_packument_sha256": source_hash,
                    "npm_metadata_url": final_url,
                })
                connection.execute(
                    "UPDATE registry_feed_events SET processing_state='enriched', metadata_json=? WHERE feed_event_id=?",
                    (_json(metadata), row["feed_event_id"]),
                )
            compact_versions = _compact_snapshot_versions(current_versions)
            published_times = [_summary_time(summary) for summary in current_versions.values()]
            published_times = [item for item in published_times if item is not None]
            last_published_at = max(published_times).isoformat().replace("+00:00", "Z") if published_times else ""
            connection.execute(
                """INSERT INTO research_npm_package_snapshots
                   (package, source_url, metadata_sha256, versions_json, known_versions_json,
                    latest_version, last_published_at, last_event_seq, status, last_error, first_seen, last_seen, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'baseline', NULL, ?, ?, ?)
                   ON CONFLICT(package) DO UPDATE SET source_url=excluded.source_url,
                    metadata_sha256=excluded.metadata_sha256, versions_json=excluded.versions_json,
                    known_versions_json=excluded.known_versions_json, latest_version=excluded.latest_version,
                    last_published_at=excluded.last_published_at, last_event_seq=excluded.last_event_seq,
                    status='baseline', last_error=NULL, last_seen=excluded.last_seen, updated_at=excluded.updated_at""",
                (
                    package,
                    final_url,
                    source_hash,
                    _json(compact_versions),
                    _json(_known_version_names(current_versions)),
                    latest,
                    last_published_at,
                    str((_event_metadata(rows[-1]).get("seq") or "")),
                    now,
                    now,
                    now,
                ),
            )
            created = 0
            for version in new_versions[:MAX_PACKUMENT_VERSIONS]:
                summary = current_versions[version]
                created += int(_insert_exact_event(
                    connection,
                    parent=rows[-1],
                    package=package,
                    version=version,
                    summary=summary,
                    metadata_url=final_url,
                    previous_version=previous_version,
                    baseline_only=baseline_only,
                ))
    return {"package": package, "versions_created": created, "versions": new_versions, "baseline_only": baseline_only}


def _static_retry_allowed(metadata: Dict[str, Any]) -> bool:
    last = _parse_time(metadata.get("npm_static_last_attempt"))
    if last is None:
        return True
    return datetime.now(timezone.utc) - last >= timedelta(seconds=MAX_RETRY_SECONDS)


def _run_static_triage(*, db_path: Optional[str], fetcher: SafeFetcher, limit: int) -> Dict[str, Any]:
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT * FROM registry_feed_events
               WHERE ecosystem='npm' AND processing_state IN ('pending', 'analysis_failed') AND version <> ''
               ORDER BY registry_timestamp ASC LIMIT ?""",
            (max(1, min(int(limit), MAX_STATIC_ANALYSES_PER_CYCLE * 4)),),
        ).fetchall()
    analyses = 0
    candidates = 0
    failures = 0
    for row in rows:
        event = dict(row)
        metadata = _event_metadata(event)
        if not _static_retry_allowed(metadata):
            continue
        summary = metadata.get("version_summary") if isinstance(metadata.get("version_summary"), dict) else {}
        previous = None
        with closing(soc_store.connect(db_path)) as connection:
            prior = connection.execute(
                "SELECT versions_json FROM research_npm_package_snapshots WHERE package=?", (event.get("package"),)
            ).fetchone()
        # Snapshot contains the current version after enrichment.  The event's
        # explicit previous_version is therefore used only when it exists in
        # the compact event metadata.
        previous_version = str(metadata.get("previous_version") or "")
        if previous_version:
            with closing(soc_store.connect(db_path)) as connection:
                snap = connection.execute(
                    "SELECT versions_json FROM research_npm_package_snapshots WHERE package=?", (event.get("package"),)
                ).fetchone()
            versions = _decode(snap["versions_json"], {}) if snap else {}
            previous = versions.get(previous_version) if isinstance(versions, dict) else None
        score, signals = _suspicion_score(
            summary,
            previous=previous,
            baseline_only=bool(metadata.get("baseline_only")),
        )
        if analyses >= max(1, min(int(limit), MAX_STATIC_ANALYSES_PER_CYCLE)):
            break
        analyses += 1
        intake: Optional[Dict[str, Any]] = None
        error = ""
        try:
            intake = collect_package_intake(
                ecosystem="npm",
                package=str(event.get("package") or ""),
                version=str(event.get("version") or ""),
                fetcher=fetcher,
            )
        except Exception as exc:
            error = str(exc)[:2000]
            failures += 1
        result = _store_analysis(
            db_path=db_path,
            event=event,
            score=score,
            signals=signals,
            intake=intake,
            error=error,
        )
        alert_id = _promote_static_candidate(db_path=db_path, event=event, result=result)
        candidates += int(bool(alert_id))
    return {"events_considered": len(rows), "analyses_started": analyses, "candidates_created": candidates, "failures": failures}


def run_npm_enrichment_cycle(
    *,
    db_path: Optional[str] = None,
    fetcher: Optional[SafeFetcher] = None,
    event_limit: Optional[int] = None,
    static_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Resolve npm package events and inspect explainably suspicious releases."""
    soc_store.init_db(db_path)
    configured_event_limit = event_limit if event_limit is not None else os.environ.get("SECOPSAI_NPM_ENRICHMENT_EVENT_LIMIT", MAX_PACKAGE_EVENTS_PER_CYCLE)
    configured_static_limit = static_limit if static_limit is not None else os.environ.get("SECOPSAI_NPM_STATIC_ANALYSIS_LIMIT", MAX_STATIC_ANALYSES_PER_CYCLE)
    event_limit = _bounded_limit(configured_event_limit, MAX_PACKAGE_EVENTS_PER_CYCLE, MAX_PACKAGE_EVENTS_PER_CYCLE)
    static_limit = _bounded_limit(configured_static_limit, MAX_STATIC_ANALYSES_PER_CYCLE, MAX_STATIC_ANALYSES_PER_CYCLE)
    fetcher = fetcher or SafeFetcher()
    run_id = _id("NEN")
    started = _now()
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            connection.execute(
                "INSERT INTO research_npm_enrichment_runs (run_id, status, started_at) VALUES (?, 'running', ?)",
                (run_id, started),
            )
        rows = connection.execute(
            """SELECT * FROM registry_feed_events
               WHERE ecosystem='npm' AND processing_state IN ('pending', 'enrichment_failed')
               ORDER BY registry_timestamp ASC LIMIT ?""",
            (max(1, min(int(event_limit), MAX_PACKAGE_EVENTS_PER_CYCLE * 4)),),
        ).fetchall()
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    skipped = 0
    for raw in rows:
        row = dict(raw)
        metadata = _event_metadata(row)
        if row.get("version"):
            continue
        if str(row.get("event_type") or "") == "deleted":
            metadata.update({"npm_enrichment_status": "not_applicable", "npm_enrichment_reason": "registry_deleted_event"})
            with closing(soc_store.connect(db_path)) as connection:
                with _write_transaction(connection, db_path):
                    connection.execute("UPDATE registry_feed_events SET processing_state='enriched', metadata_json=? WHERE feed_event_id=?", (_json(metadata), row["feed_event_id"]))
            continue
        if not _retry_allowed(metadata):
            skipped += 1
            continue
        package = _valid_package(row.get("package"))
        if package:
            grouped.setdefault(package, []).append(row)
    packages_fetched = 0
    versions_created = 0
    failures = 0
    for package, package_rows in list(grouped.items())[:max(1, min(int(event_limit), MAX_PACKAGE_EVENTS_PER_CYCLE))]:
        try:
            result = _enrich_package(package=package, rows=package_rows, db_path=db_path, fetcher=fetcher)
            packages_fetched += 1
            versions_created += int(result.get("versions_created") or 0)
        except Exception as exc:
            failures += 1
            now = _now()
            with closing(soc_store.connect(db_path)) as connection:
                with _write_transaction(connection, db_path):
                    for row in package_rows:
                        metadata = _event_metadata(row)
                        attempts = int(metadata.get("npm_enrichment_attempts") or 0) + 1
                        metadata.update({
                            "npm_enrichment_status": "failed",
                            "npm_enrichment_last_attempt": now,
                            "npm_enrichment_attempts": attempts,
                            "npm_enrichment_error": str(exc)[:1000],
                        })
                        connection.execute(
                            "UPDATE registry_feed_events SET processing_state='enrichment_failed', metadata_json=? WHERE feed_event_id=?",
                            (_json(metadata), row["feed_event_id"]),
                        )
    static_result = _run_static_triage(db_path=db_path, fetcher=fetcher, limit=static_limit)
    completed = _now()
    total_failures = failures + int(static_result.get("failures", 0))
    status = "degraded" if total_failures else "completed"
    with closing(soc_store.connect(db_path)) as connection:
        with _write_transaction(connection, db_path):
            connection.execute(
                """UPDATE research_npm_enrichment_runs
               SET status=?, events_seen=?, packages_fetched=?, versions_created=?,
                   analyses_started=?, candidates_created=?, failures=?, completed_at=?
               WHERE run_id=?""",
            (
                status,
                len(rows),
                packages_fetched,
                versions_created,
                static_result.get("analyses_started", 0),
                static_result.get("candidates_created", 0),
                total_failures,
                completed,
                run_id,
            ),
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "status": status,
        "events_seen": len(rows),
        "packages_fetched": packages_fetched,
        "versions_created": versions_created,
        "skipped_backoff": skipped,
        "static": static_result,
        "failures": total_failures,
        "enrichment_failures": failures,
        "analysis_failures": int(static_result.get("failures", 0)),
        "started_at": started,
        "completed_at": completed,
    }
