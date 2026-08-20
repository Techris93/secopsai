"""Deterministic, auditable registry discovery primitives.

This module deliberately starts with watchlist-scoped monitoring.  Registry
adapters advertise their coverage mode instead of implying that a registry is
globally clean when only a scoped query was performed.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import unicodedata
from contextlib import closing
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional

import soc_store
from secopsai.research_intake import ADAPTERS, RegistryMetadata, SafeFetcher
from secopsai.sqlite_writer_lock import sqlite_writer_lock


SCHEMA_VERSION = "secopsai.research.discovery.v1"
ALGORITHM_VERSION = "similarity-1"
WATCH_TYPES = {"package", "namespace", "publisher", "brand", "repository", "organization"}
PRIORITIES = {"low", "normal", "high", "critical"}
STATUSES = {"active", "paused", "archived", "new", "review", "dismissed", "promoted"}
PROMOTION_MODES = {"review_only", "draft_case"}
RESEARCH_ALERT_FINDING_SOURCE = "secopsai_research"
OPERATIONAL_ALERT_TYPES = {"collector_degraded", "collector_retention_risk"}


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, ValueError):
        return fallback


def _has_artifact_evidence(evidence: Any) -> bool:
    payload = evidence if isinstance(evidence, dict) else {}
    return bool(
        payload.get("artifact_sha256")
        or payload.get("artifact_url")
        or payload.get("analysis")
        or payload.get("static_analysis")
        or payload.get("sandbox_analysis")
    )


def _external_lead_severity(score: float) -> str:
    return "high" if score >= 85 else "medium" if score >= 60 else "low"


def normalize_identifier(ecosystem: str, value: str) -> str:
    """Normalize names without erasing ecosystem-specific identity."""
    ecosystem = str(ecosystem or "").strip().lower()
    raw = unicodedata.normalize("NFKC", str(value or "").strip()).lower()
    raw = raw.replace("\u2010", "-").replace("\u2011", "-").replace("\u2012", "-")
    if ecosystem == "pypi":
        raw = re.sub(r"[-_.]+", "-", raw)
    elif ecosystem == "maven":
        raw = raw.replace("/", ":")
    elif ecosystem == "go":
        raw = raw.rstrip("/")
    return raw


def _skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).casefold()


def _damerau(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    matrix = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        matrix[i][0] = i
    for j in range(len(b) + 1):
        matrix[0][j] = j
    for i, left in enumerate(a, 1):
        for j, right in enumerate(b, 1):
            cost = 0 if left == right else 1
            matrix[i][j] = min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and left == b[j - 2] and a[i - 2] == right:
                matrix[i][j] = min(matrix[i][j], matrix[i - 2][j - 2] + cost)
    return matrix[-1][-1]


def similarity_score(
    candidate: str,
    reference: str,
    *,
    candidate_publisher: str = "",
    reference_publisher: str = "",
    candidate_repository: str = "",
    reference_repository: str = "",
) -> Dict[str, Any]:
    """Return an explainable score; this is not a maliciousness verdict."""
    left = _skeleton(normalize_identifier("", candidate))
    right = _skeleton(normalize_identifier("", reference))
    distance = _damerau(left, right)
    max_len = max(len(left), len(right), 1)
    edit_similarity = round(1 - (distance / max_len), 4)
    sequence_similarity = round(SequenceMatcher(None, left, right).ratio(), 4)
    exact_tokens = set(re.findall(r"[a-z0-9]+", left)) & set(re.findall(r"[a-z0-9]+", right))
    token_overlap = round(min(len(exact_tokens), 3) / max(len(set(re.findall(r"[a-z0-9]+", right))), 1), 4)
    publisher_match = bool(candidate_publisher and reference_publisher and _skeleton(candidate_publisher) == _skeleton(reference_publisher))
    repository_match = bool(candidate_repository and reference_repository and _skeleton(candidate_repository) == _skeleton(reference_repository))
    score = min(100.0, round((edit_similarity * 55) + (sequence_similarity * 25) + (token_overlap * 10) + (publisher_match * 7) + (repository_match * 3), 2))
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "score": score,
        "components": {
            "damerau_distance": distance,
            "edit_similarity": edit_similarity,
            "sequence_similarity": sequence_similarity,
            "token_overlap": token_overlap,
            "publisher_match": publisher_match,
            "repository_match": repository_match,
        },
        "reason": "name similarity requires analyst review; it does not prove maliciousness",
    }


CAPABILITIES: Dict[str, Dict[str, Any]] = {
    ecosystem: {
        "ecosystem": ecosystem,
        "display_name": display,
        "metadata_discovery": True,
        "version_history": True,
        "artifact_download": True,
        "static_inspection": True,
        "deep_analysis": deep,
        "comparison": True,
        "monitoring_mode": mode,
        "coverage_limitations": limitations,
        "terms_url": terms,
    }
    for ecosystem, display, deep, mode, limitations, terms in (
        ("npm", "npm", False, "changes_feed_or_watchlist", ["The replica changes feed has no per-event timestamps; ledger times are collection times."], "https://docs.npmjs.com/"),
        ("crates", "crates.io", False, "metadata_watchlist", ["Global publish-time monitoring is bounded; exact crate collection and checksum verification use the Rust Package Research workflow."], "https://crates.io/"),
        ("pypi", "PyPI", False, "index_reconcile_or_watchlist", ["Index reconciliation detects project additions and removals; per-release detection requires watchlist polling or backfill."], "https://docs.pypi.org/"),
        ("nuget", "NuGet", True, "catalog_or_watchlist", ["Catalog coverage and rate limits must be reported per run."], "https://learn.microsoft.com/en-us/nuget/api/overview"),
        ("maven", "Maven Central", False, "search_tail_or_watchlist", ["The Solr index can lag the live repository by days to weeks; coverage is search-derived, never a census."], "https://central.sonatype.org/"),
        ("rubygems", "RubyGems.org", False, "timeframe_feed_or_watchlist", ["Timeframe polling covers recent versions within its page budget; compact-index census reconciliation is a later checkpoint."], "https://guides.rubygems.org/rubygems-org-api/"),
        ("packagist", "Packagist", False, "changes_feed_or_watchlist", ["The metadata change log has bounded retention; stale cursors can miss events and raise coverage alerts."], "https://packagist.org/apidoc"),
        ("go", "Go Modules", False, "module_index_or_watchlist", ["The module index records new versions only; retractions and deletions are not index events."], "https://go.dev/ref/mod"),
        ("open-vsx", "Open VSX", False, "search_reconcile_or_watchlist", ["Public search caps offsets at 10000; letter-partitioned enumeration is a best-effort census, not a publish-time feed."], "https://open-vsx.org/"),
    )
}


def capability_registry() -> Dict[str, Any]:
    return {"schema_version": "secopsai.research.ecosystem-capabilities.v1", "ecosystems": list(CAPABILITIES.values())}


def seed_registry_sources(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    now = _now()
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            for ecosystem, item in CAPABILITIES.items():
                source_id = f"REG-{ecosystem.upper().replace('-', '_')}"
                connection.execute(
                    """INSERT INTO research_registry_sources
                    (source_id, ecosystem, name, base_url, capabilities_json, coverage_mode, terms_url, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(ecosystem, name) DO UPDATE SET capabilities_json=excluded.capabilities_json,
                    coverage_mode=excluded.coverage_mode, terms_url=excluded.terms_url, updated_at=excluded.updated_at""",
                    (source_id, ecosystem, item["display_name"], item["terms_url"], _json(item), item["monitoring_mode"], item["terms_url"], now, now),
                )
            connection.commit()
            rows = connection.execute("SELECT * FROM research_registry_sources ORDER BY ecosystem").fetchall()
    return [dict(row) | {"capabilities": _decode(row["capabilities_json"], {})} for row in rows]


def create_watchlist(*, ecosystem: str, watch_type: str, identifier: str, brand: str = "", known_publishers: Iterable[str] = (), known_repositories: Iterable[str] = (), known_namespaces: Iterable[str] = (), threshold: float = 70.0, exclusions: Iterable[str] = (), priority: str = "normal", owner: str = "", expires_at: Optional[str] = None, reason: str = "", source_evidence: Iterable[str] = (), db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    ecosystem = normalize_identifier("", ecosystem)
    if ecosystem not in CAPABILITIES:
        raise ValueError(f"unsupported discovery ecosystem: {ecosystem}")
    if watch_type not in WATCH_TYPES:
        raise ValueError("unsupported watchlist type")
    if priority not in PRIORITIES:
        raise ValueError("unsupported watchlist priority")
    identifier = str(identifier or "").strip()
    if not identifier or len(identifier) > 512:
        raise ValueError("watchlist identifier is required")
    if not 0 <= float(threshold) <= 100:
        raise ValueError("threshold must be between 0 and 100")
    now = _now()
    watchlist_id = _id("WL")
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute(
                """INSERT INTO research_watchlists
                (watchlist_id, ecosystem, watch_type, identifier, normalized_identifier, brand,
                 known_publishers_json, known_repositories_json, known_namespaces_json, threshold,
                 exclusions_json, priority, owner, expires_at, reason, source_evidence_json, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)""",
                (watchlist_id, ecosystem, watch_type, identifier, normalize_identifier(ecosystem, identifier), brand[:240],
                 _json(list(known_publishers)), _json(list(known_repositories)), _json(list(known_namespaces)), float(threshold),
                 _json(list(exclusions)), priority, owner[:160], expires_at, reason[:2000], _json(list(source_evidence)), now, now),
            )
            connection.commit()
    return get_watchlist(watchlist_id, db_path=db_path)


def get_watchlist(watchlist_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_watchlists WHERE watchlist_id = ?", (watchlist_id,)).fetchone()
    if row is None:
        raise ValueError("watchlist not found")
    item = dict(row)
    for field in ("known_publishers_json", "known_repositories_json", "known_namespaces_json", "exclusions_json", "source_evidence_json"):
        item[field.removesuffix("_json")] = _decode(item.pop(field), [])
    return item


def list_watchlists(*, ecosystem: Optional[str] = None, status: str = "active", db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        if ecosystem:
            rows = connection.execute("SELECT * FROM research_watchlists WHERE status = ? AND ecosystem = ? ORDER BY priority DESC, updated_at DESC", (status, ecosystem)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM research_watchlists WHERE status = ? ORDER BY priority DESC, updated_at DESC", (status,)).fetchall()
    return [get_watchlist(row["watchlist_id"], db_path=db_path) for row in rows]


def create_monitor(*, ecosystem: str, watchlist_id: Optional[str] = None, name: str = "", interval_seconds: int = 3600, priority: str = "normal", db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    ecosystem = normalize_identifier("", ecosystem)
    if ecosystem not in CAPABILITIES:
        raise ValueError(f"unsupported discovery ecosystem: {ecosystem}")
    if interval_seconds < 900:
        raise ValueError("monitor interval must be at least 900 seconds")
    sources = seed_registry_sources(db_path=db_path)
    source = next(item for item in sources if item["ecosystem"] == ecosystem)
    if watchlist_id:
        get_watchlist(watchlist_id, db_path=db_path)
    now = datetime.now(timezone.utc)
    monitor_id = _id("MON")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_monitors
            (monitor_id, source_id, watchlist_id, ecosystem, name, interval_seconds, priority, coverage_mode,
             enabled, next_run_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
            (monitor_id, source["source_id"], watchlist_id, ecosystem, (name or f"{source['name']} monitor")[:160], int(interval_seconds), priority, source["coverage_mode"], (now).isoformat().replace("+00:00", "Z"), now.isoformat().replace("+00:00", "Z"), now.isoformat().replace("+00:00", "Z")),
        )
        connection.execute("INSERT INTO research_monitor_cursors (monitor_id, cursor_json, rate_limit_json, coverage_json, updated_at) VALUES (?, '{}', '{}', '{}', ?)", (monitor_id, now.isoformat().replace("+00:00", "Z")))
        connection.commit()
    return get_monitor(monitor_id, db_path=db_path)


def get_monitor(monitor_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_monitors WHERE monitor_id = ?", (monitor_id,)).fetchone()
        cursor = connection.execute("SELECT * FROM research_monitor_cursors WHERE monitor_id = ?", (monitor_id,)).fetchone()
    if row is None:
        raise ValueError("monitor not found")
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["cursor"] = _decode(cursor["cursor_json"], {}) if cursor else {}
    item["coverage"] = _decode(cursor["coverage_json"], {}) if cursor else {}
    return item


def list_monitors(*, ecosystem: Optional[str] = None, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT monitor_id FROM research_monitors WHERE (? IS NULL OR ecosystem = ?) ORDER BY enabled DESC, next_run_at", (ecosystem, ecosystem)).fetchall()
    return [get_monitor(row["monitor_id"], db_path=db_path) for row in rows]


def _candidate_reason(score: Dict[str, Any]) -> str:
    components = score["components"]
    return f"similarity={score['score']}; Damerau distance={components['damerau_distance']}; publisher_match={components['publisher_match']}"


def _record_registry_event(*, metadata: RegistryMetadata, source_id: str, coverage_mode: str, db_path: Optional[str]) -> Dict[str, Any]:
    """Persist one normalized registry observation without classifying it."""
    now = _now()
    event_key = hashlib.sha256(f"{source_id}|{metadata.ecosystem}|{metadata.package}|{metadata.version}|{metadata.artifact_url}".encode()).hexdigest()
    event_id = _id("REV")
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            prior = connection.execute(
                "SELECT event_id, version, observed_at FROM research_registry_events WHERE source_id = ? AND ecosystem = ? AND package = ? ORDER BY observed_at DESC LIMIT 1",
                (source_id, metadata.ecosystem, metadata.package),
            ).fetchone()
            cursor = connection.execute(
            """INSERT INTO research_registry_events
            (event_id, source_id, ecosystem, package, version, publisher, source_url, artifact_url, artifact_sha256, observed_at, provenance_json, idempotency_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?)
            ON CONFLICT(idempotency_key) DO NOTHING""",
            (event_id, source_id, metadata.ecosystem, metadata.package, metadata.version, metadata.publisher[:240], metadata.metadata_url, metadata.artifact_url, now, _json({"schema_version": "secopsai.research.registry-event.v1", "source": source_id, "coverage_mode": coverage_mode}), event_key),
            )
            created = cursor.rowcount == 1
            row = connection.execute("SELECT event_id, observed_at FROM research_registry_events WHERE idempotency_key = ?", (event_key,)).fetchone()
            connection.commit()
    return {
        "event_id": row["event_id"],
        "observed_at": row["observed_at"],
        "created": created,
        "previous_version": prior["version"] if prior else None,
    }


def _record_watchlist_observation(*, monitor: Dict[str, Any], watchlist: Dict[str, Any], metadata: RegistryMetadata, db_path: Optional[str]) -> Dict[str, Any]:
    """Record an exact watched package as a baseline, never as a typosquat."""
    event = _record_registry_event(metadata=metadata, source_id=monitor["source_id"], coverage_mode=monitor["coverage_mode"], db_path=db_path)
    changed = bool(event["created"] and event["previous_version"] and event["previous_version"] != metadata.version)
    alert_id = None
    if changed:
        now = _now()
        alert_id = _id("RAL")
        dedupe_key = f"watched-version:{monitor['monitor_id']}:{metadata.package}:{metadata.version}"
        with sqlite_writer_lock(db_path):
            with closing(soc_store.connect(db_path)) as connection:
                connection.execute(
                """INSERT INTO research_alerts
                (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
                VALUES (?, 'watched_package_version', 'info', NULL, NULL, NULL, ?, ?, ?, 'open', ?, ?, ?)
                ON CONFLICT(dedupe_key) DO NOTHING""",
                (alert_id, dedupe_key, f"Watched package {metadata.package} changed from {event['previous_version']} to {metadata.version}", _json({"event_id": event["event_id"], "ecosystem": metadata.ecosystem, "package": metadata.package, "previous_version": event["previous_version"], "version": metadata.version, "watchlist_id": watchlist["watchlist_id"]}), watchlist.get("owner", ""), now, now),
                )
                stored = connection.execute("SELECT alert_id FROM research_alerts WHERE dedupe_key = ?", (dedupe_key,)).fetchone()
                connection.commit()
        alert_id = stored["alert_id"] if stored else None
    return {
        "schema_version": "secopsai.research.registry-event.v1",
        "event_id": event["event_id"],
        "ecosystem": metadata.ecosystem,
        "package": metadata.package,
        "version": metadata.version,
        "previous_version": event["previous_version"],
        "baseline_created": bool(event["created"] and not event["previous_version"]),
        "version_changed": changed,
        "alert_id": alert_id,
        "coverage": {"mode": monitor["coverage_mode"], "complete": False, "scope": "exact_package_version"},
    }


def _watch_value(watchlist: Dict[str, Any], metadata: RegistryMetadata) -> str:
    """Choose the normalized field appropriate to the watchlist type."""
    watch_type = watchlist.get("watch_type")
    raw = metadata.raw if isinstance(metadata.raw, dict) else {}
    if watch_type == "publisher":
        return metadata.publisher
    if watch_type == "repository":
        repository = raw.get("repository") or raw.get("repository_url") or raw.get("project_url") or ""
        if isinstance(repository, dict):
            repository = repository.get("url") or repository.get("directory") or ""
        return str(repository)
    if watch_type == "namespace":
        return metadata.package.split(":", 1)[0].split("/", 1)[0].split(".", 1)[0]
    if watch_type in {"brand", "organization"}:
        return " ".join(item for item in (metadata.package, metadata.publisher) if item)
    return metadata.package


def _record_candidate(*, monitor: Dict[str, Any], watchlist: Dict[str, Any], metadata: RegistryMetadata, source_id: str, db_path: Optional[str]) -> Dict[str, Any]:
    observed_value = _watch_value(watchlist, metadata)
    score = similarity_score(observed_value, watchlist["identifier"], candidate_publisher=metadata.publisher, reference_publisher=(watchlist.get("known_publishers") or [""])[0] if watchlist.get("known_publishers") else "")
    threshold = float(watchlist["threshold"])
    now = _now()
    event = _record_registry_event(metadata=metadata, source_id=source_id, coverage_mode=monitor["coverage_mode"], db_path=db_path)
    event_id = event["event_id"]
    normalized_package = normalize_identifier(metadata.ecosystem, metadata.package)
    normalized_reference = normalize_identifier(metadata.ecosystem, watchlist["identifier"])
    exclusions = {normalize_identifier(metadata.ecosystem, item) for item in watchlist.get("exclusions", [])}
    known_publishers = {normalize_identifier("", item) for item in watchlist.get("known_publishers", []) if item}
    # Missing publisher evidence is not evidence of mismatch: feeds that do
    # not carry publisher data must not flag the legitimate exact-name
    # package as an impersonator.
    publisher_mismatch = bool(known_publishers and metadata.publisher and normalize_identifier("", metadata.publisher) not in known_publishers)
    if normalized_package in exclusions or (normalized_package == normalized_reference and not publisher_mismatch):
        return {"matched": False, "score": score, "event_id": event_id, "suppressed": "approved_exact_name_or_exclusion"}
    candidate_id = _id("CAN")
    # Exact-name observation from an unexpected publisher is an
    # impersonation signal in its own right; the name-similarity gate
    # must not suppress it when brand observation dilutes the score.
    exact_name_publisher_mismatch = normalized_package == normalized_reference and publisher_mismatch
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            if score["score"] >= threshold or exact_name_publisher_mismatch:
                reason = _candidate_reason(score)
                if exact_name_publisher_mismatch and score["score"] < threshold:
                    reason = "exact package name observed with an unexpected publisher; verify ownership before trusting this release"
                connection.execute(
                """INSERT INTO research_candidates
                (candidate_id, event_id, watchlist_id, ecosystem, package, version, reference_identifier, score, score_components_json, reason, status, case_id, evidence_json, first_seen, last_seen, algorithm_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', NULL, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, package, version, reference_identifier) DO UPDATE SET score=excluded.score,
                score_components_json=excluded.score_components_json, reason=excluded.reason, last_seen=excluded.last_seen""",
                (candidate_id, event_id, watchlist["watchlist_id"], metadata.ecosystem, metadata.package, metadata.version, watchlist["identifier"], score["score"], _json(score["components"]), reason, _json({"metadata_url": metadata.metadata_url, "artifact_url": metadata.artifact_url, "publisher": metadata.publisher, "observed_value": observed_value, "watch_type": watchlist.get("watch_type")}), now, now, score["algorithm_version"]),
                )
            connection.commit()
            row = connection.execute("SELECT * FROM research_candidates WHERE ecosystem = ? AND package = ? AND version = ? AND reference_identifier = ?", (metadata.ecosystem, metadata.package, metadata.version, watchlist["identifier"])).fetchone()
    if row is None:
        return {"matched": False, "score": score, "event_id": event_id}
    item = dict(row)
    item["score_components"] = _decode(item.pop("score_components_json"), {})
    item["evidence"] = _decode(item.pop("evidence_json"), {})
    if float(item.get("score") or 0) >= max(float(watchlist["threshold"]), 85.0):
        create_candidate_alert(item, db_path=db_path)
    return {"matched": True, "candidate": item}


def ingest_registry_metadata(*, metadata: RegistryMetadata, source_id: str, db_path: Optional[str] = None, monitor: Optional[Dict[str, Any]] = None, seed_source: bool = True) -> Dict[str, Any]:
    """Score one observed registry package against every active watchlist.

    Registry-specific event/search adapters call this function.  Keeping the
    scoring and persistence path centralized prevents each ecosystem adapter
    from inventing different candidate semantics.
    """
    soc_store.init_db(db_path)
    if seed_source:
        seed_registry_sources(db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT watchlist_id FROM research_watchlists WHERE ecosystem = ? AND status = 'active'", (metadata.ecosystem,)).fetchall()
    monitor_info = monitor or {"coverage_mode": "event_or_search", "interval_seconds": 0}
    matches = []
    for row in rows:
        watchlist = get_watchlist(row["watchlist_id"], db_path=db_path)
        result = _record_candidate(monitor=monitor_info, watchlist=watchlist, metadata=metadata, source_id=source_id, db_path=db_path)
        if result.get("matched"):
            matches.append(result["candidate"])
    return {"schema_version": "secopsai.research.registry-event.v1", "metadata": {"ecosystem": metadata.ecosystem, "package": metadata.package, "version": metadata.version}, "matched_watchlists": len(matches), "candidates": matches}


def run_monitor(monitor_id: str, *, db_path: Optional[str] = None, fetcher: Optional[SafeFetcher] = None) -> Dict[str, Any]:
    monitor = get_monitor(monitor_id, db_path=db_path)
    if not monitor["enabled"]:
        raise ValueError("monitor is disabled")
    if not monitor.get("watchlist_id"):
        raise ValueError("global registry enumeration is not enabled for this source; attach a watchlist")
    watchlist = get_watchlist(monitor["watchlist_id"], db_path=db_path)
    adapter = ADAPTERS.get(monitor["ecosystem"])
    if adapter is None:
        raise ValueError("no safe intake adapter exists for this ecosystem")
    started = _now()
    run_id = _id("MRUN")
    with closing(soc_store.connect(db_path)) as connection:
        active = connection.execute("SELECT run_id FROM research_monitor_runs WHERE monitor_id = ? AND status = 'running'", (monitor_id,)).fetchone()
        if active:
            raise ValueError("monitor already has an active run")
        connection.execute("INSERT INTO research_monitor_runs (run_id, monitor_id, status, started_at, completed_at, error_message, coverage_json) VALUES (?, ?, 'running', ?, NULL, NULL, '{}')", (run_id, monitor_id, started))
        connection.commit()
    results: List[Dict[str, Any]] = []
    try:
        metadata = adapter.resolve(watchlist["identifier"], "", fetcher or SafeFetcher())
        results.append(_record_watchlist_observation(monitor=monitor, watchlist=watchlist, metadata=metadata, db_path=db_path))
        next_run = (datetime.now(timezone.utc) + timedelta(seconds=monitor["interval_seconds"])).isoformat().replace("+00:00", "Z")
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute("UPDATE research_monitors SET last_run_at = ?, last_success_at = ?, last_error = NULL, next_run_at = ?, updated_at = ? WHERE monitor_id = ?", (started, started, next_run, _now(), monitor_id))
            connection.execute("UPDATE research_monitor_cursors SET cursor_json = ?, coverage_json = ?, updated_at = ? WHERE monitor_id = ?", (_json({"last_package": watchlist["identifier"], "last_observed": started}), _json({"mode": monitor["coverage_mode"], "complete": False, "note": "watchlist-scoped observation"}), _now(), monitor_id))
            connection.execute("UPDATE research_monitor_runs SET status = 'succeeded', completed_at = ?, coverage_json = ? WHERE run_id = ?", (_now(), _json({"mode": monitor["coverage_mode"], "complete": False}), run_id))
            connection.commit()
    except Exception as exc:
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute("UPDATE research_monitors SET last_run_at = ?, last_error = ?, updated_at = ? WHERE monitor_id = ?", (started, str(exc)[:2000], _now(), monitor_id))
            connection.execute("UPDATE research_monitor_runs SET status = 'failed', completed_at = ?, error_message = ? WHERE run_id = ?", (_now(), str(exc)[:2000], run_id))
            connection.commit()
        raise
    return {"schema_version": SCHEMA_VERSION, "monitor_id": monitor_id, "run_id": run_id, "started_at": started, "coverage": {"mode": monitor["coverage_mode"], "complete": False}, "results": results}


def run_due_monitors(*, db_path: Optional[str] = None, limit: int = 25, fetcher: Optional[SafeFetcher] = None) -> Dict[str, Any]:
    """Run due monitors once; suitable for a local worker or hosted cron trigger."""
    soc_store.init_db(db_path)
    now = datetime.now(timezone.utc)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT monitor_id FROM research_monitors WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?) ORDER BY priority DESC, next_run_at LIMIT ?", (now.isoformat().replace("+00:00", "Z"), max(1, min(int(limit), 100)))).fetchall()
    results: List[Dict[str, Any]] = []
    failures: List[Dict[str, str]] = []
    for row in rows:
        monitor_id = row["monitor_id"]
        try:
            results.append(run_monitor(monitor_id, db_path=db_path, fetcher=fetcher))
        except Exception as exc:
            failures.append({"monitor_id": monitor_id, "error": str(exc)[:2000]})
    return {"schema_version": SCHEMA_VERSION, "run_at": _now(), "due": len(rows), "succeeded": len(results), "failed": len(failures), "results": results, "failures": failures}


def recover_stale_monitor_runs(*, db_path: Optional[str] = None, max_age_seconds: int = 3600) -> Dict[str, Any]:
    """Release monitor leases left by a crashed worker without advancing cursors."""
    soc_store.init_db(db_path)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(60, min(int(max_age_seconds), 7 * 24 * 3600)))
    cutoff_text = cutoff.isoformat().replace("+00:00", "Z")
    recovered = []
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT run_id, monitor_id FROM research_monitor_runs WHERE status = 'running' AND started_at < ?", (cutoff_text,)).fetchall()
        for row in rows:
            connection.execute("UPDATE research_monitor_runs SET status = 'failed', completed_at = ?, error_message = ? WHERE run_id = ?", (_now(), "monitor run lease expired after worker inactivity", row["run_id"]))
            connection.execute("UPDATE research_monitors SET last_error = ?, updated_at = ? WHERE monitor_id = ?", ("monitor run lease expired after worker inactivity", _now(), row["monitor_id"]))
            recovered.append(row["run_id"])
        connection.commit()
    return {"recovered": recovered, "count": len(recovered)}


def list_candidates(*, status: Optional[str] = None, ecosystem: Optional[str] = None, limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    limit = max(1, min(int(limit), 500))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT * FROM research_candidates WHERE (? IS NULL OR status = ?) AND (? IS NULL OR ecosystem = ?) ORDER BY score DESC, last_seen DESC LIMIT ?", (status, status, ecosystem, ecosystem, limit)).fetchall()
    return [{**dict(row), "score_components": _decode(row["score_components_json"], {}), "evidence": _decode(row["evidence_json"], {})} for row in rows]


def get_candidate(candidate_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
    if row is None:
        raise ValueError("candidate not found")
    item = dict(row)
    item["score_components"] = _decode(item.pop("score_components_json"), {})
    item["evidence"] = _decode(item.pop("evidence_json"), {})
    return item


def get_promotion_policy(*, ecosystem: str = "all", db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return the durable, auditable candidate-promotion policy."""
    soc_store.init_db(db_path)
    ecosystem = normalize_identifier("", ecosystem or "all")
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_promotion_policies WHERE ecosystem = ?", (ecosystem,)).fetchone()
    if row:
        return dict(row)
    return {"ecosystem": ecosystem, "enabled": 0, "score_threshold": 90.0, "minimum_evidence": 2, "require_publisher": 0, "mode": "draft_case", "updated_by": "", "created_at": None, "updated_at": None}


def set_promotion_policy(*, ecosystem: str = "all", enabled: bool = False, score_threshold: float = 90.0, minimum_evidence: int = 2, require_publisher: bool = False, mode: str = "draft_case", actor: str = "operator", db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    ecosystem = normalize_identifier("", ecosystem or "all")
    if ecosystem != "all" and ecosystem not in CAPABILITIES:
        raise ValueError("unsupported promotion-policy ecosystem")
    threshold = float(score_threshold)
    if not 70 <= threshold <= 100:
        raise ValueError("score threshold must be between 70 and 100")
    evidence_count = max(1, min(int(minimum_evidence), 8))
    if mode not in PROMOTION_MODES:
        raise ValueError("unsupported promotion mode")
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("""INSERT INTO research_promotion_policies
            (ecosystem, enabled, score_threshold, minimum_evidence, require_publisher, mode, updated_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem) DO UPDATE SET enabled=excluded.enabled, score_threshold=excluded.score_threshold,
            minimum_evidence=excluded.minimum_evidence, require_publisher=excluded.require_publisher,
            mode=excluded.mode, updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
            (ecosystem, int(bool(enabled)), threshold, evidence_count, int(bool(require_publisher)), mode, str(actor or "operator")[:160], now, now))
        connection.commit()
    return get_promotion_policy(ecosystem=ecosystem, db_path=db_path)


def run_promotion_policy(*, ecosystem: str = "all", apply: bool = False, actor: str = "operator", limit: int = 100, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Evaluate candidates deterministically and optionally create draft cases.

    Promotion never records a malicious verdict. It creates an auditable draft
    investigation only when the configured evidence gates pass.
    """
    policy = get_promotion_policy(ecosystem=ecosystem, db_path=db_path)
    candidates = list_candidates(status="new", ecosystem=None if policy["ecosystem"] == "all" else policy["ecosystem"], limit=limit, db_path=db_path)
    decisions: List[Dict[str, Any]] = []
    for candidate in candidates:
        evidence = candidate.get("evidence") if isinstance(candidate.get("evidence"), dict) else {}
        evidence_values = set()
        for key in ("metadata_url", "artifact_url"):
            value = str(evidence.get(key) or "").strip().lower()
            if value:
                evidence_values.add(value)
        publisher_value = normalize_identifier("", evidence.get("publisher") or "")
        if publisher_value:
            evidence_values.add(f"publisher:{publisher_value}")
        reasons = []
        if float(candidate.get("score") or 0) < float(policy["score_threshold"]):
            reasons.append("score_below_threshold")
        if len(evidence_values) < int(policy["minimum_evidence"]):
            reasons.append("insufficient_evidence")
        if policy["require_publisher"] and not evidence.get("publisher"):
            reasons.append("publisher_missing")
        eligible = not reasons and bool(policy["enabled"])
        decision = {"candidate_id": candidate["candidate_id"], "eligible": eligible, "score": candidate["score"], "evidence_count": len(evidence_values), "reasons": reasons or (["policy_disabled"] if not policy["enabled"] else ["eligible"]), "case_id": candidate.get("case_id")}
        if apply and eligible and policy["mode"] == "draft_case" and not candidate.get("case_id"):
            case_id = f"RSC-{hashlib.sha256(candidate['candidate_id'].encode()).hexdigest()[:12].upper()}"
            subject_stable = "|".join((case_id, "package", str(candidate["ecosystem"]), str(candidate["package"]), str(candidate.get("version") or "")))
            subject_id = f"SUB-{hashlib.sha256(subject_stable.encode()).hexdigest()[:16].upper()}"
            evidence_stable = "|".join((case_id, "registry_metadata", str(evidence.get("metadata_url") or candidate["candidate_id"])))
            evidence_id = f"EVD-{hashlib.sha256(evidence_stable.encode()).hexdigest()[:16].upper()}"
            now = _now()
            with closing(soc_store.connect(db_path)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute("SELECT status, case_id FROM research_candidates WHERE candidate_id = ?", (candidate["candidate_id"],)).fetchone()
                if not current or current["status"] != "new" or current["case_id"]:
                    connection.rollback()
                    decision["eligible"] = False
                    decision["reasons"] = ["already_promoted_or_claimed"]
                    decisions.append(decision)
                    continue
                connection.execute("""INSERT OR IGNORE INTO research_cases
                    (case_id, title, summary, case_type, severity, confidence, status, owner, disclosure_status,
                     embargo_until, created_at, updated_at, closed_at, published_at, payload_json)
                    VALUES (?, ?, ?, 'typosquatting', 'medium', ?, 'draft', ?, 'not_started', NULL, ?, ?, NULL, NULL, ?)""",
                    (case_id, f"Investigate {candidate['ecosystem']} package {candidate['package']}", f"Automatically promoted as a draft investigation after deterministic policy checks. Similarity score: {candidate['score']}. This is a lead, not a maliciousness verdict.", min(int(float(candidate["score"])), 80), actor, now, now, _json({"candidate_id": candidate["candidate_id"], "promotion_policy": policy})))
                connection.execute("""INSERT OR IGNORE INTO research_subjects
                    (subject_id, case_id, subject_type, ecosystem, name, version, publisher, status, metadata_json, created_at)
                    VALUES (?, ?, 'package', ?, ?, ?, ?, 'active', ?, ?)""",
                    (subject_id, case_id, candidate["ecosystem"], candidate["package"], candidate.get("version") or "", evidence.get("publisher") or "", _json({"candidate_id": candidate["candidate_id"], "reference_identifier": candidate.get("reference_identifier")}), now))
                if evidence.get("metadata_url"):
                    connection.execute("""INSERT OR IGNORE INTO research_evidence
                        (evidence_id, case_id, evidence_type, title, locator, sha256, provenance, notes, status, collected_at, created_at, metadata_json)
                        VALUES (?, ?, 'registry_metadata', 'Registry metadata captured during candidate discovery', ?, '', 'official registry monitor', ?, 'active', ?, ?, ?)""",
                        (evidence_id, case_id, evidence["metadata_url"], candidate.get("reason") or "", now, now, _json({"candidate_id": candidate["candidate_id"]})))
                connection.execute("INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, 'case_created', ?, 'Research case created by candidate promotion policy.', ?, ?)", (case_id, actor, _json({"candidate_id": candidate["candidate_id"], "promotion_policy": policy}), now))
                connection.execute("UPDATE research_candidates SET status = 'promoted', case_id = ? WHERE candidate_id = ? AND status = 'new' AND case_id IS NULL", (case_id, candidate["candidate_id"]))
                connection.execute("INSERT OR IGNORE INTO research_promotion_events (event_id, candidate_id, policy_ecosystem, decision, reasons_json, case_id, actor, created_at) VALUES (?, ?, ?, 'draft_case_created', ?, ?, ?, ?)", (_id("RPE"), candidate["candidate_id"], policy["ecosystem"], _json(decision["reasons"]), case_id, actor, now))
                connection.commit()
            decision["case_id"] = case_id
            decision["applied"] = True
        decisions.append(decision)
    return {"schema_version": "secopsai.research.promotion-policy.v1", "policy": policy, "apply": bool(apply), "evaluated": len(decisions), "eligible": sum(bool(item["eligible"]) for item in decisions), "promoted": sum(bool(item.get("applied")) for item in decisions), "decisions": decisions}


def create_candidate_alert(
    candidate: Dict[str, Any],
    *,
    db_path: Optional[str] = None,
    alert_type: str = "candidate_detected",
    severity_override: Optional[str] = None,
    dedupe_key: Optional[str] = None,
    reason_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a deduplicated alert for a high-confidence candidate.

    External advisory feeds use the same canonical finding path but provide a
    stable source/version/hash dedupe key.  The defaults preserve the original
    watchlist candidate behavior.
    """
    soc_store.init_db(db_path)
    score = float(candidate.get("score") or 0)
    package = str(candidate.get("package") or "").strip()
    ecosystem = str(candidate.get("ecosystem") or "").strip().lower()
    version = str(candidate.get("version") or candidate.get("new_version") or "").strip()
    package_key = normalize_identifier(ecosystem, package)
    version_key = normalize_identifier(ecosystem, version)
    evidence = candidate.get("evidence") if isinstance(candidate.get("evidence"), dict) else {}
    artifact_evidence = _has_artifact_evidence(evidence)
    if alert_type == "external_advisory_match" and not artifact_evidence:
        # A public advisory is a valuable lead, but it is not yet an
        # independently verified package compromise. Cap the initial lead at
        # high severity until artifact evidence exists.
        severity = _external_lead_severity(score)
    else:
        severity = severity_override or ("critical" if score >= 95 else "high" if score >= 85 else "medium")
    severity = severity.lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "medium"
    if alert_type in {"external_advisory_match", "npm_proactive_anomaly"} and package_key and version_key:
        # Group repeat observations of one package release into one lead.
        stable_dedupe_key = f"package-lead:{alert_type}:{ecosystem}:{package_key}:{version_key}"
    else:
        stable_dedupe_key = dedupe_key or f"candidate:{candidate.get('candidate_id')}:{candidate.get('last_seen')}"
    alert_id = _id("RAL")
    now = _now()
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute(
                """INSERT INTO research_alerts
                    (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 'open', '', ?, ?)
                ON CONFLICT(dedupe_key) DO UPDATE SET severity=excluded.severity,
                    alert_type=excluded.alert_type, reason=excluded.reason,
                    evidence_json=excluded.evidence_json, updated_at=excluded.updated_at,
                    status='open'""",
                (alert_id, alert_type, severity, candidate.get("candidate_id"), candidate.get("campaign_id"), stable_dedupe_key,
                 str(reason_override or candidate.get("reason") or "Candidate requires analyst review")[:2000],
                 _json(candidate.get("evidence") or {}), now, now),
            )
            row = connection.execute("SELECT * FROM research_alerts WHERE dedupe_key = ?", (stable_dedupe_key,)).fetchone()
            finding_id = None
            if row:
                finding_id = _upsert_research_alert_finding(connection, dict(row), candidate=candidate)
            connection.commit()
    result = dict(row) if row else {"alert_id": alert_id, "dedupe_key": stable_dedupe_key}
    if row:
        result["finding_id"] = finding_id
    return result


def _upsert_research_alert_finding(
    connection: Any,
    alert: Dict[str, Any],
    *,
    candidate: Optional[Dict[str, Any]] = None,
) -> str:
    alert_id = str(alert.get("alert_id") or "")
    finding_id = f"RSCF-{hashlib.sha256(alert_id.encode()).hexdigest()[:16].upper()}"
    evidence = _decode(alert.get("evidence_json"), {})
    if candidate and isinstance(candidate.get("evidence"), dict):
        evidence = {**evidence, **candidate["evidence"]}
    alert_type = str(alert.get("alert_type") or "research_alert")
    severity = str(alert.get("severity") or "medium").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "medium"
    package = str((candidate or {}).get("package") or evidence.get("package") or "").strip()
    ecosystem = str((candidate or {}).get("ecosystem") or evidence.get("ecosystem") or "").strip().lower()
    version = str((candidate or {}).get("version") or evidence.get("version") or "").strip()
    score = (candidate or {}).get("score", evidence.get("score", 0))
    try:
        confidence = min(99, max(0, int(float(score or 0))))
    except (TypeError, ValueError):
        confidence = 0
    if alert_type == "npm_proactive_anomaly":
        title = f"Proactive npm release requires verification: {ecosystem or 'npm'} {package or alert_id}{('@' + version) if version else ''}"
        rule_ids = ["RESEARCH-NPM-PROACTIVE-STATIC"]
    elif alert_type == "external_advisory_match":
        title = f"External advisory requires verification: {ecosystem or 'package'} {package or alert_id}{('@' + version) if version else ''}"
        rule_ids = ["RESEARCH-EXTERNAL-ADVISORY"]
    elif alert_type == "candidate_detected":
        title = f"Research candidate requires verification: {ecosystem or 'package'} {package or alert_id}"
        rule_ids = ["RESEARCH-CANDIDATE-DISCOVERY"]
    elif alert_type == "watched_package_version":
        title = f"Watched package changed: {ecosystem or 'package'} {package or alert_id}{('@' + version) if version else ''}"
        rule_ids = ["RESEARCH-WATCHLIST-VERSION-CHANGE"]
    else:
        title = f"Research alert requires verification: {alert_type.replace('_', ' ')}"
        rule_ids = ["RESEARCH-ALERT-INGESTION"]
    lead_status = "research_lead" if alert_type == "external_advisory_match" and not _has_artifact_evidence(evidence) else "open"
    finding = {
        "finding_id": finding_id,
        "title": title[:500],
        "summary": str(alert.get("reason") or "Research intelligence requires evidence-led review")[:2000],
        "severity": severity,
        "severity_score": {"critical": 95, "high": 80, "medium": 55, "low": 25, "info": 10}[severity],
        "status": lead_status,
        "disposition": "unreviewed",
        "first_seen": str((candidate or {}).get("first_seen") or alert.get("created_at") or _now()),
        "last_seen": str((candidate or {}).get("last_seen") or alert.get("updated_at") or _now()),
        "event_ids": [alert_id],
        "rule_ids": rule_ids,
        "platform": "supply_chain" if package or ecosystem or alert_type in {"candidate_detected", "watched_package_version"} else "research",
        "source": RESEARCH_ALERT_FINDING_SOURCE,
        "alert_id": alert_id,
        "alert_type": alert_type,
        "candidate_id": str(alert.get("candidate_id") or (candidate or {}).get("candidate_id") or ""),
        "campaign_id": str(alert.get("campaign_id") or ""),
        "case_id": str(alert.get("case_id") or ""),
        "package": package,
        "ecosystem": ecosystem,
        "version": version,
        "confidence": confidence,
        "verdict": "unverified_research_alert",
        "evidence": evidence,
        "local_dependency_reference": "not_required_for_package_verification",
        "research_scope": "independent_registry_intelligence",
    }
    soc_store.upsert_finding(connection, finding, source=RESEARCH_ALERT_FINDING_SOURCE)
    return finding_id


def sync_actionable_alert_findings(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Idempotently normalize current and historical research alerts for agent triage."""
    soc_store.init_db(db_path)
    synced: list[str] = []
    # This path is called by the Research Monitor after degraded-alert writes
    # and can also be called by the triage helper. Keep its read/normalize/write
    # batch in the same cross-process critical section as every other Core
    # writer so Edge sync cannot interleave with finding upserts.
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            rows = connection.execute(
                """SELECT a.*, c.ecosystem, c.package, c.version, c.score,
                          c.first_seen AS candidate_first_seen, c.last_seen AS candidate_last_seen,
                          c.evidence_json AS candidate_evidence_json
                   FROM research_alerts a
                   LEFT JOIN research_candidates c ON c.candidate_id = a.candidate_id
                   WHERE a.status IN ('open', 'in_review')
                   ORDER BY a.created_at ASC"""
            ).fetchall()
            for row in rows:
                alert = dict(row)
                if str(alert.get("alert_type") or "") in OPERATIONAL_ALERT_TYPES:
                    continue
                candidate = {
                    "candidate_id": alert.get("candidate_id"),
                    "ecosystem": alert.get("ecosystem"),
                    "package": alert.get("package"),
                    "version": alert.get("version"),
                    "score": alert.get("score"),
                    "first_seen": alert.get("candidate_first_seen"),
                    "last_seen": alert.get("candidate_last_seen"),
                    "evidence": _decode(alert.get("candidate_evidence_json"), {}),
                }
                if str(alert.get("alert_type") or "") == "external_advisory_match" and not _has_artifact_evidence(candidate["evidence"]):
                    score = float(candidate.get("score") or 0)
                    normalized_severity = _external_lead_severity(score)
                    if str(alert.get("severity") or "").lower() != normalized_severity:
                        connection.execute(
                            "UPDATE research_alerts SET severity=?, updated_at=? WHERE alert_id=?",
                            (normalized_severity, _now(), alert["alert_id"]),
                        )
                        alert["severity"] = normalized_severity
                synced.append(_upsert_research_alert_finding(connection, alert, candidate=candidate))
            connection.commit()
    return {
        "schema_version": "secopsai.research.alert-sync.v1",
        "synced": len(synced),
        "finding_ids": synced,
        "operational_alert_types": sorted(OPERATIONAL_ALERT_TYPES),
    }


def list_alerts(*, status: Optional[str] = None, limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT * FROM research_alerts WHERE (? IS NULL OR status = ?) ORDER BY created_at DESC LIMIT ?", (status, status, max(1, min(int(limit), 500)))).fetchall()
    return [dict(row) for row in rows]


def resolve_alert(alert_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not row:
            raise ValueError(f"Alert not found: {alert_id}")
        connection.execute(
            "UPDATE research_alerts SET status = 'resolved', updated_at = ? WHERE alert_id = ?",
            (now, alert_id),
        )
        finding_id = f"RSCF-{hashlib.sha256(str(alert_id).encode()).hexdigest()[:16].upper()}"
        connection.execute(
            """UPDATE findings SET status = 'triaged', disposition = 'needs_review', updated_at = ?
               WHERE finding_id = ? AND source = ? AND status IN ('research_lead', 'open', 'in_review')""",
            (now, finding_id, RESEARCH_ALERT_FINDING_SOURCE),
        )
        connection.commit()
    return {"ok": True, "alert_id": alert_id, "finding_id": finding_id, "status": "resolved"}
