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


SCHEMA_VERSION = "secopsai.research.discovery.v1"
ALGORITHM_VERSION = "similarity-1"
WATCH_TYPES = {"package", "namespace", "publisher", "brand", "repository", "organization"}
PRIORITIES = {"low", "normal", "high", "critical"}
STATUSES = {"active", "paused", "archived", "new", "review", "dismissed", "promoted"}


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
        ("npm", "npm", False, "watchlist_poll", ["Global completeness depends on scoped registry queries."], "https://docs.npmjs.com/"),
        ("pypi", "PyPI", False, "watchlist_poll", ["A watchlist monitor is not a complete PyPI census."], "https://docs.pypi.org/"),
        ("nuget", "NuGet", True, "catalog_or_watchlist", ["Catalog coverage and rate limits must be reported per run."], "https://learn.microsoft.com/en-us/nuget/api/overview"),
        ("maven", "Maven Central", False, "search_or_watchlist", ["Search polling does not guarantee a complete repository census."], "https://central.sonatype.org/"),
        ("rubygems", "RubyGems.org", False, "watchlist_poll", ["Global enumeration is not assumed."], "https://guides.rubygems.org/rubygems-org-api/"),
        ("packagist", "Packagist", False, "watchlist_poll", ["Package-level monitoring is the default."], "https://packagist.org/apidoc"),
        ("go", "Go Modules", False, "module_poll", ["Module proxy polling is scoped to configured modules."], "https://go.dev/ref/mod"),
        ("open-vsx", "Open VSX", False, "publisher_or_extension_poll", ["Publisher and extension scopes are explicit."], "https://open-vsx.org/"),
    )
}


def capability_registry() -> Dict[str, Any]:
    return {"schema_version": "secopsai.research.ecosystem-capabilities.v1", "ecosystems": list(CAPABILITIES.values())}


def seed_registry_sources(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    now = _now()
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
    event_key = hashlib.sha256(f"{source_id}|{metadata.ecosystem}|{metadata.package}|{metadata.version}|{metadata.artifact_url}".encode()).hexdigest()
    event_id = _id("REV")
    candidate_id = _id("CAN")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_registry_events
            (event_id, source_id, ecosystem, package, version, publisher, source_url, artifact_url, artifact_sha256, observed_at, provenance_json, idempotency_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?)
            ON CONFLICT(idempotency_key) DO NOTHING""",
            (event_id, source_id, metadata.ecosystem, metadata.package, metadata.version, metadata.publisher[:240], metadata.metadata_url, metadata.artifact_url, now, _json({"schema_version": "secopsai.research.registry-event.v1", "source": source_id, "coverage_mode": monitor["coverage_mode"]}), event_key),
        )
        event_row = connection.execute("SELECT event_id FROM research_registry_events WHERE idempotency_key = ?", (event_key,)).fetchone()
        event_id = event_row["event_id"]
        if score["score"] >= threshold:
            connection.execute(
                """INSERT INTO research_candidates
                (candidate_id, event_id, watchlist_id, ecosystem, package, version, reference_identifier, score, score_components_json, reason, status, case_id, evidence_json, first_seen, last_seen, algorithm_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', NULL, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, package, version, reference_identifier) DO UPDATE SET score=excluded.score,
                score_components_json=excluded.score_components_json, reason=excluded.reason, last_seen=excluded.last_seen""",
            (candidate_id, event_id, watchlist["watchlist_id"], metadata.ecosystem, metadata.package, metadata.version, watchlist["identifier"], score["score"], _json(score["components"]), _candidate_reason(score), _json({"metadata_url": metadata.metadata_url, "artifact_url": metadata.artifact_url, "publisher": metadata.publisher, "observed_value": observed_value, "watch_type": watchlist.get("watch_type")}), now, now, score["algorithm_version"]),
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


def ingest_registry_metadata(*, metadata: RegistryMetadata, source_id: str, db_path: Optional[str] = None, monitor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Score one observed registry package against every active watchlist.

    Registry-specific event/search adapters call this function.  Keeping the
    scoring and persistence path centralized prevents each ecosystem adapter
    from inventing different candidate semantics.
    """
    soc_store.init_db(db_path)
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
        results.append(ingest_registry_metadata(metadata=metadata, source_id=monitor["source_id"], db_path=db_path, monitor=monitor))
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


def create_candidate_alert(candidate: Dict[str, Any], *, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Create a deduplicated alert for a high-confidence candidate."""
    soc_store.init_db(db_path)
    score = float(candidate.get("score") or 0)
    severity = "critical" if score >= 95 else "high" if score >= 85 else "medium"
    dedupe_key = f"candidate:{candidate.get('candidate_id')}:{candidate.get('last_seen')}"
    alert_id = _id("RAL")
    now = _now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_alerts
            (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key, reason, evidence_json, status, owner, created_at, updated_at)
            VALUES (?, 'candidate_detected', ?, ?, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
            ON CONFLICT(dedupe_key) DO UPDATE SET updated_at=excluded.updated_at""",
            (alert_id, severity, candidate.get("candidate_id"), dedupe_key, str(candidate.get("reason") or "Candidate requires analyst review")[:2000], _json(candidate.get("evidence") or {}), now, now),
        )
        row = connection.execute("SELECT * FROM research_alerts WHERE dedupe_key = ?", (dedupe_key,)).fetchone()
        connection.commit()
    return dict(row) if row else {"alert_id": alert_id, "dedupe_key": dedupe_key}


def list_alerts(*, status: Optional[str] = None, limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT * FROM research_alerts WHERE (? IS NULL OR status = ?) ORDER BY created_at DESC LIMIT ?", (status, status, max(1, min(int(limit), 500)))).fetchall()
    return [dict(row) for row in rows]
