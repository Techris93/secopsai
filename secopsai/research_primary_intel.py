"""Bounded primary-source intake with atomic acquisition, cursor and queue commits."""
from __future__ import annotations

import email.utils
import hashlib
import json
import os
import re
import secrets
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import feedparser
import soc_store
from secopsai.research_operation_store import read_connection
from secopsai.research_intake import SafeFetcher
from secopsai.research_operation_store import append, canonical, digest, text, timestamp, transaction

PARSER_VERSION = "primary-intel-v4"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_EVENTS = 10000
EVENT_BATCH_SIZE = 250
MAX_PENDING = 10000
PREPARE_BATCH_SIZE = 500
MAX_ATTEMPTS = 8
MSRC_INITIAL_LOOKBACK_DAYS = 7
MSRC_OVERLAP_DAYS = 3


class IntakeBackpressureError(ValueError):
    """The source snapshot is durable, but queued work has reached its bound."""


def source_headers(parser: str, *, url: str | None = None) -> dict:
    if parser in {"jfrog_index", "socket_index"}:
        headers = {"Accept": "text/html"}
    else:
        headers = {"Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8" if parser in {"rss", "msrc_rss"} else "application/json"}
    parsed = urlparse(url or "")
    token = os.environ.get("SECOPSAI_GITHUB_TOKEN", "").strip()
    # A bearer token is sent only to the reviewed public GitHub API origin;
    # a custom source URL can never receive the workflow credential.
    if parser == "github_advisories" and parsed.scheme == "https" and parsed.hostname == "api.github.com" and token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _now() -> str:
    return soc_store.utc_now()


def _future(seconds: int, now: str | None = None) -> str:
    return (datetime.fromisoformat((now or _now()).replace("Z", "+00:00")) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def source_url(value: str, *, reference: bool = False) -> str:
    value = text(value, "source URL", limit=4000)
    parsed = urlparse(value)
    allowed_schemes = {"http", "https"} if reference else {"https"}
    port = 443 if parsed.scheme == "https" else 80
    if parsed.scheme not in allowed_schemes or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, port}:
        raise ValueError("source reference must be credential-free HTTP(S)" if reference else "source URL must be credential-free HTTPS")
    return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def configure_source(config: dict, *, actor: str, db_path=None) -> dict:
    value = {"source_id": text(config.get("source_id"), "source_id", limit=160),
             "name": text(config.get("name"), "name", limit=240), "url": source_url(config.get("url", "")),
             "parser": config.get("parser"), "source_class": config.get("source_class"),
             "sharing": config.get("sharing", "public"), "license": text(config.get("license", "unknown"), "license", limit=1000),
             "interval_seconds": config.get("interval_seconds", 86400), "enabled": config.get("enabled", False)}
    if value["parser"] not in {"rss", "msrc_rss", "cisa_kev", "normalized_json", "github_advisories", "openvsx_index", "jfrog_index", "socket_index"} or value["source_class"] not in {"government", "vendor", "registry", "research", "partner", "aggregator", "project"}:
        raise ValueError("unsupported source parser or class")
    if type(value["interval_seconds"]) is not int or not 300 <= value["interval_seconds"] <= 604800 or type(value["enabled"]) is not bool:
        raise ValueError("invalid source interval or enablement")
    if value["sharing"] not in {"public", "restricted", "consented"}:
        raise ValueError("invalid source sharing rights")
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO research_intel_sources(source_id,config_json) VALUES (?,?) ON CONFLICT(source_id) DO UPDATE SET config_json=excluded.config_json", (value["source_id"], canonical(value)))
        append("source_configuration", value, actor=actor, connection=conn)
    return value


def seed_sources(*, db_path=None) -> dict:
    config_file = Path(__file__).resolve().parents[1] / "blog/data/news-sources.json"
    supported, omitted = [], []
    for source in json.loads(config_file.read_text())["sources"]:
        from secopsai.research_source_parsers import source_spec
        try:
            url, parser = source_spec(source)
        except ValueError:
            omitted.append({"name": source["name"], "reason": "source requires a reviewed parser"})
            continue
        identity = source.get("source_id") or "SRC-" + hashlib.sha256(source["feed_url"].encode()).hexdigest()[:20]
        desired = {"source_id": identity, "name": source["name"], "url": url, "parser": parser,
                   "source_class": {"external_research": "research", "platform": "registry"}.get(source["trust_level"], source["trust_level"]),
                   "sharing": "public", "license": "unknown",
                   "interval_seconds": 3600 if source.get("poll_frequency_hint") == "hourly" else 86400,
                   "enabled": bool(source.get("enabled"))}
        soc_store.init_db(db_path)
        with transaction(db_path) as conn:
            existing = conn.execute("SELECT config_json FROM research_intel_sources WHERE source_id=?", (identity,)).fetchone()
            last_config = conn.execute("SELECT actor,payload_json FROM research_operation_records WHERE kind='source_configuration' AND json_extract(payload_json,'$.source_id')=? ORDER BY created_at DESC,rowid DESC LIMIT 1", (identity,)).fetchone()
            # Update catalog-owned records in place, preserving events and cursors.
            # Operator overrides remain authoritative even when the catalog changes.
            catalog_owned = existing and last_config and last_config["actor"] == "source-catalog" and json.loads(existing["config_json"]) == json.loads(last_config["payload_json"])
            if not existing or (catalog_owned and json.loads(existing["config_json"]) != desired):
                configure_source(desired, actor="source-catalog", db_path=db_path)
                previous = json.loads(existing["config_json"]) if existing else None
                if previous and any(previous[key] != desired[key] for key in ("url", "parser")):
                    conn.execute("UPDATE research_intel_sources SET last_attempt_at=NULL,last_success_at=NULL,error_category='',consecutive_failures=0 WHERE source_id=?", (identity,))
        supported.append(identity)
    return {"sources": supported, "unsupported_sources": omitted}


def _date(raw: str) -> str | None:
    if not raw:
        return None
    try:
        return timestamp(raw)
    except (ValueError, TypeError):
        try:
            return timestamp(email.utils.parsedate_to_datetime(raw).isoformat())
        except (ValueError, TypeError, AttributeError):
            return None  # Missing provider publication time is never collection time.


def msrc_window_start(*, last_success_at: str | None = None, now=None) -> str:
    """Return the shared initial-baseline or overlap watermark for MSRC."""
    current = now or datetime.now(timezone.utc)
    if isinstance(current, str):
        current = datetime.fromisoformat(current.replace("Z", "+00:00"))
    if current.tzinfo is None:
        raise ValueError("MSRC lookback requires a timezone-aware clock")
    if last_success_at:
        watermark = datetime.fromisoformat(timestamp(last_success_at).replace("Z", "+00:00"))
        cutoff = watermark - timedelta(days=MSRC_OVERLAP_DAYS)
    else:
        cutoff = current.astimezone(timezone.utc) - timedelta(days=MSRC_INITIAL_LOOKBACK_DAYS)
    return cutoff.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_source_report(config: dict, content: bytes, *, now=None) -> dict:
    if not content or len(content) > MAX_SOURCE_BYTES:
        raise ValueError("source body is empty or exceeds budget")
    parser = config["parser"]
    historical_excluded = 0
    window_start = ""
    if parser in {"rss", "msrc_rss"}:
        feed = feedparser.parse(content)
        if feed.bozo or not feed.get("version"):
            raise ValueError("malformed or unrecognized RSS/Atom feed")
        items = []
        cutoff = None
        if parser == "msrc_rss":
            if config.get("msrc_lookback_start"):
                window_start = timestamp(config["msrc_lookback_start"])
            else:
                window_start = msrc_window_start(now=now)
            cutoff = datetime.fromisoformat(window_start.replace("Z", "+00:00"))
        for entry in feed.entries:
            excerpt = entry.get("summary") or entry.get("title")
            source_updated_at = _date(entry.get("updated", ""))
            published_at = _date(entry.get("published", "")) or source_updated_at
            if parser == "msrc_rss":
                # Use the publisher's revision time when present so late
                # advisory updates are collected even if their original
                # publication date is old. An undated entry cannot safely be
                # classified as historical or in-scope.
                event_time = source_updated_at or published_at
                if not event_time:
                    raise ValueError("MSRC feed entry has no reliable publication or update time")
                if datetime.fromisoformat(event_time.replace("Z", "+00:00")) < cutoff:
                    historical_excluded += 1
                    continue
            item = {"external_id": entry.get("id") or entry.get("link"), "url": entry.get("link"), "title": entry.get("title"),
                    "excerpt": excerpt, "published_at": published_at,
                    "root_url": entry.get("link"), "assessment": "source_reported"}
            if parser == "msrc_rss" and source_updated_at:
                item["source_updated_at"] = source_updated_at
            if isinstance(excerpt, str) and len(excerpt) > 20000:
                item.update(excerpt=excerpt[:20000], excerpt_truncated=True, excerpt_original_characters=len(excerpt),
                            excerpt_sha256=hashlib.sha256(excerpt.encode()).hexdigest(), excerpt_selection={"start": 0, "end": 20000})
            items.append(item)
        events_total = len(feed.entries)
    elif parser in {"github_advisories", "openvsx_index", "jfrog_index", "socket_index"}:
        from secopsai.research_source_parsers import parse_index
        items = parse_index(config, content)
        events_total = len(items)
    elif parser == "cisa_kev":
        body = json.loads(content)
        if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
            raise ValueError("invalid KEV catalog")
        items = [{"external_id": e["cveID"], "url": config["url"],
                  "root_url": f"https://www.cve.org/CVERecord?id={e['cveID']}", "title": f"{e['cveID']}: {e['vulnerabilityName']}",
                  "excerpt": e["shortDescription"], "published_at": None, "catalog_added_at": _date(e["dateAdded"] + "T00:00:00Z"),
                  "date_kind": "catalog_added", "required_action": e["requiredAction"], "assessment": "source_reported",
                  "observed_exploitation_by_secopsai": False} for e in body["vulnerabilities"]]
        events_total = len(items)
    else:
        body = json.loads(content)
        if not isinstance(body, dict) or not isinstance(body.get("events"), list):
            raise ValueError("normalized JSON must contain events")
        items = body["events"]
        events_total = len(items)
    if len(items) > MAX_EVENTS:
        raise ValueError("source event budget exceeded; cursor cannot advance over omitted events")
    normalized = []
    for item in items:
        value = {**item, "external_id": text(item.get("external_id"), "external ID", limit=4000),
                 "title": text(item.get("title"), "title", limit=1000), "excerpt": text(item.get("excerpt"), "source excerpt", limit=20000),
                 # Publisher citations are untrusted identifiers, never fetch
                 # targets. Retain legacy HTTP links without upgrading them
                 # into a different URL or weakening HTTPS acquisition.
                 "url": source_url(item.get("url", ""), reference=True), "root_url": source_url(item.get("root_url") or item.get("url", ""), reference=True),
                 "published_at": _date(item.get("published_at", "")), "assessment": "source_reported",
                 "observed_exploitation_by_secopsai": False}
        normalized.append(value)
    return {"items": normalized, "events_total": events_total, "events_in_scope": len(normalized),
            "historical_excluded": historical_excluded, "window_start": window_start}


def parse_source(config: dict, content: bytes) -> list[dict]:
    """Return all in-scope events; use parse_source_report for coverage counts."""
    return parse_source_report(config, content)["items"]


def acquire(config: dict, content: bytes, *, db_path=None, transport="direct") -> dict:
    """Persist an archived source snapshot and ingest it in resumable batches.

    The source cursor advances only after every in-scope item has been
    committed. If queue backpressure or a process stop interrupts a batch,
    the archived bytes and next item index remain durable for the next run.
    """
    sha256 = hashlib.sha256(content).hexdigest()
    snapshot_id = "SNP-" + digest([config["source_id"], sha256])[:32]
    now = _now()
    with read_connection(db_path) as conn:
        progress = conn.execute("SELECT * FROM research_source_ingest_progress WHERE source_id=?", (config["source_id"],)).fetchone()
    if progress and progress["snapshot_id"] != snapshot_id:
        raise ValueError("an earlier source snapshot must be resumed before accepting a newer response")
    if progress and config.get("parser") == "msrc_rss":
        config = {**config, "msrc_lookback_start": progress["window_start"]}
    report = parse_source_report(config, content)
    items = report["items"]
    if progress and int(progress["total_items"]) != len(items):
        raise ValueError("resumed source snapshot no longer matches its persisted item count")
    inserted = int(progress["inserted_items"] or 0) if progress else 0
    start_index = int(progress["next_index"] or 0) if progress else 0
    acquired_at = now
    with transaction(db_path) as conn:
        conn.execute("INSERT OR IGNORE INTO research_source_snapshots VALUES (?,?,?,?,?,?,?)", (snapshot_id, config["source_id"], sha256, "sqlite:research_source_snapshots", now, PARSER_VERSION, content))
        if progress:
            stored = conn.execute("SELECT acquired_at FROM research_source_snapshots WHERE snapshot_id=?", (snapshot_id,)).fetchone()
            acquired_at = stored["acquired_at"] if stored else now
        else:
            conn.execute("INSERT INTO research_source_ingest_progress(source_id,snapshot_id,next_index,total_items,window_start,events_total,historical_excluded,inserted_items,started_at,updated_at) VALUES (?,?,0,?,?,?,?,0,?,?)",
                         (config["source_id"], snapshot_id, len(items), report["window_start"], report["events_total"], report["historical_excluded"], now, now))

    batch_count = 0
    for offset in range(start_index, len(items), EVENT_BATCH_SIZE):
        batch = items[offset:offset + EVENT_BATCH_SIZE]
        batch_inserted = 0
        with transaction(db_path) as conn:
            current = conn.execute("SELECT next_index,inserted_items FROM research_source_ingest_progress WHERE source_id=? AND snapshot_id=?", (config["source_id"], snapshot_id)).fetchone()
            if not current:
                raise ValueError("source ingest progress disappeared before completion")
            if int(current["next_index"]) != offset:
                # Another process may have resumed the same immutable feed.
                # Restart from the persisted offset; deterministic IDs keep
                # already committed items idempotent.
                if int(current["next_index"]) > offset:
                    continue
                raise ValueError("source ingest progress is not contiguous")
            # Human review is an independent queue. Only unfinished machine
            # preparation consumes intake capacity; otherwise a growing
            # review backlog eventually prevents acquisition of new sources.
            backlog = conn.execute("SELECT COUNT(*) FROM research_operation_queue WHERE kind='verify_intel' AND state IN ('queued','running','retry')").fetchone()[0]
            pending_ids = {"INT-" + digest([config["source_id"], item["external_id"], item])[:32] for item in batch}
            new_events = sum(not conn.execute("SELECT 1 FROM research_intel_events WHERE event_id=?", (identity,)).fetchone() for identity in pending_ids)
            if backlog + new_events > MAX_PENDING:
                raise IntakeBackpressureError("intake backpressure: archived source snapshot will resume without cursor advancement")
            for item in batch:
                # Updating a source entry makes a new event; syndicated entries
                # share a root key without pretending to be independent evidence.
                event_id = "INT-" + digest([config["source_id"], item["external_id"], item])[:32]
                root = digest(item["root_url"])
                changed = conn.execute("INSERT OR IGNORE INTO research_intel_events VALUES (?,?,?,?,?,?,?,?)", (event_id, config["source_id"], root, snapshot_id, item["published_at"], now, now, canonical(item))).rowcount
                if changed:
                    batch_inserted += 1
                    conn.execute("INSERT INTO research_operation_queue(job_id,kind,event_id,payload_json,state,retry_at,created_at,updated_at) VALUES (?,?,?,?,'queued',?,?,?)",
                                 ("Q-" + digest(["verify_intel", event_id])[:32], "verify_intel", event_id, canonical({"event_id": event_id}), now, now, now))
                    conn.execute("INSERT OR IGNORE INTO research_coverage_events VALUES (?,?,?,'',?)", (config["source_id"], event_id, "observed", now))
                    if item.get("excerpt_truncated"):
                        conn.execute("INSERT OR IGNORE INTO research_coverage_events VALUES (?,?,?,?,?)", (config["source_id"], event_id, "evidence_truncated", "RSS excerpt exceeds 20000 characters; complete feed is archived", now))
            conn.execute("UPDATE research_source_ingest_progress SET next_index=?,inserted_items=inserted_items+?,updated_at=? WHERE source_id=? AND snapshot_id=?",
                         (offset + len(batch), batch_inserted, now, config["source_id"], snapshot_id))
        inserted += batch_inserted
        batch_count += 1

    with transaction(db_path) as conn:
        current = conn.execute("SELECT * FROM research_source_ingest_progress WHERE source_id=? AND snapshot_id=?", (config["source_id"], snapshot_id)).fetchone()
        if not current or int(current["next_index"]) != len(items):
            raise ValueError("source snapshot cannot advance before all in-scope events are durable")
        append("source_acquisition", {"source_id": config["source_id"], "source_url": config["url"],
               "snapshot_id": snapshot_id, "sha256": sha256, "transport": transport,
               "events_total": report["events_total"], "events_in_scope": len(items),
               "historical_excluded": report["historical_excluded"], "window_start": report["window_start"]}, actor="source-collector", connection=conn)
        run_id = "SRC-RUN-" + digest([config["source_id"], snapshot_id, now])[:24]
        conn.execute("INSERT OR IGNORE INTO research_source_collection_runs(run_id,source_id,snapshot_id,status,events_total,events_in_scope,historical_excluded,inserted_events,window_start,acquired_at,completed_at) VALUES (?,?,?,'completed',?,?,?,?,?,?,?)",
                     (run_id, config["source_id"], snapshot_id, report["events_total"], len(items), report["historical_excluded"], inserted, report["window_start"], acquired_at, now))
        conn.execute("UPDATE research_intel_sources SET cursor=?,last_success_at=?,error_category='',consecutive_failures=0 WHERE source_id=?", (snapshot_id, now, config["source_id"]))
        conn.execute("DELETE FROM research_source_ingest_progress WHERE source_id=? AND snapshot_id=?", (config["source_id"], snapshot_id))
    return {"source_id": config["source_id"], "snapshot_id": snapshot_id,
            "events": len(items), "events_total": report["events_total"], "events_in_scope": len(items),
            "historical_excluded": report["historical_excluded"], "window_start": report["window_start"],
            "inserted": inserted, "batches": batch_count, "status": "acquired"}


def collect_due(*, db_path=None, fetcher=None, limit: int = 10, force_source_ids: tuple[str, ...] = ()) -> dict:
    # Explicit recovery selects only the named sources; normal calls retain
    # the existing due schedule and never bypass operator disablement.
    seed = seed_sources(db_path=db_path)
    preparation_before = prepare_pending(db_path=db_path, limit=PREPARE_BATCH_SIZE)
    fetcher = fetcher or SafeFetcher(timeout=15)
    with read_connection(db_path) as conn:
        sources = [dict(r) for r in conn.execute("SELECT * FROM research_intel_sources ORDER BY COALESCE(last_attempt_at,'') ASC").fetchall()]
    results = []
    for source in sources:
        if force_source_ids and source["source_id"] not in force_source_ids:
            continue
        config = json.loads(source["config_json"])
        with read_connection(db_path) as conn:
            progress = conn.execute(
                "SELECT p.snapshot_id,p.window_start,s.content,s.sha256 FROM research_source_ingest_progress p "
                "JOIN research_source_snapshots s USING(snapshot_id) WHERE p.source_id=?",
                (source["source_id"],),
            ).fetchone()
        interval = min(config["interval_seconds"], 300 * 2 ** min(source["consecutive_failures"], 4)) if source["consecutive_failures"] else config["interval_seconds"]
        if not config["enabled"] or (not progress and source["source_id"] not in force_source_ids and source["last_attempt_at"] and _future(interval, source["last_attempt_at"]) > _now()):
            continue
        if len(results) >= min(10, max(1, limit)):
            break
        with transaction(db_path) as conn:
            conn.execute("UPDATE research_intel_sources SET last_attempt_at=? WHERE source_id=?", (_now(), config["source_id"]))
        stage = "fetch"
        try:
            if progress:
                content = bytes(progress["content"])
                if hashlib.sha256(content).hexdigest() != progress["sha256"]:
                    raise ValueError("archived source snapshot integrity check failed")
                if config["parser"] == "msrc_rss":
                    config = {**config, "msrc_lookback_start": progress["window_start"]}
                received_headers = {"secopsai-transport": "archived-resume"}
            else:
                from secopsai.research_source_transport import fetch_source
                if config["parser"] == "msrc_rss":
                    config = {**config, "msrc_lookback_start": msrc_window_start(last_success_at=source["last_success_at"])}
                _, received_headers, content = fetch_source(config["url"], max_bytes=MAX_SOURCE_BYTES,
                                                           headers=source_headers(config["parser"], url=config["url"]), fetcher=fetcher)
            stage = "parse"
            results.append(acquire(config, content, db_path=db_path, transport=received_headers.get("secopsai-transport", "direct")))
        except Exception as exc:
            status = re.fullmatch(r"registry returned HTTP ([0-9]{3})", str(exc)) if stage == "fetch" else None
            backpressure = isinstance(exc, IntakeBackpressureError)
            category = ("intake_backpressure" if backpressure else
                        f"source_http_{status.group(1)}" if status else
                        "transport_failure" if stage == "fetch" else "invalid_source")
            with transaction(db_path) as conn:
                conn.execute("UPDATE research_intel_sources SET error_category=?,consecutive_failures=consecutive_failures+? WHERE source_id=?", (category, 0 if backpressure else 1, config["source_id"]))
            results.append({"source_id": config["source_id"], "status": "deferred" if backpressure else "failed", "error_category": category,
                            "snapshot_resumable": bool(progress) or backpressure})
    preparation_after = prepare_pending(db_path=db_path, limit=PREPARE_BATCH_SIZE)
    preparation = {"status": "succeeded", "prepared": preparation_before["prepared"] + preparation_after["prepared"],
                   "pending": preparation_after["pending"], "awaiting_human_review": preparation_after["awaiting_human_review"],
                   "failed": preparation_before["failed"] + preparation_after["failed"]}
    return {"status": "degraded" if any(r["status"] in {"failed", "deferred"} for r in results) or preparation["failed"] else "succeeded", "results": results,
            "preparation": preparation, **seed}


def _prepare_intel_event(row: dict, *, now: str, verified_snapshots: dict[str, bool], connection) -> dict:
    """Build a provenance-preserving review packet; this is not verification."""
    event_id = row["event_id"]
    event = json.loads(row["payload_json"])
    config = json.loads(row["config_json"])
    snapshot_id = row["snapshot_id"]
    if snapshot_id not in verified_snapshots:
        snapshot = connection.execute("SELECT content,sha256 FROM research_source_snapshots WHERE snapshot_id=?", (snapshot_id,)).fetchone()
        verified_snapshots[snapshot_id] = bool(snapshot and hashlib.sha256(snapshot["content"]).hexdigest() == snapshot["sha256"] == row["sha256"])
    if not verified_snapshots[snapshot_id]:
        raise ValueError("source_snapshot_integrity")
    duplicates = [r["event_id"] for r in connection.execute(
        "SELECT event_id FROM research_intel_events WHERE root_source_key=? AND event_id<>? ORDER BY first_observed_at,event_id LIMIT 20",
        (row["root_source_key"], event_id),
    ).fetchall()]
    return {
        "schema_version": "secopsai.research.intel-preparation.v1",
        "event_id": event_id,
        "prepared_at": now,
        "route": "routine_validation",
        "assessment": "source_reported_unverified",
        "source": {"source_id": row["source_id"], "name": config["name"], "source_class": config["source_class"],
                   "sharing": config["sharing"], "url": event["url"]},
        "observation": {"title": event["title"], "excerpt": event["excerpt"][:4000],
                        "excerpt_truncated": bool(event.get("excerpt_truncated") or len(event["excerpt"]) > 4000),
                        "published_at": row["published_at"], "collected_at": row["collected_at"],
                        "first_observed_at": row["first_observed_at"]},
        "provenance": {"snapshot_id": snapshot_id, "sha256": row["sha256"],
                       "event_fingerprint": digest({"event_id": event_id, "snapshot_id": snapshot_id,
                                                     "payload": event, "sha256": row["sha256"]})},
        "related_event_ids": duplicates,
        "review_requirements": ["independent primary-source corroboration", "scope and impact assessment", "prior-art review"],
        "limitations": ["This packet records a publisher-reported item only.",
                        "No independent verification, behavior reproduction, victim impact, or publication decision was performed."],
        "human_review_required": True,
    }


def prepare_pending(*, db_path=None, limit: int = PREPARE_BATCH_SIZE, now=None) -> dict:
    """Prepare source events for a human queue without making a verdict.

    Work is committed as ``awaiting_review`` only after provenance is checked.
    Invalid snapshots remain visible as dead letters and do not affect source
    watermarks or human decisions.
    """
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError("preparation limit must be between 1 and 5000")
    now = timestamp(now or _now())
    prepared = failed = 0
    verified_snapshots: dict[str, bool] = {}
    with transaction(db_path) as conn:
        conn.execute("UPDATE research_operation_queue SET state=CASE WHEN attempt>=? THEN 'dead_letter' ELSE 'retry' END,lease_token='',lease_until=NULL,retry_at=?,updated_at=?,error_category='lease_expired' WHERE kind='verify_intel' AND state='running' AND lease_until<=?",
                     (MAX_ATTEMPTS, now, now, now))
        rows = conn.execute("""SELECT q.job_id,q.event_id,q.state,e.source_id,e.root_source_key,e.snapshot_id,e.published_at,
                    e.collected_at,e.first_observed_at,e.payload_json,s.config_json,p.sha256
            FROM research_operation_queue q
            JOIN research_intel_events e ON e.event_id=q.event_id
            JOIN research_intel_sources s ON s.source_id=e.source_id
            JOIN research_source_snapshots p ON p.snapshot_id=e.snapshot_id
            WHERE q.kind='verify_intel' AND q.state IN ('queued','retry') AND q.retry_at<=?
            ORDER BY q.created_at,q.job_id LIMIT ?""", (now, limit)).fetchall()
        for raw in rows:
            row = dict(raw)
            try:
                packet = _prepare_intel_event(row, now=now, verified_snapshots=verified_snapshots, connection=conn)
            except ValueError:
                conn.execute("UPDATE research_operation_queue SET state='dead_letter',error_category='source_snapshot_integrity',lease_token='',lease_until=NULL,updated_at=? WHERE job_id=? AND state IN ('queued','retry')",
                             (now, row["job_id"]))
                failed += 1
                continue
            encoded = canonical(packet)
            changed = conn.execute("UPDATE research_operation_queue SET state='awaiting_review',result_json=?,error_category='',lease_token='',lease_until=NULL,updated_at=? WHERE job_id=? AND state IN ('queued','retry')",
                                   (encoded, now, row["job_id"])).rowcount
            prepared += int(changed > 0)
    with read_connection(db_path) as conn:
        pending = conn.execute("SELECT COUNT(*) FROM research_operation_queue WHERE kind='verify_intel' AND state IN ('queued','running','retry')").fetchone()[0]
        awaiting = conn.execute("SELECT COUNT(*) FROM research_operation_queue WHERE kind='verify_intel' AND state='awaiting_review'").fetchone()[0]
    return {"status": "degraded" if failed else "succeeded", "prepared": prepared, "failed": failed,
            "pending": pending, "awaiting_human_review": awaiting, "limit": limit}


def claim_job(*, worker_id: str, db_path=None, lease_seconds: int = 300, now=None) -> dict | None:
    text(worker_id, "worker identity", limit=160)
    if not 30 <= lease_seconds <= 3600:
        raise ValueError("lease duration must be 30-3600 seconds")
    now = timestamp(now or _now())
    with transaction(db_path) as conn:
        conn.execute("UPDATE research_operation_queue SET state=CASE WHEN attempt>=? THEN 'dead_letter' ELSE 'retry' END,lease_token='',lease_until=NULL,retry_at=?,updated_at=?,error_category='lease_expired' WHERE state='running' AND lease_until<=?", (MAX_ATTEMPTS, now, now, now))
        job = conn.execute("SELECT * FROM research_operation_queue WHERE state IN ('queued','retry') AND retry_at<=? AND attempt<? ORDER BY created_at LIMIT 1", (now, MAX_ATTEMPTS)).fetchone()
        if not job:
            return None
        token = secrets.token_hex(24)
        conn.execute("UPDATE research_operation_queue SET state='running',attempt=attempt+1,lease_token=?,lease_until=?,updated_at=? WHERE job_id=?", (token, _future(lease_seconds, now), now, job["job_id"]))
        return {**dict(job), "lease_token": token, "state": "running", "attempt": job["attempt"] + 1, "lease_until": _future(lease_seconds, now)}


def heartbeat(job_id: str, token: str, *, db_path=None, now=None) -> None:
    now = timestamp(now or _now())
    with transaction(db_path) as conn:
        changed = conn.execute("UPDATE research_operation_queue SET lease_until=?,updated_at=? WHERE job_id=? AND lease_token=? AND state='running' AND lease_until>?", (_future(300, now), now, job_id, token, now)).rowcount
        if not changed:
            raise ValueError("stale job lease")


def complete_job(job_id: str, token: str, result: dict, *, db_path=None, now=None) -> dict:
    now = timestamp(now or _now())
    encoded = canonical(result)
    if len(encoded.encode()) > 65536:
        raise ValueError("queue result exceeds budget")
    with transaction(db_path) as conn:
        job = conn.execute("SELECT * FROM research_operation_queue WHERE job_id=?", (job_id,)).fetchone()
        if not job:
            raise ValueError("unknown queue job")
        if job["state"] == "completed":
            if job["result_json"] != encoded or job["lease_token"] != token:
                raise ValueError("conflicting completion")
            return {"job_id": job_id, "state": "completed", "reused": True}
        if job["state"] != "running" or job["lease_token"] != token or job["lease_until"] <= now:
            raise ValueError("stale job lease")
        conn.execute("UPDATE research_operation_queue SET state='completed',result_json=?,lease_until=NULL,updated_at=? WHERE job_id=?", (encoded, now, job_id))
    return {"job_id": job_id, "state": "completed", "reused": False}


def fail_job(job_id: str, token: str, *, category: str, retryable: bool, db_path=None) -> dict:
    category = text(category, "failure category", limit=100)
    now = _now()
    with transaction(db_path) as conn:
        job = conn.execute("SELECT * FROM research_operation_queue WHERE job_id=? AND lease_token=? AND state='running' AND lease_until>?", (job_id, token, now)).fetchone()
        if not job:
            raise ValueError("stale job lease")
        state = "retry" if retryable and job["attempt"] < MAX_ATTEMPTS else "dead_letter"
        conn.execute("UPDATE research_operation_queue SET state=?,error_category=?,retry_at=?,lease_until=NULL,lease_token='',updated_at=? WHERE job_id=?", (state, category, _future(min(3600, 30 * 2 ** job["attempt"])), now, job_id))
    return {"job_id": job_id, "state": state}


def intel_event(event_id: str, *, db_path=None) -> dict:
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        row = conn.execute("SELECT e.*,s.config_json,p.sha256,p.content FROM research_intel_events e JOIN research_intel_sources s USING(source_id) JOIN research_source_snapshots p USING(snapshot_id) WHERE event_id=?", (event_id,)).fetchone()
    if not row:
        raise ValueError("unknown intelligence event")
    if hashlib.sha256(row["content"]).hexdigest() != row["sha256"]:
        raise ValueError("archived source integrity check failed")
    result = {k: v for k, v in dict(row).items() if k != "content"}
    result["payload"] = json.loads(result.pop("payload_json"))
    result["source"] = json.loads(result.pop("config_json"))
    return result


def pending_public_reviews(*, db_path=None, limit: int = 20) -> list[dict]:
    """Return a bounded, privacy-safe queue for the independent human reviewer."""
    from secopsai.research_operation_store import records

    decisions = {}
    for record in records("intel_verification", db_path=db_path, limit=10000):
        event_id = record["payload"].get("event_id")
        if event_id and event_id not in decisions:
            decisions[event_id] = record["payload"]
    with read_connection(db_path) as conn:
        rows = conn.execute("""SELECT e.event_id,e.source_id,e.root_source_key,e.snapshot_id,e.published_at,
                e.collected_at,e.first_observed_at,e.payload_json,s.config_json,p.sha256,q.state AS queue_state,q.result_json AS preparation_json
            FROM research_intel_events e JOIN research_intel_sources s USING(source_id)
            JOIN research_source_snapshots p USING(snapshot_id)
            LEFT JOIN research_operation_queue q ON q.event_id=e.event_id AND q.kind='verify_intel'
            WHERE json_extract(s.config_json,'$.sharing')='public'
            ORDER BY e.first_observed_at DESC, e.event_id DESC LIMIT 500""").fetchall()
    pending = []
    verified_snapshots = {}
    for row in rows:
        event = {key: row[key] for key in ("event_id", "source_id", "root_source_key", "snapshot_id", "published_at", "collected_at", "first_observed_at", "sha256", "queue_state", "preparation_json")}
        event["payload"] = json.loads(row["payload_json"])
        event["source"] = json.loads(row["config_json"])
        decision = decisions.get(event["event_id"])
        current = bool(decision and decision.get("event_fingerprint") == digest(event))
        if current and decision.get("decision") in {"verified", "rejected"}:
            continue
        if event["snapshot_id"] not in verified_snapshots:
            with read_connection(db_path) as conn:
                snapshot = conn.execute("SELECT content,sha256 FROM research_source_snapshots WHERE snapshot_id=?", (event["snapshot_id"],)).fetchone()
            verified_snapshots[event["snapshot_id"]] = bool(
                snapshot and hashlib.sha256(snapshot["content"]).hexdigest() == snapshot["sha256"]
                and snapshot["sha256"] == event["sha256"])
        if not verified_snapshots[event["snapshot_id"]]:
            continue
        payload = event["payload"]
        excerpt = str(payload.get("excerpt") or "")
        pending.append({"event_id": event["event_id"], "source_id": event["source_id"],
                        "source_name": event["source"]["name"], "source_class": event["source"]["source_class"],
                        "url": payload["url"], "title": payload["title"], "excerpt": excerpt[:800],
                        "excerpt_truncated": len(excerpt) > 800, "published_at": event["published_at"],
                        "collected_at": event["collected_at"], "first_observed_at": event["first_observed_at"],
                        "source_sha256": event["sha256"],
                        "review_status": (decision or {}).get("decision", "pending_review") if current else "source_changed_review_required",
                        "preparation": json.loads(event["preparation_json"]) if event.get("preparation_json") else None,
                        "preparation_state": event.get("queue_state") or "unprepared"})
        if len(pending) >= max(1, min(int(limit), 50)):
            break
    return pending


def verify_event(event_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    from secopsai.research_assurance import person
    reviewer = person(actor, role="technical_reviewer", db_path=db_path)
    event = intel_event(event_id, db_path=db_path)
    verified = payload.get("decision")
    if verified not in {"verified", "rejected", "needs_review"}:
        raise ValueError("invalid event verification decision")
    public = event["source"]["sharing"] == "public"
    if verified == "verified":
        if not public or payload.get("attribution") != "source_reported" or not payload.get("defensive_action"):
            raise ValueError("brief items require public sharing rights, source attribution and a checked defensive action")
        source_url(payload.get("primary_url", ""), reference=True)
        # Aggregators require an acquired primary event, not a URL assertion.
        primary_id = payload.get("primary_event_id") or event_id
        primary = intel_event(primary_id, db_path=db_path)
        if primary["source"]["source_class"] == "aggregator" or primary["source"]["sharing"] != "public":
            raise ValueError("verification requires an acquired primary source")
        if payload["primary_url"] != primary["payload"]["url"]:
            raise ValueError("primary citation must match the acquired source event")
    value = {"event_id": event_id, "decision": verified, "rationale": text(payload.get("rationale"), "verification rationale"),
             "summary": text(payload.get("summary", ""), "checked summary", required=verified == "verified"),
             "defensive_action": text(payload.get("defensive_action", ""), "defensive action", required=False),
             "limitations": text(payload.get("limitations"), "limitations"), "primary_url": payload.get("primary_url", ""),
             "primary_event_id": payload.get("primary_event_id") or event_id, "attribution": "source_reported",
             "event_fingerprint": digest(event), "reviewer_id": actor, "reviewer_fingerprint": digest(reviewer)}
    with transaction(db_path) as conn:
        record = append("intel_verification", value, actor=actor, fingerprint=digest(event), connection=conn)
        conn.execute("UPDATE research_operation_queue SET state=?, result_json=?, lease_token='', lease_until=NULL, updated_at=? WHERE kind='verify_intel' AND event_id=?",
                     ("completed" if verified in {"verified", "rejected"} else "awaiting_review", canonical({"verification_record_id": record["record_id"], "decision": verified}), _now(), event_id))
    return record
