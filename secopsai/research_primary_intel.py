"""Bounded primary-source intake with atomic acquisition, cursor and queue commits."""
from __future__ import annotations

import email.utils
import hashlib
import json
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

PARSER_VERSION = "primary-intel-v1"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_EVENTS = 5000
MAX_PENDING = 10000
MAX_ATTEMPTS = 8


def _now() -> str:
    return soc_store.utc_now()


def _future(seconds: int, now: str | None = None) -> str:
    return (datetime.fromisoformat((now or _now()).replace("Z", "+00:00")) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def source_url(value: str) -> str:
    value = text(value, "source URL", limit=4000)
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 443}:
        raise ValueError("source URL must be credential-free HTTPS")
    return urlunparse(("https", parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def configure_source(config: dict, *, actor: str, db_path=None) -> dict:
    value = {"source_id": text(config.get("source_id"), "source_id", limit=160),
             "name": text(config.get("name"), "name", limit=240), "url": source_url(config.get("url", "")),
             "parser": config.get("parser"), "source_class": config.get("source_class"),
             "sharing": config.get("sharing", "public"), "license": text(config.get("license", "unknown"), "license", limit=1000),
             "interval_seconds": config.get("interval_seconds", 86400), "enabled": config.get("enabled", False)}
    if value["parser"] not in {"rss", "cisa_kev", "normalized_json"} or value["source_class"] not in {"government", "vendor", "registry", "research", "partner", "aggregator", "project"}:
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
        if source.get("type") == "html":
            omitted.append({"name": source["name"], "reason": "HTML source requires a dedicated verified parser; existing blog intake remains separate"})
            continue
        url = source["feed_url"]
        parser = "cisa_kev" if source["name"] == "CISA Known Exploited Vulnerabilities" else "rss"
        identity = "SRC-" + hashlib.sha256(url.encode()).hexdigest()[:20]
        soc_store.init_db(db_path)
        with read_connection(db_path) as conn:
            existing = conn.execute("SELECT 1 FROM research_intel_sources WHERE source_id=?", (identity,)).fetchone()
        if not existing:
            configure_source({"source_id": identity, "name": source["name"], "url": url, "parser": parser,
                              "source_class": {"external_research": "research", "platform": "registry"}.get(source["trust_level"], source["trust_level"]),
                              "interval_seconds": 3600 if source.get("poll_frequency_hint") == "hourly" else 86400,
                              "enabled": bool(source.get("enabled"))}, actor="source-catalog", db_path=db_path)
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


def parse_source(config: dict, content: bytes) -> list[dict]:
    if not content or len(content) > MAX_SOURCE_BYTES:
        raise ValueError("source body is empty or exceeds budget")
    parser = config["parser"]
    if parser == "rss":
        feed = feedparser.parse(content)
        if feed.bozo or not feed.get("version"):
            raise ValueError("malformed or unrecognized RSS/Atom feed")
        items = [{"external_id": e.get("id") or e.get("link"), "url": e.get("link"), "title": e.get("title"),
                  "excerpt": e.get("summary") or e.get("title"), "published_at": _date(e.get("published") or e.get("updated", "")),
                  "root_url": e.get("link"), "assessment": "source_reported"} for e in feed.entries]
    elif parser == "cisa_kev":
        body = json.loads(content)
        if not isinstance(body, dict) or not isinstance(body.get("vulnerabilities"), list):
            raise ValueError("invalid KEV catalog")
        items = [{"external_id": e["cveID"], "url": config["url"],
                  "root_url": f"https://www.cve.org/CVERecord?id={e['cveID']}", "title": f"{e['cveID']}: {e['vulnerabilityName']}",
                  "excerpt": e["shortDescription"], "published_at": None, "catalog_added_at": _date(e["dateAdded"] + "T00:00:00Z"),
                  "date_kind": "catalog_added", "required_action": e["requiredAction"], "assessment": "source_reported",
                  "observed_exploitation_by_secopsai": False} for e in body["vulnerabilities"]]
    else:
        body = json.loads(content)
        if not isinstance(body, dict) or not isinstance(body.get("events"), list):
            raise ValueError("normalized JSON must contain events")
        items = body["events"]
    if len(items) > MAX_EVENTS:
        raise ValueError("source event budget exceeded; cursor cannot advance over omitted events")
    normalized = []
    for item in items:
        value = {**item, "external_id": text(item.get("external_id"), "external ID", limit=4000),
                 "title": text(item.get("title"), "title", limit=1000), "excerpt": text(item.get("excerpt"), "source excerpt", limit=20000),
                 "url": source_url(item.get("url", "")), "root_url": source_url(item.get("root_url") or item.get("url", "")),
                 "published_at": _date(item.get("published_at", "")), "assessment": "source_reported",
                 "observed_exploitation_by_secopsai": False}
        normalized.append(value)
    return normalized


def acquire(config: dict, content: bytes, *, db_path=None) -> dict:
    """Commit the archived bytes, every parsed event and queue item before cursor advancement."""
    items = parse_source(config, content)
    sha256 = hashlib.sha256(content).hexdigest()
    snapshot_id = "SNP-" + digest([config["source_id"], sha256])[:32]
    now = _now()
    inserted = 0
    with transaction(db_path) as conn:
        backlog = conn.execute("SELECT COUNT(*) FROM research_operation_queue WHERE state IN ('queued','running','retry')").fetchone()[0]
        pending_ids = {"INT-" + digest([config["source_id"], item["external_id"], item])[:32] for item in items}
        new_events = sum(not conn.execute("SELECT 1 FROM research_intel_events WHERE event_id=?", (identity,)).fetchone() for identity in pending_ids)
        if backlog + new_events > MAX_PENDING:
            raise ValueError("intake backpressure: acquire will retry without advancing cursor")
        conn.execute("INSERT OR IGNORE INTO research_source_snapshots VALUES (?,?,?,?,?,?,?)", (snapshot_id, config["source_id"], sha256, "sqlite:research_source_snapshots", now, PARSER_VERSION, content))
        for item in items:
            # Updating a source entry makes a new event; syndicated entries
            # share a root key without pretending to be independent evidence.
            event_id = "INT-" + digest([config["source_id"], item["external_id"], item])[:32]
            root = digest(item["root_url"])
            changed = conn.execute("INSERT OR IGNORE INTO research_intel_events VALUES (?,?,?,?,?,?,?,?)", (event_id, config["source_id"], root, snapshot_id, item["published_at"], now, now, canonical(item))).rowcount
            if changed:
                inserted += 1
                conn.execute("INSERT INTO research_operation_queue(job_id,kind,event_id,payload_json,state,retry_at,created_at,updated_at) VALUES (?,?,?,?,'queued',?,?,?)",
                             ("Q-" + digest(["verify_intel", event_id])[:32], "verify_intel", event_id, canonical({"event_id": event_id}), now, now, now))
                conn.execute("INSERT OR IGNORE INTO research_coverage_events VALUES (?,?,?,'',?)", (config["source_id"], event_id, "observed", now))
        conn.execute("UPDATE research_intel_sources SET cursor=?,last_success_at=?,error_category='',consecutive_failures=0 WHERE source_id=?", (snapshot_id, now, config["source_id"]))
    return {"source_id": config["source_id"], "snapshot_id": snapshot_id, "events": len(items), "inserted": inserted, "status": "acquired"}


def collect_due(*, db_path=None, fetcher=None, limit: int = 3) -> dict:
    seed = seed_sources(db_path=db_path)
    fetcher = fetcher or SafeFetcher(timeout=15)
    with read_connection(db_path) as conn:
        sources = [dict(r) for r in conn.execute("SELECT * FROM research_intel_sources ORDER BY COALESCE(last_attempt_at,'') ASC").fetchall()]
    results = []
    for source in sources:
        config = json.loads(source["config_json"])
        interval = min(config["interval_seconds"], 300 * 2 ** min(source["consecutive_failures"], 4)) if source["consecutive_failures"] else config["interval_seconds"]
        if not config["enabled"] or (source["last_attempt_at"] and _future(interval, source["last_attempt_at"]) > _now()):
            continue
        if len(results) >= min(10, max(1, limit)):
            break
        with transaction(db_path) as conn:
            conn.execute("UPDATE research_intel_sources SET last_attempt_at=? WHERE source_id=?", (_now(), config["source_id"]))
        try:
            _, _, content = fetcher.get(config["url"], allowed_hosts=[urlparse(config["url"]).hostname], max_bytes=MAX_SOURCE_BYTES)
            results.append(acquire(config, content, db_path=db_path))
        except Exception as exc:
            category = "invalid_source" if isinstance(exc, (ValueError, KeyError, TypeError)) else "transport_failure"
            with transaction(db_path) as conn:
                conn.execute("UPDATE research_intel_sources SET error_category=?,consecutive_failures=consecutive_failures+1 WHERE source_id=?", (category, config["source_id"]))
            results.append({"source_id": config["source_id"], "status": "failed", "error_category": category})
    return {"status": "degraded" if any(r["status"] == "failed" for r in results) else "succeeded", "results": results, **seed}


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
        source_url(payload.get("primary_url", ""))
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
