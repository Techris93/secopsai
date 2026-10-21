"""Measured coverage, queue health and readiness. Unknown denominators stay unknown."""
from __future__ import annotations

import json
import os
from contextlib import closing
from datetime import datetime, timedelta, timezone

import soc_store
from secopsai.research_operation_store import read_connection
from secopsai.research_operation_store import records, timestamp, transaction

STAGES = {"eligible", "observed", "artifact_acquired", "artifact_analyzed", "substantiated", "published", "skipped", "evidence_omitted", "evidence_truncated"}
ARTIFACT_ECOSYSTEMS = {"npm", "pypi", "crates", "open-vsx", "vscode-marketplace", "mcp-registry"}


def record_stage(source_id: str, event_key: str, stage: str, *, reason: str = "", db_path=None, connection=None) -> None:
    if stage not in STAGES or not source_id or not event_key or (stage in {"skipped", "evidence_omitted", "evidence_truncated"} and not reason):
        raise ValueError("coverage stage needs identifiers and an omission reason")
    def write(conn):
        conn.execute("INSERT OR IGNORE INTO research_coverage_events VALUES (?,?,?,?,?)", (source_id, event_key, stage, reason[:2000], soc_store.utc_now()))
    if connection is not None:
        write(connection)
    else:
        with transaction(db_path) as conn:
            write(conn)


def record_case_stage(case: dict, stage: str, *, db_path=None) -> None:
    # Join exact versions only. Case counts without a retained source event
    # are reported separately and never inflate this event funnel.
    with transaction(db_path) as conn:
        for subject in case.get("subjects", []):
            rows = conn.execute("SELECT feed_event_id,collector_id FROM registry_feed_events WHERE ecosystem=? AND package=? AND version=?", (subject.get("ecosystem"), subject.get("name"), subject.get("version")))
            for row in rows:
                record_stage(row["collector_id"], row["feed_event_id"], stage, connection=conn)


def _age(value: str | None, now: datetime) -> float | None:
    if not value:
        return None
    return max(0, (now - datetime.fromisoformat(timestamp(value).replace("Z", "+00:00"))).total_seconds())


def coverage_report(*, db_path=None, now=None, window_hours: int = 24) -> dict:
    if not 1 <= window_hours <= 720:
        raise ValueError("coverage window must be 1–720 hours")
    soc_store.init_db(db_path)
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(hours=window_hours)).isoformat().replace("+00:00", "Z")
    sources = []
    with read_connection(db_path) as conn:
        for row in conn.execute("SELECT * FROM registry_collectors ORDER BY ecosystem").fetchall():
            # Search the full indexed history for the true last successful
            # completion; repeated failures must not hide older success.
            last = conn.execute("SELECT max(completed_at) FROM registry_ingestion_runs WHERE collector_id=? AND status='completed'", (row["collector_id"],)).fetchone()[0]
            latest_attempt = conn.execute("SELECT status,started_at,completed_at FROM registry_ingestion_runs WHERE collector_id=? ORDER BY started_at DESC,run_id DESC LIMIT 1", (row["collector_id"],)).fetchone()
            counters = conn.execute("SELECT count(*) AS observed,sum(CASE WHEN json_extract(metadata_json,'$.content_prescan.status') IN ('hit','clean') THEN 1 ELSE 0 END) AS scanned,min(CASE WHEN json_extract(metadata_json,'$.content_prescan') IS NULL THEN collected_at END) AS oldest FROM registry_feed_events WHERE collector_id=? AND collected_at>=?", (row["collector_id"], since)).fetchone()
            skips = conn.execute("SELECT COALESCE(json_extract(metadata_json,'$.content_prescan.reason'),'unspecified') AS reason,count(*) AS count FROM registry_feed_events WHERE collector_id=? AND collected_at>=? AND json_extract(metadata_json,'$.content_prescan.status') IN ('error','skipped') GROUP BY reason", (row["collector_id"], since)).fetchall()
            stages = {r["stage"]: r["count"] for r in conn.execute("SELECT stage,count(*) AS count FROM research_coverage_events WHERE source_id=? AND observed_at>=? GROUP BY stage", (row["collector_id"], since))}
            config = json.loads(row["config_json"])
            delay = _age(last, now)
            sources.append({"source_id": row["collector_id"], "name": row["name"], "ecosystem": row["ecosystem"], "enabled": bool(row["enabled"]),
                            "coverage_mode": "artifact_scanning_bounded" if row["ecosystem"] in ARTIFACT_ECOSYSTEMS else "metadata_only",
                            "collection_mode": row["mode"], "eligible_events": None, "eligible_events_reason": "upstream universe denominator is not recorded",
                            "observed_events": counters["observed"], "artifacts_acquired": stages.get("artifact_acquired"), "artifacts_analyzed": counters["scanned"] or 0,
                            "substantiated": stages.get("substantiated", 0), "published": stages.get("published", 0),
                            "scan_fraction_of_observed": (counters["scanned"] or 0) / counters["observed"] if counters["observed"] else None,
                            "last_success_at": last, "delay_seconds": delay,
                            "last_attempt_at": latest_attempt["started_at"] if latest_attempt else None,
                            "last_attempt_status": latest_attempt["status"] if latest_attempt else None,
                            "last_attempt_completed_at": latest_attempt["completed_at"] if latest_attempt else None,
                            "interval_seconds": int(config.get("interval_seconds", 3600)),
                            "backlog_age_seconds": _age(counters["oldest"], now),
                            "fresh": delay is not None and delay <= 2 * int(config.get("interval_seconds", 3600)), "skip_reasons": [dict(s) for s in skips],
                            "evidence_omitted": stages.get("evidence_omitted"), "evidence_truncated": stages.get("evidence_truncated"),
                            "evidence_coverage_reason": "null means not instrumented for this source/window"})
        for row in conn.execute("SELECT * FROM research_intel_sources").fetchall():
            config = json.loads(row["config_json"])
            observed = conn.execute("SELECT count(*) FROM research_intel_events WHERE source_id=? AND first_observed_at>=?", (row["source_id"], since)).fetchone()[0]
            stages = {r["stage"]: r["count"] for r in conn.execute("SELECT stage,count(*) AS count FROM research_coverage_events WHERE source_id=? AND observed_at>=? GROUP BY stage", (row["source_id"], since))}
            delay = _age(row["last_success_at"], now)
            last_collection = conn.execute(
                "SELECT events_total,events_in_scope,historical_excluded,inserted_events,window_start,acquired_at,completed_at "
                "FROM research_source_collection_runs WHERE source_id=? ORDER BY completed_at DESC LIMIT 1",
                (row["source_id"],),
            ).fetchone()
            ingest_progress = conn.execute(
                "SELECT total_items,next_index,events_total,historical_excluded,window_start,started_at "
                "FROM research_source_ingest_progress WHERE source_id=?",
                (row["source_id"],),
            ).fetchone()
            source_collection = dict(last_collection) if last_collection else None
            if source_collection:
                source_collection["status"] = "completed"
            if ingest_progress:
                source_collection = {**(source_collection or {}), "status": "resumable", **dict(ingest_progress)}
            if row["last_attempt_at"] is None:
                attempt_status = "never_attempted"
            elif ingest_progress:
                attempt_status = "resumable"
            elif row["error_category"] == "intake_backpressure":
                attempt_status = "deferred"
            elif row["error_category"]:
                attempt_status = "failed"
            elif row["last_success_at"] and row["last_success_at"] >= row["last_attempt_at"]:
                attempt_status = "acquired"
            elif row["last_success_at"]:
                attempt_status = "interrupted_or_unknown"
            else:
                attempt_status = "unknown"
            sources.append({"source_id": row["source_id"], "name": config["name"], "coverage_mode": "source_reporting", "enabled": config["enabled"],
                            "collection_scope": ("bounded_revision_overlap" if config["parser"] == "msrc_rss" else
                                                 "bounded_recent_index" if config["parser"] in {"github_advisories", "openvsx_index", "jfrog_index", "socket_index"} else "bounded_published_feed"),
                            "eligible_events": None, "observed_events": observed, "last_success_at": row["last_success_at"],
                            "last_attempt_at": row["last_attempt_at"], "last_attempt_status": attempt_status,
                            "interval_seconds": int(config["interval_seconds"]), "delay_seconds": delay,
                            "fresh": delay is not None and delay <= config["interval_seconds"] * 2, "error_category": row["error_category"],
                            "consecutive_failures": row["consecutive_failures"], "sharing": config["sharing"],
                            "last_collection": source_collection,
                            "evidence_truncated": stages.get("evidence_truncated", 0), "evidence_omitted": stages.get("evidence_omitted", 0)})
        queue = {r["state"]: r["count"] for r in conn.execute("SELECT state,count(*) AS count FROM research_operation_queue GROUP BY state")}
        oldest = conn.execute("SELECT min(created_at) FROM research_operation_queue WHERE state IN ('queued','retry','running')").fetchone()[0]
        primary_preparation = conn.execute("""SELECT count(*) AS total,
            min(created_at) AS oldest,
            sum(CASE WHEN state='awaiting_review' THEN 1 ELSE 0 END) AS awaiting_review,
            sum(CASE WHEN state='dead_letter' THEN 1 ELSE 0 END) AS dead_letter
            FROM research_operation_queue WHERE kind='verify_intel'""").fetchone()
        primary_preparation_pending = conn.execute("SELECT count(*) FROM research_operation_queue WHERE kind='verify_intel' AND state IN ('queued','retry','running')").fetchone()[0]
        editions = [dict(r) for r in conn.execute("SELECT edition_id,edition_date,state,author_id,published_url,updated_at FROM research_editorial_editions ORDER BY edition_date DESC LIMIT 90")]
        ontology_pending = conn.execute("SELECT count(*) FROM ontology_sync_outbox WHERE status='queued'").fetchone()[0]
        ontology_oldest = conn.execute("SELECT min(created_at) FROM ontology_sync_outbox WHERE status='queued'").fetchone()[0]
        ontology_due = conn.execute("SELECT count(*) FROM ontology_sync_outbox WHERE status='queued' AND next_attempt_at<=?", (now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),)).fetchone()[0]
        ontology_retries = conn.execute("SELECT COALESCE(max(attempts),0) FROM ontology_sync_outbox WHERE status='queued'").fetchone()[0]
        ontology_validation_failures = conn.execute("SELECT count(*) FROM ontology_sync_outbox WHERE status='queued' AND failure_category='validation'").fetchone()[0]
        ontology_authorization_failures = conn.execute("SELECT count(*) FROM ontology_sync_outbox WHERE status='queued' AND failure_category='authorization'").fetchone()[0]
        ontology_ack = conn.execute("SELECT max(completed_at) FROM ontology_sync_delivery_batches WHERE acknowledged>0").fetchone()[0]
        ontology_last_batch = conn.execute("SELECT completed_at,attempted,acknowledged,failed,deferred,pending,failure_category FROM ontology_sync_delivery_batches ORDER BY completed_at DESC LIMIT 1").fetchone()
        rate_since = (now.astimezone(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
        ontology_ingress_24h = conn.execute("SELECT COALESCE(sum(inserted_chunks),0) FROM ontology_sync_enqueue_batches WHERE created_at>=?", (rate_since,)).fetchone()[0]
        ontology_ack_24h = conn.execute("SELECT COALESCE(sum(acknowledged),0) FROM ontology_sync_delivery_batches WHERE completed_at>=?", (rate_since,)).fetchone()[0]
        failures = conn.execute("SELECT count(*) FROM registry_ingestion_runs WHERE status='failed' AND started_at>=?", (since,)).fetchone()[0]
        artifact_rows = conn.execute("SELECT artifact_id,provenance_json FROM research_artifacts WHERE state='collected' ORDER BY updated_at DESC LIMIT 1000").fetchall()
    backed_up = {r["payload"].get("artifact_id") for r in records("artifact_backup", db_path=db_path, limit=10000) if r["payload"].get("status") == "completed"}
    backup_pending = sum(json.loads(r["provenance_json"]).get("source") == "secopsai_safe_registry_intake" and r["artifact_id"] not in backed_up for r in artifact_rows)
    vault_enabled = os.environ.get("SECOPSAI_ARTIFACT_VAULT", "0") == "1"
    gaps = [s["name"] for s in sources if s["enabled"] and not s["fresh"]]
    metadata = [s["name"] for s in sources if s["coverage_mode"] == "metadata_only"]
    return {"schema_version": "secopsai.research.coverage.v1", "as_of": now.isoformat(), "window_start": since, "window_hours": window_hours,
            "sources": sources, "queue": {"states": queue, "oldest_pending_age_seconds": _age(oldest, now)}, "editions": editions,
            "artifact_backup": {"enabled": vault_enabled, "pending_registered_public": backup_pending,
                                "coverage": "latest 1000 collected catalog entries; restricted and unregistered artifacts excluded"},
            "health": {"freshness_gaps": gaps, "collector_failures": failures, "dead_letters": queue.get("dead_letter", 0),
                       "primary_intel_pending_preparation": primary_preparation_pending,
                       "primary_intel_awaiting_human_review": primary_preparation["awaiting_review"] or 0,
                       "primary_intel_preparation_dead_letters": primary_preparation["dead_letter"] or 0,
                       "primary_intel_oldest_preparation_age_seconds": _age(primary_preparation["oldest"], now) if primary_preparation_pending else None,
                       "artifact_backup_pending": backup_pending if vault_enabled else None,
                       "ontology_pending": ontology_pending, "ontology_due_pending": ontology_due,
                       "ontology_oldest_age_seconds": _age(ontology_oldest, now),
                       "ontology_max_attempts": ontology_retries,
                       "ontology_validation_failures": ontology_validation_failures,
                       "ontology_authorization_failures": ontology_authorization_failures,
                       "ontology_last_acknowledged_at": ontology_ack,
                       "ontology_last_batch": dict(ontology_last_batch) if ontology_last_batch else None,
                       "ontology_new_unique_chunks_24h": ontology_ingress_24h,
                       "ontology_acknowledged_chunks_24h": ontology_ack_24h},
            "public_summary": f"Collection is bounded and does not establish comprehensive surveillance. {len(gaps)} enabled sources lack a fresh successful collection. {len(metadata)} registry collectors provide metadata coverage without artifact scanning. Unknown eligible-event and evidence-coverage denominators are reported as unknown."}


def readiness_report(*, db_path=None) -> dict:
    from secopsai.research_governance import accepted_requirement
    from secopsai.decision_policy import policy_status
    from secopsai.research_ai_triage import clef_enabled
    from secopsai.research_assurance import person

    report = coverage_report(db_path=db_path)
    roster = records("editorial_roster", db_path=db_path)
    roster_current = bool(roster)
    if roster:
        try:
            for duty in roster[0]["payload"]["days"].values():
                for key, role in (("author_id", "author"), ("editor_id", "editor"), ("backup_id", "editor")):
                    person(duty[key], role=role, db_path=db_path)
        except ValueError:
            roster_current = False
    requirements = {
        "named_seven_day_roster": roster_current,
        "research_authorization_and_legal_signoff": accepted_requirement("legal_signoff", db_path=db_path),
        "partner_telemetry_access": accepted_requirement("partner_agreement", db_path=db_path),
        "recovery_drill": bool(records("recovery_drill", db_path=db_path)),
        "held_out_quality_evaluation": accepted_requirement("research_quality_evaluation", db_path=db_path),
    }
    published_days = sorted({e["edition_date"] for e in report["editions"] if e["state"] == "published"})
    longest, current, prior = 0, 0, None
    for day in published_days:
        parsed = datetime.fromisoformat(day)
        current = current + 1 if prior and (parsed - prior).days == 1 else 1
        longest = max(longest, current)
        prior = parsed
    return {"coverage": report, "requirements": requirements, "missing_requirements": [k for k, v in requirements.items() if not v],
            "reviewed_daily_brief_streak": longest, "fourteen_day_gate_met": longest >= 14,
            "rpo_target_seconds": 300, "rto_target_seconds": 3600,
            "recovery_targets_proven": False, "decision_mode": policy_status()["mode"], "clef_enabled": clef_enabled(),
            "note": "Operational evidence, real identities and agreements must be supplied; software cannot create them."}
