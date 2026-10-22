from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

import soc_store
from secopsai import blog, research_post
from secopsai.research_assurance import (
    EDITORIAL_CHECKS, TECHNICAL_CHECKS, assess_claim, assurance_state, case_fingerprint,
    record_behavior, record_experiment, record_prior_art, register_person, review_case,
)
from secopsai.research_cases import add_evidence, create_case, get_case, update_case
from secopsai.research_coverage import coverage_report
from secopsai.research_editorial import (
    BRIEF_CHECKS, approve_edition, configure_roster, correct_edition, create_daily_brief,
    edit_edition, publish_edition, validate_release,
)
from secopsai.research_operation import execute, execute_hosted, hosted_projection
from secopsai.research_operation_store import digest, records
from secopsai.research_primary_intel import (
    acquire, claim_job, complete_job, configure_source, fail_job, heartbeat, intel_event, parse_source, pending_public_reviews, prepare_pending, verify_event,
)
from secopsai.research_reliability import _verify_statement

STATEMENT = "Static inspection found a credential file read in install.js."
CODE = "const secret = fs.readFileSync('.npmrc');"


@pytest.fixture
def db(tmp_path, monkeypatch):
    # These tests never read developer credentials or use live providers.
    monkeypatch.setenv("SECOPSAI_PRIMARY_INTEL", "0")
    monkeypatch.setenv("SECOPSAI_CLEF_PRESCREEN", "0")
    path = str(tmp_path / "operation.db")
    register_person({"person_id": "operator.owner", "display_name": "Test Operator", "roles": ["operator"], "qualification": "Synthetic operator fixture"}, actor="operator.owner", db_path=path)
    for identity, roles in (("alice", ["author", "researcher"]), ("bob", ["technical_reviewer", "editor", "researcher"]), ("carol", ["editor", "technical_reviewer"])):
        register_person({"person_id": identity, "display_name": identity.title(), "roles": roles, "qualification": "Synthetic qualified reviewer fixture"}, actor="operator.owner", db_path=path)
    return path


def case(db):
    value = create_case(title="Credential access in a synthetic release", summary=STATEMENT, owner="alice", confidence=95, db_path=db)
    return add_evidence(value["case_id"], evidence_type="static_analysis", title="Install script", sha256="a" * 64,
                        provenance="synthetic package fixture", locator="artifact-analysis:fixture/install.js",
                        metadata={"file_contents": {"install.js": CODE}}, db_path=db)


def assessment(value, **changes):
    evidence = value["evidence"][0]
    result = {"statement": STATEMENT, "assessment": "observation", "confidence": 81, "likelihood": 0.6,
              "malicious_behavior": True, "references": [{"evidence_id": evidence["evidence_id"], "selector": "/metadata/file_contents/install.js", "start": 0, "end": len(CODE), "excerpt": CODE}],
              "scope": {"versions": "fixture 1.0", "environment": "static source inspection", "sample_set": "one synthetic artifact", "observation_period": "2026-10-13"},
              "rationale": "The exact code calls the file reader; execution is not claimed.", "quality": "Direct code span, one artifact, no independent runtime evidence",
              "alternatives": ["A legitimate administration tool might read this file"], "contradictions": [], "limitations": ["Synthetic fixture; no runtime observation"]}
    result.update(changes)
    return result


def prior_art(value, db):
    return record_prior_art(value["case_id"], {"searches": [{"query": "fixture credential access", "index": "synthetic index", "searched_at": "2026-10-13T09:00:00Z"}],
                                            "earlier_reports": [], "contribution": "Independent static reproduction of a synthetic example", "limitations": ["Not a live novelty assessment"]}, actor="alice", db_path=db)


def reviews(value, db, draft=STATEMENT):
    assess_claim(value["case_id"], assessment(value), actor="bob", db_path=db)
    prior_art(value, db)
    for role, actor, checks in (("technical_reviewer", "bob", TECHNICAL_CHECKS), ("editor", "carol", EDITORIAL_CHECKS)):
        review_case(value["case_id"], {"role": role, "checks": dict.fromkeys(checks, "passed"), "draft": draft, "decision": "approved",
                                     "rationale": "Synthetic exact-draft review", "claim_statements": [STATEMENT]}, actor=actor, db_path=db)


def source(db, *, source_class="vendor", source_id="vendor"):
    return configure_source({"source_id": source_id, "name": "Synthetic vendor", "url": "https://vendor.example/feed", "parser": "normalized_json", "source_class": source_class, "enabled": True}, actor="operator.owner", db_path=db)


def event(db, *, config=None):
    config = config or source(db)
    body = json.dumps({"events": [{"external_id": "notice-1", "title": "Patch available", "excerpt": "A synthetic patch is available.", "url": "https://vendor.example/notice", "published_at": "2026-10-13T08:00:00Z"}]}).encode()
    outcome = acquire(config, body, db_path=db)
    with soc_store.connect(db) as conn:
        identity = conn.execute("SELECT event_id FROM research_intel_events WHERE snapshot_id=?", (outcome["snapshot_id"],)).fetchone()[0]
    return intel_event(identity, db_path=db), body


def verify(value, db, **changes):
    payload = {"decision": "verified", "primary_url": value["payload"]["url"], "summary": "The vendor reports a patch is available.", "rationale": "Checked the acquired primary notice", "defensive_action": "Apply the vendor patch after checking affected versions", "limitations": "The fixture does not establish exploitation", "attribution": "source_reported"}
    payload.update(changes)
    return verify_event(value["event_id"], payload, actor="bob", db_path=db)


def roster(db):
    return configure_roster({"days": {str(d): {"author_id": "alice", "editor_id": "carol", "backup_id": "bob"} for d in range(7)}}, actor="operator.owner", db_path=db)


def test_scores_identifiers_and_sandbox_presence_do_not_verify_claims():
    records = {"bundle": {"status": "succeeded"}, "corpus": {"E": "package steals secrets " + "a" * 64}, "sandbox_ids": ["E"], "assessments": {}}
    for statement in ("The package steals secrets.", "The package exfiltrated credentials.", "The artifact hash is " + "a" * 64):
        result = _verify_statement(statement, records)
        assert result["support_status"] == "unsupported" and result["confidence"] == 0


def test_exact_claim_support_preserves_confidence_separate_from_likelihood(db):
    value = case(db)
    assess_claim(value["case_id"], assessment(value), actor="bob", db_path=db)
    current = get_case(value["case_id"], db_path=db)["research_assurance"]["assessed_claims"][0]
    result = _verify_statement(STATEMENT, {"bundle": {"status": "succeeded"}, "assessments": {digest(STATEMENT): current}})
    assert result["support_status"] == "supported" and result["confidence"] == 81
    assert result["verification"]["likelihood"] == 0.6
    assert _verify_statement("Static inspection found successful exfiltration in install.js.", {"bundle": {"status": "succeeded"}, "assessments": {digest(STATEMENT): current}})["support_status"] == "unsupported"


@pytest.mark.parametrize("change", [{"confidence": float("nan")}, {"likelihood": 1.2}, {"confidence": True}, {"alternatives": []}])
def test_invalid_assessments_are_rejected(db, change):
    value = case(db)
    with pytest.raises(ValueError):
        assess_claim(value["case_id"], assessment(value, **change), actor="bob", db_path=db)


def test_span_mismatch_and_author_self_review_are_rejected(db):
    value = case(db)
    payload = assessment(value)
    payload["references"][0]["excerpt"] = "fabricated code"
    with pytest.raises(ValueError, match="span"):
        assess_claim(value["case_id"], payload, actor="bob", db_path=db)
    with pytest.raises(ValueError):
        assess_claim(value["case_id"], assessment(value), actor="alice", db_path=db)


def test_runtime_claim_cannot_use_static_code_as_execution_proof(db):
    value = case(db)
    with pytest.raises(ValueError, match="runtime"):
        assess_claim(value["case_id"], assessment(value, statement="The package executed and exfiltrated credentials."), actor="bob", db_path=db)


def test_reviews_are_bound_to_evidence_scope_author_and_exact_draft(db):
    value = case(db)
    reviews(value, db)
    assert get_case(value["case_id"], db_path=db)["research_assurance"]["ready"]
    assert not assurance_state(get_case(value["case_id"], db_path=db), draft=STATEMENT + " Victims were compromised.", db_path=db)["ready"]
    update_case(value["case_id"], summary=STATEMENT + " New scope.", db_path=db)
    assert not get_case(value["case_id"], db_path=db)["research_assurance"]["ready"]
    assert len(records("human_review", case_id=value["case_id"], db_path=db)) == 2


def test_score_plus_verdict_does_not_confirm_observation(db):
    value = case(db)
    value["verdicts"] = [{"verdict": "credible"}]
    assert research_post.confidence_grade(value)["label"] != "Confirmed"
    reviews(value, db)
    current = get_case(value["case_id"], db_path=db)
    current["verdicts"] = [{"verdict": "credible"}]
    assert research_post.confidence_grade(current)["label"] == "Confirmed"


def test_keyword_mapping_is_absent_until_a_human_reviews_behavior(db):
    value = case(db)
    assert research_post.attack_mapping(value) == []
    assess_claim(value["case_id"], assessment(value), actor="bob", db_path=db)
    record_behavior(value["case_id"], {"technique": "T1552.001", "statement": STATEMENT, "rationale": "The code reads a credential file"}, actor="bob", db_path=db)
    assert research_post.attack_mapping(get_case(value["case_id"], db_path=db))[0]["technique"] == "T1552.001"


def test_rejected_new_assessment_cannot_resurrect_older_approval(db):
    value = case(db)
    reviews(value, db)
    assess_claim(value["case_id"], assessment(value, assessment="disputed", contradictions=["Benign operation"], malicious_behavior=False), actor="bob", db_path=db)
    assert not get_case(value["case_id"], db_path=db)["research_assurance"]["technical_review_current"]


def test_model_or_unregistered_human_cannot_satisfy_review(db):
    value = case(db)
    with pytest.raises(ValueError):
        assess_claim(value["case_id"], assessment(value), actor="typesafe/jev-latest", db_path=db)
    with pytest.raises(ValueError):
        register_person({"person_id": "clef", "display_name": "Model", "roles": ["technical_reviewer"], "qualification": "model"}, actor="operator.owner", db_path=db)


def test_changed_intel_reviewer_invalidates_brief_and_revoked_roster(db):
    from secopsai.research_coverage import readiness_report
    value, _ = event(db)
    verify(value, db)
    roster(db)
    edition = create_daily_brief(db_path=db)
    assert edition["draft"]["items"]
    register_person({"person_id": "bob", "display_name": "Bob", "roles": ["technical_reviewer", "editor", "researcher"],
                     "qualification": "Changed qualification assertion"}, actor="operator.owner", db_path=db)
    with pytest.raises(ValueError, match="verification changed"):
        approve_edition(edition["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "checked", "expected_fingerprint": edition["fingerprint"],
                                               "reviewed_draft": edition["draft"]["body_markdown"]}, actor="carol", db_path=db)
    register_person({"person_id": "bob", "display_name": "Bob", "roles": ["technical_reviewer", "editor", "researcher"],
                     "qualification": "Changed qualification assertion", "active": False}, actor="operator.owner", db_path=db)
    assert not readiness_report(db_path=db)["requirements"]["named_seven_day_roster"]


def test_intake_stores_bytes_events_and_queue_before_cursor_and_is_idempotent(db):
    value, body = event(db)
    repeated = acquire(source(db), body, db_path=db)
    assert repeated["inserted"] == 0
    with soc_store.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM research_operation_queue").fetchone()[0] == 1
        snapshot = conn.execute("SELECT content,sha256 FROM research_source_snapshots").fetchone()
        assert hashlib.sha256(snapshot[0]).hexdigest() == snapshot[1]
        cursor = conn.execute("SELECT cursor FROM research_intel_sources").fetchone()[0]
    assert cursor == value["snapshot_id"]


def test_human_source_review_queue_only_exposes_public_archived_events(db):
    public_event, _ = event(db)
    private = configure_source({"source_id": "private-source", "name": "Synthetic restricted source",
                                "url": "https://private.example/feed", "parser": "normalized_json",
                                "source_class": "partner", "sharing": "restricted", "enabled": True},
                               actor="operator.owner", db_path=db)
    body = json.dumps({"events": [{"external_id": "private-1", "title": "Private notice", "excerpt": "Do not project this excerpt.",
                                    "url": "https://private.example/notice"}]}).encode()
    acquire(private, body, db_path=db)
    pending = pending_public_reviews(db_path=db)
    assert [item["event_id"] for item in pending] == [public_event["event_id"]]
    assert pending[0]["excerpt"] == "A synthetic patch is available."


def test_automatic_intel_preparation_moves_work_to_human_review_without_verifying(db):
    value, _ = event(db)
    result = prepare_pending(db_path=db, limit=10)
    assert result["prepared"] == 1 and result["pending"] == 0 and result["awaiting_human_review"] == 1
    with soc_store.connect(db) as conn:
        queue = conn.execute("SELECT state,result_json FROM research_operation_queue WHERE event_id=?", (value["event_id"],)).fetchone()
    packet = json.loads(queue["result_json"])
    assert queue["state"] == "awaiting_review"
    assert packet["assessment"] == "source_reported_unverified"
    assert packet["human_review_required"] is True
    assert packet["provenance"]["sha256"] == value["sha256"]
    assert not records("intel_verification", db_path=db)
    pending = pending_public_reviews(db_path=db)
    assert pending[0]["preparation"]["event_id"] == value["event_id"]


def test_human_review_backlog_does_not_consume_source_intake_capacity(db, monkeypatch):
    config = source(db)
    first = json.dumps({"events": [{"external_id": "first", "title": "First", "excerpt": "First item", "url": "https://vendor.example/first"}]}).encode()
    acquire(config, first, db_path=db)
    assert prepare_pending(db_path=db)["awaiting_human_review"] == 1
    monkeypatch.setattr("secopsai.research_primary_intel.MAX_PENDING", 1)
    second = json.dumps({"events": [{"external_id": "second", "title": "Second", "excerpt": "Second item", "url": "https://vendor.example/second"}]}).encode()
    assert acquire(config, second, db_path=db)["inserted"] == 1
    with soc_store.connect(db) as conn:
        states = [row[0] for row in conn.execute("SELECT state FROM research_operation_queue ORDER BY created_at,event_id")]
    assert states == ["awaiting_review", "queued"]


def test_msrc_large_feed_uses_revision_window_and_accounts_for_historical_entries(db):
    from datetime import timedelta
    from secopsai.research_primary_intel import parse_source_report, msrc_window_start

    now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    items = []
    for index in range(5280):
        published = now - timedelta(days=30 + index % 100)
        updated = published
        if index == 0:
            published = updated = now - timedelta(hours=1)
        elif index == 1:
            updated = now - timedelta(minutes=30)
        items.append(
            f"<entry><id>ADV-{index:04d}</id><title>Advisory {index}</title>"
            f"<updated>{updated.isoformat()}</updated><published>{published.isoformat()}</published>"
            f"<link href=\"https://msrc.example/advisory/{index}\"/></entry>"
        )
    body = ("<feed xmlns=\"http://www.w3.org/2005/Atom\"><id>fixture</id><title>MSRC</title>"
            f"<updated>{now.isoformat()}</updated>{''.join(items)}</feed>").encode()
    config = {**source(db, source_id="msrc"), "parser": "msrc_rss"}
    report = parse_source_report({**config, "msrc_lookback_start": msrc_window_start(now=now)}, body, now=now)
    assert report["events_total"] == 5280
    assert report["events_in_scope"] == 2 and report["historical_excluded"] == 5278
    assert report["events_total"] == report["events_in_scope"] + report["historical_excluded"]
    assert report["items"][1]["published_at"].startswith("2026-09-")
    assert report["items"][1]["source_updated_at"] == "2026-10-17T11:30:00Z"
    assert msrc_window_start(last_success_at="2026-10-10T12:00:00Z", now=now) == "2026-10-07T12:00:00Z"


def test_source_ingest_resumes_archived_snapshot_after_queue_backpressure(db, monkeypatch):
    from secopsai import research_primary_intel as intake
    config = source(db)
    monkeypatch.setattr(intake, "EVENT_BATCH_SIZE", 2)
    monkeypatch.setattr(intake, "MAX_PENDING", 2)
    body = json.dumps({"events": [
        {"external_id": f"notice-{i}", "title": f"Notice {i}", "excerpt": "Fixture", "url": f"https://vendor.example/{i}"}
        for i in range(3)
    ]}).encode()
    with pytest.raises(intake.IntakeBackpressureError):
        acquire(config, body, db_path=db)
    with soc_store.connect(db) as conn:
        progress = conn.execute("SELECT snapshot_id,next_index,total_items FROM research_source_ingest_progress WHERE source_id=?", (config["source_id"],)).fetchone()
        assert tuple(progress)[1:] == (2, 3)
        assert conn.execute("SELECT cursor FROM research_intel_sources WHERE source_id=?", (config["source_id"],)).fetchone()[0] == ""
        conn.execute("UPDATE research_operation_queue SET state='completed'")
    monkeypatch.setattr(intake, "seed_sources", lambda **kwargs: {"sources": [], "unsupported_sources": []})

    class NeverFetch:
        def get(self, *args, **kwargs):
            raise AssertionError("resumable intake must use its archived response")

    result = intake.collect_due(db_path=db, fetcher=NeverFetch())
    assert result["status"] == "succeeded"
    assert result["results"][0]["snapshot_id"] == progress["snapshot_id"]
    with soc_store.connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM research_intel_events WHERE source_id=?", (config["source_id"],)).fetchone()[0] == 3
        assert conn.execute("SELECT count(*) FROM research_source_ingest_progress WHERE source_id=?", (config["source_id"],)).fetchone()[0] == 0
        assert conn.execute("SELECT cursor FROM research_intel_sources WHERE source_id=?", (config["source_id"],)).fetchone()[0] == progress["snapshot_id"]
    collection = next(item for item in coverage_report(db_path=db)["sources"] if item["source_id"] == config["source_id"])
    assert collection["last_collection"]["status"] == "completed"
    assert collection["last_collection"]["events_in_scope"] == 3


def test_invalid_intake_does_not_advance_cursor(db):
    config = source(db)
    with pytest.raises(ValueError):
        acquire(config, b'{}', db_path=db)
    with soc_store.connect(db) as conn:
        assert conn.execute("SELECT cursor FROM research_intel_sources").fetchone()[0] == ""


def test_queue_expiry_fences_old_workers_and_completion_redelivery(db):
    event(db)
    first = claim_job(worker_id="worker-one", db_path=db, now="2099-01-01T00:00:00Z", lease_seconds=30)
    second = claim_job(worker_id="worker-two", db_path=db, now="2099-01-01T00:01:00Z")
    assert second["job_id"] == first["job_id"] and second["lease_token"] != first["lease_token"]
    with pytest.raises(ValueError, match="stale"):
        complete_job(first["job_id"], first["lease_token"], {}, db_path=db, now="2099-01-01T00:01:01Z")
    result = {"normalization": "done"}
    assert complete_job(second["job_id"], second["lease_token"], result, db_path=db, now="2099-01-01T00:01:01Z")["reused"] is False
    assert complete_job(second["job_id"], second["lease_token"], result, db_path=db, now="2099-01-01T00:02:00Z")["reused"] is True
    with pytest.raises(ValueError, match="conflicting"):
        complete_job(second["job_id"], second["lease_token"], {"changed": True}, db_path=db)


def test_nonretryable_failure_becomes_visible_dead_letter(db):
    event(db)
    job = claim_job(worker_id="worker", db_path=db)
    assert fail_job(job["job_id"], job["lease_token"], category="invalid_evidence", retryable=False, db_path=db)["state"] == "dead_letter"
    assert coverage_report(db_path=db)["health"]["dead_letters"] == 1


def test_aggregator_cannot_be_its_own_primary_corroboration(db):
    value, _ = event(db, config=source(db, source_class="aggregator"))
    with pytest.raises(ValueError, match="primary source"):
        verify(value, db)


def test_feed_timestamp_does_not_turn_collection_into_publication_time(db):
    config = source(db)
    item = parse_source(config, json.dumps({"events": [{"external_id": "n", "title": "No date", "excerpt": "No date", "url": "https://vendor.example/n"}]}).encode())[0]
    assert item["published_at"] is None and item["observed_exploitation_by_secopsai"] is False


def test_daily_workflow_requires_real_roster_and_duty_editor(db, tmp_path):
    unassigned = create_daily_brief(db_path=db)
    assert unassigned["state"] == "verifying"
    assert unassigned["author_id"] == "secopsai-automated-research-desk"
    assert unassigned["draft"]["duty"]["unassigned"] is True
    assert unassigned["draft"]["items"] == []
    roster(db)
    value, _ = event(db)
    verify(value, db)
    edition = create_daily_brief(db_path=db)
    assert len(edition["draft"]["items"]) == 1
    assert edition["draft"]["items"][0]["verification_fingerprint"]
    assert create_daily_brief(db_path=db)["reused"] is True
    with pytest.raises(ValueError):
        publish_edition(edition["edition_id"], actor="carol", db_path=db, paths=blog.BlogPaths(root=tmp_path / "blog"))
    with pytest.raises(ValueError):
        approve_edition(edition["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "checked", "expected_fingerprint": edition["fingerprint"], "reviewed_draft": edition["draft"]["body_markdown"]}, actor="alice", db_path=db)
    approve_edition(edition["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "checked", "expected_fingerprint": edition["fingerprint"], "reviewed_draft": edition["draft"]["body_markdown"]}, actor="carol", db_path=db)
    published = publish_edition(edition["edition_id"], actor="carol", db_path=db, paths=blog.BlogPaths(root=tmp_path / "blog"))
    assert published["published"] and (tmp_path / "blog" / "posts" / (edition["draft"]["slug"] + ".json")).is_file()
    with pytest.raises(ValueError, match="correction workflow"):
        approve_edition(edition["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "repeat approval", "expected_fingerprint": edition["fingerprint"], "reviewed_draft": edition["draft"]["body_markdown"]}, actor="carol", db_path=db)


def test_automated_brief_picks_up_late_roster_and_preserves_human_edits(db):
    from secopsai.research_editorial import AUTOMATED_BRIEF_AUTHOR_ID

    value, _ = event(db)
    local_date = datetime.fromisoformat(value["first_observed_at"].replace("Z", "+00:00")).astimezone(ZoneInfo("Europe/Istanbul")).date().isoformat()
    initial = create_daily_brief(date=local_date, db_path=db)
    assert initial["author_id"] == AUTOMATED_BRIEF_AUTHOR_ID
    assert initial["draft"]["duty"]["unassigned"] is True

    roster(db)
    verify(value, db)
    refreshed = create_daily_brief(date=local_date, db_path=db)
    assert refreshed["author_id"] == AUTOMATED_BRIEF_AUTHOR_ID
    assert refreshed["draft"]["duty"]["editor_id"] == "carol"
    assert len(refreshed["draft"]["items"]) == 1

    revised_text = refreshed["draft"]["body_markdown"] + "\n\nHuman editorial note."
    edit_edition(refreshed["edition_id"], {"body_markdown": revised_text}, actor="alice", db_path=db)
    second_source = source(db, source_id="vendor-two")
    body = json.dumps({"events": [{"external_id": "notice-2", "title": "Second patch", "excerpt": "A second synthetic patch is available.",
                                    "url": "https://vendor.example/second", "published_at": "2026-10-13T08:00:00Z"}]}).encode()
    acquired = acquire(second_source, body, db_path=db)
    with soc_store.connect(db) as conn:
        event_id = conn.execute("SELECT event_id FROM research_intel_events WHERE snapshot_id=?", (acquired["snapshot_id"],)).fetchone()[0]
    verify(intel_event(event_id, db_path=db), db)

    waiting = create_daily_brief(date=local_date, db_path=db)
    assert waiting["updates_waiting_for_editor"] is True
    assert waiting["draft"]["body_markdown"] == revised_text
    assert len(waiting["draft"]["items"]) == 1
    pending_update = hosted_projection(db_path=db)["editions"][0]["pending_update"]
    reconciled_text = revised_text + "\n\n## Second patch\n\nSource: https://vendor.example/second\nA second synthetic patch is available."
    reconciled = edit_edition(waiting["edition_id"], {
        "body_markdown": reconciled_text,
        "incorporate_update_fingerprint": pending_update["fingerprint"],
    }, actor="alice", db_path=db)
    assert len(reconciled["draft"]["items"]) == 2
    assert "Human editorial note." in reconciled["draft"]["body_markdown"]
    assert "https://vendor.example/second" in reconciled["draft"]["sources"]
    assert hosted_projection(db_path=db)["editions"][0].get("pending_update") is None


def test_published_brief_late_source_requires_a_reviewed_correction(db, tmp_path):
    roster(db)
    value, _ = event(db)
    verify(value, db)
    local_date = datetime.fromisoformat(value["first_observed_at"].replace("Z", "+00:00")).astimezone(ZoneInfo("Europe/Istanbul")).date().isoformat()
    edition = create_daily_brief(date=local_date, db_path=db)
    approve_edition(edition["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "Checked the exact edition", "expected_fingerprint": edition["fingerprint"], "reviewed_draft": edition["draft"]["body_markdown"]}, actor="carol", db_path=db)
    paths = blog.BlogPaths(root=tmp_path / "blog")
    published = publish_edition(edition["edition_id"], actor="carol", db_path=db, paths=paths)
    assert published["published"]

    second_source = source(db, source_id="vendor-correction")
    body = json.dumps({"events": [{"external_id": "notice-correction", "title": "Correction notice", "excerpt": "A later patch notice.",
                                    "url": "https://vendor.example/correction", "published_at": "2026-10-13T08:00:00Z"}]}).encode()
    acquired = acquire(second_source, body, db_path=db)
    with soc_store.connect(db) as conn:
        event_id = conn.execute("SELECT event_id FROM research_intel_events WHERE snapshot_id=?", (acquired["snapshot_id"],)).fetchone()[0]
    verify(intel_event(event_id, db_path=db), db)
    create_daily_brief(date=local_date, db_path=db)
    pending = hosted_projection(db_path=db)["editions"][0]["pending_update"]

    correction_body = edition["draft"]["body_markdown"] + "\n\n## Correction notice\n\nSource: https://vendor.example/correction\nA later patch notice."
    corrected = correct_edition(edition["edition_id"], {
        "action": "correction", "reason": "Include newly verified source reporting",
        "body_markdown": correction_body, "incorporate_update_fingerprint": pending["fingerprint"],
    }, actor="carol", db_path=db)
    assert len(corrected["draft"]["items"]) == 2
    with pytest.raises(ValueError, match="approval"):
        publish_edition(edition["edition_id"], actor="carol", db_path=db, paths=paths)
    approve_edition(corrected["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "Reviewed the corrected exact edition", "expected_fingerprint": corrected["fingerprint"], "reviewed_draft": corrected["draft"]["body_markdown"]}, actor="carol", db_path=db)
    correction_published = publish_edition(corrected["edition_id"], actor="carol", db_path=db, paths=paths)
    assert correction_published["published"]
    assert hosted_projection(db_path=db)["editions"][0].get("pending_update") is None


def test_edition_edits_and_source_decision_changes_invalidate_release(db):
    roster(db)
    value, _ = event(db)
    verify(value, db)
    edition = create_daily_brief(db_path=db)
    approve_edition(edition["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "checked", "expected_fingerprint": edition["fingerprint"], "reviewed_draft": edition["draft"]["body_markdown"]}, actor="carol", db_path=db)
    verify(value, db, defensive_action="A different mitigation")
    with pytest.raises(ValueError):
        validate_release(edition["edition_id"], edition["draft"], db_path=db)
    edit_edition(edition["edition_id"], {"summary": "Changed text"}, actor="alice", db_path=db)
    with pytest.raises(ValueError):
        validate_release(edition["edition_id"], edition["draft"], db_path=db)


def test_unreviewed_research_cannot_publish_via_generic_blog_boundary(db, tmp_path):
    value = case(db)
    draft = blog.draft_research_case(value, paths=blog.BlogPaths(root=tmp_path / "blog"))
    with pytest.raises(ValueError, match="review"):
        blog.publish(draft["draft_path"], confirm=True, db_path=db, paths=blog.BlogPaths(root=tmp_path / "blog"))


def test_unknown_coverage_denominators_remain_unknown_and_private_notes_are_not_projected(db):
    event(db)
    coverage = coverage_report(db_path=db)
    assert coverage["sources"][0]["eligible_events"] is None
    assert coverage["sources"][0]["fresh"] is True
    projection = hosted_projection(db_path=db)
    assert "claim_assessment" not in projection and "content" not in projection
    assert projection["pending_source_reviews"][0]["title"] == "Patch available"
    assert projection["pending_source_reviews"][0]["excerpt"] == "A synthetic patch is available."
    assert projection["decision_mode"] == "observe" and projection["clef_enabled"] is False


def test_primary_source_coverage_explains_stale_attempt_state(db):
    config = source(db)
    with soc_store.connect(db) as connection:
        connection.execute("UPDATE research_intel_sources SET last_attempt_at='2026-10-21T10:00:00Z',error_category='source_http_403',consecutive_failures=2 WHERE source_id=?", (config["source_id"],))
        connection.commit()
    row = next(item for item in coverage_report(db_path=db)["sources"] if item["source_id"] == config["source_id"])
    assert row["last_attempt_status"] == "failed"
    assert row["error_category"] == "source_http_403"
    assert row["interval_seconds"] == config["interval_seconds"]


def test_hosted_duplicate_command_is_atomic_and_conflicting_delivery_rejected(db):
    payload = {"action": "source-configure", "actor": "operator.owner", "data": {"source_id": "second", "name": "Second source", "url": "https://vendor.example/second", "parser": "rss", "source_class": "vendor"}}
    first = execute_hosted("command-123", payload, db_path=db)
    assert execute_hosted("command-123", payload, db_path=db) == first
    assert len(records("source_configuration", db_path=db)) == 1
    payload["data"]["name"] = "Changed"
    with pytest.raises(ValueError, match="conflicting"):
        execute_hosted("command-123", payload, db_path=db)


def test_reviewer_qualification_change_invalidates_claims_and_approvals(db):
    value = case(db)
    reviews(value, db)
    register_person({"person_id": "bob", "display_name": "Bob", "roles": ["technical_reviewer", "editor", "researcher"], "qualification": "Changed qualification"}, actor="operator.owner", db_path=db)
    assert not get_case(value["case_id"], db_path=db)["research_assurance"]["ready"]
    register_person({"person_id": "carol", "display_name": "Carol", "roles": ["editor"], "qualification": "Revoked fixture", "active": False}, actor="operator.owner", db_path=db)
    assert not get_case(value["case_id"], db_path=db)["research_assurance"]["editorial_review_current"]


@pytest.mark.parametrize("statement", ["Actor Blue owns this payload hash " + "a" * 64, "82 victims were compromised by this package."])
def test_lab_code_cannot_prove_victim_or_actor_attribution(db, statement):
    value = case(db)
    with pytest.raises(ValueError):
        assess_claim(value["case_id"], assessment(value, statement=statement), actor="bob", db_path=db)


def test_advisory_target_requires_exact_independent_review(db):
    from secopsai.research_osv import _release_review
    value = case(db)
    reviews(value, db)
    with pytest.raises(ValueError, match="OSV review"):
        _release_review(get_case(value["case_id"], db_path=db), STATEMENT, actor="carol", db_path=db)
    for role, actor, checks in (("technical_reviewer", "bob", TECHNICAL_CHECKS), ("editor", "carol", EDITORIAL_CHECKS)):
        review_case(value["case_id"], {"target": "osv", "role": role, "checks": dict.fromkeys(checks, "passed"), "draft": STATEMENT, "decision": "approved", "rationale": "Reviewed exact advisory", "claim_statements": [STATEMENT]}, actor=actor, db_path=db)
    assert assurance_state(get_case(value["case_id"], db_path=db), draft=STATEMENT, target="osv", db_path=db)["ready"]
    with pytest.raises(ValueError, match="safety gates"):
        _release_review(get_case(value["case_id"], db_path=db), STATEMENT, actor="carol", db_path=db)
    with pytest.raises(ValueError):
        _release_review(get_case(value["case_id"], db_path=db), STATEMENT + " New impact.", actor="carol", db_path=db)


def test_human_event_verification_completes_the_durable_queue(db):
    value, _ = event(db)
    verify(value, db)
    with soc_store.connect(db) as conn:
        assert conn.execute("SELECT state FROM research_operation_queue").fetchone()[0] == "completed"
    assert claim_job(worker_id="idle-worker", db_path=db) is None


def test_consistent_recovery_reconciles_rows_and_source_hashes(db, tmp_path):
    from secopsai.research_recovery import recovery_drill, storage_assessment
    event(db)
    result = recovery_drill(output_dir=str(tmp_path / "restores"), actor="operator.owner", db_path=db)
    assert result["status"] == "passed" and result["reconciled_tables"] > 10
    assert result["source_hashes_verified"] and not result["rpo_target_proven"]
    assert storage_assessment(db_path=db)["migration_ready"] is False
    with pytest.raises(ValueError):
        recovery_drill(output_dir="", actor="operator.owner", db_path=db)


def test_recovery_detects_tampered_source_bytes(db, tmp_path):
    from secopsai.research_recovery import recovery_drill
    event(db)
    with soc_store.connect(db) as conn:
        conn.execute("UPDATE research_source_snapshots SET content=?", (b"tampered",))
    with pytest.raises(ValueError, match="provenance"):
        recovery_drill(output_dir=str(tmp_path / "restores"), actor="operator.owner", db_path=db)
    assert not records("recovery_drill", db_path=db)


def test_hosted_fault_rolls_back_the_applied_action_and_receipt(db, monkeypatch):
    from secopsai import research_operation_store
    payload = {"action": "person-register", "actor": "operator.owner", "data": {"person_id": "new.person", "display_name": "Test", "roles": ["researcher"], "qualification": "Synthetic test"}}
    real_append = research_operation_store.append
    def fail_receipt(kind, *args, **kwargs):
        if kind == "hosted_command":
            raise OSError("synthetic lost commit")
        return real_append(kind, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(research_operation_store, "append", fail_receipt)
        with pytest.raises(OSError):
            execute_hosted("rollback", payload, db_path=db)
    assert not any(p["person_id"] == "new.person" for p in execute("people", db_path=db)["people"])
    execute_hosted("rollback", payload, db_path=db)
    assert any(p["person_id"] == "new.person" for p in execute("people", db_path=db)["people"])


def test_release_comparison_requires_complete_mcp_catalog_and_keeps_annotations_untrusted(db):
    from secopsai.research_methods import compare_releases
    before = {"package": "fixture/mcp", "version": "1", "origin": "https://fixture.example/1", "acquired_at": "2026-10-13T09:00:00Z", "artifact_sha256": "a" * 64,
              "catalog_complete": True, "tools": [{"name": "read", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}}]}
    after = {**before, "version": "2", "artifact_sha256": "b" * 64, "tools": [{"name": "read", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": False}}]}
    result = compare_releases({"program": "ai_agent_security", "before": before, "after": after}, actor="alice", db_path=db)
    assert result["payload"]["observations"][0]["assessment"] == "metadata_difference"
    with pytest.raises(ValueError, match="complete"):
        compare_releases({"program": "ai_agent_security", "before": before, "after": {**after, "catalog_complete": False}}, actor="alice", db_path=db)


def test_metrics_do_not_invent_quality_denominators_or_accept_nonfinite_effort(db):
    from secopsai.research_metrics import metrics_report, record_outcome
    value = case(db)
    input = {"outcome": "effort", "reference": "timesheet:fixture", "occurred_at": "2026-10-13T09:00:00Z", "rationale": "Fixture time", "researcher_hours": 2, "cost": 10, "currency": "USD"}
    record_outcome(value["case_id"], input, actor="alice", db_path=db)
    with pytest.raises(ValueError):
        record_outcome(value["case_id"], {**input, "cost": float("inf")}, actor="alice", db_path=db)
    report = metrics_report(db_path=db)
    assert report["researcher_hours"] == 2 and report["miss_rate"] is None
    assert report["cost_per_historically_accepted_case"]["USD"] is None


def test_requirement_revocation_expiration_and_no_legal_fabrication(db):
    from secopsai.research_governance import accepted_requirement, operational_requirement
    value = {"kind": "legal_signoff", "status": "accepted", "responsible_person": "Synthetic counsel fixture", "scope": "Fixture only", "reference": "fixture agreement", "recorded_at": "2026-10-13T09:00:00Z", "limitations": "Not an actual legal opinion"}
    assert not accepted_requirement("legal_signoff", db_path=db)
    operational_requirement(value, actor="operator.owner", db_path=db)
    assert accepted_requirement("legal_signoff", db_path=db)
    operational_requirement({**value, "status": "revoked"}, actor="operator.owner", db_path=db)
    assert not accepted_requirement("legal_signoff", db_path=db)
    operational_requirement({**value, "expires_at": "2000-01-01T00:00:00Z"}, actor="operator.owner", db_path=db)
    assert not accepted_requirement("legal_signoff", db_path=db)


def test_watchdog_reports_failures_without_secrets_and_refuses_redirects(monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("research_watchdog", "scripts/research_operation_watchdog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "synthetic-confidential-token")
    report = module.inspect(reader=lambda *args: (_ for _ in ()).throw(OSError("synthetic-confidential-token")))
    assert report["status"] == "failed" and "synthetic-confidential-token" not in json.dumps(report)
    with pytest.raises(ValueError):
        module.fetch("https://user:password@fixture.example/status")
    with pytest.raises(ValueError, match="redirect"):
        module.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.example/")


def test_delivery_watchdog_keeps_source_freshness_visible_without_failing_delivery_scope():
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)

    def reader(url, _token):
        if url.endswith("/status"):
            return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                               "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
        if "/research/operation" in url:
            return json.dumps({"synced_at": now.isoformat(), "coverage": {"health": {
                "freshness_gaps": ["Synthetic stale source"], "dead_letters": 0,
                "artifact_backup_pending": 0, "ontology_pending": 0,
            }}}).encode()
        return b"<html>synthetic</html>"

    delivery = inspect(reader=reader, now=now, scope="delivery")
    assert delivery["status"] == "passed"
    assert delivery["operational_status"] == "degraded"
    assert delivery["checks"]["research_operation"]["freshness_gaps"] == ["Synthetic stale source"]
    assert delivery["warnings"] == ["enabled source freshness needs review: Synthetic stale source"]
    assert delivery["blockers"] == []

    operations = inspect(reader=reader, now=now, scope="all")
    assert operations["status"] == "failed"
    assert operations["operational_status"] == "degraded"
    assert operations["blockers"] == ["enabled research sources are outside their freshness targets"]

    def dead_letter_reader(url, token):
        raw = reader(url, token)
        if "/research/operation" not in url:
            return raw
        value = json.loads(raw)
        value["coverage"]["health"]["dead_letters"] = 1
        return json.dumps(value).encode()

    blocked_delivery = inspect(reader=dead_letter_reader, now=now, scope="delivery")
    assert blocked_delivery["status"] == "failed"
    assert blocked_delivery["blockers"] == ["research delivery has dead-letter items requiring review"]


def test_routine_delivery_scope_accepts_only_measurably_progressing_backlog():
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)

    def reader_for(*, oldest=900, last_ack=now.isoformat()):
        def reader(url, _token):
            if url.endswith("/status"):
                return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                                   "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
            if "/research/operation" in url:
                return json.dumps({"synced_at": now.isoformat(), "coverage": {"health": {
                    "freshness_gaps": [], "dead_letters": 0, "artifact_backup_pending": 0,
                    "ontology_pending": 37, "ontology_oldest_age_seconds": oldest,
                    "ontology_last_acknowledged_at": last_ack,
                    "ontology_validation_failures": 0, "ontology_authorization_failures": 0,
                }}}).encode()
            return b"<html>synthetic</html>"
        return reader

    routine = inspect(reader=reader_for(), now=now, scope="delivery", allow_pending=True)
    assert routine["status"] == "in_progress" and routine["decision_final"] is False
    assert routine["blockers"] == []
    assert "37 durable chunk(s) pending" in routine["warnings"][0]

    strict = inspect(reader=reader_for(), now=now, scope="delivery")
    assert strict["status"] == "failed"
    assert strict["blockers"] == ["semantic delivery has unacknowledged durable chunks"]

    overdue = inspect(reader=reader_for(oldest=7201), now=now, scope="delivery", allow_pending=True)
    assert overdue["status"] == "failed"
    assert overdue["blockers"] == ["oldest semantic delivery exceeds the two-hour service window"]


def test_watchdog_treats_a_superseded_worker_run_as_provisional_not_failed():
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 17, 16, 37, tzinfo=timezone.utc)

    def reader(url, _token):
        if url.endswith("/status"):
            return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                               "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
        if "/research/operation" in url:
            return json.dumps({"synced_at": now.isoformat(), "coverage": {"health": {
                "freshness_gaps": ["Synthetic stale source"], "dead_letters": 0,
                "artifact_backup_pending": 0, "ontology_pending": 34,
                "ontology_oldest_age_seconds": 9000,
            }}}).encode()
        return b"<html>synthetic</html>"

    # GitHub cancels a queued run when a newer dispatch replaces it: no blocker.
    superseded = inspect(reader=reader, now=now, worker_active=False,
                         upstream_worker_conclusion="cancelled", upstream_worker_run_id="39048013659",
                         upstream_worker_cancelled_before_start=True)
    assert superseded["blockers"] == []
    assert superseded["status"] == "in_progress"
    assert superseded["decision_final"] is False
    assert any("superseded by a newer run" in item for item in superseded["warnings"])

    # A cancellation after a worker started is a real incomplete run too.
    cancelled_after_start = inspect(reader=reader, now=now, worker_active=False,
                                    upstream_worker_conclusion="cancelled", upstream_worker_run_id="2",
                                    upstream_worker_started_at="2026-10-17T16:30:00Z")
    assert cancelled_after_start["status"] == "failed"
    assert "Research Worker run 2 concluded cancelled" in cancelled_after_start["blockers"]

    # A run that actually failed or timed out still blocks.
    for conclusion in ("failure", "timed_out"):
        failed = inspect(reader=reader, now=now, worker_active=False,
                         upstream_worker_conclusion=conclusion, upstream_worker_run_id="1")
        assert failed["status"] == "failed"
        assert f"Research Worker run 1 concluded {conclusion}" in failed["blockers"]


def test_real_source_catalog_seeds_supported_parsers_and_explicit_omissions(db):
    from secopsai.research_primary_intel import seed_sources
    seeded = seed_sources(db_path=db)
    assert len(seeded["sources"]) == 18 and not seeded["unsupported_sources"]
    with soc_store.connect(db) as conn:
        sources = [json.loads(r[0]) for r in conn.execute("SELECT config_json FROM research_intel_sources")]
    assert any(s["name"] == "OpenSSF Blog" and s["source_class"] == "project" for s in sources)
    assert any(s["parser"] == "cisa_kev" for s in sources)
    # Vendor advisories the research desk needs as primary sources.
    vendor_feeds = {s["name"]: s for s in sources if s["source_class"] == "vendor"}
    for name in ("PHP Security Advisories", "Node.js Security Releases", "GitLab Security Releases"):
        assert vendor_feeds[name]["parser"] == "rss" and vendor_feeds[name]["interval_seconds"] == 3600


def test_catalog_repairs_preserve_history_and_operator_overrides(db):
    from secopsai.research_primary_intel import seed_sources
    identity = "SRC-f5caeafa60f68ccdfed3"
    legacy = configure_source({"source_id": identity, "name": "Google Online Security Blog", "url": "https://security.googleblog.com/feeds/posts/default",
                               "parser": "normalized_json", "source_class": "vendor", "enabled": True}, actor="source-catalog", db_path=db)
    value, _ = event(db, config=legacy)
    with soc_store.connect(db) as conn:
        cursor = conn.execute("SELECT cursor FROM research_intel_sources WHERE source_id=?", (identity,)).fetchone()[0]
    seed_sources(db_path=db)
    with soc_store.connect(db) as conn:
        row = conn.execute("SELECT * FROM research_intel_sources WHERE source_id=?", (identity,)).fetchone()
    repaired = json.loads(row["config_json"])
    assert repaired["url"] == "https://feeds.feedburner.com/GoogleOnlineSecurityBlog"
    assert row["cursor"] == cursor and row["last_success_at"] is None
    assert intel_event(value["event_id"], db_path=db)["payload"]["title"] == "Patch available"
    count = len(records("source_configuration", db_path=db))
    seed_sources(db_path=db)
    assert len(records("source_configuration", db_path=db)) == count
    custom = configure_source({**repaired, "enabled": False, "url": "https://vendor.example/operator-feed"}, actor="operator.owner", db_path=db)
    seed_sources(db_path=db)
    with soc_store.connect(db) as conn:
        assert json.loads(conn.execute("SELECT config_json FROM research_intel_sources WHERE source_id=?", (identity,)).fetchone()[0]) == custom


def test_long_rss_excerpt_keeps_full_archive_and_declares_coverage_limit(db):
    config = {**source(db), "parser": "rss"}
    excerpt = "x" * 20000 + " decisive omitted tail"
    body = ('<rss version="2.0"><channel><title>Fixture</title><link>https://vendor.example/</link><description>Fixture</description>'
            '<item><guid>notice</guid><title>Notice</title><link>https://vendor.example/notice</link><description>'
            + excerpt + '</description></item></channel></rss>').encode()
    result = acquire(config, body, db_path=db)
    assert result["inserted"] == 1
    assert acquire(config, body, db_path=db)["inserted"] == 0
    with soc_store.connect(db) as conn:
        row = conn.execute("SELECT payload_json FROM research_intel_events WHERE snapshot_id=?", (result["snapshot_id"],)).fetchone()
        archived = conn.execute("SELECT content FROM research_source_snapshots WHERE snapshot_id=?", (result["snapshot_id"],)).fetchone()[0]
    value = json.loads(row[0])
    assert archived == body
    assert len(value["excerpt"]) == 20000 and value["excerpt_truncated"] is True
    assert value["excerpt_original_characters"] == len(excerpt)
    assert value["excerpt_sha256"] == hashlib.sha256(excerpt.encode()).hexdigest()
    assert value["excerpt_selection"] == {"start": 0, "end": 20000}
    assert coverage_report(db_path=db)["sources"][0]["evidence_truncated"] == 1


def test_legacy_http_citation_is_retained_without_allowing_http_acquisition(db):
    config = {**source(db), "parser": "rss"}
    body = b'<rss version="2.0"><channel><title>Fixture</title><link>https://vendor.example/</link><description>Fixture</description><item><guid>old</guid><title>Old notice</title><link>http://vendor.example/old</link><description>Archived statement</description></item></channel></rss>'
    parsed = parse_source(config, body)[0]
    assert parsed["url"] == parsed["root_url"] == "http://vendor.example/old"
    with pytest.raises(ValueError, match="HTTPS"):
        configure_source({**config, "url": "http://vendor.example/feed"}, actor="operator.owner", db_path=db)
    from secopsai.research_primary_intel import source_url
    for value in ("http://user:secret@vendor.example/", "javascript:alert(1)", "http://vendor.example:8080/"):
        with pytest.raises(ValueError):
            source_url(value, reference=True)


def test_first_collection_is_bounded_and_remaining_feeds_are_not_starved(db, monkeypatch):
    from secopsai import research_primary_intel as intake
    monkeypatch.setattr(intake, "seed_sources", lambda **kwargs: {"sources": [], "unsupported_sources": []})
    for index in range(12):
        source(db, source_id=f"source-{index}")

    class Feed:
        def get(self, url, **kwargs):
            return url, {}, json.dumps({"events": [{"external_id": "notice", "title": "Notice", "excerpt": "Fixture", "url": "https://vendor.example/notice"}]}).encode()

    first = intake.collect_due(db_path=db, fetcher=Feed())
    second = intake.collect_due(db_path=db, fetcher=Feed())
    assert len(first["results"]) == 10 and len(second["results"]) == 2
    assert len({r["source_id"] for r in first["results"] + second["results"]}) == 12


@pytest.mark.parametrize("transport_failure,category", [(True, "source_http_403"), (False, "invalid_source")])
def test_source_fetch_denial_is_distinct_from_malformed_feed(db, monkeypatch, transport_failure, category):
    from secopsai import research_primary_intel as intake
    monkeypatch.setattr(intake, "seed_sources", lambda **kwargs: {"sources": [], "unsupported_sources": []})
    config = configure_source({**source(db), "parser": "rss"}, actor="operator.owner", db_path=db)

    class Feed:
        def get(self, *args, **kwargs):
            if transport_failure:
                raise ValueError("registry returned HTTP 403")
            return config["url"], {}, b"<html>not a feed</html>"

    result = intake.collect_due(db_path=db, fetcher=Feed())
    assert result["results"][0]["error_category"] == category
    with soc_store.connect(db) as conn:
        row = conn.execute("SELECT cursor,last_success_at,error_category FROM research_intel_sources WHERE source_id=?", (config["source_id"],)).fetchone()
    assert row["cursor"] == "" and row["last_success_at"] is None and row["error_category"] == category


def test_kev_catalog_addition_is_not_source_publication_or_local_exploitation(db):
    config = {**source(db), "parser": "cisa_kev"}
    body = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1234", "vulnerabilityName": "Fixture", "shortDescription": "Fixture report", "dateAdded": "2026-10-13", "requiredAction": "Apply vendor guidance"}]}).encode()
    parsed = parse_source(config, body)[0]
    assert parsed["published_at"] is None
    assert parsed["catalog_added_at"] == "2026-10-13T00:00:00Z"
    assert not parsed["observed_exploitation_by_secopsai"]


def test_complete_original_release_is_possible_and_material_changes_block_reuse(db, tmp_path):
    """Exercise the full local publication path without any live model or deployment."""
    from secopsai.research_cases import add_subject
    from secopsai.research_reliability import (run_scaffold_research, verify_transition, run_full_safe_research, extract_claim_ledger,
                                              audit_completeness, audit_originality, record_visual_qa, publication_reliability_gate)
    from secopsai.specialist_orchestrator import create_run, record_human_review
    from secopsai.research_workflow import record_verdict, publication_safety_check, approve_publication_review
    value = case(db)
    value = add_subject(value["case_id"], subject_type="package", ecosystem="npm", name="contract-example", version="1.0", db_path=db)
    value = add_evidence(value["case_id"], evidence_type="source", title="Archived primary notice", locator="https://fixture.example/notice", sha256="b" * 64, provenance="Synthetic attributable source", db_path=db)
    record_verdict(value["case_id"], verdict="credible", confidence=90, rationale="The reviewed static observation is scoped to this contract fixture; execution is not claimed.", evidence_ids=[e["evidence_id"] for e in value["evidence"]], db_path=db)
    value = get_case(value["case_id"], db_path=db)
    # The static evidence remains the exact reference, regardless of source ordering.
    original = {**value, "evidence": [e for e in value["evidence"] if e["evidence_type"] == "static_analysis"]}
    assess_claim(value["case_id"], assessment(original), actor="bob", db_path=db)
    prior_art(value, db)
    for role, actor, checks in (("technical_reviewer", "bob", TECHNICAL_CHECKS), ("editor", "carol", EDITORIAL_CHECKS)):
        review_case(value["case_id"], {"role": role, "checks": dict.fromkeys(checks, "passed"), "draft": STATEMENT, "decision": "approved", "rationale": "Synthetic exact-draft review", "claim_statements": [STATEMENT]}, actor=actor, db_path=db)
    assert run_scaffold_research(value["case_id"], db_path=db)["status"] == "succeeded"
    assert verify_transition(value["case_id"], db_path=db)["status"] == "succeeded"
    assert run_full_safe_research(value["case_id"], db_path=db)["status"] == "succeeded"
    extract_claim_ledger(value["case_id"], text=STATEMENT, db_path=db)
    routed = create_run({"task_id": value["case_id"], "title": "Review scoped static evidence", "description": "Contract test of independent review", "domain": "threat-intelligence", "priority": "high", "analysis_only": True}, db_path=db)
    for stage, reviewer in (("primary", "alice"), ("reviewer", "bob")):
        record_human_review(routed["run_id"], stage=stage, verdict="credible", summary="The exact fixture code supports only a scoped static credential-file read, with execution and exposure explicitly unknown.", reviewer=reviewer, db_path=db)
    assert audit_completeness(value["case_id"], db_path=db)["status"] == "passed"
    assert audit_originality(value["case_id"], text=STATEMENT, db_path=db)["status"] == "passed"
    # Real generated test PNG bytes, separate from any production visual review.
    import base64
    png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aJ1sAAAAASUVORK5CYII=')
    desktop, mobile = tmp_path / "desktop.png", tmp_path / "mobile.png"
    desktop.write_bytes(png); mobile.write_bytes(png)
    assert record_visual_qa(value["case_id"], desktop_rendered=True, mobile_rendered=True, screenshots=[f"desktop={desktop}", f"mobile={mobile}"], db_path=db)["status"] == "passed"
    gate = publication_reliability_gate(value["case_id"], db_path=db)
    assert gate["ready"], gate["blockers"]
    safety = publication_safety_check(value["case_id"], db_path=db)
    approve_publication_review(value["case_id"], review_id=safety["review_id"], actor="carol", db_path=db)
    paths = blog.BlogPaths(root=tmp_path / "blog")
    draft = blog.draft_research_case(get_case(value["case_id"], db_path=db), verified_body=STATEMENT, paths=paths)
    assert blog.publish(draft["draft_path"], confirm=True, paths=paths, db_path=db)["published"]
    update_case(value["case_id"], summary=STATEMENT + " Different scope.", db_path=db)
    with pytest.raises(ValueError):
        blog.publish(draft["draft_path"], confirm=True, paths=paths, db_path=db)


def _watchdog_reader(now, *, synced_at=None, sources=(), gaps=()):
    synced = (synced_at or now).isoformat()

    def reader(url, _token):
        if url.endswith("/status"):
            return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                               "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
        if "/research/operation" in url:
            return json.dumps({"synced_at": synced, "runtime": {"worker_run_id": "older-run"},
                               "coverage": {"sources": list(sources), "health": {
                                   "freshness_gaps": list(gaps), "dead_letters": 0,
                                   "artifact_backup_pending": 0, "ontology_pending": 0}}}).encode()
        return b"<html>synthetic</html>"
    return reader


def test_watchdog_isolated_worker_failure_is_provisional_and_repeats_block_with_one_root_cause():
    """Runs 39729582527/39746678323: one checkpoint failure turned 2-3 blockers red."""
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 22, 8, 28, tzinfo=timezone.utc)
    reader = _watchdog_reader(now, synced_at=datetime(2026, 10, 22, 7, 31, tzinfo=timezone.utc))
    common = dict(reader=reader, now=now, worker_active=False, upstream_worker_conclusion="failure",
                  upstream_worker_run_id="39746678323", upstream_worker_started_at="2026-10-22T08:17:50Z",
                  upstream_worker_completed_at="2026-10-22T08:27:47Z")

    isolated = inspect(previous_worker_conclusion="success", **common)
    assert isolated["blockers"] == [] and isolated["status"] == "in_progress"
    assert any("the next run decides health" in item for item in isolated["warnings"])

    repeated = inspect(previous_worker_conclusion="failure", **common)
    assert repeated["status"] == "failed"
    assert repeated["blockers"] == ["Research Worker run 39746678323 concluded failure"]
    assert repeated["root_cause"] == "Research Worker run 39746678323 concluded failure"
    assert repeated["consequences"], "derived snapshot blockers are reported as consequences"


def test_watchdog_freshness_blocks_only_when_a_source_is_three_intervals_stale():
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)

    def source(delay_hours):
        return {"source_id": "ghsa", "name": "GitHub Security Advisories", "enabled": True, "fresh": False,
                "interval_seconds": 3600, "delay_seconds": delay_hours * 3600}

    slightly = inspect(reader=_watchdog_reader(now, sources=[source(2.5)], gaps=["GitHub Security Advisories"]),
                       now=now, worker_active=False)
    assert slightly["blockers"] == []
    assert "enabled source freshness needs review: GitHub Security Advisories" in slightly["warnings"]

    severely = inspect(reader=_watchdog_reader(now, sources=[source(3.5)], gaps=["GitHub Security Advisories"]),
                       now=now, worker_active=False)
    assert severely["blockers"] == ["enabled research sources are outside their freshness targets "
                                    "(more than three collection intervals): GitHub Security Advisories"]


def test_pipeline_health_classifies_real_failure_signatures():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("pipeline_health_report", Path(__file__).resolve().parents[1] / "scripts" / "pipeline_health_report.py")
    report = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(report)
    cases = {
        "ValueError: checkpoint chunk checksum mismatch": "ledger_restore_chunk_corrupt",
        'ledger PUT artifact-objects failed after 1 attempt(s) (http 400)': "ledger_request_failed",
        "ModuleNotFoundError: No module named 'secopsai'": "module_import_error",
        '[{"target": "pypi:duckdb", "queue_id": "x", "status": "error", "failure_category": "ValueError"}]': "fast_lane_unanalyzed_target",
        '{"status": "failed", "blockers": ["Research Worker run 1 concluded failure", "research operation snapshot predates"]}': "watchdog_worker_failed",
        '{"status": "failed", "root_cause": "enabled research sources are outside their freshness targets"}': "watchdog_sources_stale",
        "Fast Lane target completion could not be acknowledged; dispatch leases remain recoverable.": "fast_lane_completion_unacknowledged",
        "##[error]Process completed with exit code 1.": "unclassified",
    }
    for log, category in cases.items():
        assert report.classify(log)[0] == category, log
    assert report.classify('[{"target": "pypi:duckdb", "queue_id": "x", "status": "error"}]')[1] == "pypi:duckdb"


def test_watchdog_accepts_the_runs_own_final_snapshot_despite_late_github_completion():
    """Run 39799391019: snapshot stored 14:49:29, GitHub marked the run complete 14:51:28."""
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 22, 14, 52, tzinfo=timezone.utc)

    def reader_for(phase):
        def reader(url, _token):
            if url.endswith("/status"):
                return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                                   "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
            if "/research/operation" in url:
                runtime = {"worker_run_id": "39791513248", "worker_run_attempt": 1, **({"projection_phase": phase} if phase else {})}
                return json.dumps({"synced_at": "2026-10-22T14:49:29.060Z", "runtime": runtime, "coverage": {"sources": [], "health": {
                    "freshness_gaps": [], "dead_letters": 0, "artifact_backup_pending": 0, "ontology_pending": 0}}}).encode()
            return b"<html>synthetic</html>"
        return reader

    common = dict(now=now, worker_active=False, upstream_worker_conclusion="success", upstream_worker_run_id="39791513248",
                  upstream_worker_run_attempt=1, upstream_worker_started_at="2026-10-22T13:57:55Z",
                  upstream_worker_completed_at="2026-10-22T14:51:28Z")
    final = inspect(reader=reader_for("final"), **common)
    assert final["blockers"] == [] and final["status"] == "passed"
    unmarked = inspect(reader=reader_for(None), **common)
    assert unmarked["blockers"] == ["research operation snapshot predates the completed Research Worker run"]


def test_approved_edition_publishes_through_release_bundle_and_live_confirmation(db, tmp_path):
    from secopsai.research_editorial import confirm_live_publications, release_bundles
    from scripts.publish_editorial_releases import publish_all

    roster(db)
    value, _ = event(db)
    verify(value, db)
    local_date = datetime.fromisoformat(value["first_observed_at"].replace("Z", "+00:00")).astimezone(ZoneInfo("Europe/Istanbul")).date().isoformat()
    edition = create_daily_brief(date=local_date, db_path=db)
    assert release_bundles(db_path=db) == [], "unapproved editions are never exported"
    approve_edition(edition["edition_id"], {"checks": dict.fromkeys(BRIEF_CHECKS, "passed"), "rationale": "checked", "expected_fingerprint": edition["fingerprint"], "reviewed_draft": edition["draft"]["body_markdown"]}, actor="carol", db_path=db)
    bundles = release_bundles(db_path=db)
    assert [b["edition_id"] for b in bundles] == [edition["edition_id"]] and bundles[0]["editor_id"] == "carol"

    tampered = {**bundles[0], "draft": {**bundles[0]["draft"], "title": "Changed"}}
    with pytest.raises(ValueError, match="approved fingerprint"):
        publish_all([tampered], blog.BlogPaths(root=tmp_path / "blog"))
    paths = blog.BlogPaths(root=tmp_path / "blog")
    [result] = publish_all(bundles, paths)
    live = (paths.posts / (bundles[0]["draft"]["slug"] + ".json")).read_bytes()

    def offline(url):
        raise ValueError("HTTP 404")
    assert confirm_live_publications(offline, db_path=db) == {"confirmed": [], "waiting": [edition["edition_id"]]}
    assert hosted_projection(db_path=db)["editions"][0]["state"] == "approved", "nothing is published until the page is live"
    assert confirm_live_publications(lambda url: live, db_path=db) == {"confirmed": [edition["edition_id"]], "waiting": []}
    assert hosted_projection(db_path=db)["editions"][0]["state"] == "published"
    assert release_bundles(db_path=db) == [], "published editions are not exported again"
    assert result["url"].endswith(bundles[0]["draft"]["slug"] + ".html")
