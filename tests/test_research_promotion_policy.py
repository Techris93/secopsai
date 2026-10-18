from __future__ import annotations

import json
import tempfile
from pathlib import Path

import soc_store
from secopsai.research_cases import get_case
from secopsai.research_discovery import get_promotion_policy, run_due_candidate_validations, run_promotion_policy, set_promotion_policy


def _candidate(db_path: str, *, score: float = 96.0, publisher_mismatch: bool = True) -> str:
    soc_store.init_db(db_path)
    candidate_id = "CAN-POLICYTEST0001"
    with soc_store.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO research_candidates
            (candidate_id, event_id, watchlist_id, ecosystem, package, version, reference_identifier,
             score, score_components_json, reason, status, case_id, evidence_json, first_seen,
             last_seen, algorithm_version)
            VALUES (?, NULL, NULL, 'nuget', 'Braintree.Net.Test', '1.0.0', 'Braintree.Net', ?, '{}',
                    'test similarity candidate', 'new', NULL, ?, '2026-07-29T00:00:00Z',
                    '2026-07-29T00:00:00Z', 'similarity-1')""",
            (candidate_id, score, json.dumps({"metadata_url": "https://api.nuget.org/v3/registration5-gz-semver2/braintree.net.test/index.json", "artifact_url": "https://api.nuget.org/v3-flatcontainer/braintree.net.test/1.0.0/braintree.net.test.1.0.0.nupkg", "publisher": "unexpected", "publisher_mismatch": publisher_mismatch, "expected_publishers": ["braintree"]})),
        )
        connection.commit()
    return candidate_id


def test_promotion_policy_is_disabled_and_preview_only_by_default() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = str(Path(temp_dir) / "soc.db")
        _candidate(db_path)
        policy = get_promotion_policy(ecosystem="nuget", db_path=db_path)
        assert policy["enabled"] == 0
        preview = run_promotion_policy(ecosystem="nuget", db_path=db_path)
        assert preview["promoted"] == 0
        assert preview["decisions"][0]["eligible"] is False


def test_enabled_policy_creates_auditable_draft_case_without_a_verdict() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = str(Path(temp_dir) / "soc.db")
        candidate_id = _candidate(db_path)
        set_promotion_policy(ecosystem="nuget", enabled=True, score_threshold=90, minimum_evidence=2, require_publisher=True, actor="test-operator", db_path=db_path)
        result = run_promotion_policy(ecosystem="nuget", apply=True, actor="test-operator", db_path=db_path)
        assert result["promoted"] == 1
        assert result["decisions"][0]["case_id"].startswith("RSC-")
        with soc_store.connect(db_path) as connection:
            candidate = connection.execute("SELECT status, case_id FROM research_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
            case = connection.execute("SELECT status, confidence, payload_json FROM research_cases WHERE case_id = ?", (candidate["case_id"],)).fetchone()
            subject = connection.execute("SELECT metadata_json FROM research_subjects WHERE case_id = ?", (candidate["case_id"],)).fetchone()
            event = connection.execute("SELECT decision, actor FROM research_promotion_events WHERE candidate_id = ?", (candidate_id,)).fetchone()
        assert candidate["status"] == "promoted"
        assert case["status"] == "draft"
        assert case["confidence"] == 0
        assert "promotion_policy" in case["payload_json"]
        discovery = json.loads(case["payload_json"])["discovery"]
        assert discovery["score_kind"] == "name_similarity"
        assert discovery["score"] == 96.0
        subject_metadata = json.loads(subject["metadata_json"])
        assert subject_metadata["comparison_reference_configured"] is False
        assert subject_metadata["watchlist_identifier"] == "Braintree.Net"
        assert subject_metadata["discovery_score"] == {"value": 96.0, "kind": "name_similarity"}
        assert "reference_identifier" not in subject_metadata
        from secopsai.research_pipeline import _target_from_case
        assert _target_from_case(get_case(candidate["case_id"], db_path=db_path))["reference"] is None
        assert event["decision"] == "draft_case_created"
        assert event["actor"] == "test-operator"
        second = run_promotion_policy(ecosystem="nuget", apply=True, actor="test-operator", db_path=db_path)
        assert second["promoted"] == 0
        with soc_store.connect(db_path) as connection:
            assert connection.execute("SELECT COUNT(*) FROM research_cases").fetchone()[0] == 1
            assert connection.execute("SELECT COUNT(*) FROM research_promotion_events").fetchone()[0] == 1


def test_duplicate_urls_count_as_one_evidence_reference() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = str(Path(temp_dir) / "soc.db")
        candidate_id = _candidate(db_path)
        duplicate = "https://api.nuget.org/v3/registration5-gz-semver2/braintree.net.test/index.json"
        with soc_store.connect(db_path) as connection:
            connection.execute("UPDATE research_candidates SET evidence_json = ? WHERE candidate_id = ?", (json.dumps({"metadata_url": duplicate, "artifact_url": duplicate, "publisher": ""}), candidate_id))
            connection.commit()
        set_promotion_policy(ecosystem="nuget", enabled=True, score_threshold=90, minimum_evidence=2, db_path=db_path)
        preview = run_promotion_policy(ecosystem="nuget", db_path=db_path)
        assert preview["eligible"] == 0
        assert preview["decisions"][0]["evidence_count"] == 1
        assert "insufficient_evidence" in preview["decisions"][0]["reasons"]


def test_similarity_can_start_evidence_collection_but_not_human_review_or_confidence() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = str(Path(temp_dir) / "soc.db")
        candidate_id = _candidate(db_path, score=100, publisher_mismatch=False)
        set_promotion_policy(ecosystem="nuget", enabled=True, score_threshold=90, minimum_evidence=2, require_publisher=True, db_path=db_path)
        result = run_promotion_policy(ecosystem="nuget", apply=True, db_path=db_path)
        decision = result["decisions"][0]
        assert decision["eligible"] is True
        assert decision["score_kind"] == "name_similarity"
        assert decision["case_id"]
        case = get_case(decision["case_id"], db_path=db_path)
        assert case["confidence"] == 0
        assert case["routing"]["route"] == "validate"
        assert case["routing"]["review_required"] is False
        with soc_store.connect(db_path) as connection:
            candidate = connection.execute("SELECT status, case_id FROM research_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
            assert connection.execute("SELECT COUNT(*) FROM research_cases").fetchone()[0] == 1
        assert candidate["status"] == "promoted"
        assert candidate["case_id"] == decision["case_id"]


def test_promoted_plausible_candidate_starts_bounded_static_validation(tmp_path, monkeypatch) -> None:
    db_path = str(Path(tmp_path) / "soc.db")
    candidate_id = _candidate(db_path, publisher_mismatch=True)
    set_promotion_policy(ecosystem="nuget", enabled=True, score_threshold=90, minimum_evidence=2, require_publisher=True, db_path=db_path)
    promoted = run_promotion_policy(ecosystem="nuget", apply=True, db_path=db_path)
    case_id = promoted["decisions"][0]["case_id"]
    starts = []
    monkeypatch.setattr("secopsai.research_pipeline.list_pipelines", lambda **kwargs: [])
    monkeypatch.setattr("secopsai.research_pipeline.start_investigation_pipeline", lambda case, **kwargs: starts.append((case, kwargs)) or {"pipeline_id": "RPL-TEST", "status": "awaiting_ai", "summary": {"artifact_registered": True}})

    result = run_due_candidate_validations(db_path=db_path, limit=1)

    assert result["considered"] == 1
    assert result["failed"] == []
    assert result["started"][0]["candidate_id"] == candidate_id
    assert starts == [(case_id, {"actor": "secopsai-candidate-validation", "db_path": db_path, "auto_enrich": True})]


def test_candidate_validation_does_not_restart_a_recorded_pipeline(tmp_path, monkeypatch) -> None:
    db_path = str(Path(tmp_path) / "soc.db")
    _candidate(db_path, publisher_mismatch=True)
    set_promotion_policy(ecosystem="nuget", enabled=True, score_threshold=90, minimum_evidence=2, require_publisher=True, db_path=db_path)
    promoted = run_promotion_policy(ecosystem="nuget", apply=True, db_path=db_path)
    case_id = promoted["decisions"][0]["case_id"]
    monkeypatch.setattr("secopsai.research_pipeline.list_pipelines", lambda **kwargs: [{"status": "failed", "pipeline_id": "RPL-OLD"}])
    monkeypatch.setattr("secopsai.research_pipeline.start_investigation_pipeline", lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not retry an existing pipeline")))

    result = run_due_candidate_validations(db_path=db_path, limit=1)

    assert result["started"] == []
    assert result["skipped"] == [{"case_id": case_id, "reason": "pipeline_already_recorded:failed"}]
