from __future__ import annotations

import json
import tempfile
from pathlib import Path

import soc_store
from secopsai.research_discovery import get_promotion_policy, run_promotion_policy, set_promotion_policy


def _candidate(db_path: str, *, score: float = 96.0) -> str:
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
            (candidate_id, score, json.dumps({"metadata_url": "https://api.nuget.org/v3/registration5-gz-semver2/braintree.net.test/index.json", "artifact_url": "https://api.nuget.org/v3-flatcontainer/braintree.net.test/1.0.0/braintree.net.test.1.0.0.nupkg", "publisher": "unexpected"})),
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
            case = connection.execute("SELECT status, payload_json FROM research_cases WHERE case_id = ?", (candidate["case_id"],)).fetchone()
            event = connection.execute("SELECT decision, actor FROM research_promotion_events WHERE candidate_id = ?", (candidate_id,)).fetchone()
        assert candidate["status"] == "promoted"
        assert case["status"] == "draft"
        assert "promotion_policy" in case["payload_json"]
        assert event["decision"] == "draft_case_created"
        assert event["actor"] == "test-operator"
