from __future__ import annotations

from pathlib import Path

import secopsai.research_specialist_automation as specialist_automation
from secopsai.codex_bridge import persist_model_routing
from secopsai.research_cases import add_evidence, add_subject, create_case, get_case, update_case
from secopsai.research_specialist_automation import route_cases, sync_completed_reviews
from secopsai.specialist_orchestrator import (
    configure_policy,
    get_run,
    list_runs,
    record_primary_result,
    record_review_result,
)


def _research_case(db: str) -> dict:
    case = create_case(
        title="Review malicious package campaign IOCs",
        summary="A source-backed package campaign requires independent evidence review.",
        case_type="supply_chain_campaign",
        severity="critical",
        confidence=85,
        owner="research-team",
        db_path=db,
    )
    case = add_subject(
        case["case_id"],
        subject_type="package",
        ecosystem="crates",
        name="fixture-package",
        version="1.0.0",
        db_path=db,
    )
    case = add_evidence(
        case["case_id"],
        evidence_type="source",
        title="Official registry record",
        locator="https://example.test/fixture-package",
        provenance="deterministic test fixture",
        db_path=db,
    )
    return update_case(case["case_id"], status="validation", db_path=db)


def _result(summary: str) -> dict:
    return {
        "summary": summary,
        "risk_assessment": "Read-only evidence review.",
        "evidence": ["fixture"],
        "recommended_actions": ["Keep protected actions approval-gated."],
        "limitations": ["No artifact was executed."],
    }


def test_guarded_policy_routes_high_risk_case_read_only_once(tmp_path: Path) -> None:
    db = str(tmp_path / "soc.db")
    persist_model_routing("xai/grok-4.6", fallback_mode="disabled", db_path=db)
    configure_policy(mode="guarded", maximum_automatic_tier="read_only", db_path=db)
    case = _research_case(db)

    first = route_cases(limit=5, db_path=db)
    assert first["status"] == "completed"
    assert len(first["routed"]) == 1
    routed = first["routed"][0]
    assert routed["case_id"] == case["case_id"]
    assert routed["status"] == "queued"
    assert routed["primary_profile_id"] == "security/threat-intelligence-analyst"
    assert routed["reviewer_profile_id"] == "security/senior-secops"
    assert routed["selected_model"] == "xai/grok-4.6"
    assert routed["fallback_mode"] == "disabled"

    second = route_cases(limit=5, db_path=db)
    assert second["routed"] == []
    assert second["skipped"][0]["reason"] == "existing_read_only_run:queued"
    assert len([run for run in list_runs(db_path=db) if run["task_id"] == case["case_id"]]) == 1


def test_recommend_policy_does_not_queue_case_review(tmp_path: Path) -> None:
    db = str(tmp_path / "soc.db")
    persist_model_routing("xai/grok-4.6", fallback_mode="disabled", db_path=db)
    configure_policy(mode="recommend", db_path=db)
    _research_case(db)

    result = route_cases(db_path=db)
    assert result["status"] == "skipped"
    assert result["reason"] == "guarded_read_only_policy_not_enabled"
    assert list_runs(db_path=db) == []


def test_completed_independent_review_attaches_once_without_approval(tmp_path: Path) -> None:
    db = str(tmp_path / "soc.db")
    persist_model_routing("xai/grok-4.6", fallback_mode="disabled", db_path=db)
    configure_policy(mode="guarded", maximum_automatic_tier="read_only", db_path=db)
    case = _research_case(db)
    routed = route_cases(db_path=db)["routed"][0]
    run_id = routed["run_id"]

    record_primary_result(run_id, _result("Primary threat intelligence review."), model="xai/grok-4.6", db_path=db)
    record_review_result(run_id, _result("Independent Senior SecOps review."), model="xai/grok-4.6", db_path=db)
    assert get_run(run_id, db_path=db)["status"] == "needs_review"

    first = sync_completed_reviews(db_path=db)
    assert len(first["attached"]) == 1
    assert first["attached"][0]["publication_approved"] is False
    updated = get_case(case["case_id"], db_path=db)
    notes = [item for item in updated["evidence"] if item.get("locator") == f"specialist-review:{run_id}"]
    assert len(notes) == 1
    assert "Primary threat intelligence review" in notes[0]["notes"]
    assert "Independent Senior SecOps review" in notes[0]["notes"]
    assert updated["publication_reviews"][0]["status"] in {"blocked", "needs_approval"}
    assert updated["status"] == "validation"

    second = sync_completed_reviews(db_path=db)
    assert second["attached"] == []
    assert len(
        [
            item
            for item in get_case(case["case_id"], db_path=db)["evidence"]
            if item.get("locator") == f"specialist-review:{run_id}"
        ]
    ) == 1


def test_daily_specialist_cycle_advances_reliability_before_draft_handoff(monkeypatch) -> None:
    order: list[str] = []

    monkeypatch.setattr(
        specialist_automation,
        "sync_completed_reviews",
        lambda **_: order.append("sync") or {"status": "completed", "attached": []},
    )
    monkeypatch.setattr(
        specialist_automation,
        "run_guarded_reliability_batch",
        lambda **_: order.append("reliability") or {
            "status": "completed",
            "processed": [
                {
                    "case_id": "RSC-FIXTURE",
                    "stopped_at": "awaiting_model_review",
                    "reused": False,
                }
            ],
            "skipped": [],
        },
    )
    monkeypatch.setattr(
        specialist_automation,
        "create_approved_review_drafts",
        lambda **_: order.append("drafts") or {"status": "completed", "created": []},
    )

    result = specialist_automation.run_cycle(limit=5)

    assert order == ["sync", "reliability", "drafts"]
    assert result["case_routing"]["status"] == "integrated"
    assert result["case_routing"]["routed"][0]["case_id"] == "RSC-FIXTURE"
