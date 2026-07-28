from __future__ import annotations

import json
from pathlib import Path

import soc_store
from jsonschema import Draft202012Validator
from secopsai import agent_triage
from secopsai.intelligence_jobs import claim_next_job, complete_job


ROOT = Path(__file__).resolve().parents[1]


def _finding(finding_id: str = "FND-AUTO-1") -> dict:
    return {
        "finding_id": finding_id,
        "title": "Suspicious package behavior",
        "summary": "A package matched a bounded supply-chain rule.",
        "severity": "medium",
        "severity_score": 55,
        "status": "open",
        "disposition": "unreviewed",
        "source": "secopsai-supply-chain",
        "platform": "supply_chain",
        "ecosystem": "npm",
        "package": "example-package",
        "new_version": "1.0.0",
        "first_seen": "2026-07-28T00:00:00Z",
        "last_seen": "2026-07-28T00:00:00Z",
        "event_ids": [],
        "rule_ids": ["RULE-EXAMPLE"],
        "evidence": {"score": 2},
    }


def _deterministic(disposition: str = "false_positive", *, strong: bool = False) -> dict:
    return {
        "category": "supply_chain",
        "summary": "Independent deterministic assessment.",
        "recommended_disposition": disposition,
        "confidence": "high",
        "threat_assessment": {
            "advisory_backed": False,
            "denylisted": False,
            "strong_signals": ["RULE-EXAMPLE"] if strong else [],
        },
        "exposure_assessment": {"status": "not_observed_in_scope"},
        "verdict_explanation": {"matched_rules": [{"rule": "RULE-EXAMPLE"}]},
    }


def _model_result(*, proposal: bool = False) -> dict:
    return {
        "summary": "The package rule match is a corroborated false positive.",
        "risk_assessment": "Low after deterministic review.",
        "evidence": ["FND-AUTO-1", "RULE-EXAMPLE"],
        "recommended_actions": ["Retain the decision for audit."],
        "limitations": ["No runtime execution was performed."],
        "finding_verdict": "false_positive",
        "finding_confidence": 99,
        "disposition_recommendation": "false_positive",
        "decision_evidence_refs": ["FND-AUTO-1", "RULE-EXAMPLE"],
        "exposure_assessment": "not_observed",
        "automation_recommendation": "suppress_once",
        "counterarguments": [],
        "rule_tuning_proposals": (
            [
                {
                    "target_type": "rule",
                    "target_id": "RULE-EXAMPLE",
                    "change_type": "weight",
                    "proposed_value": 1,
                    "rationale": "Reduce a repeatedly reviewed weak signal.",
                    "expected_effect": "Reduce false positives without disabling the rule.",
                }
            ]
            if proposal
            else []
        ),
    }


def _complete_one(db: str, result: dict) -> dict:
    job = claim_next_job(provider="opencodex:kimi", worker_id="test-worker", db_path=db)
    assert job is not None
    return complete_job(job["job_id"], result={"data": result}, actor="test-worker", provider="opencodex:kimi", db_path=db)


def test_agent_triage_settings_are_safe_by_default_and_validated(tmp_path):
    db = str(tmp_path / "soc.db")
    settings = agent_triage.get_settings(db_path=db)
    assert settings["mode"] == "advisory"
    assert settings["auto_activate_tuning"] is False

    updated = agent_triage.update_settings(
        mode="guarded",
        selected_model="kimi/kimi-k2.7-code-highspeed",
        min_auto_close_confidence=98,
        actor="test",
        db_path=db,
    )
    assert updated["mode"] == "guarded"
    assert updated["selected_model"].startswith("kimi/")


def test_agent_triage_contract_fixture_validates():
    schema = json.loads((ROOT / "contracts" / "secopsai.agent-triage.v1.schema.json").read_text(encoding="utf-8"))
    fixture = json.loads((ROOT / "contracts" / "fixtures" / "secopsai.agent-triage.status.v1.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(fixture)


def test_guarded_model_triage_closes_only_with_deterministic_corroboration_and_rolls_back(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    agent_triage.update_settings(mode="guarded", min_evidence_refs=2, actor="test", db_path=db)
    monkeypatch.setattr(agent_triage, "_deterministic_assessment", lambda finding, search_root: _deterministic())

    queued = agent_triage.enqueue_due_findings(db_path=db)
    assert len(queued["queued"]) == 1
    _complete_one(db, _model_result(proposal=True))

    finding = soc_store.get_finding("FND-AUTO-1", db)
    assert finding and finding["status"] == "closed"
    assert finding["disposition"] == "false_positive"
    run = agent_triage.list_runs(db_path=db)[0]
    assert run["status"] == "applied"
    assert run["final_action"] == "auto_closed:false_positive"
    assert run["decision"]["validated_evidence_refs"] == ["FND-AUTO-1", "RULE-EXAMPLE"]
    proposals = agent_triage.list_tuning_proposals(db_path=db)
    assert proposals[0]["status"] == "shadow_insufficient_data"
    assert proposals[0]["shadow_metrics"]["activation_allowed"] is False

    rolled_back = agent_triage.rollback_run(run["run_id"], actor="test", db_path=db)
    assert rolled_back["status"] == "rolled_back"
    restored = soc_store.get_finding("FND-AUTO-1", db)
    assert restored and restored["status"] == "open" and restored["disposition"] == "unreviewed"


def test_model_cannot_close_when_deterministic_analysis_disagrees(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    agent_triage.update_settings(mode="guarded", min_evidence_refs=2, actor="test", db_path=db)
    monkeypatch.setattr(
        agent_triage,
        "_deterministic_assessment",
        lambda finding, search_root: _deterministic("needs_review"),
    )

    agent_triage.enqueue_due_findings(db_path=db)
    _complete_one(db, _model_result())

    finding = soc_store.get_finding("FND-AUTO-1", db)
    assert finding and finding["status"] == "in_review"
    assert finding["disposition"] == "unreviewed"
    run = agent_triage.list_runs(db_path=db)[0]
    assert "deterministic analysis does not independently support closure" in run["decision"]["guardrail_reasons"]


def test_strong_threat_signal_blocks_false_positive_suppression(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    agent_triage.update_settings(mode="guarded", min_evidence_refs=2, actor="test", db_path=db)
    monkeypatch.setattr(agent_triage, "_deterministic_assessment", lambda finding, search_root: _deterministic(strong=True))

    agent_triage.enqueue_due_findings(db_path=db)
    _complete_one(db, _model_result())

    finding = soc_store.get_finding("FND-AUTO-1", db)
    assert finding and finding["status"] == "in_review"
    run = agent_triage.list_runs(db_path=db)[0]
    assert "source-backed or strong threat evidence blocks automatic closure" in run["decision"]["guardrail_reasons"]


def test_advisory_mode_records_recommendation_without_mutating_finding(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    monkeypatch.setattr(agent_triage, "_deterministic_assessment", lambda finding, search_root: _deterministic())

    agent_triage.enqueue_due_findings(db_path=db)
    _complete_one(db, _model_result())

    finding = soc_store.get_finding("FND-AUTO-1", db)
    assert finding and finding["status"] == "open" and finding["disposition"] == "unreviewed"
    run = agent_triage.list_runs(db_path=db)[0]
    assert run["status"] == "recommended"
    assert run["final_action"] == "recommend_review"


def test_only_replay_proven_threshold_tuning_can_activate_and_rollback(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    findings = [_finding()]
    for index in range(1, 21):
        item = _finding(f"FND-HISTORY-{index}")
        item["disposition"] = "false_positive" if index <= 8 else "true_positive"
        item["status"] = "closed" if index <= 8 else "triaged"
        findings.append(item)
    soc_store.persist_findings(findings, source="secopsai-supply-chain", db_path=db)
    agent_triage.update_settings(
        mode="guarded",
        min_evidence_refs=2,
        auto_activate_tuning=True,
        actor="test",
        db_path=db,
    )
    monkeypatch.setattr(agent_triage, "_deterministic_assessment", lambda finding, search_root: _deterministic())
    monkeypatch.setattr(
        agent_triage.supply_chain,
        "suggest_threshold",
        lambda ecosystem, db_path=None: {
            "confidence": "high",
            "current_threshold": 10,
            "suggested_threshold": 12,
            "counts": {"reviewed_safe": 8, "reviewed_risky": 12},
        },
    )
    applied_values = []
    monkeypatch.setattr(
        agent_triage.supply_chain,
        "tune_threshold",
        lambda ecosystem, value: applied_values.append((ecosystem, value)) or {"target": ecosystem, "value": value},
    )
    model = _model_result()
    model["rule_tuning_proposals"] = [
        {
            "target_type": "threshold",
            "target_id": "npm",
            "change_type": "threshold",
            "proposed_value": 12,
            "rationale": "Raise the threshold to the replay-proven boundary.",
            "expected_effect": "Suppress reviewed noise without hiding reviewed true positives.",
        }
    ]

    agent_triage.enqueue_due_findings(db_path=db)
    _complete_one(db, model)
    proposal = agent_triage.list_tuning_proposals(db_path=db)[0]
    assert proposal["status"] == "active"
    assert applied_values == [("npm", 12)]
    rolled_back = agent_triage.rollback_tuning_proposal(proposal["proposal_id"], actor="test", db_path=db)
    assert rolled_back["status"] == "rolled_back"
    assert applied_values[-1] == ("npm", 10)
