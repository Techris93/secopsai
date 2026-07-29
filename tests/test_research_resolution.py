from secopsai import research_resolution
from secopsai.research_cases import add_evidence, add_rule, create_case, get_case
from secopsai.research_workflow import record_verdict


def _eligible_case(db: str) -> tuple[dict, dict]:
    case = create_case(
        title="Independent package validation",
        summary="A monitored package lead requires evidence-led validation before any external claim or defensive action.",
        case_type="malicious_package",
        severity="high",
        db_path=db,
    )
    evidence_ids = []
    for index, evidence_type in enumerate(("registry_metadata", "package_artifact", "static_analysis", "static_analysis"), 1):
        case = add_evidence(
            case["case_id"],
            evidence_type=evidence_type,
            title=f"Reviewed evidence {index}",
            locator=f"evidence://{index}",
            sha256=(f"{index:064x}" if evidence_type == "package_artifact" else ""),
            provenance="SecOpsAI deterministic test evidence",
            metadata={"pipeline_id": "RPL-AAAAAAAAAAAAAAAA"},
            db_path=db,
        )
        evidence_ids.append(case["evidence"][-1]["evidence_id"])
    record_verdict(
        case["case_id"], verdict="not_substantiated", confidence=95,
        rationale="Reviewed static evidence does not substantiate the malicious execution claim; this is not a benign classification.",
        evidence_ids=evidence_ids, actor="secopsai-agent-autonomy:RPL-AAAAAAAAAAAAAAAA", db_path=db,
    )
    case = add_rule(
        case["case_id"], rule_type="yara", name="ExactArtifactHash",
        content='import "hash" rule ExactArtifactHash { condition: filesize > 0 }',
        purpose="Test exact artifact monitoring", source_evidence_id=evidence_ids[1], db_path=db,
    )
    pipeline = {
        "pipeline_id": "RPL-AAAAAAAAAAAAAAAA",
        "case_id": case["case_id"],
        "status": "succeeded",
        "revision": 1,
        "review_items": [
            {"item_id": "RVI-AAAAAAAAAAAAAAAA", "item_type": "unsupported_claim", "status": "accepted"},
            {"item_id": "RVI-BBBBBBBBBBBBBBBB", "item_type": "intake_evidence", "status": "accepted"},
        ],
    }
    return get_case(case["case_id"], db_path=db), pipeline


def test_guarded_resolution_closes_case_and_retracts_rule(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    case, pipeline = _eligible_case(db)
    monkeypatch.setattr(research_resolution, "get_pipeline", lambda _pipeline_id, db_path=None: pipeline)
    research_resolution.update_settings(mode="guarded", min_confidence=90, min_evidence_refs=4, db_path=db)

    run = research_resolution.adjudicate_pipeline(pipeline["pipeline_id"], db_path=db)
    resolved = get_case(case["case_id"], db_path=db)

    assert run["status"] == "applied"
    assert run["decision"]["eligible"] is True
    assert resolved["status"] == "closed"
    assert resolved["severity"] == "info"
    assert resolved["disclosure_status"] == "not_required"
    assert resolved["verdicts"][0]["verdict"] == "not_substantiated"
    assert all(rule["status"] == "retracted" for rule in resolved["rules"])
    assert "No disclosure or publication action was taken" in resolved["summary"]


def test_resolution_review_can_reopen_and_restore_valid_rule(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    case, pipeline = _eligible_case(db)
    monkeypatch.setattr(research_resolution, "get_pipeline", lambda _pipeline_id, db_path=None: pipeline)
    research_resolution.update_settings(mode="guarded", db_path=db)
    run = research_resolution.adjudicate_pipeline(pipeline["pipeline_id"], db_path=db)

    reviewed = research_resolution.review_run(run["run_id"], decision="reopen", actor="reviewer", db_path=db)
    reopened = get_case(case["case_id"], db_path=db)

    assert reviewed["status"] == "rolled_back"
    assert reopened["status"] == "investigating"
    assert reopened["severity"] == "high"
    assert any(rule["status"] == "active" for rule in reopened["rules"])


def test_resolution_blocks_local_absence_and_incomplete_evidence(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    case, pipeline = _eligible_case(db)
    pipeline["review_items"] = []
    monkeypatch.setattr(research_resolution, "get_pipeline", lambda _pipeline_id, db_path=None: pipeline)
    research_resolution.update_settings(mode="guarded", db_path=db)

    run = research_resolution.adjudicate_pipeline(pipeline["pipeline_id"], db_path=db)

    assert run["status"] == "blocked"
    assert "not-substantiated closure requires an accepted unsupported-claim assessment" in run["decision"]["guardrail_reasons"]
    assert get_case(case["case_id"], db_path=db)["status"] == "investigating"
