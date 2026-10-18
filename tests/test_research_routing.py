from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

import soc_store
from secopsai.research_assurance import assess_claim, register_person
from secopsai.research_cases import add_evidence, create_case, get_case, publication_readiness
from secopsai.research_routing import record_case_disposition, route_candidate


CODE = "const token = readCredential('.npmrc');"


def _case(db_path: str) -> dict:
    value = create_case(
        title="Synthetic package endpoint review",
        summary="Static evidence is incomplete and the package behavior needs scoped validation before a public claim.",
        case_type="malicious_package",
        owner="author.human",
        confidence=0,
        db_path=db_path,
    )
    return add_evidence(
        value["case_id"], evidence_type="static_analysis", title="Install source",
        sha256="a" * 64, provenance="synthetic fixture", locator="artifact-analysis:src/install.js",
        metadata={"file_contents": {"install.js": CODE}}, db_path=db_path,
    )


def _people(db_path: str) -> None:
    register_person({"person_id": "operator.human", "display_name": "Operator", "roles": ["operator"], "qualification": "Synthetic operator fixture"}, actor="operator.human", db_path=db_path)
    register_person({"person_id": "author.human", "display_name": "Author", "roles": ["author", "researcher"], "qualification": "Synthetic author fixture"}, actor="operator.human", db_path=db_path)
    register_person({"person_id": "reviewer.human", "display_name": "Reviewer", "roles": ["technical_reviewer", "researcher"], "qualification": "Synthetic qualified technical reviewer"}, actor="operator.human", db_path=db_path)


def _claim(case: dict) -> dict:
    evidence = case["evidence"][0]
    return {
        "statement": "The exact install source contains a credential lookup and an outbound request path in the same function.",
        "assessment": "observation",
        "confidence": 0,
        "malicious_behavior": True,
        "impact_indicators": ["credential_theft"],
        "references": [{"evidence_id": evidence["evidence_id"], "selector": "/metadata/file_contents/install.js", "start": 0, "end": len(CODE), "excerpt": CODE}],
        "scope": {"versions": "1.0.0", "environment": "static source inspection", "sample_set": "one package artifact", "observation_period": "2026-10-18"},
        "rationale": "The indicator is a scoped technical review label, not a claim of execution or victim impact.",
        "quality": "Exact code excerpt from the archived package artifact.",
        "alternatives": ["The request path may be a documented service integration."],
        "contradictions": [],
        "limitations": ["Execution has not been observed."],
    }


def test_registry_candidate_routes_to_validation_without_score_based_publication():
    result = route_candidate({
        "ecosystem": "npm", "package": "universal-parcel-scraper", "version": "0.359.0",
        "score": 100, "evidence": {"metadata_url": "https://registry.example/package", "artifact_url": "https://registry.example/file"},
    })
    assert result["route"] == "validate"
    assert result["review_required"] is False
    assert result["publication_candidate"] is False
    assert "no behavior-level structural observation is recorded" in result["evidence_gaps"]
    assert result["grouping"]["release_key"] == "npm:universal-parcel-scraper@0.359.0"


def test_qualified_urgent_claim_creates_immediate_alert_and_keeps_publication_separate(tmp_path, monkeypatch):
    monkeypatch.delenv("SECOPSAI_RESEARCH_URGENT_ALERT_CHANNELS", raising=False)
    db_path = str(tmp_path / "routing.db")
    soc_store.init_db(db_path)
    _people(db_path)
    case = _case(db_path)
    source_excerpt = "The incident response report confirmed that package version 1.0.0 transmitted a recovered synthetic credential to an attacker-controlled endpoint."
    case = add_evidence(
        case["case_id"], evidence_type="source", title="Incident response report",
        sha256="b" * 64, provenance="synthetic primary-source fixture", locator="https://incident.example/report",
        metadata={"source_excerpts": {"report.txt": source_excerpt}}, db_path=db_path,
    )
    claim = _claim(case)
    claim.update({
        "statement": source_excerpt,
        "assessment": "source_reported",
        "references": [{"evidence_id": case["evidence"][-1]["evidence_id"], "selector": "/metadata/source_excerpts/report.txt", "start": 0, "end": len(source_excerpt), "excerpt": source_excerpt}],
        "scope": {"versions": "1.0.0", "environment": "incident response source report", "sample_set": "one reported package artifact", "observation_period": "2026-10-18"},
        "rationale": "A qualified technical reviewer verified the primary source excerpt and its package/version scope.",
        "quality": "Exact excerpt from a primary incident response report.",
        "alternatives": ["The reported account could be mistaken; corroborate with the incident responder if possible."],
        "limitations": ["The case file contains source reporting; SecOpsAI did not independently observe the victim environment."],
    })
    recorded = assess_claim(case["case_id"], claim, actor="reviewer.human", db_path=db_path)
    routed = get_case(case["case_id"], db_path=db_path)["routing"]
    with soc_store.connect(db_path) as connection:
        alerts = connection.execute("SELECT alert_type, severity, status, evidence_json FROM research_alerts").fetchall()
    assert routed["route"] == "urgent_review"
    assert routed["review_required"] is True
    assert routed["publication_candidate"] is False
    assert routed["urgent_indicators"] == ["credential_theft"]
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "urgent_case_review"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["status"] == "open"
    assert json.loads(alerts[0]["evidence_json"])["claim_statement_hash"] == recorded["payload"]["statement_hash"]


def test_static_credential_lookup_cannot_be_labeled_urgent_credential_theft(tmp_path):
    db_path = str(tmp_path / "static-only.db")
    soc_store.init_db(db_path)
    _people(db_path)
    case = _case(db_path)
    with pytest.raises(ValueError, match="credential_theft requires directly relevant active evidence"):
        assess_claim(case["case_id"], _claim(case), actor="reviewer.human", db_path=db_path)
    with soc_store.connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM research_alerts WHERE alert_type='urgent_case_review'").fetchone()[0] == 0


def test_confidence_is_not_a_publication_readiness_cutoff():
    result = publication_readiness({
        "title": "A sufficiently detailed title for a real finding",
        "summary": "A" * 100,
        "subjects": [{"status": "active"}],
        "evidence": [
            {"status": "active", "evidence_type": "source", "locator": "https://source.example/report"},
            {"status": "active", "evidence_type": "static_analysis", "locator": "artifact-analysis:src/main.js"},
        ],
        "confidence": 0,
        "disclosure_status": "not_required",
        "status": "ready_to_publish",
        "iocs": [], "rules": [], "findings": [],
    })
    assert not any("confidence" in blocker for blocker in result["blockers"])


def test_case_disposition_requires_evidence_and_passing_existing_regression_test(tmp_path):
    db_path = str(tmp_path / "disposition.db")
    soc_store.init_db(db_path)
    _people(db_path)
    case = _case(db_path)
    evidence = case["evidence"][0]
    ref = {"evidence_id": evidence["evidence_id"], "selector": "/metadata/file_contents/install.js", "start": 0, "end": len(CODE), "excerpt": CODE}
    common = {
        "decision": "benign",
        "explanation": "The full package source shows this credential lookup is a documented local-only configuration read, with no outbound use of the value.",
        "references": [ref],
        "regression_test": {
            "nodeid": "tests/test_research_routing.py::test_case_disposition_requires_evidence_and_passing_existing_regression_test",
            "result": "passed", "run_url": "https://github.com/Techris93/secopsai/actions/runs/123456789",
            "commit_sha": "0123456789abcdef0123456789abcdef01234567", "checked_at": "2026-10-18T10:00:00Z",
        },
    }
    with pytest.raises(ValueError, match="regression test node id does not exist"):
        record_case_disposition(case["case_id"], {**common, "regression_test": {**common["regression_test"], "nodeid": "tests/test_research_routing.py::test_missing"}}, actor="reviewer.human", db_path=db_path)
    result = record_case_disposition(case["case_id"], common, actor="reviewer.human", db_path=db_path)
    assert result["case"]["status"] == "closed"
    assert result["case"]["routing"]["route"] == "close_or_suppress"
    assert result["case"]["routing"]["disposition"]["decision"] == "benign"
    assert result["case"]["routing"]["disposition"]["regression_test"]["result"] == "passed"
