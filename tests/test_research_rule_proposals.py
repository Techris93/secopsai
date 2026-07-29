from __future__ import annotations

from secopsai.research_cases import add_evidence, add_ioc, create_case, get_case
from secopsai.research_rule_proposals import generate_rule_proposals, review_rule_proposal


def _case_with_suspect_artifact(db: str):
    case = create_case(title="Evidence-linked rule generation", db_path=db)
    case = add_evidence(
        case["case_id"],
        evidence_type="package_artifact",
        title="Reviewed suspect artifact",
        sha256="a" * 64,
        provenance="SecOpsAI safe package intake",
        metadata={"comparison_role": "suspect", "execution_performed": False},
        db_path=db,
    )
    return case


def test_generates_idempotent_yara_proposal_from_suspect_artifact(tmp_path):
    db = str(tmp_path / "research.db")
    case = _case_with_suspect_artifact(db)

    first = generate_rule_proposals(case["case_id"], db_path=db)
    second = generate_rule_proposals(case["case_id"], db_path=db)

    assert first["generated"] == 1
    assert second["generated"] == 1
    assert len(second["proposals"]) == 1
    proposal = second["proposals"][0]
    assert proposal["rule_type"] == "yara"
    assert proposal["status"] == "review_required"
    assert proposal["validation_status"] == "passed"
    assert 'hash.sha256(0, filesize) == "' + ("a" * 64) + '"' in proposal["content"]
    assert proposal["source_evidence_id"] == case["evidence"][0]["evidence_id"]


def test_reference_artifact_is_never_turned_into_detection(tmp_path):
    db = str(tmp_path / "research.db")
    case = create_case(title="Reference exclusion", db_path=db)
    case = add_evidence(
        case["case_id"],
        evidence_type="package_artifact",
        title="Legitimate reference artifact",
        sha256="b" * 64,
        metadata={"comparison_role": "reference"},
        db_path=db,
    )

    result = generate_rule_proposals(case["case_id"], db_path=db)

    assert result["proposals"] == []
    assert "No reviewed suspect artifact hash" in result["limitations"][-1]


def test_high_confidence_iocs_create_sigma_and_semgrep_proposals(tmp_path):
    db = str(tmp_path / "research.db")
    case = _case_with_suspect_artifact(db)
    evidence_id = case["evidence"][0]["evidence_id"]
    case = add_ioc(
        case["case_id"],
        ioc_type="domain",
        value="malicious.example",
        confidence=90,
        source_evidence_id=evidence_id,
        db_path=db,
    )

    result = generate_rule_proposals(case["case_id"], db_path=db)

    assert {item["rule_type"] for item in result["proposals"]} == {"yara", "sigma", "semgrep"}
    assert all(item["validation_status"] == "passed" for item in result["proposals"])


def test_accepting_proposal_activates_rule_and_rejection_is_auditable(tmp_path):
    db = str(tmp_path / "research.db")
    case = _case_with_suspect_artifact(db)
    generated = generate_rule_proposals(case["case_id"], db_path=db)
    proposal = generated["proposals"][0]

    accepted = review_rule_proposal(
        case["case_id"], proposal["proposal_id"], decision="accepted", actor="reviewer", db_path=db
    )
    repeated = review_rule_proposal(
        case["case_id"], proposal["proposal_id"], decision="accepted", actor="reviewer", db_path=db
    )

    assert accepted["proposal"]["status"] == "accepted"
    assert accepted["proposal"]["active_rule_id"]
    assert len(accepted["case"]["rules"]) == 1
    assert len(repeated["case"]["rules"]) == 1
    assert get_case(case["case_id"], db_path=db)["rule_proposals"][0]["reviewer"] == "reviewer"


def test_low_confidence_ioc_does_not_create_network_rules(tmp_path):
    db = str(tmp_path / "research.db")
    case = _case_with_suspect_artifact(db)
    case = add_ioc(
        case["case_id"], ioc_type="domain", value="unverified.example", confidence=55, db_path=db
    )

    result = generate_rule_proposals(case["case_id"], db_path=db)

    assert {item["rule_type"] for item in result["proposals"]} == {"yara"}


def test_rejected_proposal_stays_rejected_when_generation_repeats(tmp_path):
    db = str(tmp_path / "research.db")
    case = _case_with_suspect_artifact(db)
    generated = generate_rule_proposals(case["case_id"], db_path=db)
    proposal = generated["proposals"][0]

    review_rule_proposal(
        case["case_id"], proposal["proposal_id"], decision="rejected", actor="reviewer", db_path=db
    )
    repeated = generate_rule_proposals(case["case_id"], db_path=db)

    assert repeated["proposals"][0]["status"] == "rejected"
    assert repeated["review_required"] == 0
