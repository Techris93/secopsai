import json

from secopsai import research_review_brief as brief
from secopsai.research_assurance import TECHNICAL_CHECKS, case_fingerprint
from secopsai.research_case_sync import project_case
from secopsai.research_operation_store import append, digest

PACK = "# Review pack: RAT-1 (case RSC-1)\n\nModel proposals only.\n\n## Still unknown\n\n- install script not executed\n"


def _case(**extra):
    case = {"case_id": "RSC-1", "title": "evil-pkg steals tokens", "owner": "author", "severity": "high",
            "claims": [{"statement": "evil-pkg 1.0.1 reads ~/.npmrc in its postinstall script.", "status": "supported"},
                       {"statement": "An old guess.", "status": "refuted"}],
            "subjects": [{"name": "evil-pkg", "version": "1.0.1", "registry_state": "removed"}],
            "evidence": [{"evidence_id": "EVD-1", "evidence_type": "package_artifact", "sha256": "a" * 64, "status": "active"}]}
    case.update(extra)
    return case


def _by_key(assist):
    return {check["key"]: check for check in assist["checks"]}


def test_parts_join_back_exactly_and_stay_under_the_core_limit():
    text = "\n".join(f"line {i} " + "x" * 90 for i in range(400))
    chunks = brief.parts(text)
    assert "".join(chunks) == text
    assert len(chunks) > 1 and all(len(chunk) <= brief.PART_LIMIT for chunk in chunks)
    assert brief.parts("") == [""]


def test_nothing_established_suggests_changes_required_with_reasons(tmp_path):
    db = str(tmp_path / "r.db")
    assist = brief.review_assist(_case(), PACK, db_path=db)
    checks = _by_key(assist)
    assert set(checks) == TECHNICAL_CHECKS
    assert checks["claims"]["status"] == brief.MISSING
    assert checks["reproduction"]["status"] == brief.MISSING
    assert checks["detections"]["status"] == brief.MISSING
    assert checks["affected_versions"]["status"] == brief.JUDGEMENT
    assert checks["materiality"]["status"] == brief.JUDGEMENT
    assert checks["attribution"]["status"] == brief.VERIFIED
    assert assist["suggested_decision"] == "changes_required"
    assert "Nothing has run the package" in assist["suggested_rationale"]
    assert "No current prior-art search" in assist["suggested_rationale"]
    # Refuted claims are left out; the rest appear word for word in the draft.
    assert assist["claim_statements"] == ["evil-pkg 1.0.1 reads ~/.npmrc in its postinstall script."]
    draft = "".join(assist["draft_parts"])
    assert all(statement in draft for statement in assist["claim_statements"])
    # review_case strips the draft before hashing; the brief's hash must match.
    assert draft == draft.strip() and assist["draft_sha256"] == digest(draft)
    assert assist["last_review"] is None


def test_ledger_records_turn_checks_verified(tmp_path, monkeypatch):
    db = str(tmp_path / "r.db")
    case = _case(evidence=[{"evidence_id": "EVD-1", "evidence_type": "package_artifact", "status": "active"},
                           {"evidence_id": "EVD-SBX", "evidence_type": "sandbox_analysis", "status": "active"}])
    statement = case["claims"][0]["statement"]
    monkeypatch.setattr(brief, "claim_assessments", lambda case, db_path=None: {digest(statement): {"current": True, "assessment": "observation"}})
    fingerprint = case_fingerprint(case)
    for mode in ("detection_test", "patch_verification"):
        append("experiment", {"mode": mode}, actor="researcher", case_id="RSC-1", fingerprint=fingerprint, db_path=db)
    append("prior_art", {"searches": []}, actor="researcher", case_id="RSC-1", fingerprint=fingerprint, db_path=db)
    assist = brief.review_assist(case, PACK, db_path=db)
    checks = _by_key(assist)
    for key in ("claims", "reproduction", "detections", "mitigations", "attribution"):
        assert checks[key]["status"] == brief.VERIFIED, key
    assert "EVD-SBX" in checks["reproduction"]["proof"]
    assert not [c for c in assist["checks"] if c["status"] == brief.MISSING]
    assert assist["blockers"] == []
    assert assist["suggested_decision"] == "approved"


def test_stale_experiments_and_attribution_words_are_not_verified(tmp_path):
    db = str(tmp_path / "r.db")
    case = _case()
    append("experiment", {"mode": "detection_test"}, actor="researcher", case_id="RSC-1", fingerprint="old-state", db_path=db)
    assist = brief.review_assist(case, PACK + "\nThe threat actor targeted victims.\n", db_path=db)
    checks = _by_key(assist)
    assert checks["detections"]["status"] == brief.MISSING
    assert checks["attribution"]["status"] == brief.JUDGEMENT
    assert "threat actor" in checks["attribution"]["note"]


def test_unversioned_subject_and_missing_limitations_block(tmp_path):
    db = str(tmp_path / "r.db")
    assist = brief.review_assist(_case(subjects=[{"name": "evil-pkg"}]), "# Review pack\n", db_path=db)
    checks = _by_key(assist)
    assert checks["affected_versions"]["status"] == brief.MISSING
    assert checks["limitations"]["status"] == brief.MISSING


def test_last_review_is_current_only_for_this_draft_and_case_state(tmp_path):
    db = str(tmp_path / "r.db")
    case = _case()
    draft = "".join(brief.review_assist(case, PACK, db_path=db)["draft_parts"])
    append("human_review", {"role": "technical_reviewer", "target": "technical_advisory", "decision": "changes_required",
                            "draft_sha256": digest(draft)}, actor="reviewer", case_id="RSC-1", fingerprint=case_fingerprint(case), db_path=db)
    assert brief.review_assist(case, PACK, db_path=db)["last_review"]["current"] is True
    assert brief.review_assist(case, PACK + "\nnew stage\n", db_path=db)["last_review"]["current"] is False


def test_long_assist_survives_the_core_projection_intact(tmp_path):
    db = str(tmp_path / "r.db")
    case = _case()
    pack = PACK + "\n".join("- detail " + "y" * 200 for _ in range(60))
    assist = brief.review_assist(case, pack, db_path=db)
    team = {"team_id": "RAT-1", "case_id": "RSC-1", "status": "awaiting_human_review", "stages": [],
            "review_pack": brief.parts(pack), "review_assist": assist}
    detail = project_case({**case, "status": "investigating"}, {"case_id": "RSC-1"}, [team])["detail"]
    shown = detail["assistant_teams"][0]
    assert "".join(shown["review_pack"]) == pack
    joined = "".join(shown["review_assist"]["draft_parts"])
    assert digest(joined) == assist["draft_sha256"]
    assert len(json.dumps(detail)) <= 90_000
