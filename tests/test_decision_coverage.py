"""Coverage of what a bridge model receives decides whether closure is possible."""
import json

import pytest

from secopsai import intelligence, research_ai_triage
from secopsai.decision_evidence import COVERAGE_CONTRACT, context_coverage, coverage_for_result


def _prescan(**changes):
    flagged = {"path": "package/a.js", "bytes": 900_000, "complete": False, "truncated": True, "regions_found": 3, "regions_shown": 3,
               "matched_regions_shown": True, "content": "head\n[... 9 characters omitted ...]\nmatch"}
    finding = {"rule_id": "R1", "severity": "high", "score": 80, "file_path": "package/a.js", "safe_context": "match", "evidence": []}
    prescan = {"score": 80, "level": "high", "findings": [finding], "flagged_files": [flagged], "manifest": {"name": "a"},
               "fingerprints": {"author": "x"}, "install_files": [], "flag_locations": [], "decoded_payloads": [], "binaries": []}
    return {**prescan, **changes}


def _context(**changes):
    return research_ai_triage.triage_context(ecosystem="npm", package="a", version="1.0.0", prescan=_prescan(**changes))


def test_large_file_with_every_region_shown_is_complete():
    coverage = context_coverage(_context())
    assert coverage["complete"] is True and coverage["contract"] == COVERAGE_CONTRACT and coverage["gaps"] == []


def test_context_built_before_the_contract_is_never_complete():
    context = _context()
    del context["coverage_contract"]
    assert context_coverage(context)["gaps"] == ["context_predates_coverage_contract"]


@pytest.mark.parametrize("change,gap", [
    ({"regions_shown": 2}, "flagged_file_regions:package/a.js"),
    ({"regions_found": 0, "regions_shown": 0}, "flagged_file_regions:package/a.js"),
    ({"regions_trimmed": True}, "flagged_file_regions:package/a.js"),
])
def test_missing_regions_block_completeness(change, gap):
    context = _context()
    context["flagged_files"][0].update(change)
    assert gap in context_coverage(context)["gaps"]


def test_old_style_file_without_counts_is_a_gap():
    context = _context()
    for key in ("regions_found", "regions_shown"):
        del context["flagged_files"][0][key]
    assert "flagged_file_regions:package/a.js" in context_coverage(context)["gaps"]


def test_unreadable_and_absent_evidence_are_gaps():
    binary = {"path": "package/a.js", "bytes": 10, "binary": "ELF"}
    assert "flagged_file_not_readable:package/a.js" in context_coverage(_context(flagged_files=[binary]))["gaps"]
    assert "finding_file_not_supplied:package/a.js" in context_coverage(_context(flagged_files=[]))["gaps"]
    assert "no_findings" in context_coverage(_context(findings=[]))["gaps"]
    native = {"path": "package/x.node", "bytes": 10, "kind": "ELF", "referenced_by": []}
    assert "binary_not_inspected:package/x.node" in context_coverage(_context(binaries=[native]))["gaps"]
    cut_install = {"path": "package/setup.js", "content": "x", "truncated": True}
    assert "install_time_file:package/setup.js" in context_coverage(_context(install_files=[cut_install]))["gaps"]
    cut_payload = {"found_in": "package/a.js", "kind": "text", "text": "x", "truncated": True}
    assert "decoded_payload:package/a.js" in context_coverage(_context(decoded_payloads=[cut_payload]))["gaps"]


def test_silent_caps_upstream_are_gaps():
    assert context_coverage(_context(findings_total=40))["complete"] is False
    assert context_coverage(_context(flagged_files_total=9))["complete"] is False
    assert context_coverage(_context(decoded_payloads_total=7))["complete"] is False


def test_listing_limits_do_not_block_completeness_but_are_recorded():
    context = _context(missing_files=["package/b.js"], missing_files_truncated=True)
    assert context["listing_limits"] == ["missing_files"]
    assert context_coverage(context)["complete"] is True


def test_transport_cut_blocks_completeness():
    context = _context()
    context["evidence_truncated"] = True
    assert context_coverage(context)["complete"] is False


def test_fit_records_only_real_losses():
    context = _context()
    context["flagged_files"][0]["content"] = "x" * 14_000
    context["missing_files"] = [f"package/{index}.js" for index in range(200)]
    # Under the limit nothing changes.
    assert context_coverage(research_ai_triage.fit_context(context))["complete"] is True
    # Over the limit the code itself is cut, and that is a gap.
    context["flagged_files"] = [{**context["flagged_files"][0], "path": f"package/{index}.js", "content": "x" * 14_500} for index in range(6)]
    context["findings"] = [{"rule_id": "R1", "file_path": f"package/{index}.js", "safe_context": "m"} for index in range(6)]
    fitted = research_ai_triage.fit_context(context)
    coverage = context_coverage(fitted)
    assert len(json.dumps(fitted).encode()) <= research_ai_triage.MAX_CONTEXT_BYTES
    assert coverage["complete"] is False and "omitted:flagged_files" in coverage["gaps"]


def test_recheck_uses_the_measure_that_produced_the_result():
    context = _context()
    assert coverage_for_result(context, {"evidence_coverage": {"contract": COVERAGE_CONTRACT}})["complete"] is True
    # Clef's serialized-state measure stays as it was for Clef results.
    assert "contract" not in coverage_for_result(context, {"evidence_coverage": {"complete": True}})


def test_code_starting_with_a_slash_is_not_redacted_as_a_local_path():
    location = {"flag": "dns_lookup", "file_path": "package/a.js", "line": 3, "context": "// already observed\nlog.info('x')"}
    context = {"artifact_triage": {"flag_locations": [location]}}
    kept = intelligence.minimize(context, string_limit=16000, allow_artifact_code=True)
    assert kept["artifact_triage"]["flag_locations"][0] == location
    # Elsewhere a local path is still redacted.
    assert intelligence.minimize({"note": "/Users/me/secret"})["note"] == "[local path redacted]"


def test_bridge_reports_coverage_of_the_context_the_model_received(monkeypatch):
    from secopsai import codex_bridge
    # Far larger than Clef's serialized state, and every region is present.
    context = _context()
    context["flagged_files"][0]["content"] = "code " * 2_800
    raw = {"finding_verdict": "benign_expected", "decision_evidence_refs": ["R1"]}
    monkeypatch.setattr(codex_bridge, "_invoke_codex", lambda *a, **kw: dict(raw))
    monkeypatch.setattr(codex_bridge, "validate_bridge_result", lambda *a, **kw: None)
    request = {"action": {"name": "triage_artifact"}, "context": {"artifact_triage": context}}
    result, _ = codex_bridge._invoke_with_model_fallback(request, codex_bridge.BridgeSettings(), None, ["anthropic/claude-haiku-5-5"])
    assert result["evidence_coverage"]["contract"] == COVERAGE_CONTRACT
    assert result["evidence_coverage"]["complete"] is True and result["automatic_closure_eligible"] is True
    assert result["assessment_version"] == "decision-v2"


def _flag_context(**regions):
    from secopsai.decision_evidence import COVERAGE_CONTRACT
    return {"coverage_contract": COVERAGE_CONTRACT, "findings": [{"rule_id": "R1", "file_path": "package/test.js"}],
            "flagged_files": [{"path": "package/test.js", "content": "fixture", "complete": True}],
            "flag_locations": [{"flag": "child_process", "file_path": "package/bin/run.js", "line": 3, "context": "spawn()"}], **regions}


def test_a_flag_in_an_unsupplied_file_blocks_closure():
    from secopsai.decision_evidence import context_coverage
    coverage = context_coverage(_flag_context())
    assert not coverage["complete"] and "flag_file_not_supplied:package/bin/run.js" in coverage["gaps"]


def test_a_flag_whose_region_is_supplied_counts_as_read():
    from secopsai.decision_evidence import context_coverage
    region = {"path": "package/bin/run.js", "flags": ["child_process"], "content": "spawn()", "complete": False, "truncated": True, "regions_found": 1, "regions_shown": 1}
    assert context_coverage(_flag_context(flag_regions=[region]))["complete"]
    for changed in ({"regions_trimmed": True}, {"regions_shown": 0}):
        coverage = context_coverage(_flag_context(flag_regions=[{**region, **changed}]))
        assert not coverage["complete"] and "flag_region:package/bin/run.js" in coverage["gaps"]

