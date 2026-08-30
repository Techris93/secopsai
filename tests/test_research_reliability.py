from __future__ import annotations

import json
import sqlite3

import pytest

from secopsai import cli as cli_module
from secopsai.research_cases import add_evidence, add_subject, create_case, get_case
from secopsai.research_reliability import (
    HYPOTHESIS_TYPES,
    audit_completeness,
    audit_originality,
    clip_unsupported_claims,
    create_evidence_plan,
    extract_claim_ledger,
    generate_hypotheses,
    get_reliability_workspace,
    inspect_run_bundle,
    rank_hypotheses,
    record_visual_qa,
    reliability_benchmark,
    publication_reliability_gate,
    revise_evidence_plan,
    run_full_safe_research,
    run_scaffold_research,
    screen_research_safety,
    verify_transition,
)
from secopsai.codex_bridge import persist_model_routing
from secopsai.specialist_orchestrator import (
    adjudicate_review_disagreement,
    create_run,
    record_primary_result,
    record_review_result,
    specialist_bridge_context,
)


def _case(tmp_path, *, sandbox: bool = False) -> tuple[str, str]:
    db = str(tmp_path / "research.db")
    case = create_case(
        title="Source-backed package compromise investigation",
        summary="An exact package release requires evidence-led analysis before any maliciousness or impact verdict.",
        case_type="malicious_package",
        severity="high",
        confidence=70,
        db_path=db,
    )
    case = add_subject(
        case["case_id"],
        subject_type="package",
        ecosystem="crates",
        name="proc-macro1",
        version="1.0.107",
        publisher="registry publisher",
        db_path=db,
    )
    case = add_evidence(
        case["case_id"],
        evidence_type="registry_metadata",
        title="Official crates.io metadata",
        locator="https://crates.io/api/v1/crates/proc-macro1/1.0.107",
        sha256="6" * 64,
        provenance="official crates.io API snapshot",
        notes="The registry record identifies proc-macro1 version 1.0.107 and its checksum.",
        metadata={"tool": "SecOpsAI registry adapter", "tool_version": "1", "execution_performed": False},
        db_path=db,
    )
    case = add_evidence(
        case["case_id"],
        evidence_type="static_analysis",
        title="Static build script analysis",
        sha256="7" * 64,
        provenance="SecOpsAI static rules; no package code executed",
        notes="Static inspection found a network retrieval string in build.rs. Static evidence does not prove execution.",
        metadata={
            "tool": "SecOpsAI Artifact Fleet",
            "tool_version": "1",
            "execution_performed": False,
            "observations": [{"rule_id": "rust-build-network", "file": "build.rs", "severity": "high"}],
        },
        db_path=db,
    )
    if sandbox:
        add_evidence(
            case["case_id"],
            evidence_type="sandbox_analysis",
            title="Sanitized Tria.ge analysis",
            locator="https://tria.ge/fixture/report",
            sha256="6" * 64,
            provenance="Tria.ge public analysis linked to exact artifact hash",
            notes="The provider-scoped sandbox observed a child process.",
            metadata={"provider": "tria.ge", "execution_performed": True},
            db_path=db,
        )
    return case["case_id"], db


def _full(case_id: str, db: str) -> dict:
    assert run_scaffold_research(case_id, db_path=db)["status"] == "succeeded"
    assert verify_transition(case_id, db_path=db)["status"] == "succeeded"
    result = run_full_safe_research(case_id, db_path=db)
    assert result["status"] == "succeeded"
    return result


def test_hypotheses_are_bounded_falsifiable_and_ranked_without_model_calls(tmp_path):
    case_id, db = _case(tmp_path)
    generated = generate_hypotheses(case_id, db_path=db)

    assert {item["hypothesis_type"] for item in generated["hypotheses"]} == set(HYPOTHESIS_TYPES)
    assert all(item["predicted_evidence"] and item["falsifiers"] for item in generated["hypotheses"])
    assert all("fake" not in json.dumps(item).lower() for item in generated["hypotheses"])

    ranked = rank_hypotheses(case_id, candidate_budget=6, comparison_budget=15, model_call_budget=2, db_path=db)
    assert ranked["ranking"][0]["status"] == "selected"
    assert ranked["budgets"]["model_calls_used"] == 0
    assert len(ranked["comparisons"]) == 15


def test_versioned_plan_records_intended_and_executed_methods_and_blocks_composition(tmp_path):
    case_id, db = _case(tmp_path)
    plan = create_evidence_plan(case_id, db_path=db)
    assert plan["revision"] == 1
    assert plan["intended_methods"]
    assert plan["executed_methods"] == []
    assert plan["safety_decisions"]["execution_allowed"] is False

    safety = screen_research_safety(
        actions=["Read cloud credentials from the developer home directory", "Upload credentials over HTTPS to a remote server"]
    )
    assert safety["status"] == "blocked"
    assert any("credential collection" in item for item in safety["blockers"])

    revised = revise_evidence_plan(
        case_id,
        reason="The official registry record disappeared; preserve the failed method and use the retained snapshot.",
        executed_methods=["collect_official_registry_or_repository_metadata"],
        db_path=db,
    )
    assert revised["revision"] == 2
    assert revised["parent_plan_id"] == plan["plan_id"]
    assert "registry record disappeared" in revised["change_reason"]
    assert revised["executed_methods"] == ["collect_official_registry_or_repository_metadata"]


def test_scaffold_transition_and_full_bundle_are_tamper_evident(tmp_path):
    case_id, db = _case(tmp_path)
    full = _full(case_id, db)
    verified = inspect_run_bundle(full["bundle_id"], db_path=db)
    assert verified["verification"]["tamper_evident"] is True
    assert verified["payload"]["configuration"]["execution_performed"] is False
    assert verified["payload"]["errors"] == []
    assert verified["completeness_score"] >= 70
    assert verified["payload"]["resource_usage"]["disk_total_bytes"] > 0
    assert "active_queue_depth" in verified["payload"]["resource_usage"]
    assert "health" in verified["payload"]["model_routing"]
    accounting = verified["payload"]["resource_accounting"]
    assert accounting["latency_ms"] >= 0
    assert accounting["retry_count"] == 0
    assert accounting["estimated_input_tokens"] == 0
    assert accounting["estimated_output_tokens"] == 0
    assert accounting["estimated_cost_usd"] == 0

    with sqlite3.connect(db) as connection:
        connection.execute(
            "UPDATE research_run_bundles SET payload_json=? WHERE bundle_id=?",
            (json.dumps({"tampered": True}), full["bundle_id"]),
        )
        connection.commit()
    assert inspect_run_bundle(full["bundle_id"], db_path=db)["verification"]["tamper_evident"] is False


def test_transition_blocks_mock_fixture_placeholder_and_synthetic_evidence(tmp_path):
    case_id, db = _case(tmp_path)
    add_evidence(
        case_id,
        evidence_type="static_analysis",
        title="Unsafe transition fixture",
        provenance="test",
        metadata={"fixture_mode": True, "mock": True, "placeholder_hash": True, "synthetic": True},
        db_path=db,
    )
    run_scaffold_research(case_id, db_path=db)
    result = verify_transition(case_id, db_path=db)
    assert result["status"] == "blocked"
    assert result["payload"]["stage_result"]["markers"]
    with pytest.raises(ValueError, match="transition verification"):
        run_full_safe_research(case_id, db_path=db)


def test_claim_ledger_verifies_canonical_identifiers_and_blocks_fabrications(tmp_path):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    text = (
        "The investigation concerns proc-macro1@1.0.107. "
        f"The official artifact checksum is {'6' * 64}. "
        f"The payload checksum is {'a' * 64}. "
        "CVE-2099-99999 affected 82 victims on 2099-01-01."
    )
    ledger = extract_claim_ledger(case_id, text=text, source_kind="publication_draft", source_locator="draft-1", db_path=db)
    by_text = {item["text_span"]: item for item in ledger["claims"]}
    assert next(item for text, item in by_text.items() if "proc-macro1" in text)["support_status"] == "supported"
    assert next(item for text, item in by_text.items() if "official artifact checksum" in text)["support_status"] == "supported"
    assert next(item for text, item in by_text.items() if "payload checksum" in text)["support_status"] == "unsupported"
    assert next(item for text, item in by_text.items() if "CVE-2099" in text)["support_status"] == "unsupported"
    assert ledger["summary"]["publication_blocked"] is True


def test_runtime_claim_needs_exact_sandbox_evidence_and_local_execution_stays_false(tmp_path):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    ledger = extract_claim_ledger(case_id, text="The package executed a child process and connected to its runtime server.", db_path=db)
    assert ledger["claims"][0]["support_status"] == "contradicted"
    assert "local execution was not performed" in " ".join(ledger["claims"][0]["contradicting_evidence"])

    sandbox_case, sandbox_db = _case(tmp_path / "sandbox", sandbox=True)
    _full(sandbox_case, sandbox_db)
    sandbox_ledger = extract_claim_ledger(sandbox_case, text="The external sandbox observed runtime behavior and executed a child process.", db_path=sandbox_db)
    assert sandbox_ledger["claims"][0]["support_status"] in {"supported", "qualified_inference"}
    assert sandbox_ledger["claims"][0]["evidence_ids"]


def test_hallucination_clipping_keeps_revision_diff_and_never_fabricates_success(tmp_path):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    fabricated = f"The analysis succeeded and proved the payload hash {'b' * 64}."
    clipped = clip_unsupported_claims(case_id, text=fabricated, db_path=db)
    assert clipped["corrected_text"] == ""
    assert clipped["revisions"][0]["before"] == fabricated
    assert clipped["revisions"][0]["action"] == "removed"
    workspace = get_reliability_workspace(case_id, db_path=db)
    assert workspace["claim_revisions"]
    assert all(item["claim_id"] != clipped["revisions"][0]["claim_id"] for item in workspace["effective_claim_ledger"])


def test_completeness_originality_and_visual_audits_are_hard_gates(tmp_path):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    extract_claim_ledger(case_id, text="The investigation concerns proc-macro1@1.0.107.", db_path=db)

    completeness = audit_completeness(case_id, db_path=db)
    assert completeness["details"]["checks"]["selective_reporting"] == "passed"
    originality = audit_originality(case_id, text="Original SecOpsAI analysis of proc-macro1@1.0.107 based on the linked registry record.", db_path=db)
    assert originality["status"] == "passed"
    blocked_visual = record_visual_qa(case_id, desktop_rendered=True, mobile_rendered=False, missing_alt_text=1, db_path=db)
    assert blocked_visual["status"] == "blocked"
    desktop = tmp_path / "desktop.png"
    mobile = tmp_path / "mobile.png"
    desktop.write_bytes(b"\x89PNG\r\n\x1a\nvisual-desktop")
    mobile.write_bytes(b"\x89PNG\r\n\x1a\nvisual-mobile")
    passed_visual = record_visual_qa(
        case_id,
        desktop_rendered=True,
        mobile_rendered=True,
        screenshots=[f"desktop={desktop}", f"mobile={mobile}"],
        db_path=db,
    )
    assert passed_visual["status"] == "passed"
    assert {item["viewport"] for item in passed_visual["details"]["screenshots"]} == {"desktop", "mobile"}
    assert all(len(item["sha256"]) == 64 for item in passed_visual["details"]["screenshots"])

    symlink = tmp_path / "desktop-link.png"
    try:
        symlink.symlink_to(desktop)
    except OSError:
        symlink = None
    if symlink is not None:
        blocked_link = record_visual_qa(
            case_id,
            desktop_rendered=True,
            mobile_rendered=True,
            screenshots=[f"desktop={symlink}", f"mobile={mobile}"],
            db_path=db,
        )
        assert blocked_link["status"] == "blocked"
        assert any("non-symlink" in item for item in blocked_link["hard_blockers"])


def test_reliability_benchmark_has_all_adversarial_conditions_and_no_production_bypass():
    result = reliability_benchmark()
    assert result["passed"] is True
    assert result["production_controls_modified"] is False
    assert len(result["fixtures"]) == 15
    assert len(result["fixture_digest_sha256"]) == 64
    assert result["conditions"]["full_controls"]["publication_block_accuracy"] == 1.0
    assert result["conditions"]["full_controls"]["unsupported_claim_rate"] == 0.0
    assert all(item["decision_correct"] for item in result["conditions"]["full_controls"]["fixture_results"])
    assert result["conditions"]["claim_clipping_disabled"]["unsupported_claim_rate"] > 0
    assert result["conditions"]["completeness_audit_disabled"]["selective_reporting_rate"] > 0
    assert result["conditions"]["unconstrained_mock_baseline"]["result_hallucination_severity"] > 0
    assert result["conditions"]["unconstrained_mock_baseline"]["false_positives"] == 1
    assert result["conditions"]["unconstrained_mock_baseline"]["false_negatives"] == 1


def test_case_payload_exposes_one_coherent_reliability_workspace(tmp_path):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    extract_claim_ledger(case_id, text="The investigation concerns proc-macro1@1.0.107.", db_path=db)
    case = get_case(case_id, db_path=db)
    assert case["research_reliability"]["schema_version"].startswith("secopsai.execution-grounded")
    assert case["research_reliability"]["next_action"]["action"]


def test_independent_reviewer_context_is_blinded_from_primary_verdict_and_wording(tmp_path):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    extract_claim_ledger(case_id, text="The investigation concerns proc-macro1@1.0.107.", db_path=db)
    run = create_run(
        {
            "task_id": case_id,
            "title": "Review package compromise evidence",
            "description": "Review the immutable evidence bundle and claim support.",
            "domain": "threat-intelligence",
            "priority": "high",
            "analysis_only": True,
            "requires_security_review": True,
        },
        tier="recommend",
        db_path=db,
    )
    context = specialist_bridge_context(run["run_id"], db_path=db, review=True)
    assert "primary_result" not in context
    assert "verdicts" not in context["research_case"]
    assert "confidence" not in context["research_case"]
    assert context["blind_review"]["blinded"] is True
    assert context["blind_review"]["primary_result_included"] is False
    assert context["blind_review"]["run_bundles"]
    assert context["blind_review"]["claim_ledger"]


def test_material_review_disagreement_is_persisted_and_requires_human_adjudication(tmp_path):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    extract_claim_ledger(case_id, text="The investigation concerns proc-macro1@1.0.107.", db_path=db)
    persist_model_routing("xai/grok-4.6", fallback_mode="disabled", db_path=db)
    run = create_run(
        {
            "task_id": case_id,
            "title": "Review package compromise evidence",
            "description": "Review only the immutable evidence and claim ledger.",
            "domain": "threat-intelligence",
            "priority": "high",
            "analysis_only": True,
            "requires_security_review": True,
        },
        tier="read_only",
        db_path=db,
    )
    primary = record_primary_result(
        run["run_id"],
        {"verdict_recommendation": "credible", "finding_verdict": "true_positive", "verdict_evidence_refs": ["EVD-PRIMARY"]},
        model="xai/grok-4.6",
        db_path=db,
    )
    reviewed = record_review_result(
        primary["run_id"],
        {"verdict_recommendation": "benign", "finding_verdict": "false_positive", "verdict_evidence_refs": ["EVD-REVIEW"]},
        model="xai/grok-4.6",
        db_path=db,
    )
    assert reviewed["material_disagreement"] is True
    assert reviewed["adjudication_status"] == "pending_human"
    assert reviewed["review"]["comparison"]["evidence_refs"] == ["EVD-PRIMARY", "EVD-REVIEW"]
    workspace = get_reliability_workspace(case_id, db_path=db)
    assert workspace["specialist_review"]["publication_blocked"] is True
    assert workspace["next_action"]["action"] == "adjudicate_review"

    adjudicated = adjudicate_review_disagreement(
        run["run_id"],
        decision="accept_reviewer",
        rationale="The reviewer interpretation is supported by the independently verified registry evidence.",
        actor="human-analyst",
        db_path=db,
    )
    assert adjudicated["adjudication_status"] == "resolved_reviewer"
    workspace = get_reliability_workspace(case_id, db_path=db)
    assert workspace["specialist_review"]["publication_blocked"] is False
    gate = publication_reliability_gate(case_id, db_path=db)
    assert "specialist and blinded independent review must complete without material disagreement" not in gate["blockers"]


def test_reliability_cli_executes_typed_case_stages_and_benchmark(tmp_path, capsys):
    case_id, db = _case(tmp_path)
    commands = (
        ["generate-hypotheses", case_id],
        ["rank-hypotheses", case_id, "--candidate-budget", "6", "--comparison-budget", "15"],
        ["plan", case_id],
        ["run-scaffold", case_id],
        ["verify-transition", case_id],
        ["run-full", case_id],
        ["status", case_id],
    )
    outputs = []
    for command in commands:
        code = cli_module.main(["--json", "research", "reliability", *command, "--db-path", db])
        outputs.append(json.loads(capsys.readouterr().out))
        assert code == 0
    assert outputs[0]["hypotheses"]
    assert outputs[1]["ranking"][0]["status"] == "selected"
    assert outputs[4]["status"] == "succeeded"
    assert outputs[5]["payload"]["configuration"]["execution_performed"] is False
    assert outputs[6]["run_bundles"]

    code = cli_module.main(["--json", "research", "reliability", "benchmark"])
    benchmark = json.loads(capsys.readouterr().out)
    assert code == 0
    assert benchmark["passed"] is True
    assert benchmark["production_controls_modified"] is False


def test_reliability_cli_parses_typed_adjudication_contract():
    parsed = cli_module.parse_args(
        [
            "research",
            "reliability",
            "adjudicate-review",
            "SOR-ABCDEF1234567890",
            "--decision",
            "accept_primary",
            "--rationale",
            "The primary result is supported by independently verified evidence.",
        ]
    )
    assert parsed.research_reliability_cmd == "adjudicate-review"
    assert parsed.run_id == "SOR-ABCDEF1234567890"
    assert parsed.decision == "accept_primary"


def test_reliability_cli_adjudication_records_typed_human_decision(tmp_path, capsys):
    case_id, db = _case(tmp_path)
    _full(case_id, db)
    extract_claim_ledger(case_id, text="The investigation concerns proc-macro1@1.0.107.", db_path=db)
    run = create_run(
        {
            "task_id": case_id,
            "title": "Review package compromise evidence",
            "description": "Review only the immutable evidence and claim ledger.",
            "domain": "threat-intelligence",
            "priority": "high",
            "analysis_only": True,
            "requires_security_review": True,
        },
        tier="read_only",
        db_path=db,
    )
    primary = record_primary_result(
        run["run_id"],
        {"verdict_recommendation": "credible", "finding_verdict": "true_positive", "verdict_evidence_refs": ["EVD-PRIMARY"]},
        model="xai/grok-4.6",
        db_path=db,
    )
    record_review_result(
        primary["run_id"],
        {"verdict_recommendation": "benign", "finding_verdict": "false_positive", "verdict_evidence_refs": ["EVD-REVIEW"]},
        model="xai/grok-4.6",
        db_path=db,
    )
    code = cli_module.main(
        [
            "--json",
            "research",
            "reliability",
            "adjudicate-review",
            run["run_id"],
            "--decision",
            "accept_primary",
            "--rationale",
            "The primary conclusion is supported by the independent registry and static evidence.",
            "--db-path",
            db,
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["adjudication_status"] == "resolved_primary"
