"""Observation by default; closure needs a reviewed, versioned evaluation."""
from __future__ import annotations
import json
import os
from pathlib import Path
from secopsai.decision_contracts import number, DecisionError

POLICY_VERSION = "decision-v2"


def policy_status() -> dict:
    mode = os.environ.get("SECOPSAI_DECISION_MODE", "observe").strip().lower()
    if mode != "enforce":
        return {"mode": "observe", "closure_enabled": False, "reason": "observation_mode", "policy_version": POLICY_VERSION}
    try:
        path = os.environ["SECOPSAI_DECISION_POLICY_FILE"]
        manifest = json.loads(Path(path).read_text())
        if manifest.get("policy_version") != POLICY_VERSION or manifest.get("approved") is not True or not isinstance(manifest.get("evaluations"), dict):
            raise ValueError("unapproved policy")
        return {"mode": "enforce", "closure_enabled": True, "policy_version": POLICY_VERSION, "evaluations": manifest.get("evaluations", {})}
    except (KeyError, OSError, ValueError, TypeError, AttributeError):
        return {"mode": "observe", "closure_enabled": False, "reason": "calibration_not_approved", "policy_version": POLICY_VERSION}


def closure_decision(result: dict, *, clef_probability=None, clef_choice=None) -> tuple[bool, str]:
    if result.get("assessment_version") != POLICY_VERSION:
        return False, "uncalibrated_assessment_version"
    try:
        p = number(result.get("malicious_probability", result.get("probability")), 0, 100, "probability", integer=True)
        confidence = number(result.get("finding_confidence", result.get("confidence")), 0, 100, "confidence", integer=True)
    except DecisionError:
        return False, "invalid_decision"
    benign = (result.get("finding_verdict") in {"false_positive", "benign_expected"} if "finding_verdict" in result else result.get("choice") == "benign")
    if "choice" in result and result["choice"] != "benign":
        benign = False
    if result.get("disposition_recommendation") not in {None, "false_positive", "expected_behavior"}:
        benign = False
    if not benign or p > 10 or confidence < 85:
        return False, "review_required"
    coverage = result.get("evidence_coverage")
    if result.get("automatic_closure_eligible") is not True or not isinstance(coverage, dict) or coverage.get("complete") is not True:
        return False, "incomplete_evidence"
    if clef_probability is not None:
        try:
            number(clef_probability, 0, 100, "clef_probability", integer=True)
        except DecisionError:
            return False, "invalid_clef_decision"
        if abs(clef_probability - p) >= 80:
            return False, "models_disagree"
    if clef_choice is not None and clef_choice != "benign":
        return False, "models_disagree"
    status = policy_status()
    if not status["closure_enabled"]:
        return False, status["reason"]
    identity = str(result.get("provider", "")) + ":" + str(result.get("model_version", result.get("model", "")))
    evaluation = status["evaluations"].get(identity, {})
    try:
        from secopsai.decision_evaluation import evaluation_passes
        passed = evaluation_passes(evaluation) and evaluation.get("provider") + ":" + evaluation.get("model_version") == identity
    except (ValueError, TypeError, AttributeError, KeyError):
        passed = False
    return (True, "calibrated_benign") if passed else (False, "calibration_not_approved")
