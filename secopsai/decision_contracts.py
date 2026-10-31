"""Strict contracts for decisions that may influence security workflow state."""
from __future__ import annotations

import math
import re
from typing import Any, Mapping


class DecisionError(ValueError):
    def __init__(self, message: str, *, provider: str = "decision", category: str = "invalid_response", http_status: int | None = None):
        self.provider, self.category, self.http_status = provider, category, http_status
        super().__init__(f"{provider}: {message}")


# Reviews deny approval ("NOT APPROVED") and name approved procedures in nearly every
# answer (8 of 8 on Haiku, 2026-10-31). Every other use of the word still blocks.
_APPROVED = re.compile(r"\bapproved\b", re.IGNORECASE)
_DENIED = re.compile(r"(?:\b(?:not|never|no)|n't)(?:\s+\w+){0,2}\s+$", re.IGNORECASE)
_PROCEDURE = re.compile(
    r"\s+(?:\w+\s+)?(?:methods?|procedures?|process(?:es)?|plans?|sandbox(?:es)?|actions?|channels?|tools?|environments?|mechanisms?|workflows?)\b",
    re.IGNORECASE,
)
_PROCEED = re.compile(r"\bproceed\s+with\s+publication\b", re.IGNORECASE)


def _claims_approval(text: str) -> bool:
    if _PROCEED.search(text):
        return True
    return any(
        not _DENIED.search(text[:match.start()]) and not _PROCEDURE.match(text, match.end())
        for match in _APPROVED.finditer(text)
    )


def number(value: Any, low: float, high: float, name: str, *, integer: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise DecisionError(f"{name} must be a finite number")
    if not low <= value <= high or (integer and int(value) != value):
        raise DecisionError(f"{name} is outside its permitted range")
    return value


def validate_answers(data: Any, questions: Mapping[str, Mapping[str, Any]], *, provider: str) -> dict[str, Any]:
    try:
        if isinstance(data, dict) and "success" in data and data["success"] is not True:
            raise DecisionError("provider evaluation was unsuccessful")
        if not isinstance(data, dict) or not isinstance(data.get("answers"), dict):
            raise DecisionError("response must contain an answers object")
        if not isinstance(data.get("model"), str) or not data["model"].strip():
            raise DecisionError("response must identify the evaluated model")
        answers = data["answers"]
        for key, question in questions.items():
            ans = answers.get(key)
            kind = question["type"]
            if not isinstance(ans, dict) or ans.get("type") != kind:
                raise DecisionError(f"missing or mistyped answer: {key}")
            if kind == "noul":
                number(ans.get("noul"), 0, 1, key)
                continue
            criteria = question["criteria"]
            options = set(criteria) if kind == "choice" else {str(i) for i in range(len(criteria))}
            probabilities = ans.get("probabilities")
            if not isinstance(probabilities, dict) or set(probabilities) != options:
                raise DecisionError(f"{key} must include probabilities for every submitted option")
            for option, value in probabilities.items():
                number(value, 0, 1, f"{key}.{option}")
            if abs(sum(probabilities.values()) - 1) > 0.001:
                raise DecisionError(f"{key} probabilities must sum to one")
            number(ans.get("confidence"), 0, 1, f"{key}.confidence")
            if kind == "choice":
                choice = ans.get("choice")
                if not isinstance(choice, str) or choice not in options:
                    raise DecisionError(f"{key} selected an unknown option")
                if probabilities[choice] + 0.001 < max(probabilities.values()):
                    raise DecisionError(f"{key} choice contradicts its distribution")
            elif kind == "score":
                score = number(ans.get("score"), 0, len(criteria) - 1, key)
                expected = sum(int(level) * p for level, p in probabilities.items())
                if abs(score - expected) > 0.01:
                    raise DecisionError(f"{key} score contradicts its distribution")
            else:
                raise DecisionError(f"unsupported answer type: {kind}")
        return data
    except DecisionError as exc:
        raise DecisionError(str(exc), provider=provider) from exc


FINDING_VERDICTS = {"true_positive", "false_positive", "benign_expected", "policy_noise", "needs_more_evidence"}
DISPOSITIONS = {"true_positive", "false_positive", "expected_behavior", "tune_policy", "needs_review"}


def validate_action_result(
    action: str,
    value: Any,
    *,
    supplied_evidence_refs: set[str] | None = None,
    supplied_finding_ids: set[str] | None = None,
    supplied_missing_files: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DecisionError("bridge result must be an object")
    for key in ("summary", "risk_assessment"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise DecisionError(f"bridge result requires nonempty {key}")
    for key in ("evidence", "recommended_actions", "limitations"):
        if not isinstance(value.get(key), list) or any(not isinstance(v, str) for v in value[key]):
            raise DecisionError(f"bridge result requires a string array: {key}")
    if action != "analyze_research_case" and (value.get("verdict_recommendation", "inconclusive") != "inconclusive" or value.get("verdict_confidence", 0) != 0):
        raise DecisionError("research credibility was not assessed by this action", category="safety")
    if action not in {"triage_artifact", "triage_finding"} and any(
        value.get(key) is not None
        for key in ("finding_verdict", "finding_confidence", "malicious_probability", "disposition_recommendation")
    ):
        raise DecisionError("finding decision fields were returned by an unrelated action", category="safety")
    if action in {"triage_artifact", "triage_finding"}:
        if not isinstance(value.get("finding_verdict"), str) or not isinstance(value.get("disposition_recommendation"), str) or value["finding_verdict"] not in FINDING_VERDICTS or value["disposition_recommendation"] not in DISPOSITIONS:
            raise DecisionError("triage result requires valid verdict and disposition")
        if action == "triage_artifact" and value["finding_verdict"] == "policy_noise":
            raise DecisionError("artifact verdict cannot be policy_noise")
        expected = {"true_positive": "true_positive", "false_positive": "false_positive", "benign_expected": "expected_behavior", "policy_noise": "tune_policy", "needs_more_evidence": "needs_review"}
        if value["disposition_recommendation"] != expected[value["finding_verdict"]]:
            raise DecisionError("finding verdict contradicts its disposition", category="safety")
        number(value.get("finding_confidence"), 0, 100, "finding_confidence", integer=True)
        number(value.get("malicious_probability"), 0, 100, "malicious_probability", integer=True)
        if action == "triage_artifact":
            if value["finding_verdict"] == "needs_more_evidence":
                missing = value.get("missing_evidence")
                if not isinstance(missing, list) or not missing or any(not isinstance(path, str) or not path.strip() or "\n" in path for path in missing):
                    raise DecisionError("artifact abstention requires a named missing file", category="safety")
                if supplied_missing_files is not None and any(path not in supplied_missing_files for path in missing):
                    raise DecisionError("artifact abstention cites a file that was not identified as missing", category="safety")
        refs = value.get("decision_evidence_refs")
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs):
            raise DecisionError("triage requires at least one decision evidence reference")
        if supplied_evidence_refs is not None and any(ref not in supplied_evidence_refs for ref in refs):
            raise DecisionError("triage cites evidence that was not supplied", category="safety")
    if action == "prioritize_findings":
        priorities = value.get("finding_priorities")
        if not isinstance(priorities, list):
            raise DecisionError("prioritization requires a per-finding result array")
        seen: set[str] = set()
        for index, item in enumerate(priorities):
            if not isinstance(item, dict):
                raise DecisionError("each finding priority must be an object")
            finding_id = item.get("finding_id")
            if not isinstance(finding_id, str) or not finding_id.strip() or finding_id in seen:
                raise DecisionError("finding priorities require unique nonempty finding IDs")
            seen.add(finding_id)
            number(item.get("priority"), 0, 100, f"finding_priorities[{index}].priority", integer=True)
            if not isinstance(item.get("rationale"), str) or not item["rationale"].strip():
                raise DecisionError("each finding priority requires a rationale")
            refs = item.get("evidence_refs")
            if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or not ref for ref in refs):
                raise DecisionError("each finding priority requires at least one evidence reference")
            if supplied_evidence_refs is not None and any(ref not in supplied_evidence_refs for ref in refs):
                raise DecisionError("finding priority cites evidence that was not supplied", category="safety")
        if supplied_finding_ids is not None and seen != supplied_finding_ids:
            raise DecisionError("prioritization must return exactly one result for each supplied finding", category="safety")
    if action == "analyze_research_case":
        if not isinstance(value.get("verdict_recommendation"), str) or value["verdict_recommendation"] not in {"credible", "likely", "inconclusive", "not_substantiated", "benign"}:
            raise DecisionError("research result requires a verdict")
        number(value.get("verdict_confidence"), 0, 100, "verdict_confidence", integer=True)
        rationale = value.get("verdict_rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise DecisionError("research assessment requires a rationale")
        refs = value.get("verdict_evidence_refs")
        if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref for ref in refs):
            raise DecisionError("research assessment requires an evidence reference array")
        if supplied_evidence_refs is not None and any(ref not in supplied_evidence_refs for ref in refs):
            raise DecisionError("research assessment cites evidence that was not supplied", category="safety")
        if value["verdict_recommendation"] != "inconclusive":
            if not refs:
                raise DecisionError("research conclusion requires supporting evidence references and rationale")
    if action == "generate_analyst_brief":
        outline = value.get("article_outline")
        if not isinstance(outline, list) or not outline or any(not isinstance(item, str) or not item.strip() for item in outline):
            raise DecisionError("analyst brief requires an article outline")
    if action == "review_publication_safety":
        risks = value.get("publication_risks")
        if not isinstance(risks, list) or any(not isinstance(item, str) for item in risks) or not isinstance(value.get("disclosure_draft"), str) or not value["disclosure_draft"].strip():
            raise DecisionError("publication review requires risk findings and a review-only disclosure draft")
        checks = value.get("publication_checks")
        required_checks = {"evidence", "privacy", "credential_leakage", "operational_safety", "legal_disclosure", "reproducibility"}
        if not isinstance(checks, dict) or set(checks) != required_checks:
            raise DecisionError("publication review requires every structured safety check")
        unresolved: set[str] = set()
        for name, check in checks.items():
            if not isinstance(check, dict) or check.get("status") not in {"clear", "concern", "unknown"}:
                raise DecisionError(f"publication check {name} has a missing or invalid status")
            finding = check.get("finding")
            if not isinstance(finding, str) or not finding.strip():
                raise DecisionError(f"publication check {name} requires a finding")
            if check["status"] != "clear":
                unresolved.add(finding.strip())
        if set(item.strip() for item in risks) != unresolved:
            raise DecisionError("publication risks contradict the structured safety checks", category="safety")
        if unresolved and not value.get("recommended_actions"):
            raise DecisionError("publication concerns require corrective actions")
        review_text = [value.get("summary", ""), value.get("risk_assessment", ""), value["disclosure_draft"]]
        review_text.extend(value.get("recommended_actions") or [])
        review_text.extend(risks)
        review_text.extend(check["finding"] for check in checks.values())
        if _claims_approval("\n".join(review_text)):
            raise DecisionError("publication review cannot approve release", category="safety")
        if value.get("publication_approved") is True or value.get("approved") is True:
            raise DecisionError("publication review cannot authorize publication", category="safety")
    return value
