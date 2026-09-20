from __future__ import annotations

import json
import logging
import os
from typing import Any, Mapping

import requests

logger = logging.getLogger(__name__)

TYPESAFE_API_URL = os.environ.get("TYPESAFE_API_URL", "https://api.typesafe.ai/v1/systemone").strip()
TYPESAFE_MODEL = "jev-latest"
DEFAULT_TIMEOUT_SECONDS = 30


def get_typesafe_api_key() -> str:
    """Return configured TypeSafe API key or empty string.

    Checks:
    1. Environment variable: TYPESAFE_API_KEY
    2. Local .env file in current working directory or repository root
    3. User credential file: ~/.secopsai/typesafe.key or ~/.secopsai/config.env
    """
    key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if key:
        return key

    from pathlib import Path

    candidate_files = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[1] / ".env",
        Path.home() / ".secopsai" / "typesafe.key",
        Path.home() / ".secopsai" / "config.env",
    ]
    for path in candidate_files:
        try:
            if path.is_file():
                if path.suffix == ".key":
                    val = path.read_text(encoding="utf-8").strip()
                    if val:
                        return val
                else:
                    for line in path.read_text(encoding="utf-8").splitlines():
                        stripped = line.strip()
                        if stripped.startswith("TYPESAFE_API_KEY="):
                            val = stripped.split("=", 1)[1].strip().strip("\"'")
                            if val:
                                return val
        except Exception:
            continue
    return ""


def set_typesafe_api_key(api_key: str, scope: str = "user") -> str:
    """Persist the TypeSafe API key to ~/.secopsai/typesafe.key (user) or .env (local)."""
    from pathlib import Path

    key = api_key.strip()
    if not key:
        raise ValueError("API key cannot be empty.")

    if scope in ("local", "env"):
        env_file = Path.cwd() / ".env"
        lines: list[str] = []
        replaced = False
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("TYPESAFE_API_KEY="):
                    lines.append(f'TYPESAFE_API_KEY="{key}"')
                    replaced = True
                else:
                    lines.append(line)
        if not replaced:
            lines.append(f'TYPESAFE_API_KEY="{key}"')
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(env_file)
    else:
        key_dir = Path.home() / ".secopsai"
        key_dir.mkdir(parents=True, exist_ok=True)
        key_file = key_dir / "typesafe.key"
        key_file.write_text(key + "\n", encoding="utf-8")
        try:
            key_file.chmod(0o600)
        except OSError:
            pass
        return str(key_file)


def is_typesafe_available() -> bool:
    """Return True if TypeSafe API key is configured."""
    return bool(get_typesafe_api_key())


def probe_typesafe(api_key: str | None = None, timeout: int = 5) -> dict[str, Any]:
    """Check connectivity and authentication against the TypeSafe API."""
    key = api_key or get_typesafe_api_key()
    if not key:
        return {
            "status": "unconfigured",
            "ready": False,
            "message": "TYPESAFE_API_KEY is not set in environment.",
        }

    url = TYPESAFE_API_URL
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "SecOpsAI-TypeSafe-Adapter/1.0",
    }
    payload = {
        "model": TYPESAFE_MODEL,
        "state": "SecOpsAI health probe",
        "questions": {
            "probe": {
                "type": "noul",
                "instructions": "Is the system operational?",
            }
        },
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if response.status_code == 200:
            return {
                "status": "ready",
                "ready": True,
                "message": "TypeSafe Jev endpoint ready and authenticated.",
            }
        return {
            "status": "error",
            "ready": False,
            "http_status": response.status_code,
            "message": f"TypeSafe API returned HTTP {response.status_code}: {response.text[:200]}",
        }
    except Exception as exc:
        return {
            "status": "unreachable",
            "ready": False,
            "message": f"Could not reach TypeSafe API: {exc}",
        }


def evaluate_system_one(
    state: Any,
    questions: Mapping[str, Mapping[str, Any]],
    *,
    api_key: str | None = None,
    model: str = TYPESAFE_MODEL,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Send state and typed questions to TypeSafe System One (Jev) API.

    Returns the parsed response dictionary containing 'answers', 'model', and 'usage'.
    """
    key = api_key or get_typesafe_api_key()
    if not key:
        raise ValueError("TYPESAFE_API_KEY is required for TypeSafe System One evaluation.")

    url = TYPESAFE_API_URL
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "SecOpsAI-TypeSafe-Adapter/1.0",
    }
    payload = {
        "model": model,
        "state": state,
        "questions": questions,
    }

    response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    if not response.ok:
        raise RuntimeError(
            f"TypeSafe API request failed with status {response.status_code}: {response.text[:500]}"
        )

    data = response.json()
    if not isinstance(data, dict) or "answers" not in data:
        raise RuntimeError("Invalid response structure received from TypeSafe API.")

    return data


def build_triage_questions() -> dict[str, Any]:
    """Define typed Jev System One questions for security finding triage."""
    return {
        "finding_verdict": {
            "type": "choice",
            "instructions": "Determine the true security verdict for this finding based on provided context.",
            "criteria": {
                "true_positive": "Legitimate security vulnerability, exposure, or suspicious activity requiring action.",
                "false_positive": "Incorrect detection, benign artifact, or scanner error.",
                "benign_expected": "Expected configuration, intentional design, or legitimate administrative activity.",
                "policy_noise": "Low-risk non-compliance or informational alert not posing immediate operational risk.",
                "needs_more_evidence": "Inconclusive telemetry; additional logs, network flows, or investigation needed.",
            },
        },
        "exposure_assessment": {
            "type": "choice",
            "instructions": "Assess the exposure and accessibility of the affected asset or resource.",
            "criteria": {
                "affected": "Directly exposed, vulnerable, or reachable by external/untrusted actors.",
                "not_observed": "Compensating controls present; vulnerability not reachable or exploited.",
                "unknown": "Exposure status cannot be verified from available evidence.",
                "not_applicable": "Finding does not apply to this system environment.",
            },
        },
        "automation_recommendation": {
            "type": "choice",
            "instructions": "Recommend the optimal workflow automation step.",
            "criteria": {
                "escalate": "Alert security team / SOC analyst immediately for active investigation.",
                "suppress_once": "Dismiss or close this specific instance without modifying global rules.",
                "suppress_pattern": "Tune detection rule or create allowlist filter for recurring benign noise.",
                "monitor": "Keep under passive observation without paging engineers.",
                "collect_evidence": "Trigger automated forensic artifact collection or host inspection.",
            },
        },
        "risk_severity": {
            "type": "score",
            "instructions": "Rate the contextual operational risk severity of this finding.",
            "criteria": [
                "0: Informational or negligible impact",
                "1: Low impact, limited attack surface",
                "2: Medium impact, internal exposure or compliance concern",
                "3: High impact, credential or remote exposure",
                "4: Critical impact, active exploitation or severe zero-day potential",
            ],
        },
        "containment_needed": {
            "type": "noul",
            "instructions": "Does this finding warrant immediate network isolation, host quarantine, or token revocation?",
            "criteria": {
                "true": "Immediate containment/isolation strongly advised.",
                "false": "No emergency containment required.",
            },
        },
    }


def build_publication_safety_questions() -> dict[str, Any]:
    """Define typed Jev System One questions for publication safety review."""
    return {
        "safe_to_publish": {
            "type": "noul",
            "instructions": "Is this security case and brief safe for external publication and coordinated disclosure?",
            "criteria": {
                "true": "Safe to publish; compliant with disclosure standards.",
                "false": "Unsafe; contains confidential data, premature disclosures, or unverified claims.",
            },
        },
        "credential_leakage": {
            "type": "noul",
            "instructions": "Does the report contain live credentials, passwords, unredacted API tokens, or PII?",
            "criteria": {
                "true": "Unredacted sensitive secrets or personal data present.",
                "false": "All sensitive identifiers properly redacted or synthetic.",
            },
        },
        "verdict_recommendation": {
            "type": "choice",
            "instructions": "Evaluate the credibility and evidence backing the core claims of this research case.",
            "criteria": {
                "credible": "Claims are fully validated with verified artifacts and reproducible evidence.",
                "likely": "High probability of correctness based on telemetry, though partial gaps remain.",
                "inconclusive": "Insufficient proof to substantiate the central allegations.",
                "not_substantiated": "Claims appear disproven or contradicted by evidence.",
                "benign": "Analyzed behavior confirmed benign with no security impact.",
            },
        },
        "publication_risk": {
            "type": "score",
            "instructions": "Rate the overall legal, ethical, and operational risk of releasing this publication.",
            "criteria": [
                "0: Negligible risk, standard disclosure",
                "1: Minor risk, standard advisory caveats recommended",
                "2: Moderate risk, review legal and vendor attribution",
                "3: High risk, potential vendor dispute or embargo violation",
                "4: Blocking risk, serious disclosure violation or uncoordinated exploit release",
            ],
        },
    }


def build_prioritize_questions() -> dict[str, Any]:
    """Define typed Jev System One questions for finding prioritization."""
    return {
        "priority_tier": {
            "type": "choice",
            "instructions": "Assign this finding to an operational triage queue tier.",
            "criteria": {
                "p0_critical": "P0: Immediate action required (active attack or critical vulnerability).",
                "p1_high": "P1: Review within the current shift / business day.",
                "p2_medium": "P2: Normal sprint backlog remediation.",
                "p3_low": "P3: Low priority / informational review.",
            },
        },
        "exploitability": {
            "type": "score",
            "instructions": "Assess the practical exploitability of this issue in the observed environment.",
            "criteria": [
                "0: Theoretical only, no known exploit vector",
                "1: Difficult to exploit, requires complex pre-requisites",
                "2: Standard exploitability under common conditions",
                "3: Readily exploitable with public tools or trivial requests",
            ],
        },
    }


def _format_triage_result(answers: dict[str, Any], state: Any) -> dict[str, Any]:
    """Format Jev triage answers into SecOpsAI bridge output schema."""
    verdict_ans = answers.get("finding_verdict", {})
    exposure_ans = answers.get("exposure_assessment", {})
    auto_ans = answers.get("automation_recommendation", {})
    risk_ans = answers.get("risk_severity", {})
    contain_ans = answers.get("containment_needed", {})

    verdict = verdict_ans.get("choice", "needs_more_evidence")
    verdict_conf = int(round(float(verdict_ans.get("confidence", 0.8)) * 100))
    exposure = exposure_ans.get("exposure_assessment", exposure_ans.get("choice", "unknown"))
    auto_rec = auto_ans.get("automation_recommendation", auto_ans.get("choice", "monitor"))
    risk_score = round(float(risk_ans.get("score", 1.0)), 2)
    contain_prob = round(float(contain_ans.get("noul", 0.0)), 3)

    # Convert verdict to disposition recommendation
    disposition_map = {
        "true_positive": "true_positive",
        "false_positive": "false_positive",
        "benign_expected": "expected_behavior",
        "policy_noise": "tune_policy",
        "needs_more_evidence": "needs_review",
    }
    disposition = disposition_map.get(verdict, "needs_review")

    summary = (
        f"TypeSafe Jev evaluated this finding as {verdict.replace('_', ' ').title()} "
        f"(confidence: {verdict_conf}%, risk level: {risk_score}/4.0). "
        f"Recommended action: {auto_rec.replace('_', ' ')}."
    )

    risk_assessment = (
        f"Contextual operational risk score: {risk_score}/4.0 (derived from TypeSafe System One distribution). "
        f"Exposure status: {exposure.replace('_', ' ')}. "
        f"Emergency containment probability: {contain_prob:.1%}."
    )

    evidence = [
        f"Jev finding_verdict: {verdict} (p={verdict_ans.get('probabilities', {}).get(verdict, 0.0):.2f}, confidence={verdict_ans.get('confidence', 0.0):.2f})",
        f"Jev exposure_assessment: {exposure} (confidence={exposure_ans.get('confidence', 0.0):.2f})",
        f"Jev automation_recommendation: {auto_rec} (confidence={auto_ans.get('confidence', 0.0):.2f})",
        f"Jev risk_severity score: {risk_score} (confidence={risk_ans.get('confidence', 0.0):.2f})",
        f"Jev containment_needed probability: {contain_prob}",
    ]

    recommended_actions = [
        f"Execute {auto_rec.replace('_', ' ')} automation workflow for affected asset.",
    ]
    if contain_prob >= 0.65:
        recommended_actions.append("Initiate host containment or credential isolation per emergency protocol.")

    limitations = [
        "Classification generated by TypeSafe AI Jev (System One fast decision model).",
        "Calibrated probabilities reflect trained decision boundaries; escalate high-ambiguity cases for human review.",
    ]

    return {
        "summary": summary,
        "risk_assessment": risk_assessment,
        "evidence": evidence,
        "recommended_actions": recommended_actions,
        "limitations": limitations,
        "finding_verdict": verdict,
        "finding_confidence": verdict_conf,
        "disposition_recommendation": disposition,
        "exposure_assessment": exposure,
        "automation_recommendation": auto_rec,
        "verdict_recommendation": "credible" if verdict == "true_positive" else "benign" if verdict in {"false_positive", "benign_expected"} else "inconclusive",
        "verdict_confidence": verdict_conf,
    }


def _format_publication_safety_result(answers: dict[str, Any], state: Any) -> dict[str, Any]:
    """Format Jev publication safety answers into SecOpsAI bridge output schema."""
    safe_ans = answers.get("safe_to_publish", {})
    leak_ans = answers.get("credential_leakage", {})
    verdict_ans = answers.get("verdict_recommendation", {})
    risk_ans = answers.get("publication_risk", {})

    safe_prob = round(float(safe_ans.get("noul", 0.5)), 3)
    leak_prob = round(float(leak_ans.get("noul", 0.0)), 3)
    verdict = verdict_ans.get("choice", "inconclusive")
    verdict_conf = int(round(float(verdict_ans.get("confidence", 0.8)) * 100))
    risk_score = round(float(risk_ans.get("score", 1.0)), 2)

    is_safe = safe_prob >= 0.70 and leak_prob <= 0.15 and risk_score <= 2.0

    summary = (
        f"TypeSafe Jev publication review: {'APPROVED' if is_safe else 'ACTION REQUIRED'}. "
        f"Safety probability: {safe_prob:.1%}, publication risk: {risk_score}/4.0, "
        f"evidentiary verdict: {verdict.title()}."
    )

    risk_assessment = (
        f"Publication safety score: {safe_prob:.1%}. "
        f"Credential / PII leakage risk probability: {leak_prob:.1%}. "
        f"Calculated publication risk tier: {risk_score}/4.0."
    )

    evidence = [
        f"Jev safe_to_publish probability: {safe_prob}",
        f"Jev credential_leakage probability: {leak_prob}",
        f"Jev publication_risk score: {risk_score} (confidence={risk_ans.get('confidence', 0.0):.2f})",
        f"Jev verdict_recommendation: {verdict} (confidence={verdict_ans.get('confidence', 0.0):.2f})",
    ]

    publication_risks = []
    if leak_prob > 0.15:
        publication_risks.append(f"Potential unredacted credential or PII leak detected (probability: {leak_prob:.1%}).")
    if risk_score > 2.0:
        publication_risks.append(f"Elevated publication risk level ({risk_score}/4.0); manual peer review advised.")
    if safe_prob < 0.70:
        publication_risks.append("Safety criteria not fully met for autonomous release.")

    recommended_actions = []
    if is_safe:
        recommended_actions.append("Proceed with coordinated disclosure or scheduled publication.")
    else:
        recommended_actions.append("Hold release until flagged publication risks are resolved by lead researcher.")

    limitations = [
        "Safety verification assessed by TypeSafe AI Jev (System One non-autoregressive decision model).",
        "Deterministic review guarantees contract structure; human sign-off remains mandatory for external releases.",
    ]

    return {
        "summary": summary,
        "risk_assessment": risk_assessment,
        "evidence": evidence,
        "recommended_actions": recommended_actions,
        "limitations": limitations,
        "verdict_recommendation": verdict,
        "verdict_confidence": verdict_conf,
        "verdict_rationale": f"TypeSafe Jev evaluated case evidence with safety probability {safe_prob:.1%}.",
        "publication_risks": publication_risks,
    }


def _format_generic_result(answers: dict[str, Any], action: str, state: Any) -> dict[str, Any]:
    """Format generic Jev evaluation answers into SecOpsAI bridge output schema."""
    summary_parts = []
    evidence = []
    for q_id, ans in answers.items():
        ans_type = ans.get("type")
        if ans_type == "choice":
            choice = ans.get("choice", "")
            conf = ans.get("confidence", 0.0)
            summary_parts.append(f"{q_id}: {choice} ({conf:.0%})")
            evidence.append(f"Jev {q_id}: {choice} (confidence={conf:.2f})")
        elif ans_type == "score":
            score = ans.get("score", 0.0)
            conf = ans.get("confidence", 0.0)
            summary_parts.append(f"{q_id}: {score:.2f}")
            evidence.append(f"Jev {q_id}: score={score:.2f} (confidence={conf:.2f})")
        elif ans_type == "noul":
            prob = ans.get("noul", 0.5)
            summary_parts.append(f"{q_id}: {prob:.1%}")
            evidence.append(f"Jev {q_id}: probability={prob:.3f}")

    summary = f"TypeSafe Jev evaluation for {action}: " + "; ".join(summary_parts) if summary_parts else f"TypeSafe Jev completed {action}."
    return {
        "summary": summary,
        "risk_assessment": "Evaluated by TypeSafe System One model.",
        "evidence": evidence,
        "recommended_actions": ["Review typed decisions against policy threshold."],
        "limitations": ["Generated by TypeSafe AI Jev System One model."],
        "verdict_recommendation": "credible",
        "verdict_confidence": 85,
    }


def invoke_typesafe_action(
    request: dict[str, Any],
    *,
    model: str = TYPESAFE_MODEL,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Execute a SecOpsAI bridge request against TypeSafe AI (Jev).

    Matches the contract expected by _invoke_codex / _invoke_with_model_fallback.
    """
    action_info = request.get("action", {})
    action_name = action_info.get("name") if isinstance(action_info, dict) else str(request.get("action") or "")
    context = request.get("context", {})

    # Select question suite based on action
    if action_name == "triage_finding":
        questions = build_triage_questions()
        formatter = _format_triage_result
    elif action_name in {"review_publication_safety", "publication_readiness"}:
        questions = build_publication_safety_questions()
        formatter = _format_publication_safety_result
    elif action_name == "prioritize_findings":
        questions = build_prioritize_questions()

        def formatter(answers: Any, state: Any) -> dict[str, Any]:
            return _format_generic_result(answers, action_name, state)
    else:
        # Fallback to triage questions for general finding analysis
        questions = build_triage_questions()

        def formatter(answers: Any, state: Any) -> dict[str, Any]:
            return _format_generic_result(answers, action_name, state)

    # Evaluate against Jev
    raw_response = evaluate_system_one(
        state=context,
        questions=questions,
        api_key=api_key,
        model=TYPESAFE_MODEL if ("jev" in model or "typesafe" in model) else model,
        timeout=timeout,
    )

    answers = raw_response.get("answers", {})
    return formatter(answers, context)
