"""Provider capabilities are enforced independently of health and fallback."""
from __future__ import annotations
from secopsai.decision_contracts import DecisionError

DECISION_ACTIONS = ("triage_finding", "triage_artifact")
GENERIC_BRIDGE_ACTIONS = (
    "explain_finding",
    "triage_finding",
    "prioritize_findings",
    "analyze_asset_change",
    "analyze_research_case",
    "generate_analyst_brief",
    "review_publication_safety",
    "recommend_remediation",
    "triage_artifact",
    "execute_specialist_work",
    "review_specialist_work",
)


def decision_provider(model: str) -> str:
    if model.startswith(("typesafe/", "typesafe-ai/")):
        return "typesafe"
    if model in {"cloudflare/clef", "cloudflare/clef-flash"}:
        return "clef"
    return ""


def model_capabilities(model: str) -> dict:
    provider = decision_provider(model)
    return {
        "decision_only": bool(provider),
        "supported_actions": list(DECISION_ACTIONS if provider else GENERIC_BRIDGE_ACTIONS),
    }


def require_action(model: str, action: str) -> None:
    supported = DECISION_ACTIONS if decision_provider(model) else GENERIC_BRIDGE_ACTIONS
    if action not in supported:
        provider = decision_provider(model) or (model.split("/", 1)[0] if "/" in model else "opencodex")
        raise DecisionError(
            f"model {model or 'default'} does not support action {action}; choose a compatible provider",
            category="unsupported_action",
            provider=provider,
        )
