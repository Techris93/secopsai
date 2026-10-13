"""Provider capabilities are enforced independently of health and fallback."""
from __future__ import annotations
from secopsai.decision_contracts import DecisionError

DECISION_ACTIONS = ("triage_finding", "triage_artifact")


def decision_provider(model: str) -> str:
    if model.startswith(("typesafe/", "typesafe-ai/")):
        return "typesafe"
    if model in {"cloudflare/clef", "cloudflare/clef-flash"}:
        return "clef"
    return ""


def model_capabilities(model: str) -> dict:
    provider = decision_provider(model)
    return {"decision_only": bool(provider), "supported_actions": list(DECISION_ACTIONS) if provider else None}


def require_action(model: str, action: str) -> None:
    if decision_provider(model) and action not in DECISION_ACTIONS:
        raise DecisionError(f"model {model} does not support action {action}; choose a compatible provider", category="unsupported_action", provider=decision_provider(model))
