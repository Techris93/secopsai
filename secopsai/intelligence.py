from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable

import soc_store
from secopsai.graph_store import list_assets, list_changes, show_node
from secopsai.research_cases import get_case, list_cases
from secopsai.research_workflow import build_evidence_matrix


SCHEMA_VERSION = "secopsai.intelligence.v1"
MAX_LIST_ITEMS = 100
MAX_STRING_LENGTH = 4000
FORBIDDEN_KEYS = {
    "artifact_bytes",
    "artifact_content",
    "authorization",
    "bssid",
    "content",
    "cookie",
    "credential",
    "mac",
    "mac_address",
    "nmap_xml",
    "packet_capture",
    "password",
    "pcap",
    "private_key",
    "raw_artifact",
    "raw_nmap_output",
    "raw_output",
    "raw_packet_data",
    "raw_scan_log",
    "raw_scan_logs",
    "secret",
    "token",
}


@dataclass(frozen=True)
class Action:
    name: str
    title: str
    description: str
    scope: str
    target: str
    requires_bridge: bool
    handler: Callable[[dict[str, Any], str | None], dict[str, Any]] | None = None

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "scope": self.scope,
            "target": self.target,
            "read_only": True,
            "requires_bridge": self.requires_bridge,
        }


def _actions() -> tuple[Action, ...]:
    return (
        Action("workspace_summary", "Workspace summary", "Summarize current SecOpsAI findings, assets, research cases, and queue health.", "secopsai.workspace.read", "none", False, _workspace_summary),
        Action("list_findings", "List findings", "List normalized findings with optional severity, status, and source filters.", "secopsai.findings.read", "none", False, _list_findings),
        Action("get_finding", "Get finding", "Return minimized evidence and workflow state for one finding.", "secopsai.findings.read", "finding", False, _get_finding),
        Action("list_assets", "List assets", "List assets discovered by SecOpsAI Edge.", "secopsai.assets.read", "none", False, _list_assets),
        Action("asset_changes", "Asset changes", "List recent normalized asset and relationship changes.", "secopsai.assets.read", "asset_optional", False, _asset_changes),
        Action("list_research_cases", "List research cases", "List durable SecOpsAI research cases and workflow state.", "secopsai.research.read", "none", False, _list_research_cases),
        Action("get_research_case", "Get research case", "Return minimized subjects, evidence, verdicts, and publication readiness for one case.", "secopsai.research.read", "research_case", False, _get_research_case),
        Action("research_evidence_matrix", "Research evidence matrix", "Build a non-persisting claim-to-evidence matrix from normalized case records.", "secopsai.research.read", "research_case", False, _research_evidence_matrix),
        Action("publication_readiness", "Publication readiness", "Show blockers, warnings, and human approval state without publishing.", "secopsai.research.read", "research_case", False, _publication_readiness),
        Action("explain_finding", "Explain finding", "Explain one finding in plain language and identify evidence-backed next steps.", "secopsai.findings.read", "finding", True),
        Action("prioritize_findings", "Prioritize findings", "Prioritize open findings using normalized severity, recency, and context.", "secopsai.findings.read", "none", True),
        Action("analyze_asset_change", "Analyze asset change", "Explain recent asset changes and their security significance.", "secopsai.assets.read", "asset_optional", True),
        Action("analyze_research_case", "Analyze research case", "Analyze claims, contradictions, limitations, and unanswered questions.", "secopsai.research.read", "research_case", True),
        Action("generate_analyst_brief", "Generate analyst brief", "Draft an evidence-grounded analyst brief from normalized case records.", "secopsai.research.read", "research_case", True),
        Action("review_publication_safety", "Review publication safety", "Review a case for disclosure, attribution, privacy, and evidentiary risks without approving publication.", "secopsai.research.read", "research_case", True),
        Action("recommend_remediation", "Recommend remediation", "Propose prioritized remediation with verification steps for one finding.", "secopsai.findings.read", "finding", True),
    )


def list_actions() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "actions": [action.public() for action in ACTIONS.values()]}


def get_action(name: str) -> Action:
    action = ACTIONS.get(str(name or "").strip())
    if action is None:
        raise ValueError(f"unsupported intelligence action: {name}")
    return action


def run_read_action(name: str, inputs: dict[str, Any] | None = None, *, db_path: str | None = None) -> dict[str, Any]:
    action = get_action(name)
    if action.requires_bridge or action.handler is None:
        raise ValueError(f"intelligence action requires the local Codex bridge: {name}")
    normalized = _normalize_inputs(inputs)
    data = action.handler(normalized, db_path)
    return _envelope(action, data)


def prepare_bridge_request(name: str, inputs: dict[str, Any] | None = None, *, db_path: str | None = None) -> dict[str, Any]:
    action = get_action(name)
    if not action.requires_bridge:
        raise ValueError(f"intelligence action does not require the local Codex bridge: {name}")
    normalized = _normalize_inputs(inputs)
    context = _bridge_context(action, normalized, db_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "action": action.public(),
        "requested_at": soc_store.utc_now(),
        "context": minimize(context),
        "instructions": _bridge_instructions(action),
        "safety": {
            "read_only": True,
            "raw_telemetry_included": False,
            "artifact_content_included": False,
            "human_review_required": True,
        },
    }


def validate_bridge_result(
    action_name: str,
    value: dict[str, Any],
    *,
    provider: str = "opencodex_proxy",
) -> dict[str, Any]:
    action = get_action(action_name)
    if not action.requires_bridge:
        raise ValueError("bridge result is only valid for bridge actions")
    if not isinstance(value, dict):
        raise ValueError("bridge result must be an object")
    required = ("summary", "risk_assessment", "evidence", "recommended_actions", "limitations")
    missing = [key for key in required if key not in value]
    if missing:
        raise ValueError("bridge result is missing: " + ", ".join(missing))
    cleaned = minimize(value)
    if not isinstance(cleaned, dict):
        raise ValueError("bridge result is invalid after minimization")
    provider_name = str(provider or "opencodex_proxy").strip()[:120] or "opencodex_proxy"
    return _envelope(action, cleaned, provider=provider_name)


def minimize(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "[depth limit]"
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in list(value.items())[:MAX_LIST_ITEMS]:
            normalized_key = str(key).strip().lower()
            if normalized_key in FORBIDDEN_KEYS or any(part in normalized_key for part in ("password", "secret", "token", "private_key", "raw_", "quarantine")):
                continue
            output[str(key)[:120]] = minimize(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple, set)):
        return [minimize(item, depth=depth + 1) for item in list(value)[:MAX_LIST_ITEMS]]
    if isinstance(value, str):
        if os.path.isabs(value):
            return "[local path redacted]"
        return value[:MAX_STRING_LENGTH]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_STRING_LENGTH]


def _workspace_summary(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        finding_counts = {str(row["status"]): int(row["count"]) for row in connection.execute("SELECT status, COUNT(*) AS count FROM findings GROUP BY status")}
        severity_counts = {str(row["severity"]): int(row["count"]) for row in connection.execute("SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity")}
        asset_count = int(connection.execute("SELECT COUNT(*) FROM asset_graph_nodes WHERE node_type = 'asset'").fetchone()[0])
        research_counts = {str(row["status"]): int(row["count"]) for row in connection.execute("SELECT status, COUNT(*) AS count FROM research_cases GROUP BY status")}
        job_counts = {str(row["status"]): int(row["count"]) for row in connection.execute("SELECT status, COUNT(*) AS count FROM intelligence_jobs GROUP BY status")}
    return {
        "findings": {"total": sum(finding_counts.values()), "by_status": finding_counts, "by_severity": severity_counts},
        "assets": {"total": asset_count},
        "research_cases": {"total": sum(research_counts.values()), "by_status": research_counts},
        "intelligence_jobs": job_counts,
    }


def _list_findings(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    limit = _limit(inputs)
    findings = soc_store.list_findings(
        db_path=db_path,
        severity=_optional(inputs, "severity"),
        status=_optional(inputs, "status"),
        source=_optional(inputs, "source"),
        limit=limit,
        include_payload=True,
    )
    return {"findings": minimize(findings), "count": len(findings), "limit": limit}


def _get_finding(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    target = _target(inputs, "finding_id")
    finding = soc_store.get_finding(target, db_path=db_path)
    if finding is None:
        raise ValueError(f"finding not found: {target}")
    return {"finding": minimize(finding)}


def _list_assets(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    assets = list_assets(db_path=db_path, limit=_limit(inputs))
    return {"assets": minimize(assets), "count": len(assets)}


def _asset_changes(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    target = _optional(inputs, "target_id") or _optional(inputs, "asset_id")
    result: dict[str, Any] = {"changes": minimize(list_changes(db_path=db_path, limit=_limit(inputs)))}
    if target:
        result["asset"] = minimize(show_node(target, db_path=db_path))
    return result


def _list_research_cases(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    cases = list_cases(
        db_path=db_path,
        status=_optional(inputs, "status"),
        case_type=_optional(inputs, "case_type"),
        limit=_limit(inputs),
    )
    return {"cases": minimize(cases), "count": len(cases)}


def _get_research_case(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    case = get_case(_target(inputs, "case_id"), db_path=db_path)
    return {"case": _minimized_case(case)}


def _research_evidence_matrix(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    matrix = build_evidence_matrix(_target(inputs, "case_id"), persist=False, db_path=db_path)
    return {"evidence_matrix": minimize(matrix)}


def _publication_readiness(inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    case = get_case(_target(inputs, "case_id"), db_path=db_path)
    return {"case_id": case["case_id"], "publication_readiness": minimize(case["publication_readiness"])}


def _bridge_context(action: Action, inputs: dict[str, Any], db_path: str | None) -> dict[str, Any]:
    if action.name in {"explain_finding", "recommend_remediation"}:
        return _get_finding(inputs, db_path)
    if action.name == "prioritize_findings":
        return _list_findings({**inputs, "status": inputs.get("status", "open"), "limit": min(_limit(inputs), 50)}, db_path)
    if action.name == "analyze_asset_change":
        return _asset_changes(inputs, db_path)
    if action.name in {"analyze_research_case", "generate_analyst_brief", "review_publication_safety"}:
        case = _get_research_case(inputs, db_path)
        matrix = _research_evidence_matrix(inputs, db_path)
        context = {**case, **matrix}
        pipeline_id = _optional(inputs, "pipeline_id")
        if pipeline_id:
            from secopsai.research_pipeline import pipeline_intelligence_context

            context["investigation_pipeline"] = pipeline_intelligence_context(pipeline_id, db_path=db_path)
        return context
    raise ValueError(f"no bridge context builder for action: {action.name}")


def _bridge_instructions(action: Action) -> str:
    action_guidance = {
        "analyze_research_case": (
            "Also return confirmed_facts, inferences, unsupported_claims, contradictions, and missing_evidence as arrays. "
            "A confirmed fact must cite supplied normalized evidence; otherwise classify it as an inference or unsupported claim. "
            "Return verdict_recommendation as credible, likely, inconclusive, not_substantiated, or benign; "
            "verdict_confidence as 0-100; verdict_rationale; and verdict_evidence_refs using only supplied evidence or pipeline step identifiers. "
            "Never downgrade a package merely because local exposure was not observed. "
        ),
        "generate_analyst_brief": (
            "Also return an article_outline array. Keep it suitable for a technical draft, not publication-ready copy. "
        ),
        "review_publication_safety": (
            "Also return publication_risks as an array and disclosure_draft as review-only text. Do not approve or send either. "
        ),
    }.get(action.name, "")
    return (
        f"Perform the approved SecOpsAI action '{action.name}'. Use only the supplied normalized context. "
        "Do not claim that missing evidence was observed. Distinguish facts, inferences, and limitations. "
        "Do not execute commands, access files, browse, contact external parties, change product state, or approve publication. "
        f"{action_guidance}For actions other than analyze_research_case, set verdict_recommendation to inconclusive, "
        "verdict_confidence to 0, verdict_rationale to 'Verdict not assessed by this action', and verdict_evidence_refs to an empty array. "
        "Return concise JSON matching the required output schema. Model output is evidence-bounded and subject to SecOpsAI guardrails."
    )


def bridge_output_schema() -> dict[str, Any]:
    required = [
        "summary",
        "risk_assessment",
        "evidence",
        "recommended_actions",
        "limitations",
        "confirmed_facts",
        "inferences",
        "unsupported_claims",
        "contradictions",
        "missing_evidence",
        "publication_risks",
        "article_outline",
        "disclosure_draft",
        "verdict_recommendation",
        "verdict_confidence",
        "verdict_rationale",
        "verdict_evidence_refs",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "summary": {"type": "string", "maxLength": 8000},
            "risk_assessment": {"type": "string", "maxLength": 4000},
            "evidence": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
            "recommended_actions": {"type": "array", "maxItems": 25, "items": {"type": "string", "maxLength": 2000}},
            "limitations": {"type": "array", "maxItems": 25, "items": {"type": "string", "maxLength": 2000}},
            "confirmed_facts": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
            "inferences": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
            "unsupported_claims": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
            "contradictions": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
            "missing_evidence": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
            "publication_risks": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
            "article_outline": {"type": "array", "maxItems": 30, "items": {"type": "string", "maxLength": 2000}},
            "disclosure_draft": {"type": "string", "maxLength": 12000},
            "verdict_recommendation": {
                "type": "string",
                "enum": ["credible", "likely", "inconclusive", "not_substantiated", "benign"],
            },
            "verdict_confidence": {"type": "integer", "minimum": 0, "maximum": 100},
            "verdict_rationale": {"type": "string", "maxLength": 8000},
            "verdict_evidence_refs": {
                "type": "array",
                "maxItems": 50,
                "items": {"type": "string", "maxLength": 200},
            },
        },
    }


def _minimized_case(case: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "case_id", "title", "summary", "case_type", "severity", "confidence", "status", "owner",
        "disclosure_status", "embargo_until", "created_at", "updated_at", "subjects", "evidence", "iocs",
        "findings", "claims", "verdicts", "publication_reviews", "publication_readiness",
    }
    reduced = {key: value for key, value in case.items() if key in allowed}
    for evidence in reduced.get("evidence", []):
        if isinstance(evidence, dict):
            evidence.pop("locator", None)
    return minimize(reduced)


def _envelope(action: Action, data: dict[str, Any], *, provider: str = "secopsai_core") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "action": action.name,
        "generated_at": soc_store.utc_now(),
        "provider": provider,
        "read_only": True,
        "data": minimize(data),
        "limitations": ["Results reflect the normalized SecOpsAI records available at generation time."],
    }


def _normalize_inputs(inputs: dict[str, Any] | None) -> dict[str, Any]:
    if inputs is None:
        return {}
    if not isinstance(inputs, dict):
        raise ValueError("intelligence inputs must be an object")
    encoded = json.dumps(inputs, sort_keys=True)
    if len(encoded.encode()) > 64 * 1024:
        raise ValueError("intelligence inputs exceed 65536 bytes")
    return dict(inputs)


def _target(inputs: dict[str, Any], field: str) -> str:
    value = _optional(inputs, field) or _optional(inputs, "target_id")
    if not value:
        raise ValueError(f"{field} is required")
    return value[:240]


def _optional(inputs: dict[str, Any], field: str) -> str:
    return str(inputs.get(field) or "").strip()


def _limit(inputs: dict[str, Any]) -> int:
    try:
        return max(1, min(int(inputs.get("limit", 50)), MAX_LIST_ITEMS))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc


ACTIONS = {action.name: action for action in _actions()}
