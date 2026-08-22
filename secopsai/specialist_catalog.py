from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


CATALOG_SCHEMA = "secopsai.specialist-catalog.v1"
CATALOG_PATH = Path(__file__).with_name("specialists") / "catalog.v1.json"
PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}/[a-z][a-z0-9_-]{1,63}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
RISK_LEVELS = ("low", "medium", "high", "critical")

# Profiles are data, never authority. These patterns reject common attempts to
# smuggle tool access or policy overrides into a catalog update.
UNSAFE_GUIDANCE_PATTERNS = (
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions", re.IGNORECASE),
    re.compile(r"(?:bypass|disable|override)\s+(?:the\s+)?(?:policy|guardrail|approval|sandbox)", re.IGNORECASE),
    re.compile(r"(?:merge|deploy|publish|disclose|delete)\s+(?:it\s+)?without\s+(?:human|operator)\s+approval", re.IGNORECASE),
    re.compile(r"(?:curl|wget)\s+https?://", re.IGNORECASE),
    re.compile(r"(?:sudo|rm\s+-rf|git\s+push|npm\s+publish|wrangler\s+pages\s+deploy)", re.IGNORECASE),
    re.compile(r"(?:read|print|exfiltrate|send)\s+(?:all\s+)?(?:secrets|tokens|credentials|environment variables)", re.IGNORECASE),
)

TASK_RULES: tuple[tuple[str, str, str], ...] = (
    ("incident_response", r"\b(incident|breach|compromis(?:e|ed)|containment|forensic|outage|production failure)\b", "security/incident-responder"),
    ("devops_ci", r"\b(github actions|workflow run|ci/cd|ci failure|build failed|deploy(?:ment)?|docker|cloudflare|runner|release pipeline)\b", "engineering/devops-automator"),
    ("database", r"\b(database|query|n\+1|pagination|index(?:es|ing)?|connection pool|select \*|postgres|sqlite|schema migration)\b", "engineering/database-optimizer"),
    ("privacy", r"\b(privacy|pii|personal data|retention|consent|right to be forgotten|gdpr|data minimization)\b", "engineering/privacy-engineer"),
    ("compliance", r"\b(compliance|soc 2|iso 27001|iso 42001|hipaa|nist|cis|nis2|compliance audit|security audit|questionnaire|rfp)\b", "security/compliance-auditor"),
    ("threat_intelligence", r"\b(threat intel|campaign|ioc|malware|apt|yara|sigma|advisory|research publication)\b", "security/threat-intelligence-analyst"),
    ("application_security", r"\b(appsec|threat model|sast|dast|sca|owasp|secure code|vulnerability|security scan)\b", "security/appsec-engineer"),
    ("accessibility", r"\b(accessibility|wcag|screen reader|keyboard navigation|aria|color contrast|focus order)\b", "testing/accessibility-auditor"),
    ("visual_design", r"\b(ui design|visual design|information hierarchy|layout|theme|scattered|ambiguous interface)\b", "design/ui-designer"),
    ("frontend_ui", r"\b(frontend|dashboard|user interface|\bui\b|button|modal|javascript|css|html|responsive|browser)\b", "engineering/frontend-developer"),
    ("testing", r"\b(test|pytest|unittest|regression|fixture|coverage|flaky|verification)\b", "testing/test-automation-engineer"),
    ("documentation", r"\b(documentation|readme|guide|runbook|api reference|release notes|tutorial)\b", "engineering/technical-writer"),
    ("product", r"\b(product|feature|requirements|user journey|roadmap|acceptance criteria|prioriti[sz])\b", "product/product-manager"),
    ("backend", r"\b(backend|api|server|service|endpoint|architecture|queue|worker)\b", "engineering/backend-architect"),
    ("security", r"\b(security|secret|token|authentication|authorization|credential|csp|cors)\b", "security/senior-secops"),
    ("orchestration", r"\b(orchestrat|multi-agent|cross repo|cross-domain|coordinate|company workflow)\b", "orchestration/agents-orchestrator"),
)

DOMAIN_PROFILE_MAP = {
    "exec": "orchestration/agents-orchestrator",
    "platform": "engineering/backend-architect",
    "security": "security/senior-secops",
    "research": "security/threat-intelligence-analyst",
    "product": "product/product-manager",
    "design": "design/ui-designer",
    "testing": "testing/test-automation-engineer",
    "documentation": "engineering/technical-writer",
    "privacy": "engineering/privacy-engineer",
    "compliance": "security/compliance-auditor",
}


def load_catalog(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else CATALOG_PATH
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("specialist catalog must be a JSON object")
    return payload


def catalog_digest(path: str | Path | None = None) -> str:
    target = Path(path).expanduser().resolve() if path else CATALOG_PATH
    return hashlib.sha256(target.read_bytes()).hexdigest()


def profiles_by_id(catalog: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    resolved = catalog or load_catalog()
    return {
        str(profile.get("id")): profile
        for profile in resolved.get("profiles", [])
        if isinstance(profile, dict) and profile.get("id")
    }


def get_profile(profile_id: str, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = profiles_by_id(catalog).get(str(profile_id or "").strip())
    if profile is None:
        raise ValueError(f"unknown specialist profile: {profile_id}")
    return profile


def validate_catalog(
    catalog: dict[str, Any] | None = None,
    *,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    resolved = catalog or load_catalog()
    errors: list[str] = []
    warnings: list[str] = []
    if resolved.get("schema_version") != CATALOG_SCHEMA:
        errors.append(f"schema_version must be {CATALOG_SCHEMA}")
    upstream = resolved.get("upstream")
    if not isinstance(upstream, dict):
        errors.append("upstream metadata is required")
        upstream = {}
    if not COMMIT_RE.fullmatch(str(upstream.get("commit") or "")):
        errors.append("upstream.commit must be a pinned 40-character commit")
    if str(upstream.get("license") or "") != "MIT":
        errors.append("upstream license must be recorded as MIT")

    profiles = resolved.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        errors.append("profiles must be a non-empty list")
        profiles = []
    if len(profiles) > 32:
        errors.append("catalog may contain at most 32 reviewed profiles")

    ids: set[str] = set()
    source_paths: set[str] = set()
    for index, profile in enumerate(profiles):
        prefix = f"profiles[{index}]"
        if not isinstance(profile, dict):
            errors.append(f"{prefix} must be an object")
            continue
        profile_id = str(profile.get("id") or "")
        if not PROFILE_ID_RE.fullmatch(profile_id):
            errors.append(f"{prefix}.id is invalid")
        if profile_id in ids:
            errors.append(f"duplicate profile id: {profile_id}")
        ids.add(profile_id)
        source_path = str(profile.get("source_path") or "")
        if not source_path or source_path.startswith(("/", "../")) or ".." in Path(source_path).parts:
            errors.append(f"{prefix}.source_path must be a safe relative path")
        if source_path in source_paths:
            warnings.append(f"multiple profiles reference {source_path}")
        source_paths.add(source_path)
        source_hash = str(profile.get("source_sha256") or "")
        if not SHA256_RE.fullmatch(source_hash):
            errors.append(f"{prefix}.source_sha256 must be a lowercase SHA-256")
        if str(profile.get("risk_ceiling") or "") not in RISK_LEVELS:
            errors.append(f"{prefix}.risk_ceiling must be one of {', '.join(RISK_LEVELS)}")
        for field in ("task_types", "capabilities", "keywords", "guidance", "deliverables"):
            values = profile.get(field)
            if not isinstance(values, list) or not values:
                errors.append(f"{prefix}.{field} must be a non-empty list")
                continue
            if len(values) > 32:
                errors.append(f"{prefix}.{field} exceeds 32 entries")
            for value in values:
                text = str(value or "").strip()
                if not text or len(text) > 600:
                    errors.append(f"{prefix}.{field} contains an empty or oversized value")
                for pattern in UNSAFE_GUIDANCE_PATTERNS:
                    if pattern.search(text):
                        errors.append(
                            f"{prefix}.{field} contains blocked authority or tool language: {pattern.pattern}"
                        )
        reviewer = str(profile.get("reviewer_profile_id") or "")
        if reviewer == profile_id:
            errors.append(f"{prefix} cannot review itself")

    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        reviewer = str(profile.get("reviewer_profile_id") or "")
        if reviewer and reviewer not in ids:
            errors.append(f"{profile.get('id')} references missing reviewer {reviewer}")

    source_checks: list[dict[str, Any]] = []
    if source_root:
        root = Path(source_root).expanduser().resolve()
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            relative = str(profile.get("source_path") or "")
            target = (root / relative).resolve()
            contained = target == root or root in target.parents
            actual = hashlib.sha256(target.read_bytes()).hexdigest() if contained and target.is_file() else ""
            expected = str(profile.get("source_sha256") or "")
            matches = bool(actual) and actual == expected
            source_checks.append({
                "profile_id": profile.get("id"),
                "source_path": relative,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "matches": matches,
            })
            if not matches:
                errors.append(f"upstream source mismatch: {relative}")

    return {
        "ok": not errors,
        "schema_version": CATALOG_SCHEMA,
        "catalog_version": resolved.get("catalog_version"),
        "catalog_sha256": catalog_digest() if catalog is None else hashlib.sha256(
            json.dumps(resolved, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "profile_count": len(profiles),
        "upstream": upstream,
        "errors": errors,
        "warnings": warnings,
        "source_checks": source_checks,
    }


def _clean_task(task: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(task, dict):
        raise ValueError("task must be an object")
    output: dict[str, Any] = {}
    limits = {
        "task_id": 160,
        "title": 300,
        "description": 8000,
        "domain": 80,
        "priority": 40,
        "status": 40,
        "owner_role": 120,
        "reviewer_role": 120,
        "repo_alias": 40,
    }
    for key, limit in limits.items():
        value = str(task.get(key) or "").strip()
        if value:
            output[key] = value[:limit]
    output["external_facing"] = bool(task.get("external_facing"))
    output["requires_security_review"] = bool(task.get("requires_security_review"))
    evidence = task.get("evidence_refs") or []
    if not isinstance(evidence, list):
        raise ValueError("evidence_refs must be a list")
    output["evidence_refs"] = [str(value)[:300] for value in evidence[:25] if str(value).strip()]
    if not output.get("title"):
        raise ValueError("task title is required")
    return output


def _task_type_and_seed(task: dict[str, Any]) -> tuple[str, str, list[str]]:
    haystack = " ".join(
        str(task.get(key) or "")
        for key in ("title", "description", "domain", "owner_role", "reviewer_role")
    ).lower()
    for task_type, pattern, profile_id in TASK_RULES:
        match = re.search(pattern, haystack, flags=re.IGNORECASE)
        if match:
            return task_type, profile_id, [f"matched task signal '{match.group(0)}'"]
    domain = str(task.get("domain") or "").lower()
    if domain in DOMAIN_PROFILE_MAP:
        return domain, DOMAIN_PROFILE_MAP[domain], [f"used explicit task domain '{domain}'"]
    return "orchestration", "orchestration/agents-orchestrator", ["no narrow domain signal; selected bounded orchestration intake"]


def _risk(task: dict[str, Any], haystack: str) -> tuple[str, list[str]]:
    reasons: list[str] = []
    priority = str(task.get("priority") or "normal").lower()
    if priority == "urgent" or re.search(r"\b(critical|breach|production|credential|secret|token|rce)\b", haystack):
        level = "critical"
        reasons.append("critical operational or security language")
    elif priority == "high" or task.get("requires_security_review") or re.search(r"\b(security|deploy|migration|database|workflow)\b", haystack):
        level = "high"
        reasons.append("high-impact or security-reviewed work")
    elif task.get("external_facing"):
        level = "medium"
        reasons.append("external-facing output")
    else:
        level = "medium"
        reasons.append("normal implementation risk")
    if re.search(r"\b(merge|deploy|publish|disclose|delete|billing|production mutation|rotate credentials)\b", haystack):
        level = "critical"
        reasons.append("protected external or destructive action mentioned")
    return level, reasons


def infer_repo_alias(task: dict[str, Any]) -> tuple[str, list[str]]:
    explicit = str(task.get("repo_alias") or "").strip().lower()
    if explicit in {"secopsai", "secopsai-dashboard"}:
        return explicit, [f"operator supplied repo alias '{explicit}'"]
    haystack = f"{task.get('title', '')} {task.get('description', '')}".lower()
    if re.search(r"\b(dashboard|mission control|frontend|ui|button|modal|app\.js|index\.html|styles\.css)\b", haystack):
        return "secopsai-dashboard", ["task points to Mission Control or frontend files"]
    return "secopsai", ["task points to the SecOpsAI core repository"]


def route_task(
    task: dict[str, Any],
    *,
    profile_id: str = "",
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved = catalog or load_catalog()
    validation = validate_catalog() if catalog is None else validate_catalog(resolved)
    if not validation["ok"]:
        raise ValueError("specialist catalog is invalid: " + "; ".join(validation["errors"][:5]))
    normalized = _clean_task(task)
    profiles = profiles_by_id(resolved)
    task_type, seed_id, reasons = _task_type_and_seed(normalized)
    manual_override = bool(profile_id)
    if manual_override:
        get_profile(profile_id, resolved)
        seed_id = profile_id
        reasons.insert(0, "operator selected this reviewed specialist")

    haystack = " ".join(str(normalized.get(key) or "") for key in normalized).lower()
    scores: list[tuple[int, str, list[str]]] = []
    for candidate_id, profile in profiles.items():
        score = 0
        candidate_reasons: list[str] = []
        if candidate_id == seed_id:
            score += 55 if not manual_override else 100
            candidate_reasons.append("primary deterministic task-type match" if not manual_override else "operator override")
        if task_type in profile.get("task_types", []):
            score += 25
            candidate_reasons.append(f"supports task type {task_type}")
        keyword_hits = [str(keyword) for keyword in profile.get("keywords", []) if str(keyword).lower() in haystack]
        if keyword_hits:
            score += min(24, 6 * len(keyword_hits))
            candidate_reasons.append("matched " + ", ".join(keyword_hits[:4]))
        domain = str(normalized.get("domain") or "").lower()
        if DOMAIN_PROFILE_MAP.get(domain) == candidate_id:
            score += 15
            candidate_reasons.append(f"matches domain {domain}")
        scores.append((score, candidate_id, candidate_reasons))
    scores.sort(key=lambda value: (-value[0], value[1]))
    primary_score, primary_id, primary_reasons = scores[0]
    primary = profiles[primary_id]
    reviewer_id = str(primary.get("reviewer_profile_id") or "engineering/code-reviewer")
    if reviewer_id == primary_id or reviewer_id not in profiles:
        reviewer_id = "engineering/code-reviewer" if primary_id != "engineering/code-reviewer" else "testing/test-automation-engineer"
    risk, risk_reasons = _risk(normalized, haystack)
    repo_alias, repo_reasons = infer_repo_alias(normalized)
    confidence = "high" if primary_score >= 70 else "medium" if primary_score >= 45 else "low"
    missing_evidence: list[str] = []
    if not normalized.get("description"):
        missing_evidence.append("Task description is missing.")
    if not normalized.get("evidence_refs"):
        missing_evidence.append("No evidence or issue references were supplied.")
    return {
        "schema_version": "secopsai.specialist-route.v1",
        "task": normalized,
        "task_type": task_type,
        "repo_alias": repo_alias,
        "primary_profile": primary,
        "reviewer_profile": profiles[reviewer_id],
        "manual_override": manual_override,
        "score": primary_score,
        "confidence": confidence,
        "risk": risk,
        "reasons": list(dict.fromkeys(reasons + primary_reasons + repo_reasons + risk_reasons)),
        "missing_evidence": missing_evidence,
        "alternatives": [
            {
                "profile_id": candidate_id,
                "name": profiles[candidate_id]["name"],
                "score": score,
                "reasons": candidate_reasons,
            }
            for score, candidate_id, candidate_reasons in scores[1:4]
        ],
        "catalog_version": resolved.get("catalog_version"),
        "catalog_sha256": validation["catalog_sha256"],
        "upstream_commit": resolved.get("upstream", {}).get("commit"),
    }
