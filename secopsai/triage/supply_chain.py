from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from secopsai import supply_chain


STRONG_RULE_MARKERS = {
    "install hook executes remote or inline code",
    "install hook reaches remote URL",
    "combined execution and network behavior",
    "semantic dynamic execution",
    "semantic subprocess behavior",
    "shell downloader",
    "credential access",
    "network egress",
    "obfuscated eval",
    "subprocess spawn",
    "startup persistence",
}

WEAK_RULE_MARKERS = {
    "wheel/sdist artifact divergence",
    "suspicious code present only in one pypi artifact",
    "manifest executable entrypoints",
    "ast-aware semantic findings",
    "manifest install-time build customization",
}

DEPENDENCY_FILE_GLOBS = (
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements*.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
)


def _package_reference_paths(package: str, search_root: Path) -> List[str]:
    hits: List[str] = []
    needle = str(package or "").strip()
    if not needle:
        return hits
    pattern = re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(needle)}(?![A-Za-z0-9_.-])", re.IGNORECASE)
    for glob in DEPENDENCY_FILE_GLOBS:
        for path in search_root.rglob(glob):
            try:
                if pattern.search(path.read_text(encoding="utf-8", errors="ignore")):
                    hits.append(str(path.resolve()))
            except Exception:
                continue
    return sorted(set(hits))


def _extract_rule_names(explanation: Dict[str, Any]) -> List[str]:
    out = []
    for rule in explanation.get("matched_rules") or []:
        name = str(rule.get("rule") or "").strip()
        if name:
            out.append(name)
    return out


def _npm_reputation(package: str) -> Dict[str, Any]:
    try:
        payload = supply_chain._http_json(f"{supply_chain.NPM_REGISTRY}/{package}")  # type: ignore[attr-defined]
    except Exception as exc:
        return {"error": str(exc)}
    time_meta = payload.get("time") or {}
    maintainers = payload.get("maintainers") or []
    versions = payload.get("versions") or {}
    return {
        "release_count": len(versions),
        "first_release": time_meta.get("created"),
        "last_release": time_meta.get("modified"),
        "maintainer_count": len(maintainers) if isinstance(maintainers, list) else 0,
        "has_maintainers": bool(maintainers),
    }


def _reputation_summary(ecosystem: str, package: str) -> Dict[str, Any]:
    if ecosystem == "pypi":
        rep = supply_chain._get_pypi_reputation_indicators(package)  # type: ignore[attr-defined]
        if rep.get("error"):
            return rep
        return {
            "release_count": rep.get("release_count"),
            "first_release": rep.get("first_release"),
            "has_author": rep.get("has_author"),
            "days_since_first_release": rep.get("days_since_first_release"),
            "score": supply_chain._calculate_reputation_score(rep),  # type: ignore[attr-defined]
        }
    return _npm_reputation(package)


def investigate_supply_chain(finding: Dict[str, Any], *, search_root: Path) -> Dict[str, Any]:
    ecosystem = str(finding.get("ecosystem") or "").lower()
    package = str(finding.get("package") or "")
    report_path = Path(str(finding.get("report_path") or "")).resolve() if finding.get("report_path") else None
    policy = supply_chain.explain_policy(ecosystem, package)
    explanation: Dict[str, Any] = {}
    if report_path and report_path.exists():
        try:
            explanation = supply_chain.explain_verdict(
                report_path.read_text(encoding="utf-8"),
                ecosystem=ecosystem,
                package=package,
            )
        except Exception as exc:
            explanation = {"error": str(exc)}

    dependency_hits = _package_reference_paths(package, search_root)
    matched_rules = _extract_rule_names(explanation)
    lower_rules = {rule.lower() for rule in matched_rules}
    strong_signals = sorted(rule for rule in matched_rules if rule.lower() in STRONG_RULE_MARKERS)
    weak_only = bool(lower_rules) and lower_rules.issubset(WEAK_RULE_MARKERS)
    reputation = _reputation_summary(ecosystem, package) if ecosystem and package else {}

    recommended_disposition = "needs_review"
    confidence = "medium"
    summary_bits = []
    next_actions = []

    if policy.get("deny_matches"):
        recommended_disposition = "true_positive"
        confidence = "high"
        summary_bits.append("Package matches the supply-chain denylist.")
        next_actions.extend(
            [
                "Block or quarantine the package version immediately.",
                "Check whether the package or version is installed in any production dependency graph.",
            ]
        )
    elif policy.get("allow_matches"):
        recommended_disposition = "false_positive"
        confidence = "high"
        summary_bits.append("Package matches the local supply-chain allowlist.")
        next_actions.extend(
            [
                "Document the allowlist rationale in the closure note.",
                "Confirm the allowlist entry is still justified for this package owner/version.",
            ]
        )
    elif strong_signals and dependency_hits:
        recommended_disposition = "needs_review"
        confidence = "high"
        summary_bits.append("Strong malicious indicators are present and the package appears in local dependency files.")
        next_actions.extend(
            [
                "Inspect the exact dependency path and whether the version is currently installed.",
                "Review the stored diff report for install hooks, dynamic execution, or credential access.",
            ]
        )
    elif weak_only and not dependency_hits:
        recommended_disposition = "false_positive"
        confidence = "medium"
        summary_bits.append("Only weak heuristic rules fired and the package is not referenced locally.")
        next_actions.extend(
            [
                "Verify the package is not a transitive dependency in deployment manifests outside this repo.",
                "If confirmed irrelevant, close as false_positive or expected_behavior with note.",
            ]
        )
    elif not dependency_hits:
        recommended_disposition = "expected_behavior"
        confidence = "medium"
        summary_bits.append("The release is not referenced in local dependency manifests.")
        next_actions.extend(
            [
                "Treat this as ecosystem intelligence unless the package is known to be deployed elsewhere.",
                "Close as expected_behavior if you confirm it is outside your risk boundary.",
            ]
        )
    else:
        summary_bits.append("Package needs analyst review before dispositioning.")
        next_actions.extend(
            [
                "Inspect the report and package metadata manually.",
                "Decide whether this is true_positive, false_positive, or accepted_risk after review.",
            ]
        )

    evidence = [
        f"Verdict score: {explanation.get('score')} / threshold {explanation.get('effective_threshold')}"
        if explanation else "",
        f"Matched rules: {', '.join(matched_rules)}" if matched_rules else "",
        f"Dependency references: {len(dependency_hits)} file(s)" if dependency_hits else "Dependency references: none found",
        f"Allowlist matches: {', '.join(policy.get('allow_matches') or [])}" if policy.get("allow_matches") else "",
        f"Denylist matches: {', '.join(policy.get('deny_matches') or [])}" if policy.get("deny_matches") else "",
    ]
    if reputation:
        evidence.append(f"Reputation: {json.dumps(reputation, sort_keys=True)}")

    external_links = {
        "osv": f"https://osv.dev/list?ecosystem={ecosystem}&q={package}",
        "socket": f"https://socket.dev/{ecosystem}/package/{package}" if ecosystem == "npm" else f"https://socket.dev/pypi/package/{package}",
        "snyk": f"https://snyk.io/advisor/{ecosystem}-package/{package}",
    }

    return {
        "summary": " ".join(bit for bit in summary_bits if bit),
        "dependency_presence": {
            "present": bool(dependency_hits),
            "paths": dependency_hits,
        },
        "reputation": reputation,
        "policy": policy,
        "verdict_explanation": explanation,
        "recommended_disposition": recommended_disposition,
        "confidence": confidence,
        "evidence": [item for item in evidence if item],
        "next_actions": next_actions,
        "external_links": external_links,
    }


def suggest_fp_action_for_supply_chain(
    finding: Dict[str, Any],
    *,
    search_root: Path,
) -> Dict[str, Any]:
    investigation = investigate_supply_chain(finding, search_root=search_root)
    ecosystem = str(finding.get("ecosystem") or "").lower()
    package = str(finding.get("package") or "")
    finding_id = str(finding.get("finding_id") or "")
    matched_rules = [
        str(rule.get("rule") or "")
        for rule in (investigation.get("verdict_explanation", {}) or {}).get("matched_rules", []) or []
        if str(rule.get("rule") or "").strip()
    ]
    dependency_present = bool((investigation.get("dependency_presence") or {}).get("present"))
    allow_matches = (investigation.get("policy") or {}).get("allow_matches") or []
    recommended_disposition = str(investigation.get("recommended_disposition") or "")

    action = "needs_review"
    rationale = investigation.get("summary") or "Analyst review is still required."
    commands: List[str] = []

    if allow_matches:
        action = "close_false_positive"
        rationale = "The package already matches the local allowlist."
        commands = [
            f'secopsai triage close {finding_id} --disposition false_positive --note "Package already matches local allowlist; verified safe."'
        ]
    elif recommended_disposition == "expected_behavior" and not dependency_present:
        action = "close_expected_behavior"
        rationale = "The package is not referenced in local dependency manifests, so this is likely ecosystem intelligence outside your current risk boundary."
        commands = [
            f'secopsai triage close {finding_id} --disposition expected_behavior --note "Package not referenced in local dependency manifests; treating as ecosystem intelligence outside current risk boundary."'
        ]
    elif recommended_disposition == "false_positive" and not dependency_present:
        action = "allowlist_package"
        rationale = "The heuristics look weak for a package that is not in your local dependency graph. If this is a known-safe recurring package, allowlist it for immediate relief."
        commands = [
            f"secopsai supply-chain allowlist add --ecosystem {ecosystem} --package {package}",
            "secopsai supply-chain reconcile-history --json",
            f'secopsai triage close {finding_id} --disposition false_positive --note "Verified legitimate package; added to allowlist."',
        ]
    elif not dependency_present and matched_rules:
        weak_rules = [rule for rule in matched_rules if rule.lower() in WEAK_RULE_MARKERS]
        if weak_rules and len(weak_rules) == len(matched_rules):
            action = "tune_rule"
            noisy_rule = weak_rules[0]
            rationale = f"Only weak heuristic rules fired for a package outside your dependency graph. Tune the noisy rule if this pattern repeats across legitimate packages."
            commands = [
                f'secopsai supply-chain tune rule "{noisy_rule}" --weight 1',
                "secopsai supply-chain reconcile-history --json",
            ]

    return {
        "action": action,
        "rationale": rationale,
        "commands": commands,
        "investigation": investigation,
    }
