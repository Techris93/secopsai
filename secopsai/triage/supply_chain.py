from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from secopsai import supply_chain

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility.
    import tomli as tomllib


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

IGNORED_PATH_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


def _normalize_package_name(name: str) -> str:
    return str(name or "").strip().lower()


def _should_ignore_path(path: Path, search_root: Path) -> bool:
    try:
        relative_parts = path.resolve().relative_to(search_root.resolve()).parts
    except Exception:
        relative_parts = path.parts
    return any(part in IGNORED_PATH_PARTS for part in relative_parts)


def _manifest_contains_package(path: Path, package: str) -> bool:
    package_name = _normalize_package_name(package)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    if path.name == "package.json":
        try:
            payload = json.loads(text)
        except Exception:
            return False
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "overrides"):
            section = payload.get(key) or {}
            if isinstance(section, dict) and package_name in {_normalize_package_name(name) for name in section.keys()}:
                return True
        bundle = payload.get("bundleDependencies") or payload.get("bundledDependencies") or []
        if isinstance(bundle, list) and package_name in {_normalize_package_name(item) for item in bundle}:
            return True
        return False

    if path.name == "package-lock.json":
        try:
            payload = json.loads(text)
        except Exception:
            return False
        dependencies = payload.get("dependencies") or {}
        if isinstance(dependencies, dict) and package_name in {_normalize_package_name(name) for name in dependencies.keys()}:
            return True
        packages = payload.get("packages") or {}
        if isinstance(packages, dict):
            for package_path, meta in packages.items():
                if _normalize_package_name(str(meta.get("name") or "")) == package_name:
                    return True
                if f"node_modules/{package_name}" in str(package_path).lower():
                    return True
        return False

    if path.name == "pnpm-lock.yaml":
        pattern = re.compile(rf"(^|\n)\s{{2,}}(?:['\"])?{re.escape(package)}(?:['\"])?\s*:", re.IGNORECASE)
        return bool(pattern.search(text))

    if path.name == "yarn.lock":
        pattern = re.compile(rf"(^|\n)(?:['\"])?{re.escape(package)}@", re.IGNORECASE)
        return bool(pattern.search(text))

    if path.name.startswith("requirements") and path.suffix == ".txt":
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith(("-r", "--")):
                continue
            candidate = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0].strip()
            if _normalize_package_name(candidate) == package_name:
                return True
        return False

    if path.name in {"pyproject.toml", "Pipfile"}:
        try:
            payload = tomllib.loads(text)
        except Exception:
            return False
        candidates: set[str] = set()

        project = payload.get("project") or {}
        for item in project.get("dependencies") or []:
            if isinstance(item, str):
                candidates.add(_normalize_package_name(re.split(r"[<>=!~\[; ]", item, maxsplit=1)[0]))
        for deps in (project.get("optional-dependencies") or {}).values():
            for item in deps or []:
                if isinstance(item, str):
                    candidates.add(_normalize_package_name(re.split(r"[<>=!~\[; ]", item, maxsplit=1)[0]))
        for deps in (payload.get("dependency-groups") or {}).values():
            for item in deps or []:
                if isinstance(item, str):
                    candidates.add(_normalize_package_name(re.split(r"[<>=!~\[; ]", item, maxsplit=1)[0]))

        tool = payload.get("tool") or {}
        poetry = tool.get("poetry") or {}
        for key in (poetry.get("dependencies") or {}).keys():
            if _normalize_package_name(str(key)) != "python":
                candidates.add(_normalize_package_name(str(key)))
        for group in (poetry.get("group") or {}).values():
            for key in ((group or {}).get("dependencies") or {}).keys():
                if _normalize_package_name(str(key)) != "python":
                    candidates.add(_normalize_package_name(str(key)))

        pipfile_sections = [payload.get("packages") or {}, payload.get("dev-packages") or {}]
        for section in pipfile_sections:
            for key in section.keys():
                candidates.add(_normalize_package_name(str(key)))
        return package_name in candidates

    if path.name == "poetry.lock":
        pattern = re.compile(rf'(^|\n)name\s*=\s*"{re.escape(package)}"', re.IGNORECASE)
        return bool(pattern.search(text))

    pattern = re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(package)}(?![A-Za-z0-9_.-])", re.IGNORECASE)
    return bool(pattern.search(text))


def _package_reference_paths(package: str, search_root: Path) -> List[str]:
    hits: List[str] = []
    needle = str(package or "").strip()
    if not needle:
        return hits
    for glob in DEPENDENCY_FILE_GLOBS:
        for path in search_root.rglob(glob):
            if _should_ignore_path(path, search_root):
                continue
            if _manifest_contains_package(path, needle):
                hits.append(str(path.resolve()))
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
    score = explanation.get("score")
    threshold = explanation.get("effective_threshold")
    threshold_matched = (
        isinstance(score, (int, float))
        and isinstance(threshold, (int, float))
        and score >= threshold
    )
    advisory_matches = finding.get("advisory_matches") or []
    advisory_ids = finding.get("advisory_ids") or []
    campaign_ids = finding.get("campaign_ids") or []
    advisory_backed = bool(
        advisory_matches
        or advisory_ids
        or campaign_ids
        or "emergency advisory match" in lower_rules
    )
    scanner_verdict = str(
        explanation.get("verdict") or finding.get("verdict") or ""
    ).strip().lower()
    denylisted = bool(policy.get("deny_matches"))
    allowlisted = bool(policy.get("allow_matches"))

    if advisory_backed or denylisted:
        package_verdict = "confirmed_malicious"
        threat_confidence = "high"
        threat_basis = (
            "Source-backed advisory or explicit deny policy identifies this package/version."
        )
    elif strong_signals and (threshold_matched or scanner_verdict == "malicious"):
        package_verdict = "likely_malicious"
        threat_confidence = "high"
        threat_basis = "Multiple deterministic static indicators support a package-level threat assessment."
    elif threshold_matched or strong_signals or scanner_verdict in {"malicious", "suspicious"}:
        package_verdict = "suspicious"
        threat_confidence = "medium"
        threat_basis = "Scanner evidence warrants package-level investigation but is not conclusive proof."
    elif weak_only:
        package_verdict = "inconclusive"
        threat_confidence = "low"
        threat_basis = "Only weak heuristic evidence is available."
    else:
        package_verdict = "inconclusive"
        threat_confidence = "low"
        threat_basis = "Package-level evidence is incomplete."

    exposure_status = "confirmed" if dependency_hits else "not_observed_in_scope"
    exposure_assessment = {
        "status": exposure_status,
        "scope": str(search_root.resolve()),
        "references": dependency_hits,
        "searched_manifest_patterns": list(DEPENDENCY_FILE_GLOBS),
        "limitations": (
            []
            if dependency_hits
            else [
                "No reference in this repository does not prove organization-wide absence.",
                "Transitive dependencies, CI caches, containers, deployed workloads, and other repositories require separate inventory checks.",
            ]
        ),
    }
    package_actionable = package_verdict in {
        "confirmed_malicious",
        "likely_malicious",
        "suspicious",
        "inconclusive",
    }

    recommended_disposition = "needs_review"
    confidence = "medium"
    summary_bits = []
    next_actions = []

    if advisory_backed or denylisted:
        recommended_disposition = "true_positive"
        confidence = "high"
        summary_bits.append(
            "Package-level threat evidence is source-backed or explicitly denied by policy."
        )
        if not dependency_hits:
            summary_bits.append(
                "Local exposure was not observed in this repository; that does not change the package verdict."
            )
        next_actions.extend(
            [
                "Block or quarantine the exact package version in applicable dependency controls.",
                "Search organization-wide manifests, SBOMs, lockfiles, CI caches, containers, and deployed workloads for exposure.",
                "Preserve advisory sources, artifact hashes, registry metadata, and analysis tool versions in a Research Case.",
            ]
        )
    elif allowlisted and package_verdict == "inconclusive":
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
    elif weak_only:
        recommended_disposition = "needs_review"
        confidence = "low"
        summary_bits.append("Only weak heuristic rules fired; package evidence remains inconclusive.")
        next_actions.extend(
            [
                "Run safe package intake and compare the exact artifact with a trusted release before deciding the package verdict.",
                "Close as false positive only when package-level evidence, not local absence, supports that conclusion.",
            ]
        )
    elif not dependency_hits:
        recommended_disposition = "needs_review"
        confidence = "medium"
        summary_bits.append(
            "Local exposure was not observed in this repository, while package-level validation remains open."
        )
        next_actions.extend(
            [
                "Collect registry metadata and the exact artifact without executing package code.",
                "Hash, statically inspect, and compare the artifact with the legitimate or previous release.",
                "Promote credible evidence into a Research Case and correlate publishers, code, infrastructure, and timelines.",
                "Search organization-wide dependency inventories separately from the package investigation.",
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
        "threat_assessment": {
            "verdict": package_verdict,
            "confidence": threat_confidence,
            "basis": threat_basis,
            "advisory_backed": advisory_backed,
            "denylisted": denylisted,
            "scanner_verdict": scanner_verdict or "unknown",
            "score": score,
            "threshold": threshold,
            "strong_signals": strong_signals,
            "limitations": [
                "Static indicators do not by themselves prove runtime behavior or malicious intent.",
                "Attribution requires separate corroborated evidence.",
            ],
        },
        "exposure_assessment": exposure_assessment,
        "actionability": {
            "package_intelligence": "actionable" if package_actionable else "closed",
            "local_response": "required" if dependency_hits else "verify_enterprise_exposure",
            "reason": (
                "Package threat assessment is independent of whether this repository references the package."
            ),
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
