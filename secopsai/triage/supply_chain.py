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
