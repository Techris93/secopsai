"""
SecOpsAI Supply Chain Module - Enhanced with False Positive Reduction

This module provides supply chain security scanning for PyPI and NPM packages
with comprehensive false positive reduction mechanisms. It also exposes a
shared ecosystem/advisory layer for additional package registries where
SecOpsAI can safely perform deterministic manifest checks without executing
untrusted package code.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import urllib.parse
import urllib.request
import xmlrpc.client  # nosec B411
import xml.etree.ElementTree as ET
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import soc_store
from secopsai.sqlite_writer_lock import sqlite_writer_lock

try:
    from defusedxml.xmlrpc import monkey_patch as _defuse_xmlrpc

    _defuse_xmlrpc()
except ImportError:  # pragma: no cover - dependency is declared for runtime.
    pass

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility.
    import tomli as tomllib

from secopsai.alerts import (
    SUPPLY_CHAIN_SLACK_STATE_PATH,
    alert_new_supply_chain_findings,
    load_slack_state,
    save_slack_state,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPLY_CHAIN_DIR = REPO_ROOT / "data" / "supply_chain"
ADVISORIES_DIR = REPO_ROOT / "data" / "advisories"
REPORTS_DIR = SUPPLY_CHAIN_DIR / "reports"
RESULTS_PATH = SUPPLY_CHAIN_DIR / "results.jsonl"
STATE_PATH = SUPPLY_CHAIN_DIR / "state.json"
POLICY_PATH = REPO_ROOT / "config" / "supply_chain_policy.toml"
CAMPAIGN_DISCOVERY_DIR = SUPPLY_CHAIN_DIR / "campaign_discovery"
CAMPAIGN_CANDIDATES_PATH = CAMPAIGN_DISCOVERY_DIR / "candidates.json"
CAMPAIGN_WATCHLIST_PATH = CAMPAIGN_DISCOVERY_DIR / "watchlist.json"
NPM_SOURCE_SNAPSHOTS_DIR = SUPPLY_CHAIN_DIR / "npm_source"
PACKAGIST_SOURCE_SNAPSHOTS_DIR = SUPPLY_CHAIN_DIR / "packagist_source"
BLOG_NEWS_SOURCES_PATH = REPO_ROOT / "blog" / "data" / "news-sources.json"
BLOG_NEWS_CACHE_PATH = REPO_ROOT / "blog" / "data" / "news-cache.json"

PYPI_XMLRPC = "https://pypi.org/pypi"
PYPI_JSON = "https://pypi.org/pypi/{package}/json"
PYPI_VERSION_JSON = "https://pypi.org/pypi/{package}/{version}/json"
TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

NPM_REPLICATE = "https://replicate.npmjs.com"
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_MAX_CHANGES_PER_CYCLE = 10000

ECOSYSTEM_ALIASES = {
    "crate": "crates",
    "crates.io": "crates",
    "rust": "crates",
    "chrome": "chrome-web-store",
    "chrome-extension": "chrome-web-store",
    "chrome_web_store": "chrome-web-store",
    "composer": "packagist",
    "golang": "go",
    "gomod": "go",
    "go-modules": "go",
    "hugging-face": "huggingface",
    "hf": "huggingface",
    "maven-central": "maven",
    "openvsx": "open-vsx",
    "open_vsx": "open-vsx",
    "gem": "rubygems",
    "rubygems.org": "rubygems",
    "github-repo": "github",
    "github-repository": "github",
    "repo": "github",
    "repository": "github",
    "vscode": "open-vsx",
    "vs-code": "open-vsx",
    "visual-studio-code": "open-vsx",
}

SUPPORTED_ECOSYSTEMS: Dict[str, Dict[str, Any]] = {
    "npm": {
        "display_name": "npm",
        "identifier": "package/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": [],
    },
    "pypi": {
        "display_name": "PyPI",
        "identifier": "normalized project/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": [],
    },
    "crates": {
        "display_name": "crates.io",
        "identifier": "crate/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["Package-scoped monitoring uses crates.io version timestamps; no code is executed."],
    },
    "chrome-web-store": {
        "display_name": "Chrome Web Store",
        "identifier": "extension id or name/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": False,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": False,
        },
        "limitations": ["Live Chrome Web Store CRX fetch is not reliable without browser/session context; use --artifact/--previous-artifact with exported CRX or ZIP files."],
    },
    "packagist": {
        "display_name": "Packagist",
        "identifier": "vendor/package/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["Packagist dist archives are unpacked only for static analysis; Composer scripts are never run."],
    },
    "go": {
        "display_name": "Go Modules",
        "identifier": "module path/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["Go module proxy ZIPs are statically unpacked; init/build code is never executed."],
    },
    "huggingface": {
        "display_name": "Hugging Face Hub",
        "identifier": "repo id/revision",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["Model weights are not downloaded; SecOpsAI compares metadata, file listings, and small allowlisted text/source files only."],
    },
    "maven": {
        "display_name": "Maven Central",
        "identifier": "groupId:artifactId/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["Maven scans prefer source JARs/POMs; binary class files are not decompiled or executed."],
    },
    "nuget": {
        "display_name": "NuGet",
        "identifier": "package id/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["NuGet version timestamps are limited in the flat-container API; monitoring falls back to latest-version deltas."],
    },
    "open-vsx": {
        "display_name": "Open VSX",
        "identifier": "namespace.extension/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["Open VSX VSIX packages are unpacked only for static analysis; extensions are never activated."],
    },
    "github": {
        "display_name": "GitHub repository",
        "identifier": "owner/repo or organization/repository",
        "features": {
            "advisory_match": True,
            "metadata_fetch": False,
            "artifact_fetch": False,
            "diff_analysis": False,
            "behavioral_rules": True,
            "monitor": False,
        },
        "limitations": ["GitHub campaign records analyze source-backed audit/event fixtures only; repository contents are never cloned or downloaded."],
    },
    "rubygems": {
        "display_name": "RubyGems.org",
        "identifier": "gem/version",
        "features": {
            "advisory_match": True,
            "metadata_fetch": True,
            "artifact_fetch": True,
            "diff_analysis": True,
            "behavioral_rules": True,
            "monitor": True,
        },
        "limitations": ["RubyGems .gem payloads are unpacked for static checks; native extension hooks are never run."],
    },
}

SUPPORTED_ECOSYSTEM_NAMES = tuple(sorted(SUPPORTED_ECOSYSTEMS))

AGENT_PROMPT = """Review the diff in the workspace file and decide whether it is highly likely to show package supply-chain compromise.

Start the response with exactly one of:
Verdict: malicious
Verdict: benign

Then explain briefly.
"""

# Suspicious patterns with their weights
SUSPICIOUS_RULES: list[tuple[str, str, int]] = [
    ("obfuscated eval", r"\b(?:eval|exec)\s*\(|\bnew Function\s*\(|\bFunction\s*\(", 3),
    ("subprocess spawn", r"\b(child_process|subprocess|os\.system|popen|spawn|execFile)\b", 3),
    ("shell downloader", r"\b(curl|wget|Invoke-WebRequest|bitsadmin|certutil)\b", 3),
    ("base64 or encoded payload", r"\b(base64|fromCharCode|atob|btoa|decodeURIComponent)\b", 2),
    ("network egress", r"https?://", 2),
    ("credential access", r"\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|credential|aws_access_key_id|BEGIN RSA PRIVATE KEY)\b", 2),
    ("startup persistence", r"\b(postinstall|preinstall|install|cron|LaunchAgents|systemd|Startup)\b", 3),
    ("suspicious archive extraction", r"\b(tarfile|zipfile|extractall)\b", 1),
    ("module-load execution", r"\b(module-load execution|iife|self-executing|javascript module-load)\b", 4),
    ("host fingerprinting", r"\b(host fingerprinting|os\.hostname|userInfo|homedir|networkInterfaces)\b", 3),
    ("local file enumeration", r"\b(local file enumeration|readdirSync|readFileSync|\.ssh|\.npmrc|\.env|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)\b", 4),
    ("environment credential harvesting", r"\b(environment credential|process\.env|GITHUB_TOKEN|NPM_TOKEN|AWS_|GOOGLE_|AZURE_|SSH_AUTH_SOCK)\b", 4),
    ("payload wrapping or exfil staging", r"\b(payload wrapping|exfil staging|dns exfil|zlib|gzip|Buffer\.from)\b", 3),
    ("ecosystem manifest risk", r"\b(?:crates|chrome extension|composer|go module|hugging face|maven|nuget|open vsx|rubygems).*(?:install-time|credential|remote code|unsafe|eval|exec|permission|hook|lifecycle)\b", 3),
    ("github token abuse", r"\b(?:GitHub token|ghp_|gho_|ghs_|GITHUB_TOKEN|Actions secrets|GitHub API).*(?:abuse|exfil|download|repo|repository|token|secret)\b", 5),
    ("mass repository download", r"\b(?:mass repo|mass repository|downloaded repositories|repo enumeration|repos/download|zipball|tarball|git clone --mirror)\b", 4),
    ("orphan commit delivery", r"\b(?:orphan(?:ed)? commit|unreachable commit|dangling commit|unsigned commit|hidden commit)\b", 5),
    ("vscode extension compromise", r"\b(?:VS Code|VSCode|Visual Studio Code|open vsx|marketplace|extension activation|activationEvents|workspace).*?(?:credential|child_process|fetch|orphan|malicious|compromised)\b", 5),
    ("dns or https exfiltration", r"\b(?:DNS tunneling|dns exfil|HTTPS exfil|dead drop|dead-drop|GitHub dead-drop|OpenTelemetry endpoint)\b", 4),
    ("mini shai-hulud payload indicators", r"\b(?:Mini Shai-Hulud|Shai-Hulud|thebeautifulmarchoftime|f4abccab2|Miasma: The Spreading Blight|IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner)\b", 5),
]

COMMON_BUILD_BACKENDS = {
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "hatchling.build",
    "flit_core.buildapi",
    "poetry.core.masonry.api",
    "pdm.backend",
    "maturin",
    "scikit_build_core.build",
    "mesonpy",
    "uv_build",
}

# Package reputation cache to avoid repeated API calls
_reputation_cache: Dict[str, Dict[str, Any]] = {}
_advisory_cache: Dict[Tuple[str, Tuple[Tuple[str, int, int], ...]], List[Dict[str, Any]]] = {}
_advisory_index_cache: Dict[
    Tuple[str, Tuple[Tuple[str, int, int], ...]],
    Dict[Tuple[str, str], List[Tuple[Dict[str, Any], Dict[str, Any]]]],
] = {}

NPM_INSTALL_HOOK_RE = re.compile(
    r'^\+\s+"(?P<hook>preinstall|install|postinstall|prepare)"\s*:\s*"(?P<cmd>.+)"',
    re.MULTILINE | re.IGNORECASE,
)

BENIGN_ARTIFACT_PATH_PREFIXES = (
    "tests/",
    "test/",
    "docs/",
    "doc/",
    "examples/",
    "example/",
    "bench/",
    "benchmark/",
    "benchmarks/",
    "scripts/",
    ".github/",
    ".gitignore",
    "tox.ini",
    "Makefile",
    "setup.cfg",
    "requirements",
    "constraints",
)

BENIGN_ARTIFACT_PATH_SUFFIXES = (
    ".dist-info/metadata",
    ".dist-info/record",
    ".dist-info/wheel",
    ".dist-info/top_level.txt",
    ".md",
    ".rst",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
)

DEFAULT_MAX_DOWNLOAD_MB = 50
DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
ARCHIVE_MEMBER_LIMIT = 10000
HF_ALLOWED_FILE_NAMES = {"README.md", "config.json", "model_index.json", "tokenizer_config.json"}
HF_ALLOWED_SUFFIXES = (".py", ".md", ".json", ".yaml", ".yml", ".txt")


@dataclass
class ScanResult:
    ecosystem: str
    package: str
    old_version: Optional[str]
    new_version: str
    verdict: str
    analysis: str
    report_path: Optional[str]
    rank: Optional[int]
    finding_id: Optional[str]
    error: Optional[str] = None
    advisory_matches: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "verdict": self.verdict,
            "analysis": self.analysis,
            "report_path": self.report_path,
            "rank": self.rank,
            "finding_id": self.finding_id,
            "error": self.error,
            "recorded_at": _utc_now(),
        }
        if self.advisory_matches:
            payload["advisory_matches"] = self.advisory_matches
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ensure_dirs() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ADVISORIES_DIR.mkdir(parents=True, exist_ok=True)
    CAMPAIGN_DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
    NPM_SOURCE_SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    PACKAGIST_SOURCE_SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def _http_json(url: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "secopsai-supply-chain/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _http_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "secopsai-supply-chain/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _load_state() -> Dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(state: Dict[str, Any]) -> None:
    _ensure_dirs()
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def load_policy(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or Path(os.environ.get("SECOPS_SUPPLY_CHAIN_POLICY", str(POLICY_PATH)))
    default_policy = {
        "thresholds": {"malicious_score": 10},  # Increased default
        "ecosystem_thresholds": {},
        "allow": {"packages": []},
        "deny": {"packages": []},
        "package_thresholds": {},
        "rules": {},
        "rule_weights": {},
    }
    if not path.exists():
        return default_policy
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default_policy
    payload.setdefault("thresholds", {})
    payload.setdefault("ecosystem_thresholds", {})
    payload.setdefault("allow", {})
    payload.setdefault("deny", {})
    payload.setdefault("package_thresholds", {})
    payload.setdefault("rules", {})
    payload.setdefault("rule_weights", {})
    payload["thresholds"].setdefault("malicious_score", 10)
    payload["allow"].setdefault("packages", [])
    payload["deny"].setdefault("packages", [])
    return payload


def _toml_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _policy_target(ecosystem: str, package: str) -> str:
    return f"{canonical_ecosystem(ecosystem)}:{normalize_package_name(ecosystem, package)}"


def canonical_ecosystem(ecosystem: str) -> str:
    normalized = str(ecosystem or "").strip().lower().replace("_", "-")
    return ECOSYSTEM_ALIASES.get(normalized, normalized)


def normalize_package_name(ecosystem: str, package: str) -> str:
    eco = canonical_ecosystem(ecosystem)
    cleaned = " ".join(str(package or "").strip().split())
    if eco in {"npm", "pypi", "crates", "chrome-web-store", "packagist", "maven", "nuget", "open-vsx", "rubygems"}:
        return cleaned.lower()
    if eco == "go":
        return cleaned.rstrip("/")
    if eco == "huggingface":
        return cleaned.strip("/")
    return cleaned


def validate_package_identifier(ecosystem: str, package: str) -> Dict[str, Any]:
    eco = canonical_ecosystem(ecosystem)
    normalized = normalize_package_name(eco, package)
    errors: List[str] = []
    if eco not in SUPPORTED_ECOSYSTEMS:
        errors.append(f"unsupported ecosystem: {ecosystem}")
    if not normalized:
        errors.append("package identifier is required")
    elif eco == "packagist" and "/" not in normalized:
        errors.append("Packagist packages should use vendor/package")
    elif eco == "go" and "." not in normalized:
        errors.append("Go modules should use a module path such as github.com/org/module")
    elif eco == "maven" and ":" not in normalized:
        errors.append("Maven artifacts should use groupId:artifactId")
    elif eco == "open-vsx" and "." not in normalized:
        errors.append("Open VSX extensions should use namespace.extension")
    elif eco == "github" and "/" not in normalized:
        errors.append("GitHub repository identifiers should use owner/repo")
    elif eco == "huggingface" and "/" not in normalized:
        errors.append("Hugging Face identifiers should use owner/repo")
    elif eco == "chrome-web-store" and not re.fullmatch(r"[a-z0-9_.-]+", normalized):
        errors.append("Chrome Web Store identifiers may contain letters, digits, dots, underscores, or dashes")
    return {
        "ecosystem": eco,
        "package": normalized,
        "valid": not errors,
        "errors": errors,
    }


def ecosystem_capabilities(ecosystem: str) -> Dict[str, Any]:
    eco = canonical_ecosystem(ecosystem)
    details = SUPPORTED_ECOSYSTEMS.get(eco)
    if not details:
        return {
            "ecosystem": eco,
            "supported": False,
            "features": {},
            "limitations": [f"Unsupported ecosystem: {ecosystem}"],
        }
    return {
        "ecosystem": eco,
        "display_name": details["display_name"],
        "identifier": details["identifier"],
        "supported": True,
        "features": dict(details["features"]),
        "limitations": list(details.get("limitations", [])),
    }


def list_supported_ecosystems() -> Dict[str, Any]:
    return {
        "total": len(SUPPORTED_ECOSYSTEMS),
        "ecosystems": [ecosystem_capabilities(name) for name in SUPPORTED_ECOSYSTEM_NAMES],
    }


def save_policy(policy: Dict[str, Any], path: Optional[Path] = None) -> Path:
    path = path or Path(os.environ.get("SECOPS_SUPPLY_CHAIN_POLICY", str(POLICY_PATH)))
    threshold = int(policy.get("thresholds", {}).get("malicious_score", 10))
    eco_thresholds = {
        str(key).lower(): int(value) for key, value in policy.get("ecosystem_thresholds", {}).items()
    }
    allow_packages = sorted({str(item) for item in policy.get("allow", {}).get("packages", [])}, key=str.lower)
    deny_packages = sorted({str(item) for item in policy.get("deny", {}).get("packages", [])}, key=str.lower)
    package_thresholds = {
        str(key): int(value) for key, value in policy.get("package_thresholds", {}).items()
    }
    rules = {str(key): bool(value) for key, value in policy.get("rules", {}).items()}
    rule_weights = {str(key): int(value) for key, value in policy.get("rule_weights", {}).items()}

    lines: List[str] = []
    lines.append("[thresholds]")
    lines.append(f"malicious_score = {threshold}")
    lines.append("")

    lines.append("[ecosystem_thresholds]")
    if eco_thresholds:
        for key in sorted(eco_thresholds):
            lines.append(f"{key} = {eco_thresholds[key]}")
    lines.append("")

    lines.append("[allow]")
    lines.append("packages = [")
    for item in allow_packages:
        lines.append(f"    {_toml_literal(item)},")
    lines.append("]")
    lines.append("")

    lines.append("[deny]")
    lines.append("packages = [")
    for item in deny_packages:
        lines.append(f"    {_toml_literal(item)},")
    lines.append("]")
    lines.append("")

    lines.append("[package_thresholds]")
    if package_thresholds:
        for key in sorted(package_thresholds, key=str.lower):
            lines.append(f"{_toml_literal(key)} = {package_thresholds[key]}")
    lines.append("")

    lines.append("[rules]")
    if rules:
        for key in sorted(rules, key=str.lower):
            lines.append(f"{_toml_literal(key)} = {_toml_literal(rules[key])}")
    lines.append("")

    lines.append("[rule_weights]")
    if rule_weights:
        for key in sorted(rule_weights, key=str.lower):
            lines.append(f"{_toml_literal(key)} = {rule_weights[key]}")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def allowlist_add(ecosystem: str, package: str, path: Optional[Path] = None) -> Dict[str, Any]:
    policy = load_policy(path)
    target = _policy_target(ecosystem, package)
    entries = {str(item) for item in policy.get("allow", {}).get("packages", [])}
    changed = target not in entries
    entries.add(target)
    policy.setdefault("allow", {})["packages"] = sorted(entries, key=str.lower)
    saved_path = save_policy(policy, path)
    return {
        "changed": changed,
        "entry": target,
        "policy_path": str(saved_path),
        "policy": explain_policy(ecosystem, package, policy=policy),
    }


def allowlist_remove(ecosystem: str, package: str, path: Optional[Path] = None) -> Dict[str, Any]:
    policy = load_policy(path)
    target = _policy_target(ecosystem, package)
    entries = {str(item) for item in policy.get("allow", {}).get("packages", [])}
    changed = target in entries
    entries.discard(target)
    policy.setdefault("allow", {})["packages"] = sorted(entries, key=str.lower)
    saved_path = save_policy(policy, path)
    return {
        "changed": changed,
        "entry": target,
        "policy_path": str(saved_path),
        "policy": explain_policy(ecosystem, package, policy=policy),
    }


def tune_rule(
    rule_name: str,
    *,
    weight: Optional[int] = None,
    enabled: Optional[bool] = None,
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    policy = load_policy(path)
    if weight is None and enabled is None:
        raise ValueError("at least one of weight or enabled must be provided")
    if weight is not None:
        policy.setdefault("rule_weights", {})[rule_name] = int(weight)
    if enabled is not None:
        policy.setdefault("rules", {})[rule_name] = bool(enabled)
    saved_path = save_policy(policy, path)
    return {
        "rule": rule_name,
        "weight": policy.get("rule_weights", {}).get(rule_name),
        "enabled": policy.get("rules", {}).get(rule_name),
        "policy_path": str(saved_path),
    }


def tune_threshold(
    *,
    global_threshold: Optional[int] = None,
    ecosystem: Optional[str] = None,
    package: Optional[str] = None,
    value: int,
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    policy = load_policy(path)
    if package and not ecosystem:
        raise ValueError("ecosystem is required when setting a package threshold")
    if package:
        target = _policy_target(ecosystem or "", package)
        policy.setdefault("package_thresholds", {})[target] = int(value)
        scope = "package"
        target_value = target
    elif ecosystem:
        policy.setdefault("ecosystem_thresholds", {})[ecosystem.lower()] = int(value)
        scope = "ecosystem"
        target_value = ecosystem.lower()
    elif global_threshold is not None:
        policy.setdefault("thresholds", {})["malicious_score"] = int(value)
        scope = "global"
        target_value = "malicious_score"
    else:
        raise ValueError("must specify --global, --ecosystem, or --package target")
    saved_path = save_policy(policy, path)
    return {
        "scope": scope,
        "target": target_value,
        "value": int(value),
        "policy_path": str(saved_path),
    }


def _package_matches_policy(entries: List[str], ecosystem: Optional[str], package: Optional[str]) -> bool:
    if not ecosystem or not package:
        return False
    target = _policy_target(ecosystem, package).lower()
    for entry in entries:
        candidate = str(entry).strip().lower()
        if not candidate:
            continue
        if candidate == target:
            return True
        if candidate.endswith("*") and target.startswith(candidate[:-1]):
            return True
    return False


def _matching_policy_entries(entries: List[str], ecosystem: Optional[str], package: Optional[str]) -> List[str]:
    if not ecosystem or not package:
        return []
    target = _policy_target(ecosystem, package).lower()
    matches: List[str] = []
    for entry in entries:
        candidate = str(entry).strip()
        normalized = candidate.lower()
        if not normalized:
            continue
        if normalized == target:
            matches.append(candidate)
        elif normalized.endswith("*") and target.startswith(normalized[:-1]):
            matches.append(candidate)
    return matches


def _rule_enabled(policy: Dict[str, Any], rule_name: str) -> bool:
    rules = policy.get("rules", {})
    value = rules.get(rule_name, True)
    return bool(value)


def _rule_weight(policy: Dict[str, Any], rule_name: str, default_weight: int) -> int:
    override = policy.get("rule_weights", {}).get(rule_name)
    if override is None:
        return default_weight
    try:
        return int(override)
    except Exception:
        return default_weight


def _package_threshold(policy: Dict[str, Any], ecosystem: Optional[str], package: Optional[str]) -> int:
    global_threshold = int(policy.get("thresholds", {}).get("malicious_score", 10))
    if ecosystem:
        eco_thresholds = {str(key).lower(): value for key, value in policy.get("ecosystem_thresholds", {}).items()}
        if ecosystem.lower() in eco_thresholds:
            global_threshold = int(eco_thresholds[ecosystem.lower()])
    if not ecosystem or not package:
        # Report-only classification without package context should keep the
        # deterministic baseline from the native classifier instead of inheriting
        # stricter runtime thresholds meant for live package monitoring.
        return min(global_threshold, 6)
    entries = policy.get("package_thresholds", {})
    target = f"{ecosystem}:{package}".lower()
    if target in {str(key).lower(): value for key, value in entries.items()}:
        normalized = {str(key).lower(): value for key, value in entries.items()}
        return int(normalized[target])
    for key, value in entries.items():
        candidate = str(key).strip().lower()
        if candidate.endswith("*") and target.startswith(candidate[:-1]):
            return int(value)
    return global_threshold


def explain_policy(ecosystem: str, package: str, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    policy = policy or load_policy()
    ecosystem = canonical_ecosystem(ecosystem)
    package = normalize_package_name(ecosystem, package)
    allow_matches = _matching_policy_entries(policy.get("allow", {}).get("packages", []), ecosystem, package)
    deny_matches = _matching_policy_entries(policy.get("deny", {}).get("packages", []), ecosystem, package)
    target = _policy_target(ecosystem, package).lower()

    ecosystem_thresholds = {
        str(key).lower(): int(value)
        for key, value in policy.get("ecosystem_thresholds", {}).items()
    }
    package_threshold_entries = {
        str(key): int(value)
        for key, value in policy.get("package_thresholds", {}).items()
    }

    matched_package_threshold = None
    for key, value in package_threshold_entries.items():
        normalized = key.lower()
        if normalized == target or (normalized.endswith("*") and target.startswith(normalized[:-1])):
            matched_package_threshold = {"entry": key, "value": value}
        if normalized == target:
            break

    effective_threshold = _package_threshold(policy, ecosystem, package)
    disabled_rules = sorted(
        rule_name for rule_name, enabled in policy.get("rules", {}).items() if not bool(enabled)
    )
    overridden_rule_weights = {
        str(rule_name): int(weight)
        for rule_name, weight in policy.get("rule_weights", {}).items()
    }

    precedence: List[str] = []
    if deny_matches:
        precedence.append("denylist")
    elif allow_matches:
        precedence.append("allowlist")
    elif matched_package_threshold:
        precedence.append("package_threshold")
    elif ecosystem.lower() in ecosystem_thresholds:
        precedence.append("ecosystem_threshold")
    else:
        precedence.append("global_threshold")

    return {
        "target": {"ecosystem": ecosystem, "package": package},
        "effective_threshold": effective_threshold,
        "precedence": precedence,
        "allow_matches": allow_matches,
        "deny_matches": deny_matches,
        "global_threshold": int(policy.get("thresholds", {}).get("malicious_score", 10)),
        "ecosystem_threshold": ecosystem_thresholds.get(ecosystem.lower()),
        "matched_package_threshold": matched_package_threshold,
        "disabled_rules": disabled_rules,
        "rule_weight_overrides": overridden_rule_weights,
    }


def suggest_threshold(
    ecosystem: str,
    *,
    package: Optional[str] = None,
    db_path: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    reviewed_safe = {"false_positive", "expected_behavior", "tune_policy", "exception_granted"}
    reviewed_risky = {"true_positive", "needs_review", "remediated"}
    rows = load_recent_results(limit=max(limit, 1))
    filtered = [
        row for row in rows
        if str(row.get("ecosystem") or "").lower() == ecosystem.lower()
        and (not package or str(row.get("package") or "").lower() == package.lower())
    ]

    scored_rows: List[Dict[str, Any]] = []
    for row in filtered:
        report_path = row.get("report_path")
        if not report_path:
            continue
        path = Path(str(report_path))
        if not path.exists():
            continue
        try:
            explanation = explain_verdict(
                path.read_text(encoding="utf-8"),
                ecosystem=str(row.get("ecosystem") or ecosystem),
                package=str(row.get("package") or package or ""),
            )
        except Exception:
            continue
        finding = soc_store.get_finding(str(row.get("finding_id") or ""), db_path) if row.get("finding_id") else None
        disposition = str((finding or {}).get("disposition") or "unreviewed").lower()
        scored_rows.append(
            {
                "finding_id": row.get("finding_id"),
                "package": row.get("package"),
                "version": row.get("new_version"),
                "score": int(explanation.get("score") or 0),
                "disposition": disposition,
                "verdict": explanation.get("verdict"),
                "report_path": str(path),
            }
        )

    current_policy = load_policy()
    if package:
        current_threshold = _package_threshold(current_policy, ecosystem, package)
    else:
        current_threshold = int(
            {
                str(key).lower(): value for key, value in current_policy.get("ecosystem_thresholds", {}).items()
            }.get(ecosystem.lower(), current_policy.get("thresholds", {}).get("malicious_score", 10))
        )
    safe_scores = sorted(row["score"] for row in scored_rows if row["disposition"] in reviewed_safe)
    risky_scores = sorted(row["score"] for row in scored_rows if row["disposition"] in reviewed_risky)
    unreviewed_scores = sorted(row["score"] for row in scored_rows if row["disposition"] not in reviewed_safe | reviewed_risky)

    rationale = "Not enough reviewed findings to recommend a threshold change yet."
    confidence = "low"
    suggested = current_threshold

    if safe_scores and risky_scores:
        max_safe = max(safe_scores)
        min_risky = min(risky_scores)
        suggested = max_safe + 1
        if suggested <= min_risky:
            confidence = "high"
            rationale = (
                f"Reviewed safe findings cluster at or below {max_safe}, while reviewed risky findings start at {min_risky}."
            )
        else:
            confidence = "medium"
            rationale = (
                f"Reviewed safe and risky scores overlap (max safe {max_safe}, min risky {min_risky}); "
                f"{suggested} is the smallest stricter threshold that suppresses the reviewed safe cluster."
            )
    elif safe_scores:
        max_safe = max(safe_scores)
        suggested = max(current_threshold, max_safe + 1)
        confidence = "medium"
        rationale = f"Only reviewed safe findings were available; raising the threshold above max safe score {max_safe} reduces similar false positives."
    elif risky_scores:
        min_risky = min(risky_scores)
        suggested = min(current_threshold, min_risky)
        confidence = "low"
        rationale = f"Only reviewed risky findings were available; keep the threshold no higher than {min_risky} to avoid suppressing reviewed malicious activity."
    elif unreviewed_scores:
        suggested = current_threshold
        confidence = "low"
        rationale = (
            f"There are {len(unreviewed_scores)} unreviewed scored findings, but no reviewed safe/risky baseline yet. "
            "Investigate and disposition a few findings before tuning thresholds."
        )

    examples = {
        "reviewed_safe": [row for row in scored_rows if row["disposition"] in reviewed_safe][:5],
        "reviewed_risky": [row for row in scored_rows if row["disposition"] in reviewed_risky][:5],
        "unreviewed": [row for row in scored_rows if row["disposition"] not in reviewed_safe | reviewed_risky][:5],
    }

    return {
        "target": {"ecosystem": ecosystem, "package": package},
        "current_threshold": current_threshold,
        "suggested_threshold": suggested,
        "confidence": confidence,
        "rationale": rationale,
        "counts": {
            "considered_results": len(scored_rows),
            "reviewed_safe": len(safe_scores),
            "reviewed_risky": len(risky_scores),
            "unreviewed": len(unreviewed_scores),
        },
        "score_ranges": {
            "reviewed_safe": {"min": min(safe_scores) if safe_scores else None, "max": max(safe_scores) if safe_scores else None},
            "reviewed_risky": {"min": min(risky_scores) if risky_scores else None, "max": max(risky_scores) if risky_scores else None},
            "unreviewed": {"min": min(unreviewed_scores) if unreviewed_scores else None, "max": max(unreviewed_scores) if unreviewed_scores else None},
        },
        "examples": examples,
    }


def _record_rule_match(
    matched_rules: List[Dict[str, Any]],
    seen_rule_names: set[str],
    rule_name: str,
    weight: int,
    reason: str,
) -> None:
    if rule_name in seen_rule_names:
        return
    matched_rules.append({"rule": rule_name, "weight": weight, "reason": reason})
    seen_rule_names.add(rule_name)


def _finding_id(ecosystem: str, package: str, version: str) -> str:
    token = f"{ecosystem}:{package.lower()}:{version}"
    return f"SCM-{hashlib.sha256(token.encode('utf-8')).hexdigest()[:16].upper()}"


def _scan_event_id(ecosystem: str, package: str, version: str) -> str:
    token = f"scan:{ecosystem}:{package.lower()}:{version}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]


def _advisory_slug(advisory: Dict[str, Any]) -> str:
    raw = str(advisory.get("advisory_id") or advisory.get("campaign_id") or "advisory")
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-").lower() or "advisory"


def _canonical_package_name(ecosystem: str, package: str) -> str:
    return normalize_package_name(ecosystem, package)


def _version_key(version: str) -> tuple:
    parts: List[Any] = []
    for part in re.split(r"[.\-+_]", str(version)):
        if not part:
            continue
        parts.append(int(part) if part.isdigit() else part.lower())
    return tuple(parts)


def _compare_versions(left: str, right: str) -> int:
    left_parts = list(_version_key(left))
    right_parts = list(_version_key(right))
    max_len = max(len(left_parts), len(right_parts))
    left_parts.extend([0] * (max_len - len(left_parts)))
    right_parts.extend([0] * (max_len - len(right_parts)))
    for left_part, right_part in zip(left_parts, right_parts):
        if type(left_part) is not type(right_part):
            left_part = str(left_part)
            right_part = str(right_part)
        if left_part < right_part:
            return -1
        if left_part > right_part:
            return 1
    return 0


def _version_in_range(version: str, spec: Dict[str, Any]) -> bool:
    introduced = spec.get("introduced") or spec.get("min_version")
    fixed = spec.get("fixed") or spec.get("fixed_version")
    last_affected = spec.get("last_affected") or spec.get("max_version")
    if introduced and _compare_versions(version, str(introduced)) < 0:
        return False
    if fixed and _compare_versions(version, str(fixed)) >= 0:
        return False
    if last_affected and _compare_versions(version, str(last_affected)) > 0:
        return False
    return True


def _read_json_source(path_or_url: str) -> Any:
    if urllib.parse.urlparse(path_or_url).scheme in {"http", "https"}:
        with urllib.request.urlopen(path_or_url, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    return json.loads(Path(path_or_url).read_text(encoding="utf-8"))


def _advisory_signature(advisory_root: Path) -> Tuple[str, Tuple[Tuple[str, int, int], ...]]:
    root = advisory_root.expanduser().resolve()
    if not root.exists():
        return (str(root), ())
    files = [root] if root.is_file() else sorted(root.glob("*.json"))
    signature: List[Tuple[str, int, int]] = []
    for file_path in files:
        try:
            stat = file_path.stat()
        except OSError:
            continue
        signature.append((str(file_path.resolve()), int(stat.st_mtime_ns), int(stat.st_size)))
    return (str(root), tuple(signature))


def clear_advisory_cache() -> None:
    _advisory_cache.clear()
    _advisory_index_cache.clear()


def load_advisories(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    advisory_root = path or ADVISORIES_DIR
    if not advisory_root.exists():
        return []
    cache_key = _advisory_signature(advisory_root)
    cached = _advisory_cache.get(cache_key)
    if cached is not None:
        return cached
    files = [advisory_root] if advisory_root.is_file() else sorted(advisory_root.glob("*.json"))
    advisories: List[Dict[str, Any]] = []
    for advisory_file in files:
        try:
            payload = json.loads(advisory_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, list):
            advisories.extend(item for item in payload if isinstance(item, dict))
        elif isinstance(payload, dict):
            advisories.append(payload)
    _advisory_cache.clear()
    _advisory_cache[cache_key] = advisories
    return advisories


def ingest_advisory(path_or_url: str) -> Dict[str, Any]:
    payload = _read_json_source(path_or_url)
    advisories = payload if isinstance(payload, list) else [payload]
    if not all(isinstance(item, dict) for item in advisories):
        raise ValueError("advisory source must contain a JSON object or list of objects")
    _ensure_dirs()
    written: List[str] = []
    for advisory in advisories:
        if not advisory.get("advisory_id") and not advisory.get("campaign_id"):
            raise ValueError("advisory requires advisory_id or campaign_id")
        if not advisory.get("affected"):
            raise ValueError("advisory requires affected package entries")
        target = ADVISORIES_DIR / f"{_advisory_slug(advisory)}.json"
        target.write_text(json.dumps(advisory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(str(target))
    clear_advisory_cache()
    return {"ingested": len(written), "paths": written}


def _normalize_advisory_match(advisory: Dict[str, Any], affected: Dict[str, Any], version: str) -> Dict[str, Any]:
    return {
        "advisory_id": advisory.get("advisory_id"),
        "campaign_id": advisory.get("campaign_id"),
        "title": advisory.get("title"),
        "summary": advisory.get("summary"),
        "severity": advisory.get("severity", "critical"),
        "confidence": advisory.get("confidence", "high"),
        "status": advisory.get("status", "active"),
        "ecosystem": affected.get("ecosystem"),
        "package": affected.get("package"),
        "version": version,
        "matched_versions": affected.get("versions", []),
        "version_ranges": affected.get("version_ranges", []),
        "source_urls": advisory.get("source_urls", []),
        "source_names": advisory.get("source_names", []),
        "abused_services": advisory.get("abused_services", []),
        "iocs": advisory.get("iocs", {}),
        "detection_rationale": advisory.get("detection_rationale", []),
        "remediation": advisory.get("remediation", []),
        "safe_versions": affected.get("safe_versions", advisory.get("safe_versions", [])),
        "published_at": advisory.get("published_at"),
        "updated_at": advisory.get("updated_at"),
        "ingested_at": advisory.get("ingested_at"),
    }


def _advisory_index(path: Optional[Path] = None) -> Dict[Tuple[str, str], List[Tuple[Dict[str, Any], Dict[str, Any]]]]:
    advisory_root = path or ADVISORIES_DIR
    cache_key = _advisory_signature(advisory_root)
    cached = _advisory_index_cache.get(cache_key)
    if cached is not None:
        return cached
    index: Dict[Tuple[str, str], List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
    for advisory in load_advisories(path):
        if str(advisory.get("status", "active")).lower() != "active":
            continue
        for affected in advisory.get("affected", []):
            if not isinstance(affected, dict):
                continue
            affected_ecosystem = str(affected.get("ecosystem", "")).lower()
            affected_package = _canonical_package_name(affected_ecosystem, str(affected.get("package", "")))
            if affected_ecosystem and affected_package:
                index.setdefault((affected_ecosystem, affected_package), []).append((advisory, affected))
    _advisory_index_cache.clear()
    _advisory_index_cache[cache_key] = index
    return index


def find_advisory_matches(ecosystem: str, package: str, version: str) -> List[Dict[str, Any]]:
    target_ecosystem = canonical_ecosystem(ecosystem)
    target_package = _canonical_package_name(target_ecosystem, package)
    matches: List[Dict[str, Any]] = []
    for advisory, affected in _advisory_index().get((target_ecosystem, target_package), []):
        exact_versions = {str(item) for item in affected.get("versions", [])}
        range_specs = [spec for spec in affected.get("version_ranges", []) if isinstance(spec, dict)]
        if str(version) in exact_versions or any(_version_in_range(str(version), spec) for spec in range_specs):
            matches.append(_normalize_advisory_match(advisory, affected, str(version)))
    return matches


def check_advisory(ecosystem: str, package: str, version: str) -> Dict[str, Any]:
    canonical = canonical_ecosystem(ecosystem)
    normalized_package = normalize_package_name(canonical, package)
    matches = find_advisory_matches(canonical, normalized_package, version)
    return {
        "ecosystem": canonical,
        "package": normalized_package,
        "version": version,
        "matched": bool(matches),
        "matches": matches,
    }


def _advisory_analysis(matches: List[Dict[str, Any]], *, artifact_unavailable: bool = False) -> str:
    ids = ", ".join(str(match.get("advisory_id") or match.get("campaign_id")) for match in matches)
    titles = "; ".join(str(match.get("title") or "emergency advisory") for match in matches)
    prefix = "Artifact unavailable but emergency advisory matched" if artifact_unavailable else "Emergency advisory matched"
    rationale = []
    for match in matches:
        rationale.extend(str(item) for item in match.get("detection_rationale", [])[:3])
    details = f" Rationale: {'; '.join(rationale)}" if rationale else ""
    return f"{prefix}: {ids}. {titles}.{details}"


def _attach_advisory_analysis(analysis: str, matches: List[Dict[str, Any]]) -> str:
    advisory_text = _advisory_analysis(matches)
    if not analysis:
        return advisory_text
    if advisory_text in analysis:
        return analysis
    return f"{analysis} {advisory_text}"


def _report_filename(ecosystem: str, package: str, old_version: str, new_version: str) -> Path:
    safe = package.replace("/", "_").replace("@", "")
    return REPORTS_DIR / f"{ecosystem}-{safe}-{old_version}-to-{new_version}.md"


def _analysis_summary(analysis: str, fallback: str) -> str:
    cleaned = " ".join((analysis or "").split())
    return cleaned[:280] if cleaned else fallback


def _build_finding(result: ScanResult) -> Dict[str, Any]:
    assert result.old_version is not None
    assert result.finding_id is not None
    now = _utc_now()
    advisory_matches = result.advisory_matches or []
    rule_ids = ["SUPPLY-CHAIN-NATIVE"]
    if advisory_matches:
        rule_ids.append("SUPPLY-CHAIN-ADVISORY")
    return {
        "finding_id": result.finding_id,
        "title": f"Suspicious {result.ecosystem} package release: {result.package}@{result.new_version}",
        "summary": _analysis_summary(
            result.analysis,
            f"Native secopsai review marked {result.package}@{result.new_version} as malicious.",
        ),
        "severity": "critical",
        "severity_score": 98 if advisory_matches else 90,
        "status": "open",
        "disposition": "unreviewed",
        "first_seen": now,
        "last_seen": now,
        "event_ids": [_scan_event_id(result.ecosystem, result.package, result.new_version)],
        "rule_ids": rule_ids,
        "platform": "supply_chain",
        "source": "secopsai-supply-chain",
        "package": result.package,
        "ecosystem": result.ecosystem,
        "old_version": result.old_version,
        "new_version": result.new_version,
        "rank": result.rank,
        "verdict": result.verdict,
        "analysis": result.analysis,
        "report_path": result.report_path,
        "confidence": "high" if advisory_matches else None,
        "advisory_matches": advisory_matches,
        "artifact_urls": (result.metadata or {}).get("artifact_urls", []),
        "matched_rules": (result.metadata or {}).get("matched_rules", []),
        "supply_chain_metadata": result.metadata or {},
        "advisory_ids": sorted(
            {
                str(match.get("advisory_id"))
                for match in advisory_matches
                if match.get("advisory_id")
            }
        ),
        "campaign_ids": sorted(
            {
                str(match.get("campaign_id"))
                for match in advisory_matches
                if match.get("campaign_id")
            }
        ),
        "iocs": [match.get("iocs", {}) for match in advisory_matches if match.get("iocs")],
        "remediation": [match.get("remediation", []) for match in advisory_matches if match.get("remediation")],
    }


def _upsert_findings(findings: Iterable[Dict[str, Any]]) -> str:
    resolved = soc_store.default_db_path()
    with sqlite_writer_lock(resolved):
        soc_store.init_db(resolved)
        with soc_store.closing(soc_store.connect(resolved)) as connection:
            for finding in findings:
                if finding.get("advisory_matches"):
                    connection.execute(
                        """
                        UPDATE findings
                        SET status = 'open', disposition = 'unreviewed'
                        WHERE finding_id = ?
                          AND status = 'closed'
                          AND disposition = 'expected_behavior'
                        """,
                        (finding["finding_id"],),
                    )
                soc_store.upsert_finding(connection, finding, source="secopsai-supply-chain")
            connection.commit()
    return resolved


def _append_results(results: Iterable[ScanResult]) -> None:
    _ensure_dirs()
    with RESULTS_PATH.open("a", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result.to_dict(), sort_keys=True) + "\n")


def load_recent_results(limit: int = 20) -> List[Dict[str, Any]]:
    if not RESULTS_PATH.exists():
        return []
    if limit <= 0:
        return []
    tail: deque[str] = deque(maxlen=int(limit))
    with RESULTS_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                tail.append(line)
    rows = [json.loads(line) for line in reversed(tail)]
    return rows


def _load_all_results() -> List[Dict[str, Any]]:
    if not RESULTS_PATH.exists():
        return []
    return [json.loads(line) for line in RESULTS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def _save_all_results(rows: List[Dict[str, Any]]) -> None:
    _ensure_dirs()
    payload = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    RESULTS_PATH.write_text(payload, encoding="utf-8")


def _pick_best_wheel(wheels: list[dict]) -> dict:
    for wheel in wheels:
        filename = str(wheel.get("filename", "")).lower()
        if "py3-none-any" in filename or "py2.py3-none-any" in filename:
            return wheel
    return wheels[0]


def _download_file(url: str, dest: Path, *, max_bytes: int = DEFAULT_MAX_DOWNLOAD_MB * 1024 * 1024, timeout: int = 30) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "secopsai-supply-chain/0.1"})
    written = 0
    with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open("wb") as fh:
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:
                try:
                    dest.unlink()
                except OSError:
                    pass
                raise RuntimeError(f"download exceeds limit ({max_bytes} bytes): {url}")
            fh.write(chunk)
    return dest


def _download_pypi_package(package: str, version: str, dest: Path, packagetype: Optional[str] = None) -> Path:
    data = _http_json(PYPI_VERSION_JSON.format(package=package, version=version))
    files = data.get("urls", [])
    if not files:
        raise RuntimeError(f"No files available for {package}=={version}")
    if packagetype:
        typed = [f for f in files if f.get("packagetype") == packagetype]
        if not typed:
            raise RuntimeError(f"No {packagetype} for {package}=={version}")
        chosen = _pick_best_wheel(typed) if packagetype == "bdist_wheel" else typed[0]
    else:
        wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
        sdists = [f for f in files if f.get("packagetype") == "sdist"]
        chosen = _pick_best_wheel(wheels) if wheels else (sdists or files)[0]
    return _download_file(chosen["url"], dest / chosen["filename"])


def _download_npm_package(package: str, version: str, dest: Path) -> Path:
    encoded = package.replace("/", "%2F")
    data = _http_json(f"{NPM_REGISTRY}/{encoded}/{version}")
    tarball_url = data.get("dist", {}).get("tarball")
    if not tarball_url:
        raise RuntimeError(f"No tarball for {package}@{version}")
    filename = tarball_url.rsplit("/", 1)[-1]
    return _download_file(tarball_url, dest / filename)


def _safe_relative_path(dest: Path, member_name: str) -> Path:
    if member_name.startswith(("/", "\\")) or re.match(r"^[a-zA-Z]:[\\/]", member_name):
        raise RuntimeError(f"Archive absolute path blocked: {member_name}")
    root = dest.resolve()
    resolved = (dest / member_name).resolve()
    if resolved != root and root not in resolved.parents:
        raise RuntimeError(f"Archive path traversal blocked: {member_name}")
    return resolved


def _safe_tar_members(tf: tarfile.TarFile, dest: Path, *, max_files: int = DEFAULT_MAX_FILES, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES):
    root = dest.resolve()
    members = tf.getmembers()
    if len(members) > min(max_files, ARCHIVE_MEMBER_LIMIT):
        raise RuntimeError(f"Archive contains too many members: {len(members)}")
    for member in members:
        resolved = _safe_relative_path(dest, member.name)
        if resolved != root and root not in resolved.parents:
            raise RuntimeError(f"Tar path traversal blocked: {member.name}")
        if member.issym() or member.islnk():
            raise RuntimeError(f"Archive link blocked: {member.name}")
        if member.isfile() and member.size > max_file_bytes:
            raise RuntimeError(f"Archive member exceeds per-file limit: {member.name}")
        yield member


def _extract_zip_safe(archive: Path, dest: Path, *, max_files: int = DEFAULT_MAX_FILES, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
    with zipfile.ZipFile(archive, "r") as zf:
        infos = zf.infolist()
        if len(infos) > min(max_files, ARCHIVE_MEMBER_LIMIT):
            raise RuntimeError(f"Archive contains too many members: {len(infos)}")
        for info in infos:
            if info.is_dir():
                _safe_relative_path(dest, info.filename).mkdir(parents=True, exist_ok=True)
                continue
            if info.file_size > max_file_bytes:
                raise RuntimeError(f"Archive member exceeds per-file limit: {info.filename}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise RuntimeError(f"Archive symlink blocked: {info.filename}")
            target = _safe_relative_path(dest, info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 256)


def _extract_crx_safe(archive: Path, dest: Path, *, max_files: int = DEFAULT_MAX_FILES, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
    data = archive.read_bytes()
    if data[:4] == b"PK\x03\x04":
        _extract_zip_safe(archive, dest, max_files=max_files, max_file_bytes=max_file_bytes)
        return
    if data[:4] != b"Cr24" or len(data) < 12:
        raise RuntimeError(f"Unsupported CRX format: {archive.name}")
    version = int.from_bytes(data[4:8], "little")
    if version == 2 and len(data) >= 16:
        public_key_len = int.from_bytes(data[8:12], "little")
        signature_len = int.from_bytes(data[12:16], "little")
        zip_offset = 16 + public_key_len + signature_len
    elif version == 3:
        header_size = int.from_bytes(data[8:12], "little")
        zip_offset = 12 + header_size
    else:
        raise RuntimeError(f"Unsupported CRX version: {version}")
    payload = data[zip_offset:]
    if payload[:4] != b"PK\x03\x04":
        raise RuntimeError("CRX payload is not a ZIP archive")
    tmp_zip = archive.with_suffix(".payload.zip")
    tmp_zip.write_bytes(payload)
    try:
        _extract_zip_safe(tmp_zip, dest, max_files=max_files, max_file_bytes=max_file_bytes)
    finally:
        tmp_zip.unlink(missing_ok=True)


def _extract_gem_safe(archive: Path, dest: Path, *, max_files: int = DEFAULT_MAX_FILES, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
    with tarfile.open(archive, "r:*") as tf:
        member = next((item for item in tf.getmembers() if item.name == "data.tar.gz"), None)
        if member is None:
            raise RuntimeError(f"RubyGems archive missing data.tar.gz: {archive.name}")
        if member.size > DEFAULT_MAX_DOWNLOAD_MB * 1024 * 1024:
            raise RuntimeError("RubyGems data.tar.gz exceeds download limit")
        extracted = tf.extractfile(member)
        if extracted is None:
            raise RuntimeError("Unable to read RubyGems data.tar.gz")
        nested = archive.with_suffix(".data.tar.gz")
        nested.write_bytes(extracted.read())
    try:
        _extract_archive(nested, dest, max_files=max_files, max_file_bytes=max_file_bytes)
    finally:
        nested.unlink(missing_ok=True)


def _extract_archive(archive: Path, dest: Path, *, max_files: int = DEFAULT_MAX_FILES, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".crate")):
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest, members=list(_safe_tar_members(tf, dest, max_files=max_files, max_file_bytes=max_file_bytes)))
    elif name.endswith(".tar.bz2"):
        with tarfile.open(archive, "r:bz2") as tf:
            tf.extractall(dest, members=list(_safe_tar_members(tf, dest, max_files=max_files, max_file_bytes=max_file_bytes)))
    elif name.endswith((".zip", ".whl", ".nupkg", ".vsix", ".jar")):
        _extract_zip_safe(archive, dest, max_files=max_files, max_file_bytes=max_file_bytes)
    elif name.endswith(".crx"):
        _extract_crx_safe(archive, dest, max_files=max_files, max_file_bytes=max_file_bytes)
    elif name.endswith(".gem"):
        _extract_gem_safe(archive, dest, max_files=max_files, max_file_bytes=max_file_bytes)
    else:
        raise RuntimeError(f"Unsupported archive format: {archive.name}")
    children = [p for p in dest.iterdir() if not p.name.startswith(".")]
    return children[0] if len(children) == 1 and children[0].is_dir() else dest


def _collect_files(root: Path, *, max_files: int = DEFAULT_MAX_FILES) -> Dict[str, Path]:
    files: Dict[str, Path] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if len(files) >= max_files:
            raise RuntimeError(f"Artifact contains more than {max_files} files")
        files[str(path.relative_to(root))] = path
    return files


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _is_text_file(path: Path) -> bool:
    try:
        path.read_text(encoding="utf-8", errors="strict")
        return True
    except Exception:
        return False


def _unified_diff(path_a: Path, path_b: Path, label_a: str, label_b: str) -> Optional[str]:
    if not _is_text_file(path_a) or not _is_text_file(path_b):
        return None
    a = path_a.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    b = path_b.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=label_a, tofile=label_b, n=3))


def _literal_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    return None


def _python_semantic_findings(path: str, source: str) -> List[str]:
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return []

    findings: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in {"eval", "exec"}:
                findings.append(f"{path}: python dynamic execution via {func_name}()")

            if func_name in {"system", "popen", "run", "Popen", "check_output", "check_call"}:
                findings.append(f"{path}: python subprocess-capable call via {func_name}()")

            if func_name in {"urlopen", "Request", "get", "post", "put"}:
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    literal = _literal_string(arg)
                    if literal and literal.startswith(("http://", "https://")):
                        findings.append(f"{path}: python outbound URL literal {literal}")
                        break

        if isinstance(node, ast.Assign):
            literal = _literal_string(node.value)
            if literal and re.search(r"(token|secret|password|credential)", literal, re.IGNORECASE):
                findings.append(f"{path}: python embedded credential-like string")

    return sorted(set(findings))


def _javascript_semantic_findings(path: str, source: str) -> List[str]:
    findings: List[str] = []
    lowered_path = path.lower()
    lowered_source = source.lower()
    if re.search(r"\b(eval|Function)\s*\(", source):
        findings.append(f"{path}: javascript dynamic execution via eval/Function")
    if re.search(r"\bchild_process\b", source) or re.search(r"\b(execSync|spawnSync|execFileSync|spawn|execFile)\s*\(", source):
        findings.append(f"{path}: javascript subprocess-capable API")
    if re.search(r"https?://", source) and re.search(r"\b(fetch|axios|https?\.request|XMLHttpRequest)\b", source):
        findings.append(f"{path}: javascript outbound network request")
    if re.search(r"\b(Buffer\.from|atob|btoa|fromCharCode)\b", source):
        findings.append(f"{path}: javascript encoded payload primitives")
    if re.search(r"(^|\n)\s*(?:!function|\(function\s*\(|\(\s*\(\s*\)\s*=>|\(\s*async\s*\(\s*\)\s*=>)", source):
        findings.append(f"{path}: javascript module-load execution via IIFE/self-executing payload")
    if re.search(r"\bos\.(?:hostname|userInfo|homedir|networkInterfaces|platform|arch|tmpdir)\s*\(", source) or (
        re.search(r"\brequire\s*\(\s*['\"]os['\"]\s*\)", source)
        and re.search(r"\b(hostname|userInfo|homedir|networkInterfaces|platform|arch|tmpdir)\s*\(", source)
    ):
        findings.append(f"{path}: javascript host fingerprinting via os APIs")
    if re.search(r"\bfs\.(?:readdirSync|readFileSync|statSync|existsSync|opendirSync)\s*\(", source) and re.search(
        r"(\.ssh|\.npmrc|\.yarnrc|\.pnpm|\.env|\.aws|\.config|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|homedir|HOME)",
        source,
        re.IGNORECASE,
    ):
        findings.append(f"{path}: javascript local file enumeration of developer or credential paths")
    if re.search(r"\bprocess\.env\b", source) and re.search(
        r"(TOKEN|SECRET|PASSWORD|KEY|GITHUB|NPM|AWS|GOOGLE|AZURE|SSH|CI)",
        source,
        re.IGNORECASE,
    ):
        findings.append(f"{path}: javascript environment credential harvesting via process.env")
    if re.search(r"\b(zlib|gzip|deflate|JSON\.stringify|Buffer\.from)\b", source) and re.search(
        r"\b(fetch|axios|https?\.request|dns\.|resolveTxt|request|post)\b",
        source,
        re.IGNORECASE,
    ):
        findings.append(f"{path}: javascript payload wrapping or exfiltration staging")
    if re.search(r"createDecipheriv\s*\(\s*['\"]aes-128-gcm|setAuthTag\s*\(|authTagLength\s*:\s*16", source):
        findings.append(f"{path}: javascript AES-GCM encrypted payload loader")
    if re.search(r"createCipheriv\s*\(\s*['\"]aes-256-gcm|publicEncrypt\s*\(|RSA_PKCS1_OAEP_PADDING|oaepHash\s*:\s*['\"]sha256", source):
        findings.append(f"{path}: javascript encrypted credential exfiltration envelope")
    if re.search(r"\b(Bun|bun\s+run|getBunPath|oven-sh/bun|bun-v\d|/tmp/p|tmpdir\(\)|mkdtempSync)\b", source):
        findings.append(f"{path}: javascript Bun runtime or randomized temp payload staging")
    if re.search(r"\bwriteFileSync\s*\([^)]*(?:/tmp/|tmpdir|Math\.random)|\bexecSync\s*\([^)]*bun\s+run|unlinkSync\s*\(", source):
        findings.append(f"{path}: javascript writes, executes, and removes staged payload")
    if re.search(r"\bgh\s+auth\s+token\b|execSync\s*\([^)]*gh auth token", source):
        findings.append(f"{path}: javascript GitHub CLI token harvesting")
    if re.search(r"\bGITHUB_ACTIONS\b|\bRUNNER_OS\b|\bACTIONS_RUNTIME_TOKEN\b|\bACTIONS_ID_TOKEN_REQUEST_TOKEN\b|\bsudo\s+python3\b", source):
        findings.append(f"{path}: javascript GitHub Actions runner secret harvesting")
    if re.search(r"gh\[op\]_|npm_|ghs_\\d|ghs_\[|ghp_|gho_|ghs_", source):
        findings.append(f"{path}: javascript GitHub/npm token pattern harvesting")
    if re.search(r"api\.github\.com", source) and re.search(r"\b(createBlob|createTree|createCommit|/git/blobs|/git/trees|contents|repos)\b", source):
        findings.append(f"{path}: javascript GitHub dead-drop or repository write exfiltration")
    if re.search(r"\b(__IS_DAEMON|detached\s*:\s*true|child\.unref\s*\(|\.unref\s*\(\))", source):
        findings.append(f"{path}: javascript daemonization or background persistence")
    if re.search(r"Intl\.DateTimeFormat|LC_ALL|LC_MESSAGES|LANGUAGE|process\.env\[['\"]LANG", source) and "ru" in lowered_source:
        findings.append(f"{path}: javascript locale-based execution avoidance")
    if re.search(
        r"(~?/\.aws/credentials|~?/\.azure/accessTokens\.json|~?/\.config/gcloud|~?/\.docker/config\.json|~?/\.kube/config|"
        r"/var/run/secrets/kubernetes\.io/serviceaccount/token|~?/\.npmrc|~?/\.pypirc|~?/\.netrc|~?/\.ssh/id_|~?/\.git-credentials|"
        r"wallet\.dat|\.ethereum/keystore)",
        source,
        re.IGNORECASE,
    ):
        findings.append(f"{path}: javascript developer, cloud, registry, and wallet credential file targeting")
    if any(marker.lower() in lowered_source for marker in (
        "f4abccab2",
        "thebeautifulmarchoftime",
        "ifyouinvalidatethistokenitwillnukethecomputeroftheowner",
        "miasma: the spreading blight",
        "tmp.0987654321.lock",
    )):
        findings.append(f"{path}: Mini Shai-Hulud payload marker string")
    if lowered_path.endswith("node-ipc.cjs") and any(
        token in source
        for token in ("process.env", "Buffer.from", "Function(", "eval(", "networkInterfaces", ".npmrc", ".ssh")
    ):
        findings.append(f"{path}: node-ipc CommonJS bundle contains high-risk appended payload indicators")
    return sorted(set(findings))


def _package_json_policy_findings(path: str, source: str) -> List[str]:
    try:
        data = json.loads(source)
    except Exception:
        return []

    findings: List[str] = []
    scripts = data.get("scripts", {})
    lifecycle_commands: List[str] = []
    if isinstance(scripts, dict):
        for hook, command in scripts.items():
            if not isinstance(command, str):
                continue
            if hook in {"preinstall", "install", "postinstall", "prepare"}:
                lifecycle_commands.append(command)
                findings.append(f"{path}: npm lifecycle hook present ({hook}: {command})")
                if re.search(r"\b(?:node|bun)\s+\.?/?(?:index|setup|install|preinstall|postinstall)\.(?:js|mjs|cjs)\b", command, re.IGNORECASE):
                    findings.append(f"{path}: npm lifecycle hook executes package entrypoint ({hook}: {command})")
            if re.search(r"\b(curl|wget|powershell|node\s+-e|python\s+-c|bash\s+-c|sh\s+-c|npx|npm\s+exec)\b", command, re.IGNORECASE):
                findings.append(f"{path}: npm lifecycle hook runs remote or inline code ({hook})")
            if re.search(r"https?://", command, re.IGNORECASE):
                findings.append(f"{path}: npm lifecycle hook reaches remote URL ({hook})")

    main_entry = str(data.get("main") or "")
    module_entry = str(data.get("module") or "")
    if (
        main_entry in {"index.js", "./index.js", "index.cjs", "./index.cjs"}
        and module_entry
        and module_entry != main_entry
        and any(main_entry.removeprefix("./") in command for command in lifecycle_commands)
    ):
        findings.append(f"{path}: npm CommonJS entrypoint differs from module entrypoint ({main_entry} vs {module_entry})")

    if data.get("bin"):
        findings.append(f"{path}: npm executable entrypoint declared via bin")

    for dep_group in ("dependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(dep_group, {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                if not isinstance(version, str):
                    continue
                if re.search(r"^(git\+|https?://|github:|file:)", version, re.IGNORECASE):
                    findings.append(f"{path}: npm dependency uses non-registry source ({name})")

    return sorted(set(findings))


def _setup_py_policy_findings(path: str, source: str) -> List[str]:
    findings: List[str] = []
    if re.search(r"\bsetup\s*\(", source):
        if re.search(r"\bcmdclass\s*=", source):
            findings.append(f"{path}: setup.py overrides cmdclass")
        if re.search(r"\b(entry_points|scripts)\s*=", source):
            findings.append(f"{path}: setup.py defines executable entrypoints")
        if re.search(r"\b(subprocess|os\.system|popen|urllib\.request|requests\.)\b", source):
            findings.append(f"{path}: setup.py performs execution or network-capable actions")
    return sorted(set(findings))


def _pyproject_policy_findings(path: str, source: str) -> List[str]:
    try:
        data = tomllib.loads(source)
    except Exception:
        return []

    findings: List[str] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        scripts = project.get("scripts")
        if isinstance(scripts, dict) and scripts:
            findings.append(f"{path}: pyproject declares console scripts")
        dependencies = project.get("dependencies")
        if isinstance(dependencies, list):
            for dependency in dependencies:
                if isinstance(dependency, str) and ("@" in dependency and "http" in dependency):
                    findings.append(f"{path}: pyproject dependency references direct URL")

    build_system = data.get("build-system", {})
    if isinstance(build_system, dict):
        backend = build_system.get("build-backend")
        if isinstance(backend, str) and backend and backend not in COMMON_BUILD_BACKENDS:
            findings.append(f"{path}: pyproject custom build backend {backend}")

    tool = data.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            scripts = poetry.get("scripts")
            if isinstance(scripts, dict) and scripts:
                findings.append(f"{path}: pyproject poetry scripts declared")

    return sorted(set(findings))


def _rust_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith("build.rs"):
        findings.append(f"{path}: crates build.rs install-time execution risk")
        if re.search(r"\b(Command::new|std::process|reqwest|ureq|curl|wget)\b", source):
            findings.append(f"{path}: crates build.rs process or network-capable behavior")
        if re.search(r"\b(env::var|std::env|CARGO_|GITHUB_TOKEN|AWS_|NPM_TOKEN)\b", source):
            findings.append(f"{path}: crates build.rs environment credential access")
    if re.search(r"\bproc_macro\b", source) and re.search(r"\b(Command::new|std::fs|std::env|reqwest)\b", source):
        findings.append(f"{path}: crates proc-macro contains filesystem, process, env, or network behavior")
    return sorted(set(findings))


def _chrome_extension_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith("manifest.json"):
        try:
            data = json.loads(source)
        except Exception:
            return []
        permissions = data.get("permissions", []) or []
        host_permissions = data.get("host_permissions", []) or []
        permissions_text = " ".join(str(item) for item in [*permissions, *host_permissions])
        if any(item in permissions for item in ("tabs", "cookies", "webRequest", "scripting", "nativeMessaging")):
            findings.append(f"{path}: chrome extension high-risk permissions {permissions}")
        if "<all_urls>" in permissions_text or "*://*/*" in permissions_text:
            findings.append(f"{path}: chrome extension broad host access")
        if data.get("externally_connectable"):
            findings.append(f"{path}: chrome extension externally_connectable trust boundary")
        content_scripts = data.get("content_scripts", [])
        if isinstance(content_scripts, list) and any("<all_urls>" in str(script) or "*://*/*" in str(script) for script in content_scripts):
            findings.append(f"{path}: chrome extension broad content-script injection")
    elif lowered.endswith((".js", ".mjs", ".cjs")) and re.search(r"\bchrome\.(?:storage|cookies|tabs|scripting|runtime)\b", source):
        if re.search(r"\b(eval|Function|fetch|XMLHttpRequest|sendMessage)\b", source):
            findings.append(f"{path}: chrome extension remote code or sensitive API behavior")
    return sorted(set(findings))


def _packagist_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith("composer.json"):
        try:
            data = json.loads(source)
        except Exception:
            return []
        autoload = data.get("autoload", {})
        if isinstance(autoload, dict):
            autoload_files = autoload.get("files", [])
            if isinstance(autoload_files, str):
                autoload_files = [autoload_files]
            if isinstance(autoload_files, list):
                for item in autoload_files:
                    if not isinstance(item, str) or not item.strip():
                        continue
                    findings.append(f"{path}: composer autoload.files executes PHP file {item}")
                    if re.search(r"(helper|bootstrap|loader|locale|temp|tmp|download|payload)", item, re.IGNORECASE):
                        findings.append(f"{path}: composer autoload.files references high-risk bootstrap/helper path {item}")
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for hook, command in scripts.items():
                commands = command if isinstance(command, list) else [command]
                if hook in {"pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd"}:
                    findings.append(f"{path}: composer install/update lifecycle hook {hook}")
                if any(isinstance(cmd, str) and re.search(r"\b(curl|wget|php\s+-r|bash|sh|powershell|eval)\b|https?://", cmd, re.IGNORECASE) for cmd in commands):
                    findings.append(f"{path}: composer lifecycle hook executes remote or inline code ({hook})")
    elif lowered.endswith(".php"):
        if re.search(r"\b(eval|assert|base64_decode|gzinflate|str_rot13|preg_replace)\s*\(", source, re.IGNORECASE):
            findings.append(f"{path}: packagist php dynamic execution or obfuscation behavior")
        if re.search(r"\b(exec|shell_exec|system|proc_open|passthru|popen)\s*\(", source, re.IGNORECASE):
            findings.append(f"{path}: packagist php shell or process execution behavior")
        if re.search(r"\b(curl_exec|file_get_contents|stream_context_create)\s*\(|https?://", source, re.IGNORECASE):
            findings.append(f"{path}: packagist php outbound network or payload retrieval behavior")
        if re.search(r"verify_peer['\"]?\s*=>\s*false|verify_peer_name['\"]?\s*=>\s*false|CURLOPT_SSL_VERIFY(?:PEER|HOST)\b", source, re.IGNORECASE):
            findings.append(f"{path}: packagist php disables TLS verification")
        if re.search(r"\b(sys_get_temp_dir|/tmp/|\.laravel_locale|tempnam|DebugChromium\.exe|\.vbs|cscript)\b", source, re.IGNORECASE):
            findings.append(f"{path}: packagist php temp staging or background payload execution indicator")
        if re.search(r"169\.254\.169\.254|/proc/[^\\s'\"]*/environ|/var/run/secrets", source, re.IGNORECASE):
            findings.append(f"{path}: packagist php cloud, process, or Kubernetes secret discovery")
        if re.search(r"(\.env|\.ssh|id_rsa|\.git-credentials|auth\.json|\.docker/config\.json|\.vault-token|kubeconfig|GITHUB_TOKEN|AWS_|AZURE_|GOOGLE_|CI_JOB_TOKEN)", source, re.IGNORECASE):
            findings.append(f"{path}: packagist php developer, cloud, or CI credential file discovery")
    return sorted(set(findings))


def _go_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith(".go"):
        if re.search(r"\bfunc\s+init\s*\(", source) and re.search(r"\b(os/exec|exec\.Command|net/http|http\.Post|os\.UserHomeDir|os\.Environ|os\.Getenv)\b", source):
            findings.append(f"{path}: go module init() contains process, network, home, or env behavior")
        if re.search(r"\b(exec\.Command|http\.Post|http\.Get|os\.Environ|os\.Getenv|UserHomeDir)\b", source):
            findings.append(f"{path}: go module process, network, or credential-environment access")
    elif lowered.endswith("go.mod") and re.search(r"\breplace\s+.+=>\s+(?:https?://|\.\./|/)", source):
        findings.append(f"{path}: go module replace directive points outside normal module proxy")
    return sorted(set(findings))


def _huggingface_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith((".bin", ".pt", ".pth", ".pkl", ".pickle", ".safetensors")):
        if not lowered.endswith(".safetensors"):
            findings.append(f"{path}: hugging face model artifact may require unsafe pickle-style loading")
    if lowered.endswith(("config.json", "model_index.json", "README.md".lower(), "readme.md")):
        if re.search(r"\btrust_remote_code\s*[:=]\s*true\b|custom code|pickle|unsafe deserialization", source, re.IGNORECASE):
            findings.append(f"{path}: hugging face metadata references trust_remote_code or unsafe loading")
    if lowered.endswith((".py", ".sh")) and re.search(r"\b(subprocess|os\.system|eval|exec|requests\.|urllib|curl|wget|HF_TOKEN|HUGGINGFACE_TOKEN)\b", source):
        findings.append(f"{path}: hugging face repository script has execution, network, or token access")
    return sorted(set(findings))


def _maven_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith("pom.xml"):
        if re.search(r"<plugin>|exec-maven-plugin|maven-antrun-plugin|gmaven|build-helper", source, re.IGNORECASE):
            findings.append(f"{path}: maven build plugin can execute lifecycle code")
        if re.search(r"<url>https?://|<systemPath>|<scope>system</scope>", source, re.IGNORECASE):
            findings.append(f"{path}: maven pom references remote/system dependency source")
    if lowered.endswith((".java", ".kt", ".scala", ".class.txt")) and re.search(r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|System\.getenv|HttpURLConnection|java\.net\.http|Files\.walk)\b", source):
        findings.append(f"{path}: maven artifact source has process, env, network, or file enumeration behavior")
    return sorted(set(findings))


def _nuget_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith(".nuspec") and re.search(r"<files|tools/|build/", source, re.IGNORECASE):
        findings.append(f"{path}: nuget package includes tools/build files that may execute during install/build")
    if lowered.endswith((".ps1", ".targets", ".props")) and re.search(r"\b(Invoke-WebRequest|iwr|DownloadString|Start-Process|powershell|cmd\.exe|System\.Environment|Get-ChildItem)\b", source, re.IGNORECASE):
        findings.append(f"{path}: nuget install/build script has download, process, env, or file enumeration behavior")
    return sorted(set(findings))


def _open_vsx_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith("package.json"):
        try:
            data = json.loads(source)
        except Exception:
            return []
        activation = data.get("activationEvents", []) or []
        scripts = data.get("scripts", {}) or {}
        if any(str(item) == "*" or str(item).startswith("onStartupFinished") or str(item).startswith("workspaceContains") for item in activation):
            findings.append(f"{path}: open vsx extension broad activation event")
        if any(hook in scripts for hook in ("postinstall", "preinstall", "install")):
            findings.append(f"{path}: open vsx extension npm lifecycle hook")
    elif lowered.endswith((".js", ".ts", ".mjs", ".cjs")) and re.search(r"\bvscode\.workspace|process\.env|child_process|eval\s*\(|Function\s*\(|fetch\s*\(", source):
        findings.append(f"{path}: open vsx extension workspace, credential, process, or remote code behavior")
        if re.search(r"\b(child_process|exec|spawn|execFile|execSync|spawnSync)\b", source):
            findings.append(f"{path}: open vsx extension child_process execution capability")
        if re.search(r"\b(process\.env|GITHUB_TOKEN|NPM_TOKEN|AWS_|\.npmrc|\.ssh|1Password|op\s+)\b", source, re.IGNORECASE):
            findings.append(f"{path}: open vsx extension credential harvesting indicators")
        if re.search(r"\b(fetch|https?\.request|dns\.|resolveTxt|github\.com|api\.github\.com)\b", source, re.IGNORECASE):
            findings.append(f"{path}: open vsx extension exfiltration or GitHub dead-drop behavior")
    return sorted(set(findings))


def _github_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if not lowered.endswith((".json", ".txt", ".log", ".ndjson", ".md")):
        return findings
    if re.search(r"\b(ghp_|gho_|ghs_|GITHUB_TOKEN|github workflow token|personal access token|PAT)\b", source, re.IGNORECASE):
        findings.append(f"{path}: github token exposure or suspicious token use")
    if re.search(r"\b(api\.github\.com/repos|/zipball|/tarball|git\s+clone|downloaded repositories|mass repo|repo enumeration)\b", source, re.IGNORECASE):
        findings.append(f"{path}: github repository enumeration or code download behavior")
    if re.search(r"\b(orphan(?:ed)? commit|unreachable commit|dangling commit|unsigned commit|refs/heads|git data api|create blob|create tree)\b", source, re.IGNORECASE):
        findings.append(f"{path}: github orphan commit or Git Data API abuse indicator")
    if re.search(r"\b(repository secrets|actions secrets|workflow tokens|OIDC|ACTIONS_ID_TOKEN_REQUEST_TOKEN)\b", source, re.IGNORECASE):
        findings.append(f"{path}: github actions or CI/CD secret exposure indicator")
    return sorted(set(findings))


def _rubygems_policy_findings(path: str, source: str) -> List[str]:
    lowered = path.lower()
    findings: List[str] = []
    if lowered.endswith(("extconf.rb", "rakefile")) or lowered.endswith(".gemspec"):
        if re.search(r"\b(system|exec|spawn|Open3|Net::HTTP|URI\.open|eval|`[^`]+`|ENV\[)\b", source):
            findings.append(f"{path}: rubygems install/build metadata has process, network, eval, or env behavior")
    elif lowered.endswith(".rb") and re.search(r"\b(eval|system|exec|spawn|Open3|Net::HTTP|URI\.open|ENV\[|File\.read|Dir\.glob)\b", source):
        findings.append(f"{path}: rubygems ruby source has dynamic execution, network, env, or file access")
    return sorted(set(findings))


def _ecosystem_policy_findings(path: str, source: str, ecosystem: Optional[str] = None) -> List[str]:
    if ecosystem:
        eco = canonical_ecosystem(ecosystem)
        lowered = path.lower()
        if eco == "npm":
            findings: List[str] = []
            if lowered.endswith("package.json"):
                findings.extend(_package_json_policy_findings(path, source))
            if lowered.endswith((".js", ".mjs", ".cjs", ".ts")):
                findings.extend(_javascript_semantic_findings(path, source))
            return sorted(set(findings))
        if eco == "pypi":
            findings = []
            if lowered.endswith("setup.py"):
                findings.extend(_setup_py_policy_findings(path, source))
            if lowered.endswith("pyproject.toml"):
                findings.extend(_pyproject_policy_findings(path, source))
            if lowered.endswith(".py"):
                findings.extend(_python_semantic_findings(path, source))
            return sorted(set(findings))
        ecosystem_rules = {
            "crates": _rust_policy_findings,
            "chrome-web-store": _chrome_extension_policy_findings,
            "packagist": _packagist_policy_findings,
            "go": _go_policy_findings,
            "huggingface": _huggingface_policy_findings,
            "maven": _maven_policy_findings,
            "nuget": _nuget_policy_findings,
            "open-vsx": _open_vsx_policy_findings,
            "github": _github_policy_findings,
            "rubygems": _rubygems_policy_findings,
        }
        rule = ecosystem_rules.get(eco)
        return sorted(set(rule(path, source) if rule else []))
    findings: List[str] = []
    findings.extend(_rust_policy_findings(path, source))
    findings.extend(_chrome_extension_policy_findings(path, source))
    findings.extend(_packagist_policy_findings(path, source))
    findings.extend(_go_policy_findings(path, source))
    findings.extend(_huggingface_policy_findings(path, source))
    findings.extend(_maven_policy_findings(path, source))
    findings.extend(_nuget_policy_findings(path, source))
    findings.extend(_open_vsx_policy_findings(path, source))
    findings.extend(_github_policy_findings(path, source))
    findings.extend(_rubygems_policy_findings(path, source))
    return sorted(set(findings))


def analyze_ecosystem_files(ecosystem: str, files: Dict[str, str]) -> Dict[str, Any]:
    canonical = canonical_ecosystem(ecosystem)
    findings: List[str] = []
    manifest_files: List[str] = []
    suspicious_files: List[str] = []
    for path, source in sorted(files.items()):
        file_findings = _ecosystem_policy_findings(path, source, canonical)
        if file_findings:
            findings.extend(file_findings)
            suspicious_files.append(path)
        if path.lower().endswith((
            "package.json",
            "manifest.json",
            "composer.json",
            "go.mod",
            "pom.xml",
            ".nuspec",
            ".gemspec",
            "cargo.toml",
            "readme.md",
            "config.json",
        )):
            manifest_files.append(path)
    report = "\n".join(["## Ecosystem Findings", "", *[f"- {finding}" for finding in sorted(set(findings))]])
    explanation = explain_verdict(report, ecosystem=canonical, package="fixture", policy=load_policy())
    return {
        "ecosystem": canonical,
        "manifest_files": sorted(set(manifest_files)),
        "suspicious_files": sorted(set(suspicious_files)),
        "matched_rules": explanation.get("matched_rules", []),
        "findings": sorted(set(findings)),
        "score": explanation.get("score", 0),
        "verdict": explanation.get("verdict", "benign"),
        "confidence": "medium" if findings else "low",
        "severity": "high" if explanation.get("verdict") == "malicious" else "info",
        "fetch_status": "not_requested",
        "artifact_status": "local_fixture",
        "limitations": ecosystem_capabilities(canonical).get("limitations", []),
    }


def _added_text_scope(report: str) -> str:
    added_lines: List[str] = []
    for line in report.splitlines():
        if line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added_lines.append(line[1:])
    scoped = "\n".join(added_lines).strip()
    if scoped:
        return scoped
    if "## Semantic Findings" in report or "## Artifact Divergence" in report:
        return ""
    return report


def _normalized_artifact_path(path: str) -> str:
    cleaned = path.strip().strip("`").replace("\\", "/").lower()
    cleaned = re.sub(r"/+", "/", cleaned)
    cleaned = re.sub(r"^[^/]+\.dist-info/", "", cleaned)
    return cleaned


def _artifact_path_is_benign(path: str) -> bool:
    normalized = _normalized_artifact_path(path)
    if normalized in {"package.json", "manifest.json", "composer.json", "go.mod", "pom.xml", "pyproject.toml", "setup.py", "build.rs"}:
        return False
    if normalized.endswith((".nuspec", ".gemspec", "extconf.rb")):
        return False
    if normalized.startswith(BENIGN_ARTIFACT_PATH_PREFIXES):
        return True
    return normalized.endswith(BENIGN_ARTIFACT_PATH_SUFFIXES)


def _filter_semantic_findings(findings: List[str]) -> List[str]:
    """
    Enhanced filtering to reduce false positives from semantic analysis.
    Filters out findings from test files, docs, and benign contexts.
    """
    filtered: List[str] = []
    for finding in findings:
        path_part, _, detail = finding.partition(":")
        detail = detail.strip()
        path_lower = path_part.lower()

        is_manifest_policy_finding = (
            path_lower.endswith("package.json")
            or path_lower.endswith("pyproject.toml")
            or path_lower.endswith("setup.py")
        )
        
        # Skip test files entirely
        if any(pattern in path_lower for pattern in [
            "tests/", "test/", "_test.", "test_.", 
            "spec/", "specs/", "__tests__/", 
            ".test.", ".spec.", "_spec.", "spec_",
            "conftest.py", "pytest.ini", "tox.ini",
            "test_requirements", "dev-requirements", "requirements-dev",
            "/testing/", "/testfixtures/", "/test_data/",
        ]):
            continue
            
        # Skip documentation
        if any(pattern in path_lower for pattern in [
            "docs/", "doc/", "documentation/",
            "readme", "changelog", "contributing", "license", "authors",
            ".md", ".rst", ".txt", ".html", ".htm",
            "/site/", "/guide/", "/tutorial/", "/manual/",
            "sphinx", "mkdocs", "docusaurus", "vuepress", "gitbook",
        ]):
            continue
            
        # Skip examples
        if any(pattern in path_lower for pattern in [
            "examples/", "example/", "demo/", "demos/",
            "samples/", "sample/", "tutorials/", "snippets/",
            "playground/", "showcase/",
        ]):
            continue
            
        # Skip CI/config files
        if not is_manifest_policy_finding and any(pattern in path_lower for pattern in [
            ".github/", ".gitlab/", ".circleci/", ".travis.yml", ".appveyor.yml",
            "azure-pipelines", "jenkins", ".buildkite/",
            "Makefile", "makefile", "GNUmakefile",
            ".editorconfig", ".gitignore", ".gitattributes",
            ".dockerignore", "docker-compose", "Dockerfile",
            ".pre-commit", ".husky/", ".lintstagedrc",
            ".flake8", ".pylintrc", "setup.cfg",
            "requirements", "constraints", "Pipfile", "poetry.lock",
        ]):
            continue
        
        # Skip type stubs
        if path_lower.endswith(".pyi") or "/types/" in path_lower or "/stubs/" in path_lower:
            continue
            
        # Skip vendored/bundled dependencies
        if any(pattern in path_lower for pattern in [
            "vendor/", "vendored/", "third_party/", "thirdparty/",
            "deps/", "dependencies/", "extern/", "external/",
            ".bundle", "_vendor", "_bundled",
        ]):
            continue
        
        # Existing filters
        if _artifact_path_is_benign(path_part):
            continue
            
        # Filter npm lifecycle hooks that are standard
        if detail.startswith("npm lifecycle hook present"):
            # Only flag if it's actually suspicious (downloads code, etc.)
            if any(hook in detail for hook in ("prepublishOnly", "prepack", "prepare", "prepublish")):
                continue
            # Check if the hook command is actually suspicious
            if not any(cmd in detail for cmd in ("curl", "wget", "powershell", "eval", "exec", "fetch", "node ", "bun ")):
                continue
                
        # Filter custom build backends that are common
        backend_match = re.search(r"custom build backend\s+([^\s]+)", detail)
        if backend_match and backend_match.group(1) in COMMON_BUILD_BACKENDS:
            continue
            
        # Filter benign setup.py patterns
        if "setup.py defines executable entrypoints" in detail:
            # Entrypoints are normal for CLI tools
            continue
            
        # Filter pyproject.toml console scripts (normal for CLI tools)
        if "pyproject declares console scripts" in detail:
            continue
            
        # Filter npm bin declarations (normal for CLI tools)
        if "npm executable entrypoint declared via bin" in detail:
            continue
        
        filtered.append(finding)
    return filtered


def _artifact_divergence_candidates(report: str) -> tuple[List[str], List[str]]:
    suspicious_wheel: List[str] = []
    suspicious_sdist: List[str] = []
    current: Optional[str] = None
    for raw_line in report.splitlines():
        line = raw_line.strip()
        if line == "- suspicious_wheel_only_files:":
            current = "wheel"
            continue
        if line == "- suspicious_sdist_only_files:":
            current = "sdist"
            continue
        if line.startswith("- ") and not line.startswith("- `"):
            current = None
            continue
        if current and line.startswith("- `") and line.endswith("`"):
            path = line[3:-1]
            if _artifact_path_is_benign(path):
                continue
            if current == "wheel":
                suspicious_wheel.append(path)
            else:
                suspicious_sdist.append(path)
    return suspicious_wheel, suspicious_sdist


def _semantic_findings_for_file(path: str, file_path: Path) -> List[str]:
    if not _is_text_file(file_path):
        return []
    source = file_path.read_text(encoding="utf-8", errors="replace")
    lowered = path.lower()
    findings: List[str] = []
    findings.extend(_ecosystem_policy_findings(path, source))
    if lowered.endswith(".py"):
        findings.extend(_python_semantic_findings(path, source))
    if lowered.endswith("setup.py"):
        findings.extend(_setup_py_policy_findings(path, source))
    elif lowered.endswith((".js", ".mjs", ".cjs", ".ts")):
        findings.extend(_javascript_semantic_findings(path, source))
    elif lowered.endswith("package.json"):
        findings.extend(_package_json_policy_findings(path, source))
    elif lowered.endswith("pyproject.toml"):
        findings.extend(_pyproject_policy_findings(path, source))
    return sorted(set(findings))


def _added_lines_fragment(old_path: Path, new_path: Path) -> str:
    if not _is_text_file(old_path) or not _is_text_file(new_path):
        return ""
    old_lines = old_path.read_text(encoding="utf-8", errors="replace").splitlines()
    new_lines = new_path.read_text(encoding="utf-8", errors="replace").splitlines()
    added: List[str] = []
    for line in difflib.ndiff(old_lines, new_lines):
        if line.startswith("+ "):
            added.append(line[2:])
    return "\n".join(added)


def _semantic_findings_for_changed_file(path: str, old_path: Path, new_path: Path) -> List[str]:
    lowered = path.lower()
    fragment = _added_lines_fragment(old_path, new_path)
    if not fragment.strip():
        return []

    fragment_lines = fragment.splitlines() or [fragment]
    max_line_length = max((len(line) for line in fragment_lines), default=0)
    if lowered.endswith((".js", ".mjs", ".cjs")) and len(fragment_lines) <= 3 and max_line_length > 2000:
        return []

    findings: List[str] = []
    if lowered.endswith(".py"):
        findings.extend(_python_semantic_findings(path, fragment))
        if lowered.endswith("setup.py") and re.search(r"\b(cmdclass|entry_points|scripts|subprocess|os\.system|popen|urllib\.request|requests\.)\b", fragment):
            findings.extend(_setup_py_policy_findings(path, fragment))
    elif lowered.endswith((".js", ".mjs", ".cjs", ".ts")):
        findings.extend(_javascript_semantic_findings(path, fragment))
    elif lowered.endswith("package.json"):
        if re.search(r'"(preinstall|install|postinstall|prepare|prepack|prepublishOnly|bin|dependencies|optionalDependencies|peerDependencies)"', fragment):
            findings.extend(_package_json_policy_findings(path, new_path.read_text(encoding="utf-8", errors="replace")))
    elif lowered.endswith("pyproject.toml"):
        if re.search(r"(build-backend|scripts|dependencies)", fragment):
            findings.extend(_pyproject_policy_findings(path, new_path.read_text(encoding="utf-8", errors="replace")))
    return sorted(set(findings))


def _semantic_summary_section(
    files_v1: Dict[str, Path],
    files_v2: Dict[str, Path],
    changed: List[str],
    added: List[str],
) -> List[str]:
    findings: List[str] = []
    for path in added[:200]:
        if path in files_v2:
            findings.extend(_semantic_findings_for_file(path, files_v2[path]))
    for path in changed[:200]:
        if path in files_v1 and path in files_v2:
            findings.extend(_semantic_findings_for_changed_file(path, files_v1[path], files_v2[path]))
    findings = sorted(set(findings))
    
    # Apply enhanced filtering
    findings = _filter_semantic_findings(findings)
    
    if not findings:
        return []
    lines = ["## Semantic Findings", ""]
    lines.extend(f"- {finding}" for finding in findings[:50])
    lines.append("")
    return lines


def _generate_report(package: str, v1: str, v2: str, files_v1: Dict[str, Path], files_v2: Dict[str, Path]) -> str:
    keys_v1 = set(files_v1)
    keys_v2 = set(files_v2)
    added = sorted(keys_v2 - keys_v1)
    deleted = sorted(keys_v1 - keys_v2)
    common = sorted(keys_v1 & keys_v2)
    changed = [key for key in common if _file_hash(files_v1[key]) != _file_hash(files_v2[key])]
    unchanged = [key for key in common if key not in changed]

    lines = [
        f"# Diff Report: {package} {v1} -> {v2}",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Files in {v1} | {len(files_v1)} |",
        f"| Files in {v2} | {len(files_v2)} |",
        f"| Added | {len(added)} |",
        f"| Deleted | {len(deleted)} |",
        f"| Changed | {len(changed)} |",
        f"| Unchanged | {len(unchanged)} |",
        "",
    ]

    if added:
        lines.extend(["## Added Files", ""])
        lines.extend(f"- `{name}`" for name in added[:200])
        lines.append("")

    if deleted:
        lines.extend(["## Deleted Files", ""])
        lines.extend(f"- `{name}`" for name in deleted[:200])
        lines.append("")

    if changed:
        lines.extend(["## Changed Files", ""])
        for name in changed[:100]:
            lines.extend([f"### `{name}`", ""])
            diff = _unified_diff(files_v1[name], files_v2[name], f"{v1}/{name}", f"{v2}/{name}")
            if diff is None:
                lines.append("*Binary file changed.*")
            elif not diff:
                lines.append("*Whitespace-only or encoding difference.*")
            else:
                lines.extend(["```diff", diff.rstrip(), "```"])
            lines.append("")
    semantic_lines = _semantic_summary_section(files_v1, files_v2, changed, added)
    if semantic_lines:
        lines.extend(semantic_lines)
    return "\n".join(lines)


def _build_artifact_report(
    package: str,
    artifact_name: str,
    v1: str,
    v2: str,
    files_v1: Dict[str, Path],
    files_v2: Dict[str, Path],
) -> str:
    return "\n".join(
        [
            f"## Artifact: {artifact_name}",
            "",
            _generate_report(package, v1, v2, files_v1, files_v2),
            "",
        ]
    )


def _summarize_artifact_mismatch(artifact_reports: Dict[str, Dict[str, Any]]) -> List[str]:
    if "bdist_wheel" not in artifact_reports or "sdist" not in artifact_reports:
        return []

    wheel_files = set(artifact_reports["bdist_wheel"]["files_new"])
    sdist_files = set(artifact_reports["sdist"]["files_new"])

    def _normalize_runtime_path(path: str) -> Optional[str]:
        normalized = path.replace("\\", "/")
        if "/dist-info/" in normalized or normalized.endswith(".dist-info") or normalized.startswith((".github/", "docs/", "doc/", "tests/", "test/", "bench/", "examples/", "example/")):
            return None
        if normalized.startswith("src/"):
            normalized = normalized[4:]
        if normalized in {"setup.py", "pyproject.toml", "PKG-INFO"}:
            return None
        return normalized

    normalized_wheel = {item for item in (_normalize_runtime_path(path) for path in wheel_files) if item}
    normalized_sdist = {item for item in (_normalize_runtime_path(path) for path in sdist_files) if item}

    wheel_only = sorted(normalized_wheel - normalized_sdist)
    sdist_only = sorted(normalized_sdist - normalized_wheel)

    suspicious_wheel_only = [
        path for path in wheel_only
        if path.endswith((".py", ".so", ".dll", ".dylib", ".pyd", ".js", ".ts", ".sh", ".ps1", ".bat"))
    ]
    suspicious_sdist_only = [
        path for path in sdist_only
        if path.endswith((".py", ".so", ".dll", ".dylib", ".pyd", ".js", ".ts", ".sh", ".ps1", ".bat"))
    ]

    lines: List[str] = []
    if suspicious_wheel_only or suspicious_sdist_only:
        lines.extend(
            [
                "## Artifact Divergence",
                "",
                f"- wheel_only_count={len(wheel_only)}",
                f"- sdist_only_count={len(sdist_only)}",
            ]
        )
        if suspicious_wheel_only:
            lines.append("- suspicious_wheel_only_files:")
            lines.extend(f" - `{path}`" for path in suspicious_wheel_only[:25])
        if suspicious_sdist_only:
            lines.append("- suspicious_sdist_only_files:")
            lines.extend(f" - `{path}`" for path in suspicious_sdist_only[:25])
        lines.append("")
    return lines


def _registry_package_path(ecosystem: str, package: str) -> str:
    if ecosystem == "go":
        return urllib.parse.quote(package, safe="/")
    if ecosystem == "maven":
        group, artifact = package.split(":", 1)
        return f"{group.replace('.', '/')}/{artifact}"
    return urllib.parse.quote(package, safe="/")


def _version_rows_from_metadata(ecosystem: str, package: str, metadata: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if ecosystem == "crates":
        for item in metadata.get("versions", []) or []:
            version = str(item.get("num") or "")
            if not version:
                continue
            rows.append({
                "version": version,
                "published_at": item.get("created_at"),
                "artifact_url": f"https://crates.io/api/v1/crates/{urllib.parse.quote(package)}/{urllib.parse.quote(version)}/download",
                "artifact_name": f"{package}-{version}.crate",
            })
    elif ecosystem == "packagist":
        packages = metadata.get("packages", {}) or {}
        versions = packages.get(package) or packages.get(package.lower()) or []
        for item in versions:
            version = str(item.get("version") or item.get("version_normalized") or "")
            dist = item.get("dist") or {}
            source = item.get("source") or {}
            url = dist.get("url")
            if version and url:
                rows.append({
                    "version": version,
                    "published_at": item.get("time"),
                    "artifact_url": url,
                    "artifact_name": Path(urllib.parse.urlparse(url).path).name or f"{package.replace('/', '-')}-{version}.zip",
                    "dist_reference": dist.get("reference"),
                    "dist_type": dist.get("type"),
                    "source_url": source.get("url"),
                    "source_reference": source.get("reference"),
                    "source_type": source.get("type"),
                })
    elif ecosystem == "go":
        for item in metadata.get("versions", []) or []:
            version = str(item.get("version") or "")
            if not version:
                continue
            encoded = _registry_package_path("go", package)
            rows.append({
                "version": version,
                "published_at": item.get("published_at"),
                "artifact_url": f"https://proxy.golang.org/{encoded}/@v/{urllib.parse.quote(version)}.zip",
                "artifact_name": f"{package.replace('/', '_')}@{version}.zip",
            })
    elif ecosystem == "huggingface":
        revisions = metadata.get("revisions") or metadata.get("tags") or []
        if not revisions:
            revisions = [{"version": str(metadata.get("sha") or metadata.get("revision") or "main"), "published_at": metadata.get("lastModified")}]
        for item in revisions:
            version = str(item.get("version") or item.get("name") or item.get("ref") or item.get("sha") or "main")
            rows.append({
                "version": version,
                "published_at": item.get("published_at") or item.get("lastModified") or metadata.get("lastModified"),
                "artifact_url": f"hf://{package}@{version}",
                "artifact_name": f"{package.replace('/', '_')}@{version}.metadata",
            })
    elif ecosystem == "maven":
        for item in metadata.get("versions", []) or []:
            version = str(item.get("version") or "")
            if not version:
                continue
            group_path = _registry_package_path("maven", package)
            _group, artifact = package.split(":", 1)
            base = f"https://repo1.maven.org/maven2/{group_path}/{urllib.parse.quote(version)}"
            rows.append({
                "version": version,
                "published_at": item.get("published_at"),
                "artifact_url": f"{base}/{artifact}-{version}-sources.jar",
                "fallback_artifact_url": f"{base}/{artifact}-{version}.jar",
                "artifact_name": f"{artifact}-{version}-sources.jar",
            })
    elif ecosystem == "nuget":
        lower = package.lower()
        for version in metadata.get("versions", []) or []:
            ver = str(version)
            rows.append({
                "version": ver,
                "published_at": None,
                "artifact_url": f"https://api.nuget.org/v3-flatcontainer/{lower}/{ver.lower()}/{lower}.{ver.lower()}.nupkg",
                "artifact_name": f"{lower}.{ver.lower()}.nupkg",
            })
    elif ecosystem == "open-vsx":
        namespace, extension = package.split(".", 1)
        versions = metadata.get("versions") or []
        if isinstance(versions, dict):
            versions = [dict(value, version=key) if isinstance(value, dict) else {"version": key} for key, value in versions.items()]
        for item in versions:
            version = str(item.get("version") or item.get("name") or "")
            files = item.get("files") or {}
            url = files.get("download") or item.get("downloadUrl") or item.get("download")
            if not url and version:
                url = f"https://open-vsx.org/api/{urllib.parse.quote(namespace)}/{urllib.parse.quote(extension)}/{urllib.parse.quote(version)}/file/{urllib.parse.quote(namespace)}.{urllib.parse.quote(extension)}-{urllib.parse.quote(version)}.vsix"
            if version and url:
                rows.append({
                    "version": version,
                    "published_at": item.get("timestamp") or item.get("publishedTimestamp"),
                    "artifact_url": url,
                    "artifact_name": Path(urllib.parse.urlparse(url).path).name or f"{namespace}.{extension}-{version}.vsix",
                })
    elif ecosystem == "rubygems":
        for item in metadata if isinstance(metadata, list) else []:
            version = str(item.get("number") or item.get("version") or "")
            if version:
                rows.append({
                    "version": version,
                    "published_at": item.get("built_at") or item.get("created_at"),
                    "artifact_url": f"https://rubygems.org/downloads/{urllib.parse.quote(package)}-{urllib.parse.quote(version)}.gem",
                    "artifact_name": f"{package}-{version}.gem",
                })
    return rows


def _fetch_ecosystem_metadata(ecosystem: str, package: str, *, timeout: int = 30) -> Any:
    if ecosystem == "crates":
        return _http_json(f"https://crates.io/api/v1/crates/{urllib.parse.quote(package)}", timeout=timeout)
    if ecosystem == "packagist":
        return _http_json(f"https://repo.packagist.org/p2/{urllib.parse.quote(package, safe='/')}.json", timeout=timeout)
    if ecosystem == "go":
        encoded = _registry_package_path("go", package)
        versions = []
        for version in _http_text(f"https://proxy.golang.org/{encoded}/@v/list", timeout=timeout).splitlines():
            version = version.strip()
            if not version:
                continue
            published_at = None
            try:
                published_at = _http_json(f"https://proxy.golang.org/{encoded}/@v/{urllib.parse.quote(version)}.info", timeout=timeout).get("Time")
            except Exception:
                pass
            versions.append({"version": version, "published_at": published_at})
        return {"versions": versions}
    if ecosystem == "huggingface":
        errors: List[str] = []
        for repo_type, prefix in (("model", "models"), ("dataset", "datasets"), ("space", "spaces")):
            try:
                data = _http_json(f"https://huggingface.co/api/{prefix}/{urllib.parse.quote(package, safe='/')}", timeout=timeout)
                data["repo_type"] = repo_type
                return data
            except Exception as exc:
                errors.append(f"{repo_type}: {exc}")
        raise RuntimeError("; ".join(errors))
    if ecosystem == "maven":
        metadata_url = f"https://repo1.maven.org/maven2/{_registry_package_path('maven', package)}/maven-metadata.xml"
        raw = _http_text(metadata_url, timeout=timeout)
        root = ET.fromstring(raw)
        versions = [{"version": item.text or "", "published_at": None} for item in root.findall(".//versions/version")]
        return {"metadata_url": metadata_url, "versions": versions, "lastUpdated": (root.findtext(".//lastUpdated") or "")}
    if ecosystem == "nuget":
        return _http_json(f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package.lower())}/index.json", timeout=timeout)
    if ecosystem == "open-vsx":
        namespace, extension = package.split(".", 1)
        return _http_json(f"https://open-vsx.org/api/{urllib.parse.quote(namespace)}/{urllib.parse.quote(extension)}", timeout=timeout)
    if ecosystem == "rubygems":
        return _http_json(f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(package)}.json", timeout=timeout)
    raise RuntimeError(f"Live metadata fetch is not supported for {ecosystem}")


def _fetch_packagist_namespace_packages(namespace: str, *, timeout: int = 30, limit: int = 100) -> List[str]:
    namespace = normalize_package_name("packagist", namespace).strip("/")
    if not namespace or "/" in namespace:
        raise ValueError("Packagist namespace should be a vendor name such as laravel-lang")
    url = f"https://packagist.org/search.json?q={urllib.parse.quote(namespace + '/')}"
    data = _http_json(url, timeout=timeout)
    rows = data.get("results", []) if isinstance(data, dict) else []
    packages: List[str] = []
    for row in rows:
        name = str(row.get("name") or "").lower() if isinstance(row, dict) else ""
        if name.startswith(f"{namespace}/") and validate_package_identifier("packagist", name).get("valid"):
            packages.append(name)
        if len(packages) >= limit:
            break
    return sorted(set(packages))


def _ecosystem_version_rows(ecosystem: str, package: str, metadata: Optional[Any] = None, *, timeout: int = 30) -> List[Dict[str, Any]]:
    metadata = metadata if metadata is not None else _fetch_ecosystem_metadata(ecosystem, package, timeout=timeout)
    rows = _version_rows_from_metadata(ecosystem, package, metadata)
    rows.sort(key=lambda item: (_safe_timestamp_sort(item.get("published_at")), _version_key(str(item.get("version", "")))))
    return rows


def _packagist_source_snapshot_path(package: str) -> Path:
    safe = normalize_package_name("packagist", package).replace("/", "__")
    return PACKAGIST_SOURCE_SNAPSHOTS_DIR / f"{safe}.json"


def _packagist_source_snapshot(package: str, metadata: Any) -> Dict[str, Any]:
    package = normalize_package_name("packagist", package)
    rows = _version_rows_from_metadata("packagist", package, metadata)
    return {
        "ecosystem": "packagist",
        "package": package,
        "fetched_at": _utc_now(),
        "versions": [
            {
                "version": row.get("version"),
                "published_at": row.get("published_at"),
                "artifact_url": row.get("artifact_url"),
                "dist_reference": row.get("dist_reference"),
                "source_url": row.get("source_url"),
                "source_reference": row.get("source_reference"),
            }
            for row in rows
        ],
    }


def _snapshot_version_map(snapshot: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(snapshot, dict):
        return {}
    versions = snapshot.get("versions", [])
    if isinstance(versions, dict):
        return {
            str(version): dict(value) if isinstance(value, dict) else {"source_reference": value}
            for version, value in versions.items()
        }
    if isinstance(versions, list):
        return {
            str(row.get("version")): row
            for row in versions
            if isinstance(row, dict) and row.get("version")
        }
    return {}


def _github_repo_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(str(url or ""))
    host = parsed.netloc.lower()
    if host.endswith("github.com"):
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1].removesuffix('.git')}"
    return ""


def detect_packagist_source_signals(
    package: str,
    metadata: Any,
    *,
    previous_snapshot: Optional[Dict[str, Any]] = None,
    burst_window_seconds: int = 900,
    burst_threshold: int = 10,
) -> Dict[str, Any]:
    """Detect source-of-truth Packagist metadata anomalies without executing package code."""
    package = normalize_package_name("packagist", package)
    rows = _version_rows_from_metadata("packagist", package, metadata)
    previous = _snapshot_version_map(previous_snapshot)
    signals: List[Dict[str, Any]] = []

    epochs = [(row, _safe_timestamp_sort(row.get("published_at"))) for row in rows if _safe_timestamp_sort(row.get("published_at"))]
    epochs.sort(key=lambda item: item[1])
    for index, (_row, epoch) in enumerate(epochs):
        clustered = [candidate for candidate, candidate_epoch in epochs if 0 <= candidate_epoch - epoch <= burst_window_seconds]
        if len(clustered) >= burst_threshold:
            signals.append({
                "rule_id": "PACKAGIST-MASS-VERSION-UPDATE",
                "severity": "high",
                "confidence": "medium",
                "matched_behavior": "many Packagist versions changed inside a short window",
                "version_count": len(clustered),
                "window_seconds": burst_window_seconds,
                "versions": [str(item.get("version")) for item in clustered[:25]],
            })
            break

    for row in rows:
        version = str(row.get("version") or "")
        old = previous.get(version) or {}
        old_source = str(old.get("source_reference") or old.get("source_ref") or "")
        new_source = str(row.get("source_reference") or "")
        old_dist = str(old.get("dist_reference") or old.get("dist_ref") or "")
        new_dist = str(row.get("dist_reference") or "")
        if version and old_source and new_source and old_source != new_source:
            signals.append({
                "rule_id": "PACKAGIST-HISTORICAL-SOURCE-REF-CHANGED",
                "severity": "critical",
                "confidence": "high",
                "matched_behavior": "historical Packagist version source reference changed",
                "version": version,
                "previous_source_reference": old_source,
                "source_reference": new_source,
            })
        if version and old_dist and new_dist and old_dist != new_dist:
            signals.append({
                "rule_id": "PACKAGIST-HISTORICAL-DIST-REF-CHANGED",
                "severity": "critical",
                "confidence": "high",
                "matched_behavior": "historical Packagist version dist reference changed",
                "version": version,
                "previous_dist_reference": old_dist,
                "dist_reference": new_dist,
            })

    expected_vendor = package.split("/", 1)[0].lower() if "/" in package else ""
    for row in rows[:50]:
        repo = _github_repo_from_url(str(row.get("source_url") or ""))
        if repo and expected_vendor and repo.split("/", 1)[0].lower() != expected_vendor:
            signals.append({
                "rule_id": "PACKAGIST-SOURCE-REPO-MISMATCH",
                "severity": "high",
                "confidence": "medium",
                "matched_behavior": "Packagist source repository owner differs from package namespace",
                "version": row.get("version"),
                "source_repo": repo,
                "expected_namespace": expected_vendor,
            })

    return {
        "ecosystem": "packagist",
        "package": package,
        "version_count": len(rows),
        "source_repos": sorted(set(repo for repo in (_github_repo_from_url(str(row.get("source_url") or "")) for row in rows if row.get("source_url")) if repo)),
        "signals": signals,
    }


def normalize_github_tag_rows(repo: str, rows: Iterable[Dict[str, Any]], *, source_package: Optional[str] = None) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        ref = str(row.get("ref") or row.get("name") or row.get("tag") or "")
        tag = ref.removeprefix("refs/tags/")
        target = row.get("object") if isinstance(row.get("object"), dict) else row
        sha = str(target.get("sha") or row.get("sha") or row.get("target_sha") or "")
        target_type = str(target.get("type") or row.get("target_type") or "commit")
        if tag and sha:
            normalized.append({
                "repo": repo,
                "source_package": source_package,
                "tag": tag,
                "target_sha": sha,
                "target_type": target_type,
                "tagger_date": row.get("tagger_date") or row.get("commit_date") or row.get("date"),
                "source_repo": row.get("source_repo") or repo,
                "reachable": row.get("reachable", True),
                "signed": row.get("signed"),
            })
    return normalized


def detect_github_tag_provenance(
    repo: str,
    current_tags: Iterable[Dict[str, Any]],
    *,
    previous_tags: Optional[Iterable[Dict[str, Any]]] = None,
    source_package: Optional[str] = None,
    burst_window_seconds: int = 900,
    burst_threshold: int = 10,
) -> Dict[str, Any]:
    current = normalize_github_tag_rows(repo, current_tags, source_package=source_package)
    previous = {
        str(row.get("tag")): row
        for row in normalize_github_tag_rows(repo, previous_tags or [], source_package=source_package)
        if row.get("tag")
    }
    signals: List[Dict[str, Any]] = []
    for row in current:
        old = previous.get(str(row.get("tag")))
        if old and old.get("target_sha") and row.get("target_sha") != old.get("target_sha"):
            signals.append({
                "rule_id": "GITHUB-TAG-REWRITTEN",
                "severity": "critical",
                "confidence": "high",
                "matched_behavior": "GitHub tag target changed compared with prior snapshot",
                "repo": repo,
                "tag": row.get("tag"),
                "previous_sha": old.get("target_sha"),
                "target_sha": row.get("target_sha"),
            })
        if row.get("reachable") is False:
            signals.append({
                "rule_id": "GITHUB-TAG-UNREACHABLE-COMMIT",
                "severity": "high",
                "confidence": "medium",
                "matched_behavior": "GitHub tag points to commit marked unreachable from expected lineage",
                "repo": repo,
                "tag": row.get("tag"),
                "target_sha": row.get("target_sha"),
            })
        if str(row.get("source_repo") or repo).lower() != repo.lower():
            signals.append({
                "rule_id": "GITHUB-TAG-FORK-ORIGIN",
                "severity": "high",
                "confidence": "medium",
                "matched_behavior": "GitHub tag metadata references an unexpected repository origin",
                "repo": repo,
                "tag": row.get("tag"),
                "source_repo": row.get("source_repo"),
            })

    dated = [(row, _safe_timestamp_sort(row.get("tagger_date"))) for row in current if _safe_timestamp_sort(row.get("tagger_date"))]
    dated.sort(key=lambda item: item[1])
    for _index, (_row, epoch) in enumerate(dated):
        clustered = [candidate for candidate, candidate_epoch in dated if 0 <= candidate_epoch - epoch <= burst_window_seconds]
        if len(clustered) >= burst_threshold:
            signals.append({
                "rule_id": "GITHUB-MASS-TAG-ACTIVITY",
                "severity": "high",
                "confidence": "medium",
                "matched_behavior": "many GitHub tags were created or updated inside a short window",
                "repo": repo,
                "tag_count": len(clustered),
                "window_seconds": burst_window_seconds,
                "tags": [str(item.get("tag")) for item in clustered[:25]],
            })
            break

    return {"repo": repo, "source_package": source_package, "tag_count": len(current), "signals": signals}


def analyze_packagist_source_package(
    package: str,
    *,
    metadata: Optional[Any] = None,
    previous_snapshot: Optional[Dict[str, Any]] = None,
    current_tags: Optional[Iterable[Dict[str, Any]]] = None,
    previous_tags: Optional[Iterable[Dict[str, Any]]] = None,
    files: Optional[Dict[str, str]] = None,
    save_snapshot: bool = False,
) -> Dict[str, Any]:
    package = normalize_package_name("packagist", package)
    metadata = metadata if metadata is not None else _fetch_ecosystem_metadata("packagist", package)
    if previous_snapshot is None:
        snapshot_path = _packagist_source_snapshot_path(package)
        if snapshot_path.exists():
            try:
                previous_snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            except Exception:
                previous_snapshot = None
    metadata_result = detect_packagist_source_signals(package, metadata, previous_snapshot=previous_snapshot)
    repos = [repo for repo in metadata_result.get("source_repos", []) if repo]
    tag_result = {"signals": [], "tag_count": 0}
    if current_tags is not None:
        tag_result = detect_github_tag_provenance(
            repos[0] if repos else package,
            current_tags,
            previous_tags=previous_tags,
            source_package=package,
        )
    artifact_result = analyze_ecosystem_files("packagist", files or {}) if files else {
        "findings": [],
        "matched_rules": [],
        "score": 0,
        "verdict": "not_analyzed",
        "confidence": "low",
    }
    artifact_text = "\n".join((files or {}).values())
    iocs = _merge_iocs(artifact_text)
    signals = list(metadata_result.get("signals", [])) + list(tag_result.get("signals", []))
    critical = any(str(signal.get("severity")) == "critical" for signal in signals)
    verdict = "malicious" if critical or artifact_result.get("verdict") == "malicious" else "needs_review" if signals or artifact_result.get("findings") else "benign"
    if save_snapshot:
        _ensure_dirs()
        _packagist_source_snapshot_path(package).write_text(json.dumps(_packagist_source_snapshot(package, metadata), indent=2), encoding="utf-8")
    return {
        "ecosystem": "packagist",
        "package": package,
        "verdict": verdict,
        "confidence": "high" if critical else "medium" if signals or artifact_result.get("findings") else "low",
        "metadata_evidence": metadata_result,
        "tag_evidence": tag_result,
        "artifact_evidence": artifact_result,
        "iocs": iocs,
        "behavior_indicators": sorted(set(_campaign_behavior_indicators(
            {"ecosystem": "packagist", "package": package},
            artifact_result,
            {"behavioral_indicators": []},
            iocs,
        ))),
        "recommended_mitigation": package_compromise_mitigation("packagist", package),
    }


def _get_ecosystem_previous_version(ecosystem: str, package: str, new_version: str, metadata: Optional[Any] = None, *, timeout: int = 30) -> Optional[str]:
    rows = _ecosystem_version_rows(ecosystem, package, metadata, timeout=timeout)
    versions = [row["version"] for row in rows]
    if new_version not in versions:
        versions.append(new_version)
        versions.sort(key=_version_key)
    try:
        index = versions.index(new_version)
    except ValueError:
        return None
    return versions[index - 1] if index > 0 else None


def _version_row(ecosystem: str, package: str, version: str, metadata: Optional[Any] = None, *, timeout: int = 30) -> Dict[str, Any]:
    for row in _ecosystem_version_rows(ecosystem, package, metadata, timeout=timeout):
        if row.get("version") == version:
            return row
    rows = _version_rows_from_metadata(ecosystem, package, metadata if metadata is not None else {})
    if rows:
        raise RuntimeError(f"No artifact metadata for {ecosystem}:{package}@{version}")
    raise RuntimeError(f"No versions found for {ecosystem}:{package}")


def _download_ecosystem_artifact(
    ecosystem: str,
    package: str,
    version: str,
    dest: Path,
    *,
    metadata: Optional[Any] = None,
    max_download_mb: int = DEFAULT_MAX_DOWNLOAD_MB,
    timeout: int = 30,
) -> tuple[Path, Dict[str, Any]]:
    if ecosystem == "huggingface":
        return _materialize_huggingface_snapshot(package, version, dest, metadata=metadata, max_download_mb=max_download_mb, timeout=timeout)
    row = _version_row(ecosystem, package, version, metadata, timeout=timeout)
    url = row.get("artifact_url")
    name = row.get("artifact_name") or Path(urllib.parse.urlparse(str(url)).path).name or f"{package.replace('/', '_')}-{version}.artifact"
    try:
        archive = _download_file(str(url), dest / name, max_bytes=max_download_mb * 1024 * 1024, timeout=timeout)
    except Exception:
        fallback = row.get("fallback_artifact_url")
        if not fallback:
            raise
        archive = _download_file(str(fallback), dest / Path(urllib.parse.urlparse(str(fallback)).path).name, max_bytes=max_download_mb * 1024 * 1024, timeout=timeout)
        row = dict(row, artifact_url=fallback, artifact_name=archive.name)
    return archive, row


def _materialize_huggingface_snapshot(
    package: str,
    version: str,
    dest: Path,
    *,
    metadata: Optional[Any] = None,
    max_download_mb: int = DEFAULT_MAX_DOWNLOAD_MB,
    timeout: int = 30,
) -> tuple[Path, Dict[str, Any]]:
    data = metadata if metadata is not None else _fetch_ecosystem_metadata("huggingface", package, timeout=timeout)
    root = dest / f"{package.replace('/', '_')}@{version}"
    root.mkdir(parents=True, exist_ok=True)
    siblings = data.get("siblings") or []
    listing = {
        "repo": package,
        "revision": version,
        "repo_type": data.get("repo_type", "model"),
        "last_modified": data.get("lastModified"),
        "files": [item.get("rfilename") for item in siblings if item.get("rfilename")],
    }
    (root / "huggingface-file-list.json").write_text(json.dumps(listing, indent=2, sort_keys=True), encoding="utf-8")
    for item in siblings:
        filename = str(item.get("rfilename") or "")
        if not filename or filename.startswith(("/", "\\")) or ".." in Path(filename).parts:
            continue
        if Path(filename).name not in HF_ALLOWED_FILE_NAMES and not filename.endswith(HF_ALLOWED_SUFFIXES):
            continue
        target = root / filename
        try:
            url = f"https://huggingface.co/{urllib.parse.quote(package, safe='/')}/resolve/{urllib.parse.quote(version, safe='')}/{urllib.parse.quote(filename, safe='/')}"
            _download_file(url, target, max_bytes=min(max_download_mb * 1024 * 1024, DEFAULT_MAX_FILE_BYTES), timeout=timeout)
        except Exception:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"# fetch unavailable for {filename}\n", encoding="utf-8")
    return root, {"artifact_url": f"hf://{package}@{version}", "artifact_name": root.name, "metadata_only": True}


def _diff_local_artifacts(
    ecosystem: str,
    package: str,
    old_version: str,
    new_version: str,
    old_artifact: Optional[Path],
    new_artifact: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
) -> tuple[str, Path]:
    tmp = Path(tempfile.mkdtemp(prefix=f"scm_local_{ecosystem}_{package.replace('/', '_').replace('@', '')}_"))
    try:
        old_root = tmp / "empty_old"
        old_root.mkdir(parents=True, exist_ok=True)
        if old_artifact:
            old_root = _extract_archive(old_artifact, tmp / "ext_old", max_files=max_files)
        new_root = _extract_archive(new_artifact, tmp / "ext_new", max_files=max_files)
        report = _build_artifact_report(
            package,
            f"{ecosystem}-local-artifact",
            old_artifact.name if old_artifact else old_version,
            new_artifact.name,
            _collect_files(old_root, max_files=max_files),
            _collect_files(new_root, max_files=max_files),
        )
        return report, tmp
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _safe_timestamp_sort(stamp: Any) -> float:
    if not stamp:
        return 0.0
    try:
        return _parse_registry_timestamp(str(stamp))
    except Exception:
        return 0.0


def _diff_package(
    ecosystem: str,
    package: str,
    old_version: str,
    new_version: str,
    *,
    max_download_mb: int = DEFAULT_MAX_DOWNLOAD_MB,
    max_files: int = DEFAULT_MAX_FILES,
    timeout: int = 30,
) -> tuple[str | None, Path | None, Dict[str, Any]]:
    tmp = Path(tempfile.mkdtemp(prefix=f"scm_{ecosystem}_{package.replace('/', '_').replace('@', '')}_"))
    diff_meta: Dict[str, Any] = {
        "ecosystem": ecosystem,
        "artifact_urls": [],
        "artifact_names": [],
        "fetch_status": "started",
        "artifact_status": "started",
        "limitations": ecosystem_capabilities(ecosystem).get("limitations", []),
    }
    try:
        if ecosystem == "npm":
            archive_old = _download_npm_package(package, old_version, tmp / "dl_old")
            archive_new = _download_npm_package(package, new_version, tmp / "dl_new")
            root_old = _extract_archive(archive_old, tmp / "ext_old")
            root_new = _extract_archive(archive_new, tmp / "ext_new")
            diff_meta.update({
                "artifact_names": [archive_old.name, archive_new.name],
                "artifact_status": "downloaded",
                "files_scanned": len(_collect_files(root_old)) + len(_collect_files(root_new)),
            })
            report = _build_artifact_report(
                package,
                "npm-tarball",
                archive_old.stem,
                archive_new.stem,
                _collect_files(root_old),
                _collect_files(root_new),
            )
            return report, tmp, diff_meta

        reports: List[str] = []
        artifact_reports: Dict[str, Dict[str, Any]] = {}
        if ecosystem == "pypi":
            for packagetype in ("bdist_wheel", "sdist"):
                try:
                    archive_old = _download_pypi_package(package, old_version, tmp / f"dl_old_{packagetype}", packagetype)
                    archive_new = _download_pypi_package(package, new_version, tmp / f"dl_new_{packagetype}", packagetype)
                except RuntimeError:
                    continue
                root_old = _extract_archive(archive_old, tmp / f"ext_old_{packagetype}", max_files=max_files)
                root_new = _extract_archive(archive_new, tmp / f"ext_new_{packagetype}", max_files=max_files)
                label_old = archive_old.name.rsplit(".", 2)[0]
                label_new = archive_new.name.rsplit(".", 2)[0]
                files_old = _collect_files(root_old, max_files=max_files)
                files_new = _collect_files(root_new, max_files=max_files)
                artifact_reports[packagetype] = {"files_old": files_old, "files_new": files_new}
                diff_meta["artifact_names"].extend([archive_old.name, archive_new.name])
                reports.append(_build_artifact_report(package, packagetype, label_old, label_new, files_old, files_new))
            if not reports:
                raise RuntimeError(f"No common artifact types for {package} {old_version} / {new_version}")
            mismatch_summary = _summarize_artifact_mismatch(artifact_reports)
            if mismatch_summary:
                reports.extend(mismatch_summary)
            diff_meta["artifact_status"] = "downloaded"
            return "\n\n---\n\n".join(reports), tmp, diff_meta

        metadata = _fetch_ecosystem_metadata(ecosystem, package, timeout=timeout)
        archive_old, row_old = _download_ecosystem_artifact(
            ecosystem,
            package,
            old_version,
            tmp / "dl_old",
            metadata=metadata,
            max_download_mb=max_download_mb,
            timeout=timeout,
        )
        archive_new, row_new = _download_ecosystem_artifact(
            ecosystem,
            package,
            new_version,
            tmp / "dl_new",
            metadata=metadata,
            max_download_mb=max_download_mb,
            timeout=timeout,
        )
        if archive_old.is_dir():
            root_old = archive_old
        else:
            root_old = _extract_archive(archive_old, tmp / "ext_old", max_files=max_files)
        if archive_new.is_dir():
            root_new = archive_new
        else:
            root_new = _extract_archive(archive_new, tmp / "ext_new", max_files=max_files)
        files_old = _collect_files(root_old, max_files=max_files)
        files_new = _collect_files(root_new, max_files=max_files)
        diff_meta.update({
            "registry_url": row_new.get("registry_url"),
            "artifact_urls": [row_old.get("artifact_url"), row_new.get("artifact_url")],
            "artifact_names": [archive_old.name, archive_new.name],
            "fetch_status": "ok",
            "artifact_status": "downloaded",
            "files_scanned": len(files_old) + len(files_new),
            "files_added": len(set(files_new) - set(files_old)),
            "files_changed": sum(1 for path in set(files_old) & set(files_new) if _file_hash(files_old[path]) != _file_hash(files_new[path])),
        })
        report = _build_artifact_report(package, f"{ecosystem}-artifact", archive_old.name, archive_new.name, files_old, files_new)
        return report, tmp, diff_meta
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None, diff_meta


# ============================================================================
# PACKAGE REPUTATION CHECKING - NEW FUNCTIONS FOR FALSE POSITIVE REDUCTION
# ============================================================================

def _get_pypi_package_metadata(package: str) -> Dict[str, Any]:
    """Fetch package metadata from PyPI with caching."""
    cache_key = f"pypi:{package.lower()}"
    if cache_key in _reputation_cache:
        return _reputation_cache[cache_key]
    
    try:
        data = _http_json(PYPI_JSON.format(package=package))
        _reputation_cache[cache_key] = data
        return data
    except Exception:
        return {}


def _get_pypi_reputation_indicators(package: str) -> Dict[str, Any]:
    """
    Calculate reputation indicators for a PyPI package.
    Returns dict with indicators of package legitimacy.
    """
    data = _get_pypi_package_metadata(package)
    if not data:
        return {"error": "Could not fetch metadata"}
    
    info = data.get("info", {})
    releases = data.get("releases", {})
    
    # Count total releases
    release_count = len([v for v in releases.values() if v])
    
    # Get first release date
    first_release = None
    for version, files in releases.items():
        if files:
            upload_time = files[0].get("upload_time", "")
            if upload_time:
                if first_release is None or upload_time < first_release:
                    first_release = upload_time
    
    # Parse author info
    author = info.get("author", "")
    author_email = info.get("author_email", "")
    maintainer = info.get("maintainer", "")
    
    # Check classifiers for maturity indicators
    classifiers = info.get("classifiers", [])
    maturity_indicators = []
    for c in classifiers:
        if "Development Status :: 5 - Production/Stable" in c:
            maturity_indicators.append("production_stable")
        elif "Development Status :: 6 - Mature" in c:
            maturity_indicators.append("mature")
        elif "Development Status :: 4 - Beta" in c:
            maturity_indicators.append("beta")
    
    # Check for project URLs
    project_urls = info.get("project_urls") or {}
    has_github = any("github.com" in str(url) for url in project_urls.values() if url)
    has_docs = any(any(x in str(url).lower() for x in ["docs", "documentation", "readthedocs"]) for url in project_urls.values() if url)
    
    # Check license
    license_info = info.get("license", "")
    
    return {
        "release_count": release_count,
        "first_release": first_release,
        "has_author": bool(author or author_email or maintainer),
        "has_github": has_github,
        "has_docs": has_docs,
        "maturity_indicators": maturity_indicators,
        "license": license_info,
        "summary": info.get("summary", ""),
        "homepage": info.get("home_page", ""),
        "package_url": info.get("package_url", ""),
    }


def _calculate_reputation_score(reputation: Dict[str, Any]) -> int:
    """
    Calculate a reputation score (0-100) based on package metadata.
    Higher score = more likely to be legitimate.
    """
    score = 0
    
    # Many releases indicates established package
    release_count = reputation.get("release_count", 0)
    if release_count > 50:
        score += 30
    elif release_count > 20:
        score += 20
    elif release_count > 10:
        score += 10
    elif release_count > 5:
        score += 5
    
    # Maturity indicators
    maturity = reputation.get("maturity_indicators", [])
    if "mature" in maturity:
        score += 20
    elif "production_stable" in maturity:
        score += 15
    elif "beta" in maturity:
        score += 5
    
    # Presence of metadata
    if reputation.get("has_author"):
        score += 10
    if reputation.get("has_github"):
        score += 15
    if reputation.get("has_docs"):
        score += 10
    
    # License presence
    if reputation.get("license"):
        score += 10
    
    return min(100, score)


def _is_likely_legitimate_pypi(package: str, min_reputation_score: int = 50) -> bool:
    """
    Determine if a PyPI package is likely legitimate based on reputation indicators.
    
    Args:
        package: Package name
        min_reputation_score: Minimum reputation score to consider legitimate (0-100)
    
    Returns:
        True if package appears legitimate
    """
    reputation = _get_pypi_reputation_indicators(package)
    
    if "error" in reputation:
        return False  # Can't verify, err on side of caution
    
    score = _calculate_reputation_score(reputation)
    return score >= min_reputation_score


def _is_popular_package(package: str, ecosystem: str) -> bool:
    """Check if a package is in the top packages list."""
    if ecosystem != "pypi":
        return False  # TODO: Implement for NPM
    
    try:
        data = _http_json(TOP_PACKAGES_URL)
        top_packages = {row["project"].lower() for row in data.get("rows", [])}
        return package.lower() in top_packages
    except Exception:
        return False


# ============================================================================
# ENHANCED VERDICT CLASSIFICATION
# ============================================================================

def _classify_report_text(
    report: str,
    *,
    ecosystem: Optional[str] = None,
    package: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> tuple[str, str]:
    explanation = explain_verdict(report, ecosystem=ecosystem, package=package, policy=policy)
    return explanation["verdict"], explanation["analysis"]


def _has_strong_malicious_indicators(matched_rules: List[Dict[str, Any]], score: int) -> bool:
    """
    Determine if the matched rules represent strong malicious indicators.
    Returns True only if there's a high confidence of actual malicious behavior.
    """
    rule_names = {r["rule"] for r in matched_rules}
    
    # Strong indicators that should always be flagged
    strong_indicators = {
        "obfuscated eval",
        "shell downloader",
        "suspicious code present only in one PyPI artifact",
        "wheel/sdist artifact divergence",
        "install hook executes remote or inline code",
        "manifest lifecycle hook policy",
        "semantic dynamic execution",
        "semantic module-load execution",
        "semantic credential harvesting",
        "semantic exfiltration staging",
        "node-ipc bundle payload indicators",
        "mini shai-hulud payload indicators",
        "semantic encrypted payload loader",
        "semantic bun temp payload staging",
        "semantic github cli token harvesting",
        "semantic github actions secret harvesting",
        "semantic github dead-drop exfiltration",
        "semantic encrypted credential exfiltration",
        "environment credential harvesting",
        "module-load execution",
        "local file enumeration",
    }
    
    # Check if any strong indicator is present
    has_strong = bool(rule_names & strong_indicators)
    
    # Check for combination of medium indicators
    medium_indicators = {
        "subprocess spawn",
        "semantic subprocess behavior",
        "manifest remote dependency source",
        "install hook reaches remote URL",
        "semantic host fingerprinting",
        "semantic local file enumeration",
        "payload wrapping or exfil staging",
        "host fingerprinting",
    }
    medium_count = len(rule_names & medium_indicators)
    
    # Strong if has any strong indicator OR multiple medium indicators
    if has_strong:
        return True
    if medium_count >= 2 and score >= 8:
        return True
    
    return False


def _validate_malicious_verdict(
    ecosystem: str,
    package: str,
    version: str,
    score: int,
    matched_rules: List[Dict[str, Any]],
    reputation: Optional[Dict[str, Any]] = None,
) -> tuple[bool, str]:
    """
    Validate that a 'malicious' verdict is not a false positive.
    
    Returns:
        (is_valid_malicious, reason)
    """
    if not ecosystem or not package:
        return True, "No package context available; keeping deterministic malicious verdict"

    # Check if package is whitelisted
    policy = load_policy()
    if _package_matches_policy(policy.get("allow", {}).get("packages", []), ecosystem, package):
        return False, "Package is in allowlist"
    
    # Check reputation for PyPI packages
    if ecosystem == "pypi":
        if reputation is None:
            reputation = _get_pypi_reputation_indicators(package)
        
        rep_score = _calculate_reputation_score(reputation)
        
        # High reputation packages need stronger evidence
        if rep_score >= 70:
            if not _has_strong_malicious_indicators(matched_rules, score):
                return False, f"High reputation package (score: {rep_score}) without strong malicious indicators"
        
        # Very high reputation packages are almost never malicious
        if rep_score >= 85:
            # Require extremely strong evidence
            rule_names = {r["rule"] for r in matched_rules}
            ultra_strong = {
                "obfuscated eval",
                "shell downloader",
                "install hook executes remote or inline code",
                "semantic credential harvesting",
                "semantic module-load execution",
                "node-ipc bundle payload indicators",
            }
            if not (rule_names & ultra_strong):
                return False, f"Very high reputation package (score: {rep_score}) - requires ultra-strong indicators"
    
    # Check for weak signal dominance
    weak_signals = {
        "network egress",
        "base64 or encoded payload",
        "credential access",
        "startup persistence",
    }
    rule_names = {r["rule"] for r in matched_rules}
    
    # If all signals are weak, require higher score
    if rule_names.issubset(weak_signals):
        threshold = _package_threshold(policy, ecosystem, package)
        if score < threshold + 2:  # Require 2 extra points for weak-only signals
            return False, "Only weak signals present without sufficient score"
    
    return True, "Strong malicious indicators confirmed"


def explain_verdict(
    report: str,
    *,
    ecosystem: Optional[str] = None,
    package: Optional[str] = None,
    version: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    policy = policy or load_policy()
    matched_rules: List[Dict[str, Any]] = []
    seen_rule_names: set[str] = set()
    score = 0
    lowered = _added_text_scope(report).lower()
    
    # Get package reputation for context
    reputation = None
    if ecosystem == "pypi" and package:
        reputation = _get_pypi_reputation_indicators(package)
    
    for name, pattern, weight in SUSPICIOUS_RULES:
        if not _rule_enabled(policy, name):
            continue
        if name == "network egress":
            # Enhanced network egress check - require suspicious context
            if not re.search(r"\b(fetch|axios|requests\.|urllib|httpx|XMLHttpRequest|https?\.request|curl|wget|Invoke-WebRequest)\b", lowered, re.IGNORECASE):
                continue
            # Additional check: look for suspicious combination patterns
            has_suspicious_context = any(pattern in lowered for pattern in [
                "postinstall", "preinstall", "eval", "exec", "child_process",
                "subprocess", "os.system", "popen", "base64", "decode",
                "obfuscate", "encrypt", "decrypt", "shell"
            ])
            if not has_suspicious_context:
                continue  # Skip if no suspicious context
        if re.search(pattern, lowered, re.IGNORECASE):
            applied_weight = _rule_weight(policy, name, weight)
            score += applied_weight
            _record_rule_match(
                matched_rules,
                seen_rule_names,
                name,
                applied_weight,
                f"Matched suspicious pattern /{pattern}/ in report text.",
            )

    install_hooks = list(NPM_INSTALL_HOOK_RE.finditer(report))
    added_install_hook = bool(install_hooks)
    added_exec = bool(re.search(r"^\+.*\b(eval|exec|child_process|subprocess|curl|wget)\b", report, re.MULTILINE | re.IGNORECASE))
    added_network = bool(re.search(r"^\+.*https?://", report, re.MULTILINE | re.IGNORECASE))
    if added_install_hook and _rule_enabled(policy, "new install hook"):
        applied_weight = _rule_weight(policy, "new install hook", 3)
        score += applied_weight
        _record_rule_match(
            matched_rules,
            seen_rule_names,
            "new install hook",
            applied_weight,
            "Detected newly added npm lifecycle hook in diff.",
        )
        suspicious_hook_cmds = [
            match.group("cmd")
            for match in install_hooks
            if re.search(r"\b(curl|wget|powershell|node\s+-e|python\s+-c|bash\s+-c|sh\s+-c|npx|npm\s+exec)\b", match.group("cmd"), re.IGNORECASE)
        ]
        if suspicious_hook_cmds and _rule_enabled(policy, "install hook executes remote or inline code"):
            applied_weight = _rule_weight(policy, "install hook executes remote or inline code", 4)
            score += applied_weight
            _record_rule_match(
                matched_rules,
                seen_rule_names,
                "install hook executes remote or inline code",
                applied_weight,
                "Lifecycle hook command executes remote fetcher or inline interpreter.",
            )
        if any(re.search(r"https?://", match.group("cmd"), re.IGNORECASE) for match in install_hooks) and _rule_enabled(policy, "install hook reaches remote URL"):
            applied_weight = _rule_weight(policy, "install hook reaches remote URL", 2)
            score += applied_weight
            _record_rule_match(
                matched_rules,
                seen_rule_names,
                "install hook reaches remote URL",
                applied_weight,
                "Lifecycle hook command references an outbound URL.",
            )
    if added_exec and added_network and _rule_enabled(policy, "combined execution and network behavior"):
        applied_weight = _rule_weight(policy, "combined execution and network behavior", 3)
        score += applied_weight
        _record_rule_match(
            matched_rules,
            seen_rule_names,
            "combined execution and network behavior",
            applied_weight,
            "Diff adds both execution-capable code and outbound network behavior.",
        )

    semantic_findings = _filter_semantic_findings(re.findall(r"^- (.+:.+)$", report, re.MULTILINE))
    if semantic_findings and _rule_enabled(policy, "ast-aware semantic findings"):
        semantic_dynamic = any("dynamic execution" in finding for finding in semantic_findings)
        semantic_outbound = any("outbound" in finding for finding in semantic_findings)
        semantic_subprocess = any("subprocess" in finding for finding in semantic_findings)
        semantic_lifecycle = any("lifecycle hook" in finding for finding in semantic_findings)
        semantic_remote_dep = any("non-registry source" in finding or "direct URL" in finding for finding in semantic_findings)
        semantic_entrypoint = any("console scripts" in finding or "entrypoints" in finding or "entrypoint" in finding for finding in semantic_findings)
        semantic_build_custom = any("custom build backend" in finding or "cmdclass" in finding for finding in semantic_findings)
        semantic_setup_exec = any("setup.py performs execution or network-capable actions" in finding for finding in semantic_findings)
        semantic_module_load = any("module-load execution" in finding or "self-executing payload" in finding for finding in semantic_findings)
        semantic_host_fingerprint = any("host fingerprinting" in finding for finding in semantic_findings)
        semantic_file_enum = any("local file enumeration" in finding for finding in semantic_findings)
        semantic_credential_harvest = any("credential harvesting" in finding for finding in semantic_findings)
        semantic_exfil_staging = any("exfiltration staging" in finding or "payload wrapping" in finding for finding in semantic_findings)
        semantic_node_ipc_bundle = any("node-ipc CommonJS bundle" in finding for finding in semantic_findings)
        semantic_encrypted_loader = any("AES-GCM encrypted payload loader" in finding for finding in semantic_findings)
        semantic_encrypted_exfil = any("encrypted credential exfiltration envelope" in finding for finding in semantic_findings)
        semantic_bun_staging = any("Bun runtime" in finding or "staged payload" in finding for finding in semantic_findings)
        semantic_github_cli_token = any("GitHub CLI token harvesting" in finding for finding in semantic_findings)
        semantic_github_actions_secret = any("GitHub Actions runner secret harvesting" in finding for finding in semantic_findings)
        semantic_github_dead_drop = any("GitHub dead-drop" in finding for finding in semantic_findings)
        semantic_token_patterns = any("token pattern harvesting" in finding for finding in semantic_findings)
        semantic_daemonization = any("daemonization" in finding or "background persistence" in finding for finding in semantic_findings)
        semantic_locale_avoidance = any("locale-based execution avoidance" in finding for finding in semantic_findings)
        semantic_mini_shai_hulud = any("Mini Shai-Hulud payload marker" in finding for finding in semantic_findings)
        semantic_ecosystem_manifest = any(
            needle in finding
            for finding in semantic_findings
            for needle in (
                "crates ",
                "chrome extension",
                "composer ",
                "go module",
                "hugging face",
                "maven ",
                "nuget ",
                "open vsx",
                "rubygems ",
                "install-time",
                "lifecycle hook",
                "remote code",
                "unsafe loading",
            )
        )
        raw_subprocess = bool(re.search(r"\b(child_process|subprocess|os\.system|popen|spawn|execFile)\b", _added_text_scope(report), re.IGNORECASE))
        semantic_contextual = (
            semantic_dynamic
            or semantic_lifecycle
            or semantic_remote_dep
            or semantic_build_custom
            or semantic_setup_exec
            or semantic_module_load
            or semantic_credential_harvest
            or semantic_exfil_staging
            or semantic_node_ipc_bundle
            or semantic_encrypted_loader
            or semantic_encrypted_exfil
            or semantic_bun_staging
            or semantic_github_cli_token
            or semantic_github_actions_secret
            or semantic_github_dead_drop
            or semantic_token_patterns
            or semantic_daemonization
            or semantic_mini_shai_hulud
            or semantic_ecosystem_manifest
            or (semantic_subprocess and raw_subprocess)
        )

        if semantic_contextual:
            semantic_weight = min(3, max(1, len(semantic_findings) // 2))
            applied_weight = _rule_weight(policy, "ast-aware semantic findings", semantic_weight)
            score += applied_weight
            _record_rule_match(
                matched_rules,
                seen_rule_names,
                "ast-aware semantic findings",
                applied_weight,
                f"Semantic inspection reported {len(semantic_findings)} contextual finding(s).",
            )
            if semantic_dynamic and _rule_enabled(policy, "semantic dynamic execution"):
                applied_weight = _rule_weight(policy, "semantic dynamic execution", 2)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic dynamic execution",
                    applied_weight,
                    "Semantic findings include dynamic execution behavior.",
                )
            if semantic_outbound and semantic_contextual and _rule_enabled(policy, "semantic outbound network behavior"):
                applied_weight = _rule_weight(policy, "semantic outbound network behavior", 2)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic outbound network behavior",
                    applied_weight,
                    "Semantic findings include outbound network behavior.",
                )
            if semantic_subprocess and (semantic_dynamic or raw_subprocess) and _rule_enabled(policy, "semantic subprocess behavior"):
                applied_weight = _rule_weight(policy, "semantic subprocess behavior", 2)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic subprocess behavior",
                    applied_weight,
                    "Semantic findings include subprocess-capable behavior.",
                )
            if semantic_module_load and _rule_enabled(policy, "semantic module-load execution"):
                applied_weight = _rule_weight(policy, "semantic module-load execution", 3)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic module-load execution",
                    applied_weight,
                    "Semantic findings include import/module-load execution.",
                )
            if semantic_credential_harvest and _rule_enabled(policy, "semantic credential harvesting"):
                applied_weight = _rule_weight(policy, "semantic credential harvesting", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic credential harvesting",
                    applied_weight,
                    "Semantic findings include environment credential harvesting.",
                )
            if semantic_host_fingerprint and _rule_enabled(policy, "semantic host fingerprinting"):
                applied_weight = _rule_weight(policy, "semantic host fingerprinting", 2)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic host fingerprinting",
                    applied_weight,
                    "Semantic findings include host fingerprinting.",
                )
            if semantic_file_enum and _rule_enabled(policy, "semantic local file enumeration"):
                applied_weight = _rule_weight(policy, "semantic local file enumeration", 3)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic local file enumeration",
                    applied_weight,
                    "Semantic findings include local developer or credential file enumeration.",
                )
            if semantic_exfil_staging and _rule_enabled(policy, "semantic exfiltration staging"):
                applied_weight = _rule_weight(policy, "semantic exfiltration staging", 3)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic exfiltration staging",
                    applied_weight,
                    "Semantic findings include payload wrapping or exfiltration staging.",
                )
            if semantic_node_ipc_bundle and _rule_enabled(policy, "node-ipc bundle payload indicators"):
                applied_weight = _rule_weight(policy, "node-ipc bundle payload indicators", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "node-ipc bundle payload indicators",
                    applied_weight,
                    "node-ipc CommonJS bundle contains appended high-risk payload indicators.",
                )
            if semantic_mini_shai_hulud and _rule_enabled(policy, "mini shai-hulud payload indicators"):
                applied_weight = _rule_weight(policy, "mini shai-hulud payload indicators", 5)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "mini shai-hulud payload indicators",
                    applied_weight,
                    "Semantic findings include Mini Shai-Hulud marker strings.",
                )
            if semantic_encrypted_loader and _rule_enabled(policy, "semantic encrypted payload loader"):
                applied_weight = _rule_weight(policy, "semantic encrypted payload loader", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic encrypted payload loader",
                    applied_weight,
                    "JavaScript decrypts embedded payloads with AES-GCM before execution.",
                )
            if semantic_bun_staging and _rule_enabled(policy, "semantic bun temp payload staging"):
                applied_weight = _rule_weight(policy, "semantic bun temp payload staging", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic bun temp payload staging",
                    applied_weight,
                    "JavaScript stages decrypted payloads through Bun and temporary files.",
                )
            if semantic_github_cli_token and _rule_enabled(policy, "semantic github cli token harvesting"):
                applied_weight = _rule_weight(policy, "semantic github cli token harvesting", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic github cli token harvesting",
                    applied_weight,
                    "JavaScript invokes gh auth token to collect GitHub CLI credentials.",
                )
            if semantic_github_actions_secret and _rule_enabled(policy, "semantic github actions secret harvesting"):
                applied_weight = _rule_weight(policy, "semantic github actions secret harvesting", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic github actions secret harvesting",
                    applied_weight,
                    "JavaScript targets GitHub Actions runner secrets or OIDC material.",
                )
            if semantic_github_dead_drop and _rule_enabled(policy, "semantic github dead-drop exfiltration"):
                applied_weight = _rule_weight(policy, "semantic github dead-drop exfiltration", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic github dead-drop exfiltration",
                    applied_weight,
                    "JavaScript references GitHub API repository write paths for dead-drop exfiltration.",
                )
            if semantic_encrypted_exfil and _rule_enabled(policy, "semantic encrypted credential exfiltration"):
                applied_weight = _rule_weight(policy, "semantic encrypted credential exfiltration", 4)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic encrypted credential exfiltration",
                    applied_weight,
                    "JavaScript wraps collected data in encrypted exfiltration envelopes.",
                )
            if (semantic_daemonization or semantic_locale_avoidance) and _rule_enabled(policy, "semantic evasive execution controls"):
                applied_weight = _rule_weight(policy, "semantic evasive execution controls", 2)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "semantic evasive execution controls",
                    applied_weight,
                    "JavaScript includes daemonization or locale-based execution avoidance.",
                )
            if semantic_ecosystem_manifest and _rule_enabled(policy, "ecosystem manifest risk"):
                applied_weight = _rule_weight(policy, "ecosystem manifest risk", 3)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "ecosystem manifest risk",
                    applied_weight,
                    "Ecosystem-specific manifest or source inspection found install, permission, credential, or remote-code risk.",
                )
            if semantic_lifecycle and _rule_enabled(policy, "manifest lifecycle hook policy"):
                applied_weight = _rule_weight(policy, "manifest lifecycle hook policy", 3)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "manifest lifecycle hook policy",
                    applied_weight,
                    "Manifest findings include lifecycle hook behavior.",
                )
            if semantic_remote_dep and _rule_enabled(policy, "manifest remote dependency source"):
                applied_weight = _rule_weight(policy, "manifest remote dependency source", 2)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "manifest remote dependency source",
                    applied_weight,
                    "Manifest findings include non-registry or direct-URL dependency sources.",
                )
            if semantic_entrypoint and (semantic_lifecycle or semantic_remote_dep or semantic_build_custom) and _rule_enabled(policy, "manifest executable entrypoints"):
                applied_weight = _rule_weight(policy, "manifest executable entrypoints", 1)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "manifest executable entrypoints",
                    applied_weight,
                    "Manifest findings declare executable entrypoints or scripts.",
                )
            if semantic_build_custom and _rule_enabled(policy, "manifest install-time build customization"):
                applied_weight = _rule_weight(policy, "manifest install-time build customization", 2)
                score += applied_weight
                _record_rule_match(
                    matched_rules,
                    seen_rule_names,
                    "manifest install-time build customization",
                    applied_weight,
                    "Manifest findings customize install-time build behavior.",
                )

    wheel_only_count_match = re.search(r"wheel_only_count=(\d+)", report)
    sdist_only_count_match = re.search(r"sdist_only_count=(\d+)", report)
    suspicious_wheel_only_paths, suspicious_sdist_only_paths = _artifact_divergence_candidates(report)
    if wheel_only_count_match and sdist_only_count_match:
        wheel_only_count = int(wheel_only_count_match.group(1))
        sdist_only_count = int(sdist_only_count_match.group(1))
        suspicious_divergence = bool(suspicious_wheel_only_paths or suspicious_sdist_only_paths)
        if suspicious_divergence and (wheel_only_count or sdist_only_count) and _rule_enabled(policy, "wheel/sdist artifact divergence"):
            applied_weight = _rule_weight(policy, "wheel/sdist artifact divergence", 2)
            score += applied_weight
            _record_rule_match(
                matched_rules,
                seen_rule_names,
                "wheel/sdist artifact divergence",
                applied_weight,
                "Wheel and sdist file inventories diverge.",
            )
        if suspicious_wheel_only_paths and _rule_enabled(policy, "suspicious code present only in one PyPI artifact"):
            applied_weight = _rule_weight(policy, "suspicious code present only in one PyPI artifact", 4)
            score += applied_weight
            _record_rule_match(
                matched_rules,
                seen_rule_names,
                "suspicious code present only in one PyPI artifact",
                applied_weight,
                "Suspicious files appear only in one PyPI artifact variant.",
            )

    policy_context = explain_policy(ecosystem or "", package or "", policy=policy) if ecosystem and package else None
    malicious_threshold = _package_threshold(policy, ecosystem, package)
    advisory_matches = find_advisory_matches(ecosystem, package, version) if ecosystem and package and version else []
    mitigation = package_compromise_mitigation(ecosystem or "", package or "", version, advisory_matches)
    environment_impact = {
        "status": "unknown",
        "guidance": "Check local manifests and lockfiles for exact package/version references before concluding local exposure.",
    }
    if advisory_matches:
        applied_weight = max(malicious_threshold, 10)
        score += applied_weight
        _record_rule_match(
            matched_rules,
            seen_rule_names,
            "emergency advisory match",
            applied_weight,
            "Named package version matches a source-backed emergency advisory.",
        )
        return {
            "target": {"ecosystem": ecosystem, "package": package},
            "version": version,
            "score": score,
            "effective_threshold": malicious_threshold,
            "verdict": "malicious",
            "analysis": _attach_advisory_analysis(
                "Deterministic rules flagged: " + ", ".join(match["rule"] for match in matched_rules)
                if len(matched_rules) > 1
                else "",
                advisory_matches,
            ),
            "matched_rules": matched_rules,
            "policy": policy_context,
            "allow_matches": policy_context["allow_matches"] if policy_context else [],
            "deny_matches": policy_context["deny_matches"] if policy_context else [],
            "advisory_matches": advisory_matches,
            "environment_impact": environment_impact,
            "mitigation": mitigation,
        }

    if _package_matches_policy(policy.get("deny", {}).get("packages", []), ecosystem, package):
        return {
            "target": {"ecosystem": ecosystem, "package": package},
            "score": score,
            "effective_threshold": malicious_threshold,
            "verdict": "malicious",
            "analysis": f"Policy denylist matched for {ecosystem}:{package}",
            "matched_rules": matched_rules,
            "policy": policy_context,
            "allow_matches": policy_context["allow_matches"] if policy_context else [],
            "deny_matches": policy_context["deny_matches"] if policy_context else [],
            "advisory_matches": [],
            "environment_impact": environment_impact,
            "mitigation": mitigation,
        }

    if _package_matches_policy(policy.get("allow", {}).get("packages", []), ecosystem, package):
        return {
            "target": {"ecosystem": ecosystem, "package": package},
            "score": score,
            "effective_threshold": malicious_threshold,
            "verdict": "benign",
            "analysis": f"Policy allowlist matched for {ecosystem}:{package}",
            "matched_rules": matched_rules,
            "policy": policy_context,
            "allow_matches": policy_context["allow_matches"] if policy_context else [],
            "deny_matches": policy_context["deny_matches"] if policy_context else [],
            "advisory_matches": [],
            "environment_impact": environment_impact,
            "mitigation": mitigation,
        }

    rule_names = [match["rule"] for match in matched_rules]
    if score >= malicious_threshold:
        # Validate the malicious verdict before confirming
        is_valid, validation_reason = _validate_malicious_verdict(
            ecosystem or "", package or "", "", score, matched_rules, reputation
        )
        
        if is_valid:
            analysis = f"Deterministic rules flagged: {', '.join(rule_names)}"
            verdict = "malicious"
        else:
            analysis = f"Indicators found but insufficient for malicious verdict: {validation_reason}. Rules: {', '.join(rule_names)}"
            verdict = "benign"
    else:
        analysis = "No strong compromise indicators found." if not rule_names else f"Observed low-confidence indicators: {', '.join(rule_names)}"
        verdict = "benign"

    return {
        "target": {"ecosystem": ecosystem, "package": package},
        "score": score,
        "effective_threshold": malicious_threshold,
        "verdict": verdict,
        "analysis": analysis,
        "matched_rules": matched_rules,
        "policy": policy_context,
        "allow_matches": policy_context["allow_matches"] if policy_context else [],
        "deny_matches": policy_context["deny_matches"] if policy_context else [],
        "advisory_matches": [],
        "environment_impact": environment_impact,
        "mitigation": mitigation,
    }


def _find_agent() -> Optional[str]:
    return shutil.which("agent")


def _classify_with_agent(report: str, model: Optional[str]) -> tuple[str, str]:
    agent_bin = _find_agent()
    if not agent_bin:
        raise FileNotFoundError("agent binary not found")
    workspace = Path(tempfile.mkdtemp(prefix="scm_agent_"))
    try:
        diff_file = workspace / "diff.md"
        instructions = workspace / "instructions.md"
        diff_file.write_text(report, encoding="utf-8")
        instructions.write_text(AGENT_PROMPT, encoding="utf-8")
        cmd = [agent_bin, "Follow instructions.md", "-p", "--mode", "ask", "--workspace", str(workspace)]
        if model:
            cmd.extend(["--model", model])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        output = result.stdout or ""
        match = re.search(r"Verdict:\s*(malicious|benign)", output, re.IGNORECASE)
        return (match.group(1).lower() if match else "benign"), output.strip()
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _analyze_report(
    report: str,
    model: Optional[str],
    *,
    ecosystem: Optional[str] = None,
    package: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> tuple[str, str]:
    verdict, analysis = _classify_report_text(report, ecosystem=ecosystem, package=package, policy=policy)
    if verdict == "malicious":
        return verdict, analysis
    if model or os.environ.get("SECOPS_SUPPLY_CHAIN_USE_AGENT") == "1":
        try:
            return _classify_with_agent(report, model)
        except Exception as exc:
            return verdict, f"{analysis} Agent review unavailable: {exc}"
    return verdict, analysis


def _scan_release(
    ecosystem: str,
    package: str,
    new_version: str,
    *,
    old_version: Optional[str] = None,
    rank: Optional[int] = None,
    model: Optional[str] = None,
    keep_report: bool = True,
    artifact: Optional[Path] = None,
    previous_artifact: Optional[Path] = None,
    metadata_only: bool = False,
    max_download_mb: int = DEFAULT_MAX_DOWNLOAD_MB,
    max_files: int = DEFAULT_MAX_FILES,
    timeout: int = 30,
) -> ScanResult:
    _ensure_dirs()
    ecosystem = canonical_ecosystem(ecosystem)
    package = normalize_package_name(ecosystem, package)
    policy = load_policy()
    advisory_matches = find_advisory_matches(ecosystem, package, new_version)
    capabilities = ecosystem_capabilities(ecosystem)
    scan_meta: Dict[str, Any] = {
        "capabilities": capabilities.get("features", {}),
        "limitations": capabilities.get("limitations", []),
        "metadata_only": bool(metadata_only or ecosystem == "huggingface"),
    }

    if artifact:
        old_label = old_version or (previous_artifact.name if previous_artifact else "empty-baseline")
        try:
            report, tmp_dir = _diff_local_artifacts(
                ecosystem,
                package,
                old_label,
                new_version,
                previous_artifact,
                artifact,
                max_files=max_files,
            )
            scan_meta.update({
                "artifact_status": "local-artifact",
                "artifact_names": [previous_artifact.name if previous_artifact else None, artifact.name],
                "files_scanned": len(report.splitlines()),
            })
        except Exception as exc:
            if advisory_matches:
                return ScanResult(
                    ecosystem,
                    package,
                    old_label,
                    new_version,
                    "malicious",
                    _advisory_analysis(advisory_matches, artifact_unavailable=True),
                    None,
                    rank,
                    _finding_id(ecosystem, package, new_version),
                    str(exc),
                    advisory_matches,
                    scan_meta,
                )
            return ScanResult(ecosystem, package, old_label, new_version, "error", repr(exc), None, rank, None, str(exc), None, scan_meta)
        try:
            report_path = None
            if keep_report:
                report_file = _report_filename(ecosystem, package, old_label, new_version)
                report_file.write_text(report, encoding="utf-8")
                report_path = str(report_file)
            verdict, analysis = _analyze_report(report, model, ecosystem=ecosystem, package=package, policy=policy)
            if advisory_matches:
                verdict = "malicious"
                analysis = _attach_advisory_analysis(analysis, advisory_matches)
            finding_id = _finding_id(ecosystem, package, new_version) if verdict == "malicious" else None
            return ScanResult(ecosystem, package, old_label, new_version, verdict, analysis, report_path, rank, finding_id, None, advisory_matches or None, scan_meta)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    if not capabilities.get("features", {}).get("metadata_fetch", False) or not capabilities.get("features", {}).get("artifact_fetch", False):
        if advisory_matches:
            return ScanResult(
                ecosystem,
                package,
                "unavailable",
                new_version,
                "malicious",
                _advisory_analysis(advisory_matches, artifact_unavailable=True),
                None,
                rank,
                _finding_id(ecosystem, package, new_version),
                "artifact fetch not implemented for this ecosystem; advisory matched",
                advisory_matches,
                scan_meta,
            )
        return ScanResult(
            ecosystem,
            package,
            None,
            new_version,
            "skipped",
            f"{capabilities.get('display_name', ecosystem)} live registry fetch is not available from this command without --artifact; advisory matching and local artifact rules are supported.",
            None,
            rank,
            None,
            "live registry fetch unsupported for ecosystem; use --artifact when available",
            None,
            scan_meta,
        )
    
    # Emergency advisories intentionally override local allow/reputation shortcuts.
    if not advisory_matches and _package_matches_policy(policy.get("allow", {}).get("packages", []), ecosystem, package):
        return ScanResult(
            ecosystem, package, None, new_version,
            "benign",
            f"Skipped analysis - package {ecosystem}:{package} is in allowlist",
            None, rank, None
        )
    
    # Check package reputation for PyPI
    if not advisory_matches and ecosystem == "pypi":
        reputation = _get_pypi_reputation_indicators(package)
        rep_score = _calculate_reputation_score(reputation)
        
        # Skip detailed analysis for high-reputation packages
        if rep_score >= 80:
            return ScanResult(
                ecosystem, package, None, new_version,
                "benign",
                f"Skipped detailed analysis - high reputation package (score: {rep_score})",
                None, rank, None
            )
    
    old_version = old_version or (
        _npm_get_previous_version(package, new_version)
        if ecosystem == "npm"
        else (_get_previous_version(package, new_version) if ecosystem == "pypi" else _get_ecosystem_previous_version(ecosystem, package, new_version, timeout=timeout))
    )
    if not old_version:
        if advisory_matches:
            return ScanResult(
                ecosystem,
                package,
                "unavailable",
                new_version,
                "malicious",
                _advisory_analysis(advisory_matches, artifact_unavailable=True),
                None,
                rank,
                _finding_id(ecosystem, package, new_version),
                "artifact unavailable; advisory matched",
                advisory_matches,
                scan_meta,
            )
        return ScanResult(ecosystem, package, None, new_version, "skipped", "", None, rank, None, "no previous version found")
    
    diff_result = _diff_package(
        ecosystem,
        package,
        old_version,
        new_version,
        max_download_mb=max_download_mb,
        max_files=max_files,
        timeout=timeout,
    )
    if len(diff_result) == 2:  # Backward-compatible for older tests/mocks.
        report, tmp_dir = diff_result
        diff_meta = {}
    else:
        report, tmp_dir, diff_meta = diff_result
    scan_meta.update(diff_meta or {})
    try:
        if not report:
            if advisory_matches:
                return ScanResult(
                    ecosystem,
                    package,
                    old_version,
                    new_version,
                    "malicious",
                    _advisory_analysis(advisory_matches, artifact_unavailable=True),
                    None,
                    rank,
                    _finding_id(ecosystem, package, new_version),
                    "artifact unavailable; advisory matched",
                    advisory_matches,
                    scan_meta,
                )
            return ScanResult(ecosystem, package, old_version, new_version, "error", "", None, rank, None, "diff generation failed")
        report_path = None
        if keep_report:
            report_file = _report_filename(ecosystem, package, old_version, new_version)
            report_file.write_text(report, encoding="utf-8")
            report_path = str(report_file)
        verdict, analysis = _analyze_report(
            report,
            model,
            ecosystem=ecosystem,
            package=package,
            policy=policy,
        )
        if advisory_matches:
            verdict = "malicious"
            analysis = _attach_advisory_analysis(analysis, advisory_matches)
        finding_id = _finding_id(ecosystem, package, new_version) if verdict == "malicious" else None
        return ScanResult(
            ecosystem,
            package,
            old_version,
            new_version,
            verdict,
            analysis,
            report_path,
            rank,
            finding_id,
            None,
            advisory_matches or None,
            scan_meta,
        )
    except Exception as exc:
        if advisory_matches:
            return ScanResult(
                ecosystem,
                package,
                old_version,
                new_version,
                "malicious",
                _advisory_analysis(advisory_matches, artifact_unavailable=True),
                None,
                rank,
                _finding_id(ecosystem, package, new_version),
                str(exc),
                advisory_matches,
                scan_meta,
            )
        return ScanResult(ecosystem, package, old_version, new_version, "error", repr(exc), None, rank, None, str(exc), None, scan_meta)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _get_previous_version(package: str, new_version: str) -> Optional[str]:
    try:
        data = _http_json(PYPI_JSON.format(package=package))
    except Exception:
        return None
    releases = data.get("releases", {})
    versions = [version for version, files in releases.items() if files]
    if new_version not in versions:
        versions.append(new_version)

    def upload_time(version: str) -> str:
        files = releases.get(version, [])
        stamps = [row.get("upload_time_iso_8601", "") for row in files]
        return min((stamp for stamp in stamps if stamp), default="9999-12-31T23:59:59")

    versions.sort(key=upload_time)
    try:
        index = versions.index(new_version)
    except ValueError:
        return None
    return versions[index - 1] if index > 0 else None


def _load_watchlist(top_n: int) -> Dict[str, int]:
    data = _http_json(TOP_PACKAGES_URL)
    return {row["project"].lower(): index for index, row in enumerate(data["rows"][:top_n], 1)}


def _extract_new_releases(events: list, watchlist: Dict[str, int]) -> List[tuple[str, str, int]]:
    seen = set()
    releases = []
    for name, version, timestamp, action, _serial_id in events:
        if action != "new release":
            continue
        key = (name.lower(), version)
        if key in seen or name.lower() not in watchlist:
            continue
        seen.add(key)
        releases.append((name, version, timestamp))
    return releases


def _load_npm_watchlist(top_n: int) -> Dict[str, int]:
    watchlist: Dict[str, int] = {}
    page_size = 250
    for offset in range(0, top_n, page_size):
        remaining = min(page_size, top_n - offset)
        params = urllib.parse.urlencode(
            {
                "text": "boost-exact:false",
                "popularity": "1.0",
                "quality": "0.0",
                "maintenance": "0.0",
                "size": str(remaining),
                "from": str(offset),
            }
        )
        data = _http_json(f"{NPM_SEARCH}?{params}")
        rows = data.get("objects", [])
        for index, row in enumerate(rows, start=offset + 1):
            watchlist[str(row["package"]["name"]).lower()] = index
        if len(rows) < remaining:
            break
    return watchlist


def _npm_get_current_seq() -> int:
    data = _http_json(NPM_REPLICATE)
    return int(data["update_seq"])


def _npm_poll_changes(since: int, limit: int = 500) -> tuple[list[dict], int]:
    data = _http_json(f"{NPM_REPLICATE}/_changes?since={since}&limit={limit}")
    return data.get("results", []), int(data.get("last_seq", since))


def _npm_get_package_info(package: str) -> Optional[dict]:
    encoded = urllib.parse.quote(package, safe="@")
    try:
        return _http_json(f"{NPM_REGISTRY}/{encoded}")
    except Exception:
        return None


def _npm_detect_new_releases(package: str, since_epoch: float) -> List[str]:
    info = _npm_get_package_info(package)
    if not info:
        return []
    since_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(since_epoch))
    version_times = []
    for version, stamp in (info.get("time", {}) or {}).items():
        if version in {"created", "modified"} or not isinstance(stamp, str):
            continue
        if stamp > since_iso:
            version_times.append((version, stamp))
    version_times.sort(key=lambda item: item[1])
    return [version for version, _stamp in version_times]


def _npm_get_previous_version(package: str, new_version: str) -> Optional[str]:
    info = _npm_get_package_info(package)
    if not info:
        return None
    version_times = {
        version: stamp
        for version, stamp in (info.get("time", {}) or {}).items()
        if version not in {"created", "modified"} and isinstance(stamp, str)
    }
    ordered = sorted(version_times, key=lambda version: version_times[version])
    try:
        index = ordered.index(new_version)
    except ValueError:
        return None
    return ordered[index - 1] if index > 0 else None


def _parse_duration_seconds(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([smhd])?\s*", value or "")
    if not match:
        raise ValueError(f"invalid duration: {value!r}; expected values like 10m, 2h, or 1d")
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return amount * multipliers[unit]


def _parse_registry_timestamp(stamp: str) -> float:
    normalized = stamp.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).timestamp()


def _ordered_npm_versions(metadata: Dict[str, Any]) -> List[tuple[str, str, float]]:
    rows: List[tuple[str, str, float]] = []
    for version, stamp in (metadata.get("time", {}) or {}).items():
        if version in {"created", "modified"} or not isinstance(stamp, str):
            continue
        try:
            rows.append((version, stamp, _parse_registry_timestamp(stamp)))
        except Exception:
            continue
    rows.sort(key=lambda item: item[2])
    return rows


def _normalize_npm_namespace(namespace: str) -> str:
    normalized = str(namespace or "").strip().lower()
    normalized = normalized.removeprefix("scope:")
    normalized = normalized.removeprefix("@")
    if not normalized or "/" in normalized:
        raise ValueError("npm namespace should be a scope such as redhat-cloud-services")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", normalized):
        raise ValueError(f"invalid npm namespace: {namespace!r}")
    return normalized


def _npm_source_snapshot_path(package: str) -> Path:
    safe = normalize_package_name("npm", package).replace("/", "__").replace("@", "scope__")
    return NPM_SOURCE_SNAPSHOTS_DIR / f"{safe}.json"


def _npm_source_snapshot(package: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    package = normalize_package_name("npm", package)
    versions = metadata.get("versions", {}) if isinstance(metadata, dict) else {}
    return {
        "ecosystem": "npm",
        "package": package,
        "fetched_at": _utc_now(),
        "dist_tags": metadata.get("dist-tags", {}) if isinstance(metadata, dict) else {},
        "maintainers": [
            str(item.get("name") or item.get("email") or item)
            for item in (metadata.get("maintainers", []) if isinstance(metadata, dict) else [])
        ],
        "versions": [
            {
                "version": version,
                "published_at": stamp,
                "tarball": ((versions.get(version) or {}).get("dist") or {}).get("tarball") if isinstance(versions, dict) else None,
                "integrity": ((versions.get(version) or {}).get("dist") or {}).get("integrity") if isinstance(versions, dict) else None,
                "shasum": ((versions.get(version) or {}).get("dist") or {}).get("shasum") if isinstance(versions, dict) else None,
                "scripts": (versions.get(version) or {}).get("scripts") if isinstance(versions, dict) else None,
                "main": (versions.get(version) or {}).get("main") if isinstance(versions, dict) else None,
                "module": (versions.get(version) or {}).get("module") if isinstance(versions, dict) else None,
            }
            for version, stamp, _epoch in _ordered_npm_versions(metadata if isinstance(metadata, dict) else {})
        ],
    }


def _fetch_npm_namespace_packages(namespace: str, *, timeout: int = 30, limit: int = 250) -> List[str]:
    scope = _normalize_npm_namespace(namespace)
    packages: List[str] = []
    offset = 0
    while len(packages) < limit:
        size = min(250, limit - len(packages))
        params = urllib.parse.urlencode({"text": f"scope:{scope}", "size": str(size), "from": str(offset)})
        data = _http_json(f"{NPM_SEARCH}?{params}", timeout=timeout)
        rows = data.get("objects", []) if isinstance(data, dict) else []
        for row in rows:
            pkg = (row.get("package") or {}) if isinstance(row, dict) else {}
            name = normalize_package_name("npm", str(pkg.get("name") or ""))
            if name.startswith(f"@{scope}/") and validate_package_identifier("npm", name).get("valid"):
                packages.append(name)
        if len(rows) < size:
            break
        offset += size
    return sorted(set(packages))


def detect_npm_package_source_signals(
    package: str,
    metadata: Dict[str, Any],
    *,
    previous_snapshot: Optional[Dict[str, Any]] = None,
    burst_window_seconds: int = 3600,
    burst_threshold: int = 2,
) -> Dict[str, Any]:
    package = normalize_package_name("npm", package)
    ordered = _ordered_npm_versions(metadata)
    previous = _snapshot_version_map(previous_snapshot)
    signals: List[Dict[str, Any]] = []
    epochs = [(version, stamp, epoch) for version, stamp, epoch in ordered if epoch]
    for _version, _stamp, epoch in epochs:
        clustered = [(version, stamp, candidate_epoch) for version, stamp, candidate_epoch in epochs if 0 <= candidate_epoch - epoch <= burst_window_seconds]
        if len(clustered) >= burst_threshold:
            signals.append({
                "rule_id": "NPM-PACKAGE-VERSION-BURST",
                "severity": "medium" if len(clustered) < 4 else "high",
                "confidence": "medium",
                "matched_behavior": "multiple npm versions published inside a short window",
                "package": package,
                "version_count": len(clustered),
                "window_seconds": burst_window_seconds,
                "versions": [version for version, _stamp, _epoch in clustered[:25]],
            })
            break

    snapshot = _npm_source_snapshot(package, metadata)
    current_versions = _snapshot_version_map(snapshot)
    for version, current in current_versions.items():
        old = previous.get(version) or {}
        for key, rule_id in (
            ("integrity", "NPM-HISTORICAL-INTEGRITY-CHANGED"),
            ("shasum", "NPM-HISTORICAL-SHASUM-CHANGED"),
            ("tarball", "NPM-HISTORICAL-TARBALL-CHANGED"),
        ):
            old_value = str(old.get(key) or "")
            new_value = str(current.get(key) or "")
            if old_value and new_value and old_value != new_value:
                signals.append({
                    "rule_id": rule_id,
                    "severity": "critical",
                    "confidence": "high",
                    "matched_behavior": f"historical npm version {key} changed compared with prior snapshot",
                    "package": package,
                    "version": version,
                    f"previous_{key}": old_value,
                    key: new_value,
                })
        scripts = current.get("scripts") or {}
        if isinstance(scripts, dict):
            for hook, command in scripts.items():
                if hook in {"preinstall", "install", "postinstall", "prepare"} and isinstance(command, str):
                    signals.append({
                        "rule_id": "NPM-METADATA-LIFECYCLE-HOOK",
                        "severity": "high" if re.search(r"\bnode\s+index\.js\b|\bbun\b|\bcurl\b|\bwget\b|https?://", command, re.IGNORECASE) else "medium",
                        "confidence": "medium",
                        "matched_behavior": "npm registry metadata declares install-time lifecycle execution",
                        "package": package,
                        "version": version,
                        "hook": hook,
                        "command": command,
                    })

    return {
        "ecosystem": "npm",
        "package": package,
        "version_count": len(ordered),
        "signals": signals,
    }


def _aggregate_npm_namespace_source_signals(
    namespace: str,
    package_rows: Iterable[Dict[str, Any]],
    *,
    burst_window_seconds: int = 3600,
    burst_threshold: int = 10,
) -> Dict[str, Any]:
    scope = _normalize_npm_namespace(namespace)
    rows = [
        row for row in package_rows
        if row.get("published_epoch") and str(row.get("package") or "").lower().startswith(f"@{scope}/")
    ]
    rows.sort(key=lambda item: float(item.get("published_epoch") or 0))
    signals: List[Dict[str, Any]] = []
    for row in rows:
        epoch = float(row.get("published_epoch") or 0)
        clustered = [candidate for candidate in rows if 0 <= float(candidate.get("published_epoch") or 0) - epoch <= burst_window_seconds]
        unique_packages = sorted(set(str(item.get("package")) for item in clustered if item.get("package")))
        if len(clustered) >= burst_threshold and len(unique_packages) >= max(3, burst_threshold // 3):
            signals.append({
                "rule_id": "NPM-NAMESPACE-MASS-PUBLISH-BURST",
                "severity": "critical" if len(clustered) >= 25 else "high",
                "confidence": "high",
                "matched_behavior": "many npm package artifacts in one scope were published inside a short window",
                "namespace": f"@{scope}",
                "artifact_count": len(clustered),
                "unique_package_count": len(unique_packages),
                "window_seconds": burst_window_seconds,
                "packages": unique_packages[:50],
                "versions": [
                    {"package": item.get("package"), "version": item.get("version"), "published_at": item.get("published_at")}
                    for item in clustered[:50]
                ],
            })
            break
    return {
        "ecosystem": "npm",
        "namespace": f"@{scope}",
        "total_recent_artifacts": len(rows),
        "unique_recent_packages": len(set(str(row.get("package")) for row in rows if row.get("package"))),
        "signals": signals,
    }


def _node_ipc_mitigation(package: str, versions: Iterable[str]) -> List[str]:
    version_list = ", ".join(f"{package}@{version}" for version in versions)
    return [
        f"Block affected versions: {version_list}.",
        "Audit package-lock.json, pnpm-lock.yaml, yarn.lock, npm-shrinkwrap.json, node_modules/node-ipc, CI runner caches, and container build layers.",
        "Rotate npm tokens, GitHub/GitLab tokens, cloud keys, SSH keys, CI/CD secrets, and developer-machine credentials if an affected version was installed or loaded.",
        "Search dependency manifests with: rg -n \"node-ipc|9\\.1\\.6|9\\.2\\.3|12\\.0\\.1\" package-lock.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json package.json .",
    ]


def package_compromise_mitigation(
    ecosystem: str,
    package: str,
    version: Optional[str] = None,
    advisory_matches: Optional[List[Dict[str, Any]]] = None,
) -> List[str]:
    ecosystem = canonical_ecosystem(ecosystem)
    package = normalize_package_name(ecosystem, package)
    versions: List[str] = []
    if version:
        versions.append(version)
    for match in advisory_matches or []:
        versions.extend(str(item) for item in match.get("matched_versions", []) or [])
        for affected in match.get("affected", []) or []:
            if str(affected.get("ecosystem", "")).lower() == ecosystem.lower() and str(affected.get("package", "")).lower() == package.lower():
                versions.extend(str(item) for item in affected.get("versions", []) or [])
    if ecosystem == "npm" and package == "node-ipc":
        detected_versions = {item for item in versions if re.fullmatch(r"\d+\.\d+\.\d+", item)}
        canonical_order = ["9.1.6", "9.2.3", "12.0.1"]
        affected_versions = [item for item in canonical_order if item in detected_versions] or canonical_order
        return _node_ipc_mitigation(package, [item for item in affected_versions if item])
    ecosystem_specific = {
        "crates": "Audit Cargo.lock, build.rs, proc-macro crates, cargo registry cache, and CI build logs.",
        "chrome-web-store": "Audit installed extension IDs, manifest permissions, service workers, and browser policy allowlists.",
        "packagist": "Audit composer.lock, vendor packages, Composer scripts, and PHP autoload paths.",
        "go": "Audit go.mod, go.sum, module cache, init() paths, and CI build logs.",
        "huggingface": "Audit model revisions, trust_remote_code usage, unsafe pickle artifacts, and inference runtime secrets.",
        "maven": "Audit pom.xml, dependency trees, local Maven cache, build plugins, and CI artifact layers.",
        "nuget": "Audit packages.lock.json, obj/project.assets.json, NuGet cache, PowerShell install scripts, and build targets.",
        "open-vsx": "Audit installed VS Code/Open VSX extensions, activation events, workspace trust, and extension host logs.",
        "rubygems": "Audit Gemfile.lock, gem cache, extconf/Rake hooks, and Bundler install logs.",
    }
    return [
        f"Block {ecosystem}:{package}@{version or '<affected-version>'} in package-manager policy, CI allowlists, and artifact proxies.",
        ecosystem_specific.get(ecosystem, "Audit lockfiles, local package caches, build caches, and container layers for the affected version."),
        "Rotate credentials only if the affected artifact was installed, imported, or executed in an environment with secrets.",
    ]


CAMPAIGN_MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "cargo.toml",
    "cargo.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "gradle.lockfile",
    "packages.lock.json",
    "packages.config",
    "gemfile",
    "gemfile.lock",
    "manifest.json",
    "extensions.json",
}

CAMPAIGN_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "tests",
    "data",
    "docs",
    "blog",
    "dist",
    "build",
    "target",
    ".next",
}


def _safe_str(value: Any) -> str:
    return " ".join(str(value or "").split())


def _defang_to_indicator(value: str) -> str:
    return (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
    )


def extract_campaign_iocs(values: Iterable[Any]) -> Dict[str, List[str]]:
    """Extract simple campaign indicators from operator/source text.

    This is intentionally deterministic and conservative. It supports defanged
    domains used in public reports, but does not fetch or enrich indicators.
    """
    text = "\n".join(_defang_to_indicator(str(value or "")) for value in values)
    domains = {
        item.lower().strip(".,;:()[]{}<>\"'")
        for item in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", text, re.IGNORECASE)
        if item.rsplit(".", 1)[-1].lower() not in {"html", "json", "js", "css", "png", "jpg", "jpeg", "svg", "md", "files"}
    }
    urls = {
        item.rstrip(".,;:()[]{}<>\"'")
        for item in re.findall(r"https?://[^\s)>\]\"']+", text, re.IGNORECASE)
    }
    ip_ports = {
        item
        for item in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", text)
    }
    ips = {
        item.split(":", 1)[0]
        for item in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b", text)
    }
    repo_descriptions = {
        item.strip()
        for item in re.findall(r"A Mini Sha1-Hulud has Appeared", text, re.IGNORECASE)
    }
    return {
        "domains": sorted(domains),
        "urls": sorted(urls),
        "ips": sorted(ips),
        "ip_ports": sorted(ip_ports),
        "repository_descriptions": sorted(repo_descriptions),
    }


DISCOVERY_SUPPLY_CHAIN_TERMS = (
    "supply chain",
    "supply-chain",
    "malicious package",
    "compromised package",
    "compromised",
    "backdoor",
    "rce",
    "remote code execution",
    "typosquat",
    "dependency confusion",
    "package manager",
    "npm",
    "pypi",
    "rubygems",
    "packagist",
    "composer",
    "autoload",
    "autoload.files",
    "php package",
    "tag rewrite",
    "tag-rewrite",
    "repointed tag",
    "historical versions",
    "crates.io",
    "maven",
    "nuget",
    "open vsx",
    "hugging face",
    "chrome web store",
    "stealer",
    "infostealer",
    "botnet",
    "credential theft",
    "c2",
    "exfiltration",
    "shai-hulud",
    "github token",
    "workflow token",
    "personal access token",
    "github breach",
    "source code",
    "repository download",
    "mass repo",
    "orphan commit",
    "unreachable commit",
    "dangling commit",
    "vs code extension",
    "vscode extension",
    "visual studio code marketplace",
    "extension marketplace",
    "marketplace extension",
)

DISCOVERY_BEHAVIOR_KEYWORDS = {
    "credential theft": ("credential", "token", "secret", "ssh key", "api key"),
    "environment variable harvesting": ("environment variable", "process.env", "os.environ", "env var"),
    "cloud credential harvesting": ("cloud credential", "aws", "gcp", "azure", ".aws", ".config/gcloud"),
    "GitHub token abuse": ("github token", "github api", "repository creation", "public repository"),
    "GitHub repository/code download": ("downloaded repositories", "source code", "repo enumeration", "mass repo", "github repositories"),
    "orphan commit delivery": ("orphan commit", "orphaned commit", "unreachable commit", "dangling commit", "unsigned commit"),
    "VS Code extension compromise": ("vs code extension", "vscode extension", "vs code developers", "visual studio code marketplace", "openvsx", "open vsx", "extension activation", "extension fetched"),
    "DNS tunneling or HTTPS exfiltration": ("dns tunneling", "dns exfil", "https exfil", "github api", "dead drop", "dead-drop"),
    "outbound C2 communication": ("c2", "command and control", "exfiltration", "exfiltrate"),
    "botnet or DDoS behavior": ("botnet", "ddos", "tcp flood", "udp flood", "http flood"),
    "persistence": ("persistence", "startup", "scheduled task", "launch agent", "cron"),
    "obfuscation": ("obfuscated", "base64", "eval", "packed payload", "encoded payload"),
    "install-time execution": ("postinstall", "preinstall", "setup.py", "build.rs", "install.ps1", "composer scripts"),
    "composer autoload backdoor": ("autoload.files", "composer autoload", "src/helpers.php", "php package"),
    "tag rewrite/provenance anomaly": ("tag rewrite", "repointed tag", "historical tags", "historical versions", "fork commit"),
    "remote code execution backdoor": ("rce", "remote code execution", "backdoor"),
    "module-load execution": ("import-time", "module-load", "iife", "when imported"),
    "Shai-Hulud clone or derivative indicator": ("shai-hulud", "sha1-hulud", "mini shai", "mini sha1"),
    "typosquatting package-name indicator": ("typosquat", "typo-squatting", "clone package"),
}

DISCOVERY_ECOSYSTEM_HINTS = {
    "npm": ("npm", "node.js", "node package", "package.json", "javascript package"),
    "pypi": ("pypi", "python package", "pip", "wheel", "sdist"),
    "crates": ("crates.io", "rust crate", "cargo"),
    "packagist": ("packagist", "composer", "php package"),
    "go": ("go module", "golang", "go package"),
    "huggingface": ("hugging face", "huggingface", "model hub", "model repository"),
    "maven": ("maven central", "maven", "java package", "jar"),
    "nuget": ("nuget", ".net package", "powershell package"),
    "open-vsx": ("open vsx", "vs code extension", "vscode extension"),
    "github": ("github repository", "github repositories", "github token", "github api", "source code repository", "orphan commit"),
    "rubygems": ("rubygems", "ruby gem", "gem package"),
    "chrome-web-store": ("chrome web store", "chrome extension", "crx"),
}

CAMPAIGN_PACKAGE_EXTRACTION_NOISE = {
    "overview",
    "description",
    "impact",
    "solution",
    "mitigation",
    "mitigations",
    "acknowledgment",
    "acknowledgments",
    "acknowledgement",
    "acknowledgements",
    "byline-author",
    "separator",
    "ltr",
    "presentation",
    "font-family",
    "sans-serif",
    "font-size",
    "font-weight",
    "font-variant-alternates",
    "font-variant-east-asian",
    "font-variant-emoji",
    "font-variant-numeric",
    "font-variant-position",
    "vertical-align",
    "white-space-collapse",
    "line-height",
    "margin-bottom",
    "margin-top",
    "margin-left",
    "padding-inline-start",
    "text-decoration-line",
    "text-decoration-skip-ink",
    "all-time",
    "inline-block",
    "aria-level",
    "list-style-type",
    "white-space",
    "text-wrap-mode",
    "open-source",
    "out-of-bounds",
    "gpt-generated",
    "user-supplied",
    "ai-assisted",
    "web-based",
    "content-serving",
    "attacker-controlled",
    "drc-managed",
    "host-based",
    "chrome-friends",
    "unsafe.slice",
    "denial-of-service",
    "remote-code-execution",
    "credential-stealing",
    "credential-theft",
    "credential-harvesting",
    "secret-stealing",
    "token-stealing",
    "local-privilege-escalation",
    "privilege-escalation",
}

CAMPAIGN_ACTOR_EXTRACTION_NOISE = {
    "actor",
    "known",
    "unknown",
    "publisher",
    "maintainer",
    "author",
    "group",
    "team",
    "user",
}

CAMPAIGN_SOURCE_REFERENCE_DOMAINS = {
    "thehackernews.com",
    "www.thehackernews.com",
    "security.googleblog.com",
    "blog.google",
    "blog.chromium.org",
    "blogger.googleusercontent.com",
    "kb.cert.org",
    "cert.org",
    "certcc.github.io",
    "cisa.gov",
    "nvd.nist.gov",
    "cve.org",
    "www.cve.org",
    "github.com",
    "research.jfrog.com",
    "jfrog.com",
    "socket.dev",
    "theori.io",
    "checkmarx.com",
    "reversinglabs.com",
    "snyk.io",
    "wiz.io",
    "microsoft.com",
    "msrc.microsoft.com",
    "cloudflare.com",
    "copy.fail",
}

CAMPAIGN_MALWARE_APT_TERMS = (
    "apt",
    "threat actor",
    "china-aligned",
    "nation-state",
    "malware",
    "backdoor",
    "webworm",
    "echocreep",
    "graphworm",
    "command-and-control",
    "command and control",
    "c2",
    "c&c",
)

CAMPAIGN_VULNERABILITY_TERMS = (
    "cve-",
    "vulnerability",
    "vulnerable",
    "remote code execution",
    "path traversal",
    "memory leak",
    "out-of-bounds",
    "denial of service",
    "vu#",
)

CAMPAIGN_GITHUB_BREACH_TERMS = (
    "github breach",
    "stolen github token",
    "github token",
    "personal access token",
    "downloaded repositories",
    "source code",
    "mass repo",
    "repository download",
    "orphan commit",
    "unreachable commit",
    "dangling commit",
)

CAMPAIGN_EXTENSION_TERMS = (
    "vs code extension",
    "vscode extension",
    "visual studio code marketplace",
    "open vsx",
    "open-vsx",
    "extension marketplace",
    "nx console",
)

CAMPAIGN_SUPPLY_CHAIN_TERMS = (
    "supply chain",
    "supply-chain",
    "malicious package",
    "compromised package",
    "package compromise",
    "dependency confusion",
    "typosquat",
    "registry",
    "npm",
    "pypi",
    "rubygems",
    "packagist",
    "composer",
    "php package",
    "autoload",
    "autoload.files",
    "rce",
    "remote code execution",
    "backdoor",
    "tag rewrite",
    "repointed tag",
    "historical versions",
    "crates.io",
    "maven",
    "nuget",
    "postinstall",
    "install script",
    "package manager",
)


def _slug(value: str, *, limit: int = 96) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return (slug or "campaign")[:limit].strip("-") or "campaign"


def _load_json_file(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    return default


def _write_json_file(path: Path, payload: Any) -> None:
    _ensure_dirs()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _discovery_text_values(payload: Dict[str, Any]) -> List[str]:
    values = [
        payload.get("title"),
        payload.get("summary"),
        payload.get("description"),
        payload.get("content"),
        payload.get("source_name"),
        payload.get("source_url"),
        payload.get("url"),
    ]
    values.extend(payload.get("behavioral_indicators", []) or [])
    values.extend(payload.get("source_urls", []) or [])
    return [str(value) for value in values if value]


def load_campaign_watchlist(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or CAMPAIGN_WATCHLIST_PATH
    payload = _load_json_file(path, {})
    if not isinstance(payload, dict):
        payload = {}
    return {
        "updated_at": payload.get("updated_at"),
        "packages": [str(item) for item in payload.get("packages", []) if item],
        "publishers": [str(item) for item in payload.get("publishers", []) if item],
        "iocs": [str(item) for item in payload.get("iocs", []) if item],
        "source_urls": [str(item) for item in payload.get("source_urls", []) if item],
    }


def save_campaign_watchlist(payload: Dict[str, Any], path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or CAMPAIGN_WATCHLIST_PATH
    cleaned = {
        "updated_at": _utc_now(),
        "packages": sorted(set(str(item) for item in payload.get("packages", []) if item)),
        "publishers": sorted(set(str(item) for item in payload.get("publishers", []) if item)),
        "iocs": sorted(set(str(item) for item in payload.get("iocs", []) if item)),
        "source_urls": sorted(set(str(item) for item in payload.get("source_urls", []) if item)),
    }
    _write_json_file(path, cleaned)
    return cleaned


def campaign_watchlist_add(
    *,
    package: Optional[str] = None,
    publisher: Optional[str] = None,
    ioc: Optional[str] = None,
    source_url: Optional[str] = None,
    path: Optional[Path] = None,
) -> Dict[str, Any]:
    watchlist = load_campaign_watchlist(path)
    if package:
        watchlist.setdefault("packages", []).append(_safe_str(package))
    if publisher:
        watchlist.setdefault("publishers", []).append(_safe_str(publisher))
    if ioc:
        watchlist.setdefault("iocs", []).append(_defang_to_indicator(_safe_str(ioc)))
    if source_url:
        watchlist.setdefault("source_urls", []).append(_safe_str(source_url))
    return save_campaign_watchlist(watchlist, path)


def campaign_watchlist_list(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or CAMPAIGN_WATCHLIST_PATH
    watchlist = load_campaign_watchlist(path)
    watchlist["path"] = str(path)
    return watchlist


def load_campaign_candidates(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or CAMPAIGN_CANDIDATES_PATH
    payload = _load_json_file(path, {"candidates": []})
    if not isinstance(payload, dict):
        payload = {"candidates": []}
    payload.setdefault("candidates", [])
    refreshed: List[Dict[str, Any]] = []
    for candidate in payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        try:
            refreshed.append(orchestrate_campaign_candidate(candidate))
        except Exception:
            refreshed.append(candidate)
    payload["candidates"] = refreshed
    return payload


def save_campaign_candidates(candidates: List[Dict[str, Any]], path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or CAMPAIGN_CANDIDATES_PATH
    payload = {
        "updated_at": _utc_now(),
        "total": len(candidates),
        "candidates": candidates,
    }
    _write_json_file(path, payload)
    return payload


def _watchlist_matches(campaign: Dict[str, Any], watchlist: Dict[str, Any]) -> List[Dict[str, str]]:
    values = " ".join(_discovery_text_values(campaign)).lower()
    matches: List[Dict[str, str]] = []
    package_labels = {
        f"{pkg.get('ecosystem')}:{pkg.get('package')}".lower(): str(pkg.get("package"))
        for pkg in campaign.get("packages", [])
    }
    for item in watchlist.get("packages", []):
        lowered = str(item).lower()
        if lowered in values or any(lowered in key or lowered in value.lower() for key, value in package_labels.items()):
            matches.append({"type": "package", "value": str(item)})
    for item in watchlist.get("publishers", []):
        if str(item).lower() in values:
            matches.append({"type": "publisher", "value": str(item)})
    flattened_iocs = " ".join(_flatten_iocs(campaign.get("iocs", {}))).lower()
    for item in watchlist.get("iocs", []):
        if str(item).lower() in values or str(item).lower() in flattened_iocs:
            matches.append({"type": "ioc", "value": str(item)})
    for item in watchlist.get("source_urls", []):
        if str(item).lower() in values:
            matches.append({"type": "source_url", "value": str(item)})
    return matches


def _discovery_behavior_indicators(text: str) -> List[str]:
    lowered = text.lower()
    indicators: List[str] = []
    for label, needles in DISCOVERY_BEHAVIOR_KEYWORDS.items():
        if any(needle in lowered for needle in needles):
            indicators.append(label)
    return sorted(set(indicators))


def _infer_ecosystems_from_text(text: str) -> List[str]:
    lowered = text.lower()
    ecosystems = [
        ecosystem
        for ecosystem, hints in DISCOVERY_ECOSYSTEM_HINTS.items()
        if any(hint in lowered for hint in hints)
    ]
    return sorted(set(ecosystems))


def _looks_like_campaign_package_noise(ecosystem: str, name: str) -> bool:
    normalized = str(name or "").strip().lower()
    if not normalized:
        return True
    if normalized in {"@scope/pkg", "group:artifact", "org/model", "package-name", "package_name"}:
        return True
    if normalized in CAMPAIGN_PACKAGE_EXTRACTION_NOISE:
        return True
    if re.fullmatch(r"\d+(?:\.\d+)?", normalized):
        return True
    if re.fullmatch(r"cve-\d{4}-\d{4,}\.?", normalized):
        return True
    if re.fullmatch(r"docs-internal-guid-[a-f0-9-]{20,}", normalized):
        return True
    if re.search(r"\.(?:png|jpe?g|gif|webp|svg|html?|css|js)$", normalized):
        return True
    if normalized.startswith(("http://", "https://", "www.")):
        return True
    if re.match(r"^[a-z0-9.-]+\.(?:com|org|net|io|dev|gov|edu|life|app|co)(?:/|$)", normalized):
        return True
    if len(normalized) > 90 and "/" not in normalized:
        return True
    if len(normalized) > 55 and normalized.count("-") > 6 and not normalized.startswith("@"):
        return True
    if normalized.startswith(("docs-internal-guid-", "language-", "data-original-")):
        return True
    if normalized.startswith(("font-", "margin-", "padding-", "text-", "white-space")):
        return True
    if ecosystem == "npm" and "/" in normalized and not normalized.startswith("@") and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}/", normalized):
        return True
    if ecosystem == "go" and re.search(r"/(?:issues|pulls|actions|blob|tree)(?:/|$)", normalized):
        return True
    return False


def _has_campaign_package_context(text: str, start: int, end: int, ecosystem: str) -> bool:
    window = text[max(0, start - 120): min(len(text), end + 120)].lower()
    if ecosystem == "npm":
        return any(
            marker in window
            for marker in (
                "npm",
                "node package",
                "node packages",
                "package name",
                "package names",
                "packages",
                "malicious package",
                "malicious packages",
                "published package",
                "typosquat",
                "typosquatting",
                "registry",
            )
        )
    return any(marker in window for marker in ("package", "packages", "module", "modules", "artifact", "artifacts", "registry"))


def _extract_campaign_packages_from_text(text: str) -> List[Dict[str, Any]]:
    packages: List[Dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    lowered = text.lower()
    default_ecosystems = _infer_ecosystems_from_text(text)

    def add_package(ecosystem: str, raw_name: str, version: str = "unknown") -> None:
        ecosystem = canonical_ecosystem(ecosystem)
        name = normalize_package_name(ecosystem, raw_name)
        if _looks_like_campaign_package_noise(ecosystem, name):
            return
        key = (ecosystem, name, version or "unknown")
        if key in seen:
            return
        if not validate_package_identifier(ecosystem, name).get("valid"):
            return
        seen.add(key)
        packages.append({"ecosystem": ecosystem, "package": name, "version": version or "unknown"})

    patterns: List[tuple[str, str]] = [
        ("crates", r"\bcrates\.io/crates/([A-Za-z0-9_-]{2,80})(?:[/#?]|$)"),
        ("packagist", r"\bpackagist\.org/packages/([a-z0-9_.-]+/[a-z0-9_.-]+)(?:[/#?]|$)"),
        ("packagist", r"(?<![./\w-])([a-z0-9_.-]+/[a-z0-9_.-]+)(?:@([0-9][A-Za-z0-9.+:_~!-]{0,80}))?\b"),
        ("npm", r"(?<![\w.-])(@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*[-_.][a-z0-9][a-z0-9._-]*)(?:@([0-9][A-Za-z0-9.+:_~!-]{0,80}))?"),
        ("pypi", r"\b([a-z0-9][a-z0-9._-]{2,80})(?:==|@)([0-9][A-Za-z0-9.+:_~!-]{0,80})\b"),
        ("maven", r"\b([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+)(?:[:@]([0-9][A-Za-z0-9.+:_~!-]{0,80}))?\b"),
        ("go", r"\b((?:github|gitlab|bitbucket)\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.:/-]+)(?:@([vV]?[0-9][A-Za-z0-9.+:_~!-]{0,80}))?\b"),
        ("open-vsx", r"\b([a-z][a-z0-9_-]{1,50}\.[a-z][a-z0-9_.-]{1,80})\s*(?:extension)?\s*(?:version\s*)?([0-9][A-Za-z0-9.+:_~!-]{0,80})\b"),
        ("github", r"\bgithub\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?=[\s,.;:)\\\]]|[/#?]|$)"),
    ]
    extension_aliases = {
        "nx console": "nrwl.angular-console",
    }
    if "vs code" in lowered or "vscode" in lowered or "visual studio code" in lowered or "openvsx" in lowered:
        for alias, identifier in extension_aliases.items():
            if alias in lowered:
                version_match = re.search(rf"{re.escape(alias)}(?:\s+extension)?(?:\s+version)?\s+([0-9][A-Za-z0-9.+:_~!-]{{0,80}})", text, re.IGNORECASE)
                add_package("open-vsx", identifier, version_match.group(1) if version_match else "unknown")
    quoted = re.findall(r"['\"`]([@A-Za-z0-9][@A-Za-z0-9._:/-]{2,120})['\"`]", text)
    for raw in quoted:
        if raw.startswith(("http:", "https:")):
            continue
        if not default_ecosystems and not raw.startswith("@") and "npm" not in lowered:
            continue
        if "/" in raw and raw.count("/") == 1 and not raw.startswith("@"):
            ecosystem = "packagist" if "packagist" in lowered or "composer" in lowered else default_ecosystems[0]
        elif raw.startswith("@") or "npm" in lowered:
            ecosystem = "npm"
        else:
            ecosystem = default_ecosystems[0]
        if not raw.startswith("@") and "/" not in raw:
            raw_index = text.find(raw)
            if raw_index >= 0 and not _has_campaign_package_context(text, raw_index, raw_index + len(raw), ecosystem):
                continue
        add_package(ecosystem, raw, "unknown")

    for ecosystem_hint, pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            raw_name = match.group(1)
            if not raw_name:
                continue
            if ecosystem_hint == "packagist" and "packagist" not in default_ecosystems:
                continue
            if ecosystem_hint == "npm" and "npm" not in default_ecosystems and not raw_name.startswith("@"):
                continue
            if ecosystem_hint == "npm" and not raw_name.startswith("@") and not _has_campaign_package_context(text, match.start(1), match.end(1), ecosystem_hint):
                continue
            if ecosystem_hint == "maven" and "maven" not in default_ecosystems and not _has_campaign_package_context(text, match.start(1), match.end(1), ecosystem_hint):
                continue
            if ecosystem_hint == "npm" and raw_name.lower() in {
                "security", "package", "packages", "registry", "versions", "malware", "credentials",
                "github", "windows", "linux", "remote", "server", "source", "article", "follow", "google",
                "supply-chain", "thehackernews.com", "lhr.life",
            }:
                continue
            ecosystem = ecosystem_hint
            version = match.group(2) if (match.lastindex or 0) >= 2 and match.group(2) else "unknown"
            add_package(ecosystem, raw_name, version)
    return packages[:40]


def _extract_actors_from_text(text: str) -> List[str]:
    actors: set[str] = set()
    patterns = [
        r"(?:known as|tracked as|called)\s+['\"]?([A-Z][A-Za-z0-9_.-]{3,80})['\"]?",
        r"(?:published by|npm user|publisher|maintainer|actor|threat actor)\s+['\"]?([@A-Za-z0-9_.-]{3,80})['\"]?",
        r"same\s+(?:npm\s+)?user,\s*['\"]([@A-Za-z0-9_.-]{3,80})['\"]",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            label = match.group(1).strip("@'\"")
            if label.lower() not in CAMPAIGN_ACTOR_EXTRACTION_NOISE:
                actors.add(label)
    return sorted(actors)


def _candidate_score(campaign: Dict[str, Any], watchlist_matches: List[Dict[str, str]]) -> tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0
    packages = campaign.get("packages", [])
    iocs = campaign.get("iocs", {})
    behaviors = campaign.get("behavioral_indicators", [])
    if packages:
        score += 20
        reasons.append("package identifiers extracted")
    if any(pkg.get("version") and pkg.get("version") != "unknown" for pkg in packages):
        score += 12
        reasons.append("exact package version mentioned")
    if iocs:
        score += min(20, len(_flatten_iocs(iocs)) * 4)
        reasons.append("IOC/C2 indicators extracted")
    behavior_text = " ".join(behaviors).lower()
    for needle, weight in (
        ("credential", 12),
        ("botnet", 12),
        ("persistence", 10),
        ("shai-hulud", 10),
        ("c2", 8),
        ("install-time", 8),
        ("module-load", 8),
        ("typosquatting", 6),
    ):
        if needle in behavior_text:
            score += weight
            reasons.append(f"{needle} behavior signal")
    if watchlist_matches:
        score += min(20, len(watchlist_matches) * 8)
        reasons.append("watchlist overlap")
    source_count = len(campaign.get("source_urls", []) or [])
    if source_count:
        score += min(10, source_count * 5)
        reasons.append("trusted source reference")
    return min(100, score), sorted(set(reasons))


def _campaign_id_from_source(title: str, source_url: str, packages: List[Dict[str, Any]]) -> str:
    base = title or source_url or "autonomous-campaign"
    if packages:
        base = f"{packages[0]['package']}-{base}"
    digest = hashlib.sha256(f"{base}|{source_url}".encode("utf-8")).hexdigest()[:10]
    return f"{_slug(base, limit=64)}-{digest}"


def campaign_intake(
    *,
    url: Optional[str] = None,
    text: Optional[str] = None,
    title: Optional[str] = None,
    source_name: Optional[str] = None,
    source_url: Optional[str] = None,
    watchlist: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    fetched_text = ""
    effective_url = source_url or url or ""
    if url and not text:
        fetched_text = _http_text(url, timeout=20)
    raw_text = "\n".join(value for value in [title or "", text or "", fetched_text] if value)
    raw_text = raw_text[:120000]
    if text:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict) and parsed.get("packages"):
                campaign = normalize_campaign_input(parsed)
                active_watchlist = watchlist if watchlist is not None else load_campaign_watchlist()
                matches = _watchlist_matches(campaign, active_watchlist)
                score, reasons = _candidate_score(campaign, matches)
                return orchestrate_campaign_candidate({
                    "candidate_id": campaign["campaign_id"],
                    "campaign": campaign,
                    "score": score,
                    "score_reasons": reasons,
                    "watchlist_matches": matches,
                    "source_url": (campaign.get("source_urls") or [effective_url or ""])[0],
                    "source_name": (campaign.get("source_names") or [source_name or ""])[0],
                    "raw_excerpt": raw_text[:2000],
                })
        except Exception:
            pass
    packages = _extract_campaign_packages_from_text(raw_text)
    iocs = _merge_iocs(raw_text)
    actors = _extract_actors_from_text(raw_text)
    behaviors = _discovery_behavior_indicators(raw_text)
    inferred_ecosystems = sorted(set([pkg["ecosystem"] for pkg in packages] or _infer_ecosystems_from_text(raw_text)))
    derived_title = _safe_str(title or (raw_text.splitlines()[0] if raw_text.splitlines() else "") or "Autonomous supply-chain campaign candidate")
    summary = _safe_str(raw_text[:900])
    campaign = normalize_campaign_input({
        "campaign_id": _campaign_id_from_source(derived_title, effective_url, packages),
        "title": derived_title[:240],
        "summary": summary,
        "ecosystems": inferred_ecosystems,
        "packages": packages,
        "actors": actors,
        "publishers": actors,
        "source_urls": [effective_url] if effective_url else [],
        "source_names": [source_name] if source_name else [],
        "iocs": iocs,
        "behavioral_indicators": behaviors,
        "severity": "critical" if {"credential theft", "botnet or DDoS behavior"} & set(behaviors) else "high",
        "confidence": "medium",
    })
    active_watchlist = watchlist if watchlist is not None else load_campaign_watchlist()
    matches = _watchlist_matches(campaign, active_watchlist)
    score, reasons = _candidate_score(campaign, matches)
    candidate = {
        "candidate_id": campaign["campaign_id"],
        "campaign": campaign,
        "score": score,
        "score_reasons": reasons,
        "watchlist_matches": matches,
        "source_url": effective_url,
        "source_name": source_name or "",
        "raw_excerpt": raw_text[:2000],
    }
    return orchestrate_campaign_candidate(candidate)


def _campaign_text_for_classification(candidate: Dict[str, Any], campaign: Dict[str, Any]) -> str:
    values = [
        candidate.get("candidate_id"),
        candidate.get("source_name"),
        candidate.get("source_url"),
        candidate.get("raw_excerpt"),
        campaign.get("campaign_id"),
        campaign.get("title"),
        campaign.get("summary"),
    ]
    values.extend(campaign.get("behavioral_indicators", []) or [])
    values.extend(campaign.get("source_names", []) or [])
    values.extend(campaign.get("source_urls", []) or [])
    return " ".join(str(value) for value in values if value).lower()


def _classify_campaign_candidate(
    *,
    candidate: Dict[str, Any],
    campaign: Dict[str, Any],
    packages: List[Dict[str, Any]],
    iocs: Dict[str, List[str]],
) -> Dict[str, Any]:
    text = _campaign_text_for_classification(candidate, campaign)
    ecosystems = {str(pkg.get("ecosystem") or "") for pkg in packages}
    package_artifacts = [pkg for pkg in packages if str(pkg.get("ecosystem") or "") != "github"]
    github_repos = [pkg for pkg in packages if str(pkg.get("ecosystem") or "") == "github"]
    has_packages = bool(package_artifacts)
    has_github_repos = bool(github_repos)
    has_extension = "open-vsx" in ecosystems or any(term in text for term in CAMPAIGN_EXTENSION_TERMS)
    has_github_signal = any(term in text for term in CAMPAIGN_GITHUB_BREACH_TERMS)
    has_malware_apt = any(term in text for term in CAMPAIGN_MALWARE_APT_TERMS)
    has_strong_vulnerability = any(term in text for term in ("cve-", "vu#", "vulnerability", "vulnerable"))
    has_vulnerability = has_strong_vulnerability or (
        any(term in text for term in CAMPAIGN_VULNERABILITY_TERMS) and not has_malware_apt
    )
    has_supply_chain = any(term in text for term in CAMPAIGN_SUPPLY_CHAIN_TERMS)
    route_blockers: List[str] = []

    if has_extension:
        campaign_type = "vscode_extension_compromise"
        recommended_route = "extension_security_review"
        supply_chain_relevance = "medium" if has_packages else "low"
    elif has_packages and has_supply_chain:
        campaign_type = "supply_chain_package_campaign"
        recommended_route = "campaign_research"
        supply_chain_relevance = "high"
    elif has_packages:
        campaign_type = "malicious_package" if iocs or campaign.get("behavioral_indicators") else "package_compromise"
        recommended_route = "campaign_research"
        supply_chain_relevance = "medium"
    elif has_github_signal:
        campaign_type = "github_token_breach"
        recommended_route = "github_security_review"
        supply_chain_relevance = "low"
    elif has_vulnerability:
        campaign_type = "vulnerability_advisory"
        recommended_route = "vulnerability_tracking"
        supply_chain_relevance = "low" if not has_github_repos else "context_only"
    elif has_malware_apt:
        campaign_type = "malware_apt_c2"
        recommended_route = "threat_intel_review"
        supply_chain_relevance = "low"
    else:
        campaign_type = "general_threat_intel"
        recommended_route = "needs_human_review"
        supply_chain_relevance = "unknown"

    if not has_packages and recommended_route == "campaign_research":
        route_blockers.append("no validated package or extension artifacts")
    if not has_packages and recommended_route != "campaign_research":
        route_blockers.append("not a package supply-chain campaign")
    if has_github_repos and not has_packages and recommended_route != "github_security_review":
        route_blockers.append("github repositories are project context, not package artifacts")
    if not _flatten_iocs(iocs) and campaign_type in {"malware_apt_c2", "general_threat_intel"}:
        route_blockers.append("no attacker infrastructure IOC validated")

    if recommended_route == "campaign_research" and has_packages:
        allowed_actions = ["copy_cli_fallback", "run_campaign_research", "check_local_usage"]
        blocked_actions: Dict[str, str] = {}
    else:
        allowed_actions = ["copy_cli_fallback", "add_validated_watchlist_items"]
        blocked_actions = {
            "promote_to_campaign_research": "Candidate is not routed to package Campaign Research.",
            "persist_findings": "Persistence requires validated package/extension evidence and analyst approval.",
            "create_blog_draft": "Drafting requires a supported route and minimum evidence.",
        }

    confidence = "high" if has_packages and (has_supply_chain or has_extension) else "medium" if (has_malware_apt or has_vulnerability or has_github_signal or iocs or has_github_repos) else "low"
    missing_evidence = []
    if not has_packages:
        missing_evidence.append("validated package or extension artifact")
    if not _flatten_iocs(iocs):
        missing_evidence.append("validated attacker IOC")

    return {
        "campaign_type": campaign_type,
        "recommended_route": recommended_route,
        "supply_chain_relevance": supply_chain_relevance,
        "confidence": confidence,
        "route_blockers": route_blockers,
        "allowed_actions": allowed_actions,
        "blocked_actions": blocked_actions,
        "missing_evidence": missing_evidence,
    }


def orchestrate_campaign_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    raw_campaign = candidate.get("campaign") or {}
    campaign = normalize_campaign_input(raw_campaign)
    source_urls = sorted(set([
        *(str(url) for url in campaign.get("source_urls", []) if url),
        str(candidate.get("source_url") or ""),
    ]))
    source_urls = [url for url in source_urls if url]
    validated_packages, rejected_packages = _validate_campaign_package_rows(campaign.get("packages", []))
    raw_iocs = _merge_iocs(raw_campaign.get("iocs"), raw_campaign.get("summary"), raw_campaign.get("behavioral_indicators"))
    validated_iocs, rejected_iocs, source_references = _clean_iocs_for_sources(raw_iocs, source_urls)
    actors, rejected_actors = _clean_actor_values(raw_campaign.get("actors", campaign.get("actors", [])))
    publishers, rejected_publishers = _clean_actor_values(raw_campaign.get("publishers", campaign.get("publishers", [])))
    cleaned_campaign = {
        **campaign,
        "ecosystems": sorted(set(str(pkg.get("ecosystem")) for pkg in validated_packages if pkg.get("ecosystem"))),
        "packages": validated_packages,
        "actors": actors,
        "publishers": publishers,
        "iocs": validated_iocs,
        "source_urls": source_urls,
    }
    route = _classify_campaign_candidate(
        candidate=candidate,
        campaign=cleaned_campaign,
        packages=validated_packages,
        iocs=validated_iocs,
    )
    score, reasons = _candidate_score(cleaned_campaign, candidate.get("watchlist_matches", []))
    if route["recommended_route"] != "campaign_research" and not validated_packages:
        score = min(score, 35 if route["campaign_type"] in {"malware_apt_c2", "vulnerability_advisory", "github_token_breach"} else 25)
    explanation = (
        "Candidate has validated package/extension evidence and can be researched as a supply-chain campaign."
        if route["recommended_route"] == "campaign_research"
        else f"Candidate appears to be {route['campaign_type'].replace('_', ' ')}; keep it out of package Campaign Research until package evidence exists."
    )
    orchestrator = {
        "candidate_id": candidate.get("candidate_id") or cleaned_campaign.get("campaign_id"),
        "title": cleaned_campaign.get("title"),
        "summary": cleaned_campaign.get("summary"),
        "source_urls": source_urls,
        "source_names": cleaned_campaign.get("source_names", []),
        "score": score,
        "score_reasons": reasons,
        **route,
        "validated_packages": validated_packages,
        "rejected_package_candidates": rejected_packages,
        "validated_iocs": validated_iocs,
        "rejected_iocs": rejected_iocs,
        "source_references": source_references,
        "actors": actors,
        "rejected_actors": rejected_actors,
        "publishers": publishers,
        "rejected_publishers": rejected_publishers,
        "malware_names": sorted(set(re.findall(r"\b(?:Webworm|EchoCreep|GraphWorm|Shai-Hulud|Sha1-Hulud)\b", _campaign_text_for_classification(candidate, cleaned_campaign), re.IGNORECASE))),
        "cves": sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", _campaign_text_for_classification(candidate, cleaned_campaign), re.IGNORECASE))),
        "ghsas": sorted(set(re.findall(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", _campaign_text_for_classification(candidate, cleaned_campaign), re.IGNORECASE))),
        "extension_ids": sorted(set(pkg["package"] for pkg in validated_packages if pkg.get("ecosystem") == "open-vsx")),
        "github_repos": sorted(set(pkg["package"] for pkg in validated_packages if pkg.get("ecosystem") == "github")),
        "behavior_indicators": cleaned_campaign.get("behavioral_indicators", []),
        "explanation": explanation,
        "recommended_next_action": (
            "Run Campaign Research, then review package verdicts before persisting."
            if route["recommended_route"] == "campaign_research"
            else "Review as a threat-intel lead or add only validated attacker IOCs/packages to the watchlist."
        ),
    }
    return {
        **candidate,
        "candidate_id": orchestrator["candidate_id"],
        "campaign": cleaned_campaign,
        "score": score,
        "score_reasons": reasons,
        "orchestrator": orchestrator,
    }


def _parse_feed_items(text: str, source: Dict[str, Any], *, limit: int) -> List[Dict[str, Any]]:
    source_type = str(source.get("type") or "rss").lower()
    items: List[Dict[str, Any]] = []
    if source_type == "html" or text.lstrip()[:200].lower().startswith("<!doctype html") or "<html" in text[:500].lower():
        for match in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', text, re.IGNORECASE | re.DOTALL):
            href = match.group(1)
            label = re.sub(r"<[^>]+>", " ", match.group(2))
            title = " ".join(label.split())
            if not title or len(title) < 8:
                continue
            if href.startswith("/"):
                parsed = urllib.parse.urlparse(str(source.get("url") or source.get("feed_url") or ""))
                href = f"{parsed.scheme}://{parsed.netloc}{href}" if parsed.netloc else href
            items.append({
                "title": title[:240],
                "summary": title[:500],
                "url": href,
                "published_at": None,
                "source": source,
            })
            if len(items) >= limit:
                break
        return items[:limit]
    if source_type == "json":
        payload = json.loads(text)
        rows: Iterable[Any]
        if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
            rows = payload["vulnerabilities"]
        elif isinstance(payload, dict) and isinstance(payload.get("items"), list):
            rows = payload["items"]
        elif isinstance(payload, list):
            rows = payload
        else:
            rows = []
        for row in list(rows)[:limit]:
            if not isinstance(row, dict):
                continue
            title = row.get("title") or row.get("name") or row.get("cveID") or row.get("id") or source.get("name")
            summary = row.get("summary") or row.get("description") or row.get("shortDescription") or row.get("notes") or ""
            url = row.get("url") or row.get("link") or row.get("knownRansomwareCampaignUse") or source.get("url") or source.get("feed_url")
            published = row.get("dateAdded") or row.get("published_at") or row.get("published") or row.get("updated")
            items.append({"title": title, "summary": summary, "url": url, "published_at": published, "source": source})
        return items
    root = ET.fromstring(text)
    for item in root.findall(".//item")[:limit]:
        title = item.findtext("title") or source.get("name")
        link = item.findtext("link") or item.findtext("guid") or source.get("url") or source.get("feed_url")
        summary = item.findtext("description") or item.findtext("summary") or ""
        published = item.findtext("pubDate") or item.findtext("updated") or item.findtext("published")
        items.append({"title": title, "summary": summary, "url": link, "published_at": published, "source": source})
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//atom:entry", ns)[:limit]:
        title = entry.findtext("atom:title", default="", namespaces=ns) or source.get("name")
        link_node = entry.find("atom:link[@href]", ns) or entry.find("atom:link", ns)
        link = link_node.get("href") if link_node is not None else source.get("url") or source.get("feed_url")
        summary = entry.findtext("atom:summary", default="", namespaces=ns) or entry.findtext("atom:content", default="", namespaces=ns)
        published = entry.findtext("atom:published", default="", namespaces=ns) or entry.findtext("atom:updated", default="", namespaces=ns)
        items.append({"title": title, "summary": summary, "url": link, "published_at": published, "source": source})
    return items[:limit]


def _poll_hint_to_seconds(value: Any) -> int:
    hint = str(value or "").strip().lower()
    if hint == "hourly":
        return 3600
    if hint == "daily":
        return 86400
    if hint == "weekly":
        return 604800
    match = re.fullmatch(r"(\d+)\s*([smhdw])", hint)
    if not match:
        return 86400
    amount = int(match.group(1))
    unit = match.group(2)
    return amount * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]


def _load_discovery_sources() -> List[Dict[str, Any]]:
    payload = _load_json_file(BLOG_NEWS_SOURCES_PATH, {"sources": []})
    sources = payload.get("sources", []) if isinstance(payload, dict) else []
    cleaned: List[Dict[str, Any]] = []
    for source in sources:
        if not isinstance(source, dict) or source.get("enabled") is False:
            continue
        feed_url = str(source.get("feed_url") or source.get("url") or "")
        if not feed_url.startswith(("http://", "https://")):
            continue
        cleaned.append(source)
    return cleaned


def _cached_news_items(limit: int) -> List[Dict[str, Any]]:
    payload = _load_json_file(BLOG_NEWS_CACHE_PATH, {"items": []})
    rows = payload.get("items", []) if isinstance(payload, dict) else []
    items: List[Dict[str, Any]] = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        source = {
            "name": row.get("source_name") or "SecOpsAI news cache",
            "url": row.get("source_url") or row.get("url"),
            "feed_url": row.get("source_url") or row.get("url"),
            "type": row.get("source_type") or "cache",
        }
        items.append({
            "title": row.get("title"),
            "summary": row.get("summary"),
            "url": row.get("canonical_url") or row.get("url"),
            "published_at": row.get("published_at"),
            "source": source,
        })
    return items


def _is_campaign_relevant(item: Dict[str, Any]) -> bool:
    text = " ".join(str(item.get(key) or "") for key in ("title", "summary", "url")).lower()
    return any(term in text for term in DISCOVERY_SUPPLY_CHAIN_TERMS)


def _dedupe_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    deduped: List[Dict[str, Any]] = []
    for candidate in sorted(candidates, key=lambda row: int(row.get("score") or 0), reverse=True):
        campaign = candidate.get("campaign", {})
        packages = ",".join(sorted(f"{p.get('ecosystem')}:{p.get('package')}:{p.get('version')}" for p in campaign.get("packages", [])))
        iocs = ",".join(_flatten_iocs(campaign.get("iocs", {}))[:8])
        key = "|".join([str(candidate.get("source_url") or ""), packages, iocs, str(candidate.get("candidate_id") or "")])
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        candidate["dedupe_key"] = digest[:16]
        deduped.append(candidate)
    return deduped


def discover_campaigns(
    *,
    since: str = "24h",
    source: str = "all",
    limit: int = 50,
    save: bool = True,
    watchlist: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _parse_duration_seconds(since)  # Validate for stable CLI behavior.
    errors: List[Dict[str, str]] = []
    source_status: List[Dict[str, Any]] = []
    items: List[Dict[str, Any]] = []
    sources = _load_discovery_sources()
    if source != "all":
        sources = [row for row in sources if source.lower() in str(row.get("name") or row.get("url") or row.get("feed_url") or "").lower()]
    for src in sources[: max(1, min(limit, 50))]:
        source_label = str(src.get("name") or src.get("feed_url") or src.get("url"))
        source_url = str(src.get("feed_url") or src.get("url"))
        started_at = _utc_now()
        try:
            text = _http_text(source_url, timeout=20)
            parsed = _parse_feed_items(text, src, limit=max(5, min(limit, 50)))
            items.extend(parsed)
            newest = sorted((str(item.get("published_at") or "") for item in parsed if item.get("published_at")), reverse=True)
            source_status.append({
                "source": source_label,
                "url": source_url,
                "status": "ok",
                "fetched_at": started_at,
                "items": len(parsed),
                "newest_published_at": newest[0] if newest else None,
                "sla_seconds": _poll_hint_to_seconds(src.get("poll_frequency_hint")),
            })
        except Exception as exc:
            error = str(exc)
            errors.append({"source": source_label, "error": error})
            source_status.append({
                "source": source_label,
                "url": source_url,
                "status": "error",
                "fetched_at": started_at,
                "items": 0,
                "error": error[:500],
                "sla_seconds": _poll_hint_to_seconds(src.get("poll_frequency_hint")),
            })
    items.extend(_cached_news_items(limit * 2))
    active_watchlist = watchlist if watchlist is not None else load_campaign_watchlist()
    candidates: List[Dict[str, Any]] = []
    for item in items:
        if not _is_campaign_relevant(item):
            continue
        src = item.get("source") or {}
        try:
            candidate = campaign_intake(
                text="\n".join(str(item.get(key) or "") for key in ("title", "summary", "url")),
                title=str(item.get("title") or ""),
                source_name=str(src.get("name") or ""),
                source_url=str(item.get("url") or src.get("url") or src.get("feed_url") or ""),
                watchlist=active_watchlist,
            )
            candidate["published_at"] = item.get("published_at")
            candidates.append(candidate)
        except Exception as exc:
            errors.append({"source": str(item.get("url") or src.get("name") or "item"), "error": str(exc)})
    candidates = _dedupe_candidates(candidates)[: max(1, min(limit, 200))]
    saved = save_campaign_candidates(candidates) if save else None
    return {
        "ok": True,
        "generated_at": _utc_now(),
        "since": since,
        "source": source,
        "total_candidates": len(candidates),
        "candidates": candidates,
        "watchlist": active_watchlist,
        "source_status": source_status,
        "errors": errors[:20],
        "saved_to": str(CAMPAIGN_CANDIDATES_PATH) if saved else None,
    }


def promote_campaign_candidate(candidate_id: str, path: Optional[Path] = None) -> Dict[str, Any]:
    payload = load_campaign_candidates(path)
    for candidate in payload.get("candidates", []):
        if str(candidate.get("candidate_id") or "") == candidate_id:
            return {"ok": True, "candidate": candidate, "campaign": candidate.get("campaign")}
    raise ValueError(f"campaign candidate not found: {candidate_id}")


def campaign_autopilot(
    *,
    since: str = "24h",
    dry_run: bool = True,
    persist: bool = False,
    create_drafts: bool = False,
    search_root: Optional[str] = None,
    limit: int = 10,
    min_score: int = 35,
) -> Dict[str, Any]:
    if dry_run and persist:
        raise ValueError("--dry-run and --persist are mutually exclusive")
    discovery = discover_campaigns(since=since, limit=limit, save=True)
    selected = [
        candidate
        for candidate in discovery.get("candidates", [])
        if int(candidate.get("score") or 0) >= min_score
        and candidate.get("campaign", {}).get("packages")
        and (candidate.get("orchestrator") or {}).get("recommended_route") == "campaign_research"
        and not (candidate.get("orchestrator") or {}).get("route_blockers")
    ][: max(1, min(limit, 50))]
    results: List[Dict[str, Any]] = []
    for candidate in selected:
        campaign = candidate.get("campaign") or {}
        result = research_campaign(
            campaign=campaign,
            search_root=search_root,
            dry_run=dry_run or not persist,
            persist=persist,
            no_fetch=True,
            create_blog_draft=bool(create_drafts and persist and not dry_run),
        )
        results.append({
            "candidate_id": candidate.get("candidate_id"),
            "score": candidate.get("score"),
            "campaign_id": result.get("campaign_id"),
            "campaign_verdict": result.get("campaign_verdict"),
            "environment_impact": result.get("environment_impact"),
            "finding_ids": result.get("finding_ids", []),
            "blog_draft": result.get("blog_draft"),
            "result": result,
        })
    return {
        "ok": True,
        "generated_at": _utc_now(),
        "since": since,
        "dry_run": dry_run,
        "persist": persist,
        "create_drafts": create_drafts,
        "min_score": min_score,
        "selected_candidates": len(selected),
        "discovery": discovery,
        "results": results,
    }


def _merge_iocs(*items: Any) -> Dict[str, List[str]]:
    merged: Dict[str, set[str]] = {
        "domains": set(),
        "urls": set(),
        "ips": set(),
        "ip_ports": set(),
        "hashes": set(),
        "file_paths": set(),
        "filenames": set(),
        "repository_descriptions": set(),
    }
    text_values: List[str] = []
    for item in items:
        if not item:
            continue
        if isinstance(item, dict):
            for key, values in item.items():
                bucket = merged.setdefault(str(key), set())
                if isinstance(values, list):
                    bucket.update(_defang_to_indicator(str(value)) for value in values if value)
                    text_values.extend(str(value) for value in values if value)
                elif values:
                    bucket.add(_defang_to_indicator(str(values)))
                    text_values.append(str(values))
        elif isinstance(item, list):
            text_values.extend(str(value) for value in item if value)
        else:
            text_values.append(str(item))
    extracted = extract_campaign_iocs(text_values)
    for key, values in extracted.items():
        merged.setdefault(key, set()).update(values)
    return {key: sorted(values) for key, values in merged.items() if values}


def _flatten_iocs(iocs: Dict[str, List[str]]) -> List[str]:
    flattened: List[str] = []
    for values in iocs.values():
        flattened.extend(str(value) for value in values)
    return sorted(set(flattened))


def _domain_from_indicator(value: str) -> str:
    raw = _defang_to_indicator(str(value or "").strip())
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(raw)
        return (parsed.hostname or "").lower()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", raw):
        raw = raw.split(":", 1)[0]
    return raw.strip(".").lower()


def _source_reference_domains(source_urls: Iterable[str]) -> set[str]:
    domains = set(CAMPAIGN_SOURCE_REFERENCE_DOMAINS)
    for url in source_urls:
        domain = _domain_from_indicator(str(url or ""))
        if domain:
            domains.add(domain)
            parts = domain.split(".")
            if len(parts) > 2:
                domains.add(".".join(parts[-2:]))
    return domains


def _is_source_reference_indicator(value: str, source_domains: set[str]) -> bool:
    domain = _domain_from_indicator(value)
    if not domain:
        return False
    if domain in source_domains:
        return True
    return any(domain.endswith(f".{source_domain}") for source_domain in source_domains if source_domain.count(".") >= 1)


def _clean_iocs_for_sources(
    iocs: Dict[str, List[str]],
    source_urls: Iterable[str],
) -> tuple[Dict[str, List[str]], List[Dict[str, str]], List[str]]:
    source_domains = _source_reference_domains(source_urls)
    validated: Dict[str, List[str]] = {}
    rejected: List[Dict[str, str]] = []
    source_references = sorted(set(str(url) for url in source_urls if str(url or "").strip()))
    for kind, values in (iocs or {}).items():
        clean_values: List[str] = []
        for value in values or []:
            indicator = _defang_to_indicator(str(value or "").strip())
            if not indicator:
                continue
            if "<" in indicator or ">" in indicator:
                rejected.append({"type": kind, "value": indicator, "reason": "malformed HTML fragment, not an IOC"})
                continue
            if kind == "domains" and re.search(r"\.(?:conf|cfg|ini|ya?ml|json|xml|html?|css|js|png|jpe?g|svg|md|txt)$", indicator, re.IGNORECASE):
                rejected.append({"type": kind, "value": indicator, "reason": "file or page reference, not domain IOC"})
                continue
            if _is_source_reference_indicator(indicator, source_domains):
                rejected.append({"type": kind, "value": indicator, "reason": "source reference, not attacker IOC"})
                if indicator.startswith(("http://", "https://")):
                    source_references.append(indicator)
                continue
            clean_values.append(indicator)
        if clean_values:
            validated[kind] = sorted(set(clean_values))
    return validated, rejected, sorted(set(source_references))


def _clean_actor_values(values: Iterable[Any]) -> tuple[List[str], List[Dict[str, str]]]:
    cleaned: List[str] = []
    rejected: List[Dict[str, str]] = []
    seen: set[str] = set()
    for value in values or []:
        label = _safe_str(value).strip("@'\" ")
        lowered = label.lower()
        if not label:
            continue
        if lowered in CAMPAIGN_ACTOR_EXTRACTION_NOISE:
            rejected.append({"value": label, "reason": "generic actor/publisher placeholder"})
            continue
        if re.fullmatch(r"cve-\d{4}-\d{4,}\.?", lowered):
            rejected.append({"value": label, "reason": "advisory identifier, not actor or publisher"})
            continue
        if len(label) < 3:
            rejected.append({"value": label, "reason": "too short to be a stable actor label"})
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(label)
    return cleaned, rejected


def _validate_campaign_package_rows(packages: Iterable[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    validated: List[Dict[str, Any]] = []
    rejected: List[Dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in packages or []:
        if not isinstance(row, dict):
            rejected.append({"ecosystem": "", "package": str(row), "reason": "package row is not an object"})
            continue
        ecosystem = canonical_ecosystem(str(row.get("ecosystem") or row.get("registry") or "npm"))
        package = normalize_package_name(ecosystem, str(row.get("package") or row.get("name") or row.get("artifact") or ""))
        version = _safe_str(row.get("version") or row.get("revision") or "unknown") or "unknown"
        if _looks_like_campaign_package_noise(ecosystem, package):
            rejected.append({"ecosystem": ecosystem, "package": package, "version": version, "reason": "likely extraction noise"})
            continue
        validation = validate_package_identifier(ecosystem, package)
        if not validation.get("valid"):
            rejected.append({"ecosystem": ecosystem, "package": package, "version": version, "reason": str(validation.get("reason") or "invalid package identifier")})
            continue
        key = (ecosystem, package, version)
        if key in seen:
            continue
        seen.add(key)
        validated.append({**row, "ecosystem": ecosystem, "package": package, "version": version})
    return validated, rejected


def _campaign_score(
    *,
    advisory_matches: List[Dict[str, Any]],
    matched_rules: List[Dict[str, Any]],
    behavioral_indicators: List[str],
    iocs: Dict[str, List[str]],
) -> int:
    score = 0
    if advisory_matches:
        score += 40
    rule_names = {str(rule.get("rule") or "").lower() for rule in matched_rules}
    strong_rule_needles = (
        "credential",
        "environment credential",
        "local file enumeration",
        "module-load",
        "install hook",
        "lifecycle",
        "subprocess",
        "dynamic execution",
        "network",
        "exfil",
        "persistence",
    )
    score += min(30, len([name for name in rule_names if any(needle in name for needle in strong_rule_needles)]) * 8)
    behavior_text = " ".join(behavioral_indicators).lower()
    for needle, weight in (
        ("credential", 12),
        ("token", 10),
        ("ssh", 8),
        ("cloud", 8),
        ("github", 8),
        ("botnet", 12),
        ("ddos", 12),
        ("persistence", 10),
        ("shai-hulud", 12),
        ("c2", 10),
        ("exfil", 10),
        ("typosquat", 6),
    ):
        if needle in behavior_text:
            score += weight
    if iocs:
        score += min(20, len(_flatten_iocs(iocs)) * 4)
    return max(0, min(100, score))


def _package_verdict_from_score(score: int, advisory_matches: List[Dict[str, Any]]) -> Tuple[str, str]:
    if advisory_matches and score >= 75:
        return "confirmed_true_positive", "high"
    if advisory_matches or score >= 65:
        return "likely_true_positive", "high" if score >= 75 else "medium"
    if score >= 35:
        return "needs_review", "medium"
    if score >= 15:
        return "likely_false_positive", "low"
    return "needs_review", "low"


def _campaign_package_spec(spec: str) -> Dict[str, str]:
    parts = str(spec or "").split(":")
    if len(parts) < 3:
        raise ValueError("--package must look like ecosystem:package:version")
    ecosystem = canonical_ecosystem(parts[0])
    version = parts[-1]
    package = ":".join(parts[1:-1])
    return {"ecosystem": ecosystem, "package": normalize_package_name(ecosystem, package), "version": version}


def _normalize_campaign_packages(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    packages = payload.get("packages") or []
    normalized: List[Dict[str, Any]] = []
    for item in packages:
        if isinstance(item, str):
            item = _campaign_package_spec(item)
        if not isinstance(item, dict):
            continue
        ecosystem = canonical_ecosystem(str(item.get("ecosystem") or item.get("registry") or ""))
        package = normalize_package_name(ecosystem, str(item.get("package") or item.get("name") or item.get("artifact") or ""))
        if isinstance(item.get("versions"), list):
            versions = [_safe_str(value) for value in item["versions"] if _safe_str(value)]
        else:
            versions = []
        version = _safe_str(item.get("version") or item.get("revision") or (versions[0] if versions else "") or "unknown")
        if not versions and version and version != "unknown":
            versions = [version]
        normalized.append({
            **item,
            "ecosystem": ecosystem,
            "package": package,
            "version": version,
            "versions": versions,
            "publisher": _safe_str(item.get("publisher") or item.get("maintainer") or item.get("owner")),
        })
    return normalized


def _campaign_search_terms(package: Dict[str, Any], campaign: Dict[str, Any], iocs: Dict[str, List[str]]) -> List[str]:
    terms = [
        str(package.get("package") or ""),
        str(package.get("version") or ""),
        str(package.get("publisher") or ""),
        str(campaign.get("campaign_id") or ""),
    ]
    terms.extend(str(item) for item in campaign.get("actors", []) if item)
    terms.extend(_flatten_iocs(iocs))
    seen: set[str] = set()
    cleaned: List[str] = []
    for term in terms:
        term = term.strip()
        if len(term) < 3:
            continue
        lowered = term.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(term)
    return cleaned


def _campaign_local_usage(search_root: Optional[str], terms: Iterable[str], *, limit: int = 10) -> Dict[str, Any]:
    if not search_root:
        return {
            "status": "not_observed",
            "present": False,
            "matches": [],
            "reason": "local usage scan not requested; pass --search-root to check manifests and lockfiles",
        }
    root = Path(search_root).expanduser().resolve()
    if not root.exists():
        return {"status": "unknown", "present": False, "matches": [], "reason": f"search root does not exist: {root}"}
    lowered_terms = [term.lower() for term in terms if term]
    matches: List[Dict[str, Any]] = []
    for path in root.rglob("*"):
        if len(matches) >= limit:
            break
        if not path.is_file():
            continue
        if any(part in CAMPAIGN_SKIP_DIRS for part in path.parts):
            continue
        name = path.name.lower()
        if name not in CAMPAIGN_MANIFEST_FILES and path.suffix.lower() not in {".json", ".toml", ".lock", ".mod", ".sum", ".csproj", ".gradle"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lowered = text.lower()
        matched = [term for term in lowered_terms if term.lower() in lowered]
        if not matched:
            continue
        matches.append({
            "path": str(path),
            "matched_terms": matched[:5],
            "manifest": name in CAMPAIGN_MANIFEST_FILES,
        })
    exact_version = any(any(re.fullmatch(r"v?\d+(?:\.\d+)+(?:[A-Za-z0-9_.+-]*)?", term) for term in match["matched_terms"]) for match in matches)
    status = "confirmed_affected" if exact_version else "likely_affected" if matches else "not_observed"
    return {"status": status, "present": bool(matches), "matches": matches}


def find_composer_lock_usage(search_root: str, package: str, *, limit: int = 20) -> Dict[str, Any]:
    package = normalize_package_name("packagist", package)
    root = Path(search_root).expanduser().resolve()
    matches: List[Dict[str, Any]] = []
    if not root.exists():
        return {"package": package, "present": False, "matches": [], "status": "unknown", "reason": f"search root does not exist: {root}"}
    for path in root.rglob("composer.lock"):
        if len(matches) >= limit:
            break
        if any(part in CAMPAIGN_SKIP_DIRS for part in path.parts):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for section in ("packages", "packages-dev"):
            for row in data.get(section, []) or []:
                if not isinstance(row, dict):
                    continue
                if normalize_package_name("packagist", str(row.get("name") or "")) != package:
                    continue
                source = row.get("source") if isinstance(row.get("source"), dict) else {}
                dist = row.get("dist") if isinstance(row.get("dist"), dict) else {}
                matches.append({
                    "path": str(path),
                    "section": section,
                    "package": package,
                    "version": row.get("version"),
                    "source_reference": source.get("reference"),
                    "source_url": source.get("url"),
                    "dist_reference": dist.get("reference"),
                    "installed_at": row.get("time"),
                })
    return {
        "package": package,
        "present": bool(matches),
        "matches": matches,
        "status": "confirmed_affected" if matches else "not_observed",
    }


def _campaign_behavior_indicators(package: Dict[str, Any], analysis: Dict[str, Any], campaign: Dict[str, Any], iocs: Dict[str, List[str]]) -> List[str]:
    values: List[str] = []
    values.extend(str(item) for item in campaign.get("behavioral_indicators", []) if item)
    values.extend(str(item) for item in package.get("behavioral_indicators", []) if item)
    values.extend(str(item) for item in analysis.get("findings", []) if item)
    text = " ".join(values + _flatten_iocs(iocs)).lower()
    if "shai" in text or "hulud" in text:
        values.append("Shai-Hulud clone or derivative indicator")
    if "github" in text and ("token" in text or "repository" in text):
        values.append("GitHub token or repository abuse")
    if "ddos" in text or "botnet" in text:
        values.append("botnet or DDoS behavior")
    if "ssh" in text or "cloud credential" in text or "environment variable" in text:
        values.append("credential harvesting")
    if "lhr.life" in text or iocs.get("domains") or iocs.get("ip_ports"):
        values.append("outbound C2 indicators")
    pkg_name = str(package.get("package") or "")
    if "axois" in pkg_name or "tempalte" in pkg_name:
        values.append("typosquatting package-name indicator")
    return sorted(set(_safe_str(value) for value in values if _safe_str(value)))


def _research_one_campaign_package(
    package: Dict[str, Any],
    campaign: Dict[str, Any],
    *,
    search_root: Optional[str],
    no_fetch: bool,
) -> Dict[str, Any]:
    ecosystem = str(package["ecosystem"])
    package_name = str(package["package"])
    version = str(package.get("version") or "unknown")
    validation = validate_package_identifier(ecosystem, package_name)
    advisory_matches = find_advisory_matches(ecosystem, package_name, version) if version != "unknown" else []
    files = package.get("files") if isinstance(package.get("files"), dict) else {}
    analysis = analyze_ecosystem_files(ecosystem, files) if files else {
        "ecosystem": ecosystem,
        "findings": [],
        "matched_rules": [],
        "score": 0,
        "verdict": "skipped" if no_fetch else "not_analyzed",
        "confidence": "low",
        "manifest_files": [],
        "suspicious_files": [],
        "limitations": ecosystem_capabilities(ecosystem).get("limitations", []),
    }
    package_iocs = _merge_iocs(campaign.get("iocs"), package.get("iocs"), campaign.get("summary"), package.get("notes"))
    behavior = _campaign_behavior_indicators(package, analysis, campaign, package_iocs)
    local_usage = _campaign_local_usage(search_root, _campaign_search_terms(package, campaign, package_iocs))
    score = _campaign_score(
        advisory_matches=advisory_matches,
        matched_rules=analysis.get("matched_rules", []),
        behavioral_indicators=behavior,
        iocs=package_iocs,
    )
    package_verdict, confidence = _package_verdict_from_score(score, advisory_matches)
    if analysis.get("verdict") == "malicious" and package_verdict == "needs_review":
        package_verdict = "likely_true_positive"
        confidence = "medium"
    mitigation = package_compromise_mitigation(ecosystem, package_name, version, advisory_matches)
    if package_iocs:
        mitigation.append("Block or hunt the listed campaign IOCs before rotating credentials.")
    if local_usage["status"] in {"confirmed_affected", "likely_affected"}:
        mitigation.append("Treat local exposure as active until affected lockfiles, caches, and runtime artifacts are cleaned.")
    return {
        "ecosystem": ecosystem,
        "package": package_name,
        "version": version,
        "publisher": package.get("publisher") or "",
        "validation": validation,
        "advisory_matches": advisory_matches,
        "analysis": analysis,
        "matched_rules": analysis.get("matched_rules", []),
        "behavioral_indicators": behavior,
        "iocs": package_iocs,
        "score": score,
        "package_verdict": package_verdict,
        "environment_impact": {
            "status": local_usage["status"],
            "local_usage": local_usage["matches"],
            "guidance": "Local usage affects exposure, not package-level maliciousness.",
        },
        "confidence": confidence,
        "recommended_mitigation": mitigation,
        "artifact_reports": [],
        "references": sorted(set(str(url) for url in campaign.get("source_urls", []) if url)),
    }


def _campaign_correlations(packages: List[Dict[str, Any]], campaign: Dict[str, Any]) -> List[Dict[str, Any]]:
    correlations: List[Dict[str, Any]] = []
    by_publisher: Dict[str, List[str]] = {}
    by_ioc: Dict[str, List[str]] = {}
    for package in packages:
        label = f"{package['ecosystem']}:{package['package']}@{package['version']}"
        publisher = str(package.get("publisher") or "").strip()
        if publisher:
            by_publisher.setdefault(publisher, []).append(label)
        for ioc in _flatten_iocs(package.get("iocs", {})):
            by_ioc.setdefault(ioc, []).append(label)
    for publisher, labels in sorted(by_publisher.items()):
        if len(labels) > 1:
            correlations.append({"signal": "same_publisher", "value": publisher, "packages": labels})
    for ioc, labels in sorted(by_ioc.items()):
        if len(labels) > 1:
            correlations.append({"signal": "shared_ioc", "value": ioc, "packages": labels})
    if campaign.get("source_urls") and len(packages) > 1:
        correlations.append({
            "signal": "same_external_source",
            "value": ", ".join(str(url) for url in campaign.get("source_urls", [])[:3]),
            "packages": [f"{p['ecosystem']}:{p['package']}@{p['version']}" for p in packages],
        })
    return correlations


def _campaign_verdict(packages: List[Dict[str, Any]]) -> Tuple[str, str, int]:
    score = max((int(package.get("score") or 0) for package in packages), default=0)
    verdicts = {str(package.get("package_verdict")) for package in packages}
    if "confirmed_true_positive" in verdicts:
        return "confirmed_true_positive", "high", score
    if "likely_true_positive" in verdicts:
        return "likely_true_positive", "high" if score >= 75 else "medium", score
    if "needs_review" in verdicts:
        return "needs_review", "medium", score
    return "likely_false_positive", "low", score


def _build_campaign_finding(campaign: Dict[str, Any], package: Dict[str, Any]) -> Dict[str, Any]:
    now = _utc_now()
    finding_id = _finding_id(package["ecosystem"], package["package"], package["version"])
    summary = (
        f"{package['ecosystem']}:{package['package']}@{package['version']} is linked to "
        f"{campaign['campaign_id']} with verdict {package['package_verdict']}."
    )
    return {
        "finding_id": finding_id,
        "campaign_id": campaign["campaign_id"],
        "title": f"Supply-chain campaign package: {package['package']}@{package['version']}",
        "summary": summary,
        "severity": campaign.get("severity", "critical"),
        "severity_score": 98 if package.get("advisory_matches") else 90,
        "status": "open",
        "disposition": "unreviewed",
        "first_seen": now,
        "last_seen": now,
        "event_ids": [_scan_event_id(package["ecosystem"], package["package"], package["version"])],
        "rule_ids": ["SUPPLY-CHAIN-CAMPAIGN", "SUPPLY-CHAIN-NATIVE"],
        "platform": "supply_chain",
        "source": "secopsai-supply-chain",
        "package": package["package"],
        "ecosystem": package["ecosystem"],
        "new_version": package["version"],
        "verdict": package["package_verdict"],
        "package_verdict": package["package_verdict"],
        "environment_impact": package["environment_impact"],
        "confidence": package["confidence"],
        "analysis": "; ".join(package.get("behavioral_indicators", [])[:8]),
        "matched_rules": package.get("matched_rules", []),
        "advisory_matches": package.get("advisory_matches", []),
        "campaign_ids": [campaign["campaign_id"]],
        "iocs": package.get("iocs", {}),
        "remediation": package.get("recommended_mitigation", []),
        "supply_chain_metadata": {
            "campaign_id": campaign["campaign_id"],
            "package_verdict": package["package_verdict"],
            "environment_impact": package["environment_impact"],
            "correlation_source": "research-campaign",
        },
    }


def normalize_campaign_input(payload: Dict[str, Any]) -> Dict[str, Any]:
    campaign_id = _safe_str(payload.get("campaign_id") or payload.get("id") or "supply-chain-campaign")
    packages = _normalize_campaign_packages(payload)
    iocs = _merge_iocs(payload.get("iocs"), payload.get("summary"), payload.get("behavioral_indicators"))
    source_urls = [str(item) for item in payload.get("source_urls", []) if item]
    iocs, _, _ = _clean_iocs_for_sources(iocs, source_urls)
    actors, _ = _clean_actor_values(payload.get("actors", []) if isinstance(payload.get("actors"), list) else [])
    publishers, _ = _clean_actor_values(payload.get("publishers", []) if isinstance(payload.get("publishers"), list) else [])
    return {
        **payload,
        "campaign_id": campaign_id,
        "title": _safe_str(payload.get("title") or campaign_id.replace("-", " ").title()),
        "summary": _safe_str(payload.get("summary") or "Cross-ecosystem supply-chain campaign research."),
        "ecosystems": sorted(set(package["ecosystem"] for package in packages)),
        "packages": packages,
        "actors": actors,
        "publishers": publishers,
        "source_urls": source_urls,
        "source_names": [str(item) for item in payload.get("source_names", []) if item],
        "iocs": iocs,
        "behavioral_indicators": [str(item) for item in payload.get("behavioral_indicators", []) if item],
        "severity": str(payload.get("severity") or "critical"),
        "confidence": str(payload.get("confidence") or "medium"),
    }


def research_campaign(
    *,
    campaign: Dict[str, Any],
    search_root: Optional[str] = None,
    dry_run: bool = True,
    persist: bool = False,
    no_fetch: bool = False,
    create_blog_draft: bool = False,
) -> Dict[str, Any]:
    normalized = normalize_campaign_input(campaign)
    package_results = [
        _research_one_campaign_package(package, normalized, search_root=search_root, no_fetch=no_fetch)
        for package in normalized["packages"]
    ]
    verdict, confidence, score = _campaign_verdict(package_results)
    campaign_iocs = _merge_iocs(normalized.get("iocs"), *[package.get("iocs", {}) for package in package_results])
    correlations = _campaign_correlations(package_results, normalized)
    mitigation = sorted(set(
        step
        for package in package_results
        for step in package.get("recommended_mitigation", [])
    ))
    output = {
        "generated_at": _utc_now(),
        "campaign_id": normalized["campaign_id"],
        "title": normalized["title"],
        "summary": normalized["summary"],
        "ecosystems": sorted(set(package["ecosystem"] for package in package_results)),
        "actors": normalized.get("actors", []),
        "publishers": sorted(set([*normalized.get("publishers", []), *[p.get("publisher") for p in package_results if p.get("publisher")]])),
        "source_urls": normalized.get("source_urls", []),
        "source_names": normalized.get("source_names", []),
        "first_seen": normalized.get("first_seen"),
        "last_seen": normalized.get("last_seen"),
        "severity": normalized.get("severity", "critical"),
        "confidence": confidence,
        "campaign_verdict": verdict,
        "score": score,
        "package_verdict": verdict,
        "environment_impact": {
            "status": "confirmed_affected" if any(p["environment_impact"]["status"] == "confirmed_affected" for p in package_results)
            else "likely_affected" if any(p["environment_impact"]["status"] == "likely_affected" for p in package_results)
            else "not_observed",
            "guidance": "Package maliciousness is assessed separately from local environment impact.",
        },
        "iocs": campaign_iocs,
        "behavioral_indicators": sorted(set(
            indicator
            for package in package_results
            for indicator in package.get("behavioral_indicators", [])
        )),
        "packages": package_results,
        "correlations": correlations,
        "recommended_mitigation": mitigation,
        "blog_ready_summary": (
            f"SecOpsAI correlated {len(package_results)} package artifact(s) across "
            f"{', '.join(sorted(set(package['ecosystem'] for package in package_results))) or 'unknown ecosystems'} "
            f"for {normalized['campaign_id']} and assessed the campaign as {verdict}."
        ),
        "references": normalized.get("source_urls", []),
        "dry_run": dry_run,
        "persist": persist,
        "db_path": None,
        "finding_ids": [],
        "blog_draft": None,
    }
    if persist and not dry_run:
        findings = [
            _build_campaign_finding(output, package)
            for package in package_results
            if package.get("package_verdict") in {"confirmed_true_positive", "likely_true_positive", "needs_review"}
        ]
        output["db_path"] = _upsert_findings(findings) if findings else None
        output["finding_ids"] = [finding["finding_id"] for finding in findings]
    if create_blog_draft:
        from secopsai import blog

        output["blog_draft"] = blog.draft_campaign(campaign_data=output)
    return output


def watch_registry(
    *,
    ecosystem: str,
    package: str,
    since: str = "10m",
    dry_run: bool = True,
    persist: bool = False,
    limit: int = 20,
    model: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    ecosystem = canonical_ecosystem(ecosystem)
    if not package:
        raise ValueError("--package is required for package-scoped registry watching")

    seconds = _parse_duration_seconds(since)
    now_epoch = float(now if now is not None else time.time())
    cutoff = now_epoch - seconds
    if ecosystem == "npm":
        metadata = metadata if metadata is not None else (_npm_get_package_info(package) or {})
        ordered = _ordered_npm_versions(metadata)
    else:
        capabilities = ecosystem_capabilities(ecosystem)
        if not capabilities.get("features", {}).get("monitor", False):
            return {
                "ecosystem": ecosystem,
                "package": package,
                "since": since,
                "dry_run": dry_run,
                "persist": persist,
                "supported": False,
                "limitations": capabilities.get("limitations", []),
                "recent_versions": [],
                "scanned": [],
                "total_scanned": 0,
                "malicious": 0,
                "errors": 0,
                "db_path": None,
            }
        package = normalize_package_name(ecosystem, package)
        metadata = metadata if metadata is not None else _fetch_ecosystem_metadata(ecosystem, package)
        rows = _ecosystem_version_rows(ecosystem, package, metadata)
        ordered = []
        for row in rows:
            stamp = row.get("published_at")
            epoch = _safe_timestamp_sort(stamp)
            if not epoch:
                epoch = now_epoch
                stamp = stamp or "version-delta-only"
            ordered.append((row["version"], str(stamp), epoch))
    recent = [row for row in ordered if row[2] >= cutoff][:limit]
    if ecosystem != "npm" and not recent and ordered:
        recent = ordered[-limit:]
    previous_by_version: Dict[str, Optional[str]] = {}
    for index, (version, _stamp, _epoch) in enumerate(ordered):
        previous_by_version[version] = ordered[index - 1][0] if index > 0 else None

    results: List[ScanResult] = []
    scanned: List[Dict[str, Any]] = []
    for version, stamp, epoch in recent:
        previous = previous_by_version.get(version)
        result = _scan_release(
            ecosystem,
            package,
            version,
            old_version=previous,
            model=model,
            keep_report=not dry_run,
        )
        results.append(result)
        scanned.append(
            {
                "package": package,
                "version": version,
                "published_at": stamp,
                "published_epoch": epoch,
                "previous_version": previous,
                "result": result.to_dict(),
            }
        )

    db_path = None
    if persist and results:
        _append_results(results)
        findings = [_build_finding(result) for result in results if result.verdict == "malicious" and result.finding_id]
        db_path = _upsert_findings(findings) if findings else None

    source_evidence = None
    if ecosystem == "npm":
        try:
            previous_snapshot = None
            snapshot_path = _npm_source_snapshot_path(package)
            if snapshot_path.exists():
                try:
                    previous_snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
                except Exception:
                    previous_snapshot = None
            source_evidence = detect_npm_package_source_signals(package, metadata or {}, previous_snapshot=previous_snapshot)
            if persist and not dry_run:
                _ensure_dirs()
                snapshot_path.write_text(json.dumps(_npm_source_snapshot(package, metadata or {}), indent=2), encoding="utf-8")
        except Exception as exc:
            source_evidence = {"error": str(exc), "status": "source_evidence_unavailable"}
    elif ecosystem == "packagist":
        try:
            source_evidence = analyze_packagist_source_package(package, metadata=metadata, save_snapshot=persist and not dry_run)
        except Exception as exc:
            source_evidence = {"error": str(exc), "status": "source_evidence_unavailable"}

    return {
        "ecosystem": ecosystem,
        "package": package,
        "since": since,
        "dry_run": dry_run,
        "persist": persist,
        "cutoff_epoch": cutoff,
        "recent_versions": [
            {"version": version, "published_at": stamp, "previous_version": previous_by_version.get(version)}
            for version, stamp, _epoch in recent
        ],
        "scanned": scanned,
        "total_scanned": len(scanned),
        "malicious": sum(1 for result in results if result.verdict == "malicious"),
        "errors": sum(1 for result in results if result.verdict == "error"),
        "db_path": db_path,
        "source_evidence": source_evidence,
    }


def watch_npm_namespace(
    *,
    namespace: str,
    since: str = "10m",
    dry_run: bool = True,
    persist: bool = False,
    limit: int = 50,
    model: Optional[str] = None,
    packages: Optional[List[str]] = None,
    metadata_map: Optional[Dict[str, Dict[str, Any]]] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    scope = _normalize_npm_namespace(namespace)
    try:
        package_names = packages if packages is not None else _fetch_npm_namespace_packages(scope, limit=limit)
    except Exception as exc:
        return {
            "ecosystem": "npm",
            "namespace": f"@{scope}",
            "since": since,
            "dry_run": dry_run,
            "persist": persist,
            "packages": [],
            "results": [],
            "total_packages": 0,
            "total_scanned": 0,
            "malicious": 0,
            "errors": 1,
            "namespace_evidence": {
                "namespace": f"@{scope}",
                "signals": [],
                "source_status": "fetch_error",
                "error": str(exc),
                "recommended_action": "retry after npm registry rate limit clears or provide an allowlisted package set",
            },
            "package_source_signals": [],
        }
    package_names = [normalize_package_name("npm", package) for package in package_names if package]
    results = [
        watch_registry(
            ecosystem="npm",
            package=package,
            since=since,
            dry_run=dry_run,
            persist=persist,
            limit=limit,
            model=model,
            metadata=(metadata_map or {}).get(package) or (metadata_map or {}).get(package.lower()),
            now=now,
        )
        for package in package_names[:limit]
    ]
    scanned_rows: List[Dict[str, Any]] = []
    package_source_signals: List[Dict[str, Any]] = []
    for result in results:
        scanned_rows.extend(result.get("scanned", []))
        source_evidence = result.get("source_evidence") or {}
        package_source_signals.extend(source_evidence.get("signals", []) if isinstance(source_evidence, dict) else [])
    namespace_evidence = _aggregate_npm_namespace_source_signals(scope, scanned_rows)
    return {
        "ecosystem": "npm",
        "namespace": f"@{scope}",
        "since": since,
        "dry_run": dry_run,
        "persist": persist,
        "packages": package_names[:limit],
        "results": results,
        "total_packages": len(package_names[:limit]),
        "total_scanned": sum(int(row.get("total_scanned") or 0) for row in results),
        "malicious": sum(int(row.get("malicious") or 0) for row in results),
        "errors": sum(int(row.get("errors") or 0) for row in results),
        "namespace_evidence": namespace_evidence,
        "package_source_signals": package_source_signals,
    }


def watch_packagist_namespace(
    *,
    namespace: str,
    since: str = "10m",
    dry_run: bool = True,
    persist: bool = False,
    limit: int = 20,
    model: Optional[str] = None,
    packages: Optional[List[str]] = None,
) -> Dict[str, Any]:
    namespace = normalize_package_name("packagist", namespace).strip("/")
    package_names = packages if packages is not None else _fetch_packagist_namespace_packages(namespace, limit=limit)
    results = [
        watch_registry(
            ecosystem="packagist",
            package=package,
            since=since,
            dry_run=dry_run,
            persist=persist,
            limit=limit,
            model=model,
        )
        for package in package_names[:limit]
    ]
    return {
        "ecosystem": "packagist",
        "namespace": namespace,
        "since": since,
        "dry_run": dry_run,
        "persist": persist,
        "packages": package_names[:limit],
        "results": results,
        "total_packages": len(package_names[:limit]),
        "total_scanned": sum(int(row.get("total_scanned") or 0) for row in results),
        "malicious": sum(int(row.get("malicious") or 0) for row in results),
        "errors": sum(int(row.get("errors") or 0) for row in results),
    }


def _iter_recent_pypi_releases(top: int, lookback_seconds: int, use_state: bool) -> tuple[List[tuple[str, str, int]], Dict[str, int]]:
    watchlist = _load_watchlist(top)
    client = xmlrpc.client.ServerProxy(PYPI_XMLRPC)
    state = _load_state() if use_state else {}
    start_serial = int(state.get("pypi_serial", 0)) if use_state and state.get("pypi_serial") else None
    if start_serial is None:
        current_serial = client.changelog_last_serial()
        start_serial = max(0, current_serial - lookback_seconds * 15)
    events = client.changelog_since_serial(start_serial)
    if use_state and events:
        state["pypi_serial"] = max(event[4] for event in events)
        _save_state(state)
    return _extract_new_releases(events, watchlist), watchlist


def _iter_recent_npm_releases(top: int, lookback_seconds: int, use_state: bool) -> tuple[List[tuple[str, str]], Dict[str, int]]:
    watchlist = _load_npm_watchlist(top)
    state = _load_state() if use_state else {}
    current_seq = _npm_get_current_seq()
    if use_state and state.get("npm_seq") is not None:
        seq = int(state["npm_seq"])
        cutoff_epoch = float(state.get("npm_epoch", time.time() - lookback_seconds))
    else:
        seq = max(0, current_seq - lookback_seconds * 50)
        cutoff_epoch = time.time() - lookback_seconds

    changed_packages: set[str] = set()
    fetched = 0
    while fetched < NPM_MAX_CHANGES_PER_CYCLE:
        batch, next_seq = _npm_poll_changes(seq)
        fetched += len(batch)
        for row in batch:
            package = str(row.get("id", ""))
            if not package.startswith("_design/") and package.lower() in watchlist:
                changed_packages.add(package)
        if not batch or next_seq == seq:
            seq = next_seq
            break
        seq = next_seq

    releases: List[tuple[str, str]] = []
    for package in changed_packages:
        for version in _npm_detect_new_releases(package, cutoff_epoch):
            releases.append((package, version))

    if use_state:
        state["npm_seq"] = seq
        state["npm_epoch"] = time.time()
        _save_state(state)
    return releases, watchlist


def run_scan(
    *,
    ecosystem: str,
    package: str,
    version: str,
    previous_version: Optional[str] = None,
    model: Optional[str] = None,
    keep_report: bool = True,
    slack: bool = False,
    artifact: Optional[Path] = None,
    previous_artifact: Optional[Path] = None,
    metadata_only: bool = False,
    max_download_mb: int = DEFAULT_MAX_DOWNLOAD_MB,
    max_files: int = DEFAULT_MAX_FILES,
    timeout: int = 30,
) -> Dict[str, Any]:
    result = _scan_release(
        ecosystem,
        package,
        version,
        old_version=previous_version,
        model=model,
        keep_report=keep_report,
        artifact=artifact,
        previous_artifact=previous_artifact,
        metadata_only=metadata_only,
        max_download_mb=max_download_mb,
        max_files=max_files,
        timeout=timeout,
    )
    _append_results([result])
    findings = [_build_finding(result)] if result.verdict == "malicious" and result.finding_id else []
    db_path = _upsert_findings(findings) if findings else None
    slack_meta = alert_new_supply_chain_findings(findings) if slack else {"new_findings": 0, "sent": False}
    return {"result": result.to_dict(), "db_path": db_path, "slack_alerts_sent": int(bool(slack_meta.get("sent")))}


def run_recent_top_scan(
    *,
    enable_pypi: bool = True,
    enable_npm: bool = True,
    top: int = 1000,
    npm_top: Optional[int] = None,
    lookback_seconds: int = 600,
    model: Optional[str] = None,
    slack: bool = False,
    use_state: bool = False,
) -> Dict[str, Any]:
    if not enable_pypi and not enable_npm:
        raise ValueError("At least one ecosystem must be enabled")

    results: List[ScanResult] = []

    if enable_pypi:
        releases, watchlist = _iter_recent_pypi_releases(top, lookback_seconds, use_state)
        for package, version, _timestamp in releases:
            results.append(_scan_release("pypi", package, version, rank=watchlist.get(package.lower()), model=model))

    if enable_npm:
        releases, watchlist = _iter_recent_npm_releases(npm_top or top, lookback_seconds, use_state)
        for package, version in releases:
            results.append(_scan_release("npm", package, version, rank=watchlist.get(package.lower()), model=model))

    _append_results(results)
    findings = [_build_finding(result) for result in results if result.verdict == "malicious" and result.finding_id]
    db_path = _upsert_findings(findings) if findings else None
    slack_meta = alert_new_supply_chain_findings(findings) if slack else {"new_findings": 0, "sent": False}
    return {
        "total_scanned": len(results),
        "malicious": len(findings),
        "benign": sum(1 for result in results if result.verdict == "benign"),
        "errors": sum(1 for result in results if result.verdict == "error"),
        "skipped": sum(1 for result in results if result.verdict == "skipped"),
        "db_path": db_path,
        "slack_alerts_sent": int(bool(slack_meta.get("sent"))),
        "results": [result.to_dict() for result in results],
    }


def reconcile_history(*, drop_benign: bool = False, include_advisories: bool = False) -> Dict[str, Any]:
    rows = _load_all_results()
    if not rows:
        return {
            "total_rows": 0,
            "reclassified": 0,
            "dropped": 0,
            "removed_from_slack_state": 0,
            "removed_from_db": 0,
            "changed_finding_ids": [],
            "advisory_finding_ids": [],
        }

    retained_rows: List[Dict[str, Any]] = []
    changed_finding_ids: List[str] = []
    advisory_finding_ids: List[str] = []
    removed_finding_ids: List[str] = []
    advisory_findings: List[Dict[str, Any]] = []

    for row in rows:
        report_path = row.get("report_path")
        finding_id = str(row.get("finding_id") or "")
        ecosystem = str(row.get("ecosystem") or "")
        package = str(row.get("package") or "")
        new_version = str(row.get("new_version") or "")
        advisory_matches = find_advisory_matches(ecosystem, package, new_version) if include_advisories else []
        if advisory_matches and row.get("verdict") != "malicious":
            finding_id = _finding_id(ecosystem, package, new_version)
            row["verdict"] = "malicious"
            row["finding_id"] = finding_id
            row["analysis"] = _advisory_analysis(
                advisory_matches,
                artifact_unavailable=not bool(report_path),
            )
            row["advisory_matches"] = advisory_matches
            if row.get("error"):
                row["error"] = f"{row['error']}; advisory matched"
            advisory_finding_ids.append(finding_id)
            advisory_findings.append(
                _build_finding(
                    ScanResult(
                        ecosystem,
                        package,
                        str(row.get("old_version") or "unavailable"),
                        new_version,
                        "malicious",
                        str(row["analysis"]),
                        str(report_path) if report_path else None,
                        int(row["rank"]) if row.get("rank") is not None else None,
                        finding_id,
                        str(row.get("error") or "") or None,
                        advisory_matches,
                    )
                )
            )
            retained_rows.append(row)
            continue
        if row.get("verdict") not in {"malicious", "benign"} or not report_path:
            retained_rows.append(row)
            continue

        path = Path(str(report_path))
        if not path.exists():
            retained_rows.append(row)
            continue

        try:
            report = path.read_text(encoding="utf-8")
            explained = explain_verdict(
                report,
                ecosystem=ecosystem,
                package=package,
                version=new_version if include_advisories else None,
            )
        except Exception:
            retained_rows.append(row)
            continue

        old_verdict = str(row.get("verdict") or "")
        new_verdict = str(explained.get("verdict") or old_verdict)
        row["verdict"] = new_verdict
        row["analysis"] = str(explained.get("analysis") or row.get("analysis") or "")
        if explained.get("advisory_matches"):
            row["advisory_matches"] = explained["advisory_matches"]

        if old_verdict != new_verdict and finding_id:
            if explained.get("advisory_matches"):
                advisory_finding_ids.append(finding_id)
            else:
                changed_finding_ids.append(finding_id)

        if drop_benign and new_verdict == "benign":
            if finding_id:
                removed_finding_ids.append(finding_id)
            continue

        retained_rows.append(row)

    _save_all_results(retained_rows)
    if advisory_findings:
        _upsert_findings(advisory_findings)

    if changed_finding_ids or removed_finding_ids:
        state = load_slack_state(SUPPLY_CHAIN_SLACK_STATE_PATH)
        to_remove = set(changed_finding_ids) | set(removed_finding_ids)
        before = set(state["finding_ids"])
        after = sorted(before - to_remove)
        state["finding_ids"] = after
        save_slack_state(state, SUPPLY_CHAIN_SLACK_STATE_PATH)
        removed_from_slack_state = len(before) - len(after)
    else:
        removed_from_slack_state = 0

    removed_from_db = 0
    if changed_finding_ids or removed_finding_ids:
        resolved = soc_store.default_db_path()
        soc_store.init_db(resolved)
        to_remove = sorted(set(changed_finding_ids) | set(removed_finding_ids))
        with soc_store.closing(soc_store.connect(resolved)) as connection:
            for finding_id in to_remove:
                removed_from_db += connection.execute(
                    "DELETE FROM findings WHERE finding_id = ?",
                    (finding_id,),
                ).rowcount
            connection.commit()

    return {
        "total_rows": len(rows),
        "reclassified": len(changed_finding_ids) + len(advisory_finding_ids),
        "dropped": len(removed_finding_ids),
        "removed_from_slack_state": removed_from_slack_state,
        "removed_from_db": removed_from_db,
        "changed_finding_ids": sorted(set(changed_finding_ids + advisory_finding_ids)),
        "advisory_finding_ids": sorted(set(advisory_finding_ids)),
        "removed_finding_ids": sorted(set(removed_finding_ids)),
    }
