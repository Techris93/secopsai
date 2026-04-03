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
import time
import tomllib
import textwrap
import urllib.parse
import urllib.request
import xmlrpc.client
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import soc_store

from secopsai.alerts import alert_new_supply_chain_findings


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPLY_CHAIN_DIR = REPO_ROOT / "data" / "supply_chain"
REPORTS_DIR = SUPPLY_CHAIN_DIR / "reports"
RESULTS_PATH = SUPPLY_CHAIN_DIR / "results.jsonl"
STATE_PATH = SUPPLY_CHAIN_DIR / "state.json"
POLICY_PATH = REPO_ROOT / "config" / "supply_chain_policy.toml"

PYPI_XMLRPC = "https://pypi.org/pypi"
PYPI_JSON = "https://pypi.org/pypi/{package}/json"
PYPI_VERSION_JSON = "https://pypi.org/pypi/{package}/{version}/json"
TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

NPM_REPLICATE = "https://replicate.npmjs.com"
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_MAX_CHANGES_PER_CYCLE = 10000

AGENT_PROMPT = """Review the diff in the workspace file and decide whether it is highly likely to show package supply-chain compromise.

Start the response with exactly one of:
Verdict: malicious
Verdict: benign

Then explain briefly.
"""

SUSPICIOUS_RULES: list[tuple[str, str, int]] = [
    ("obfuscated eval", r"\b(?:eval|exec)\s*\(|\bnew Function\s*\(|\bFunction\s*\(", 3),
    ("subprocess spawn", r"\b(child_process|subprocess|os\.system|popen|spawn|execFile)\b", 3),
    ("shell downloader", r"\b(curl|wget|Invoke-WebRequest|bitsadmin|certutil)\b", 3),
    ("base64 or encoded payload", r"\b(base64|fromCharCode|atob|btoa|decodeURIComponent)\b", 2),
    ("network egress", r"https?://", 2),
    ("credential access", r"\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|credential|aws_access_key_id|BEGIN RSA PRIVATE KEY)\b", 2),
    ("startup persistence", r"\b(postinstall|preinstall|install|cron|LaunchAgents|systemd|Startup)\b", 3),
    ("suspicious archive extraction", r"\b(tarfile|zipfile|extractall)\b", 1),
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
)

BENIGN_ARTIFACT_PATH_SUFFIXES = (
    ".dist-info/metadata",
    ".dist-info/record",
    ".dist-info/wheel",
    ".dist-info/top_level.txt",
)


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

    def to_dict(self) -> Dict[str, Any]:
        return {
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


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ensure_dirs() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _http_json(url: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "secopsai-supply-chain/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


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
        "thresholds": {"malicious_score": 6},
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
    payload["thresholds"].setdefault("malicious_score", 6)
    payload["allow"].setdefault("packages", [])
    payload["deny"].setdefault("packages", [])
    return payload


def _package_matches_policy(entries: List[str], ecosystem: Optional[str], package: Optional[str]) -> bool:
    if not ecosystem or not package:
        return False
    target = f"{ecosystem}:{package}".lower()
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
    target = f"{ecosystem}:{package}".lower()
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
    global_threshold = int(policy.get("thresholds", {}).get("malicious_score", 6))
    if ecosystem:
        eco_thresholds = {str(key).lower(): value for key, value in policy.get("ecosystem_thresholds", {}).items()}
        if ecosystem.lower() in eco_thresholds:
            global_threshold = int(eco_thresholds[ecosystem.lower()])
    if not ecosystem or not package:
        return global_threshold
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
    allow_matches = _matching_policy_entries(policy.get("allow", {}).get("packages", []), ecosystem, package)
    deny_matches = _matching_policy_entries(policy.get("deny", {}).get("packages", []), ecosystem, package)
    target = f"{ecosystem}:{package}".lower()

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
        "global_threshold": int(policy.get("thresholds", {}).get("malicious_score", 6)),
        "ecosystem_threshold": ecosystem_thresholds.get(ecosystem.lower()),
        "matched_package_threshold": matched_package_threshold,
        "disabled_rules": disabled_rules,
        "rule_weight_overrides": overridden_rule_weights,
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
    return {
        "finding_id": result.finding_id,
        "title": f"Suspicious {result.ecosystem} package release: {result.package}@{result.new_version}",
        "summary": _analysis_summary(
            result.analysis,
            f"Native secopsai review marked {result.package}@{result.new_version} as malicious.",
        ),
        "severity": "critical",
        "severity_score": 90,
        "status": "open",
        "disposition": "unreviewed",
        "first_seen": now,
        "last_seen": now,
        "event_ids": [_scan_event_id(result.ecosystem, result.package, result.new_version)],
        "rule_ids": ["SUPPLY-CHAIN-NATIVE"],
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
    }


def _upsert_findings(findings: Iterable[Dict[str, Any]]) -> str:
    resolved = soc_store.default_db_path()
    soc_store.init_db(resolved)
    with soc_store.closing(soc_store.connect(resolved)) as connection:
        for finding in findings:
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
    rows = [json.loads(line) for line in RESULTS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows.reverse()
    return rows[:limit]


def _pick_best_wheel(wheels: list[dict]) -> dict:
    for wheel in wheels:
        filename = str(wheel.get("filename", "")).lower()
        if "py3-none-any" in filename or "py2.py3-none-any" in filename:
            return wheel
    return wheels[0]


def _download_file(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest)
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


def _safe_tar_members(tf: tarfile.TarFile, dest: Path):
    root = dest.resolve()
    for member in tf.getmembers():
        resolved = (dest / member.name).resolve()
        if not str(resolved).startswith(str(root)):
            raise RuntimeError(f"Tar path traversal blocked: {member.name}")
        yield member


def _extract_archive(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest, members=list(_safe_tar_members(tf, dest)))
    elif name.endswith(".tar.bz2"):
        with tarfile.open(archive, "r:bz2") as tf:
            tf.extractall(dest, members=list(_safe_tar_members(tf, dest)))
    elif name.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(dest)
    else:
        raise RuntimeError(f"Unsupported archive format: {archive.name}")
    children = [p for p in dest.iterdir() if not p.name.startswith(".")]
    return children[0] if len(children) == 1 and children[0].is_dir() else dest


def _collect_files(root: Path) -> Dict[str, Path]:
    return {str(path.relative_to(root)): path for path in sorted(root.rglob("*")) if path.is_file()}


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
    if re.search(r"\b(eval|Function)\s*\(", source):
        findings.append(f"{path}: javascript dynamic execution via eval/Function")
    if re.search(r"\bchild_process\b", source) or re.search(r"\b(execSync|spawnSync|execFileSync|spawn|execFile)\s*\(", source):
        findings.append(f"{path}: javascript subprocess-capable API")
    if re.search(r"https?://", source) and re.search(r"\b(fetch|axios|https?\.request|XMLHttpRequest)\b", source):
        findings.append(f"{path}: javascript outbound network request")
    if re.search(r"\b(Buffer\.from|atob|btoa|fromCharCode)\b", source):
        findings.append(f"{path}: javascript encoded payload primitives")
    return sorted(set(findings))


def _package_json_policy_findings(path: str, source: str) -> List[str]:
    try:
        data = json.loads(source)
    except Exception:
        return []

    findings: List[str] = []
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for hook, command in scripts.items():
            if not isinstance(command, str):
                continue
            if hook in {"preinstall", "install", "postinstall", "prepare"}:
                findings.append(f"{path}: npm lifecycle hook present ({hook})")
                if re.search(r"\b(curl|wget|powershell|node\s+-e|python\s+-c|bash\s+-c|sh\s+-c|npx|npm\s+exec)\b", command, re.IGNORECASE):
                    findings.append(f"{path}: npm lifecycle hook runs remote or inline code ({hook})")
                if re.search(r"https?://", command, re.IGNORECASE):
                    findings.append(f"{path}: npm lifecycle hook reaches remote URL ({hook})")

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


def _added_text_scope(report: str) -> str:
    added_lines: List[str] = []
    for line in report.splitlines():
        if line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added_lines.append(line[1:])
    scoped = "\n".join(added_lines).strip()
    return scoped if scoped else report


def _normalized_artifact_path(path: str) -> str:
    cleaned = path.strip().strip("`").replace("\\", "/").lower()
    cleaned = re.sub(r"/+", "/", cleaned)
    cleaned = re.sub(r"^[^/]+\.dist-info/", "", cleaned)
    return cleaned


def _artifact_path_is_benign(path: str) -> bool:
    normalized = _normalized_artifact_path(path)
    if normalized.startswith(BENIGN_ARTIFACT_PATH_PREFIXES):
        return True
    return normalized.endswith(BENIGN_ARTIFACT_PATH_SUFFIXES)


def _filter_semantic_findings(findings: List[str]) -> List[str]:
    filtered: List[str] = []
    for finding in findings:
        path_part, _, detail = finding.partition(":")
        detail = detail.strip()
        if _artifact_path_is_benign(path_part):
            continue
        if detail.startswith("npm lifecycle hook present") and any(hook in detail for hook in ("prepublishOnly", "prepack")):
            continue
        backend_match = re.search(r"custom build backend\s+([^\s]+)", detail)
        if backend_match and backend_match.group(1) in COMMON_BUILD_BACKENDS:
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
            lines.extend(f"  - `{path}`" for path in suspicious_wheel_only[:25])
        if suspicious_sdist_only:
            lines.append("- suspicious_sdist_only_files:")
            lines.extend(f"  - `{path}`" for path in suspicious_sdist_only[:25])
        lines.append("")
    return lines


def _diff_package(ecosystem: str, package: str, old_version: str, new_version: str) -> tuple[str | None, Path | None]:
    tmp = Path(tempfile.mkdtemp(prefix=f"scm_{ecosystem}_{package.replace('/', '_').replace('@', '')}_"))
    try:
        if ecosystem == "npm":
            archive_old = _download_npm_package(package, old_version, tmp / "dl_old")
            archive_new = _download_npm_package(package, new_version, tmp / "dl_new")
            root_old = _extract_archive(archive_old, tmp / "ext_old")
            root_new = _extract_archive(archive_new, tmp / "ext_new")
            report = _build_artifact_report(
                package,
                "npm-tarball",
                archive_old.stem,
                archive_new.stem,
                _collect_files(root_old),
                _collect_files(root_new),
            )
            return report, tmp

        reports: List[str] = []
        artifact_reports: Dict[str, Dict[str, Any]] = {}
        for packagetype in ("bdist_wheel", "sdist"):
            try:
                archive_old = _download_pypi_package(package, old_version, tmp / f"dl_old_{packagetype}", packagetype)
                archive_new = _download_pypi_package(package, new_version, tmp / f"dl_new_{packagetype}", packagetype)
            except RuntimeError:
                continue
            root_old = _extract_archive(archive_old, tmp / f"ext_old_{packagetype}")
            root_new = _extract_archive(archive_new, tmp / f"ext_new_{packagetype}")
            label_old = archive_old.name.rsplit(".", 2)[0]
            label_new = archive_new.name.rsplit(".", 2)[0]
            files_old = _collect_files(root_old)
            files_new = _collect_files(root_new)
            artifact_reports[packagetype] = {"files_old": files_old, "files_new": files_new}
            reports.append(_build_artifact_report(package, packagetype, label_old, label_new, files_old, files_new))
        if not reports:
            raise RuntimeError(f"No common artifact types for {package} {old_version} / {new_version}")
        mismatch_summary = _summarize_artifact_mismatch(artifact_reports)
        if mismatch_summary:
            reports.extend(mismatch_summary)
        return "\n\n---\n\n".join(reports), tmp
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None


def _classify_report_text(
    report: str,
    *,
    ecosystem: Optional[str] = None,
    package: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> tuple[str, str]:
    explanation = explain_verdict(report, ecosystem=ecosystem, package=package, policy=policy)
    return explanation["verdict"], explanation["analysis"]


def explain_verdict(
    report: str,
    *,
    ecosystem: Optional[str] = None,
    package: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    policy = policy or load_policy()
    matched_rules: List[Dict[str, Any]] = []
    seen_rule_names: set[str] = set()
    score = 0
    lowered = _added_text_scope(report).lower()
    for name, pattern, weight in SUSPICIOUS_RULES:
        if not _rule_enabled(policy, name):
            continue
        if name == "network egress":
            if not re.search(r"\b(fetch|axios|requests\.|urllib|httpx|XMLHttpRequest|https?\.request|curl|wget|Invoke-WebRequest)\b", lowered, re.IGNORECASE):
                continue
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
        semantic_contextual = semantic_dynamic or semantic_subprocess or semantic_lifecycle or semantic_remote_dep or semantic_build_custom or semantic_setup_exec

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
        if semantic_subprocess and _rule_enabled(policy, "semantic subprocess behavior"):
            applied_weight = _rule_weight(policy, "semantic subprocess behavior", 2)
            score += applied_weight
            _record_rule_match(
                matched_rules,
                seen_rule_names,
                "semantic subprocess behavior",
                applied_weight,
                "Semantic findings include subprocess-capable behavior.",
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
        }

    rule_names = [match["rule"] for match in matched_rules]
    if score >= malicious_threshold:
        analysis = "Deterministic rules flagged: " + ", ".join(rule_names)
        verdict = "malicious"
    else:
        analysis = "No strong compromise indicators found." if not rule_names else "Observed low-confidence indicators: " + ", ".join(rule_names)
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
) -> ScanResult:
    _ensure_dirs()
    policy = load_policy()
    old_version = old_version or (_npm_get_previous_version(package, new_version) if ecosystem == "npm" else _get_previous_version(package, new_version))
    if not old_version:
        return ScanResult(ecosystem, package, None, new_version, "skipped", "", None, rank, None, "no previous version found")
    report, tmp_dir = _diff_package(ecosystem, package, old_version, new_version)
    try:
        if not report:
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
        finding_id = _finding_id(ecosystem, package, new_version) if verdict == "malicious" else None
        return ScanResult(ecosystem, package, old_version, new_version, verdict, analysis, report_path, rank, finding_id)
    except Exception as exc:
        return ScanResult(ecosystem, package, old_version, new_version, "error", repr(exc), None, rank, None, str(exc))
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
) -> Dict[str, Any]:
    result = _scan_release(ecosystem, package, version, old_version=previous_version, model=model, keep_report=keep_report)
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
