"""AI dependency guard for hallucinated and slopsquatted packages.

The guard is intentionally static: it reads repository files and optional
redacted agent telemetry, then checks package names against registry metadata.
It never installs packages, imports generated code, runs lifecycle hooks, or
activates extensions.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

import soc_store

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility.
    import tomli as tomllib

from secopsai import supply_chain


SOURCE = "secopsai-ai-dependency-guard"
DEFAULT_MAX_FILE_BYTES = 512 * 1024
DEFAULT_REGISTRATION_WINDOW_DAYS = 30
SUPPORTED_ECOSYSTEMS = (
    "npm",
    "pypi",
    "packagist",
    "go",
    "maven",
    "nuget",
    "rubygems",
    "open-vsx",
    "crates",
    "huggingface",
)

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "site",
}

PY_STDLIB_LIKE = {
    "__future__",
    "argparse",
    "asyncio",
    "base64",
    "collections",
    "contextlib",
    "csv",
    "dataclasses",
    "datetime",
    "email",
    "enum",
    "functools",
    "hashlib",
    "html",
    "http",
    "importlib",
    "inspect",
    "io",
    "itertools",
    "json",
    "logging",
    "math",
    "os",
    "pathlib",
    "queue",
    "random",
    "re",
    "shlex",
    "shutil",
    "sqlite3",
    "statistics",
    "string",
    "subprocess",
    "sys",
    "tempfile",
    "textwrap",
    "threading",
    "time",
    "tomllib",
    "typing",
    "unittest",
    "urllib",
    "uuid",
    "xml",
    "zipfile",
}

COMMON_TRUSTED_NAMES = {
    "aiohttp",
    "anthropic",
    "axios",
    "boto3",
    "chalk",
    "click",
    "django",
    "express",
    "fastapi",
    "flask",
    "jest",
    "langchain",
    "lodash",
    "numpy",
    "openai",
    "pandas",
    "pytest",
    "react",
    "requests",
    "scikit-learn",
    "tensorflow",
    "torch",
    "typescript",
    "vite",
}

PACKAGE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,214}$")
NPM_SCOPED_RE = re.compile(r"^@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
PACKAGIST_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAVEN_RE = re.compile(r"^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$")
OPEN_VSX_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")
GO_RE = re.compile(r"^[A-Za-z0-9_.-]+\.[A-Za-z0-9_.~/-]+$")
VERSION_SPLIT_RE = re.compile(r"\s*(?:==|~=|!=|<=|>=|<|>|=|\[|;|,|\s)\s*")
AI_WORD_RE = re.compile(r"\b(?:ai|llm|agent|assistant|codex|openclaw|hermes|copilot|cursor|windsurf|claude|chatgpt|generated|vibe)\b", re.I)


@dataclass
class Evidence:
    path: str
    source_type: str
    detail: str
    line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = {"path": self.path, "source_type": self.source_type, "detail": self.detail}
        if self.line is not None:
            payload["line"] = self.line
        return payload


@dataclass
class Candidate:
    ecosystem: str
    package: str
    evidence: List[Evidence] = field(default_factory=list)
    requested_version: Optional[str] = None

    @property
    def key(self) -> Tuple[str, str]:
        return (self.ecosystem, self.package)

    @property
    def ai_origin(self) -> bool:
        return any(item.source_type.startswith("ai_") or AI_WORD_RE.search(item.path) for item in self.evidence)

    @property
    def manifest_origin(self) -> bool:
        return any(item.source_type in {"manifest", "lockfile", "ci", "dockerfile"} for item in self.evidence)


@dataclass
class RegistryInfo:
    exists: bool
    ecosystem: str
    package: str
    created_at: Optional[str] = None
    latest_version: Optional[str] = None
    version_count: int = 0
    error: Optional[str] = None
    metadata_url: Optional[str] = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _days_since(value: Optional[str]) -> Optional[float]:
    parsed = _parse_datetime(value)
    if parsed is None:
        return None
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > DEFAULT_MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _iter_repo_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [item for item in dirs if item not in SKIP_DIRS and not item.startswith(".cache")]
        base = Path(current)
        for name in files:
            path = base / name
            if path.is_file():
                yield path


def _versionless_requirement(value: str) -> str:
    text = value.strip().strip("`'\".,;:)]}")
    if not text or text.startswith(("-", "#", "git+", "http://", "https://", ".")):
        return ""
    text = text.split("#", 1)[0].strip()
    if " @ " in text:
        text = text.split(" @ ", 1)[0].strip()
    return VERSION_SPLIT_RE.split(text, 1)[0].strip()


def _is_valid_package(ecosystem: str, package: str) -> bool:
    if not package or package in {".", ".."}:
        return False
    eco = supply_chain.canonical_ecosystem(ecosystem)
    package = supply_chain.normalize_package_name(eco, package)
    if eco == "npm":
        return bool(NPM_SCOPED_RE.match(package) or PACKAGE_TOKEN_RE.match(package))
    if eco in {"pypi", "crates", "rubygems", "nuget"}:
        return bool(PACKAGE_TOKEN_RE.match(package))
    if eco == "packagist":
        return bool(PACKAGIST_RE.match(package))
    if eco == "maven":
        return bool(MAVEN_RE.match(package))
    if eco == "open-vsx":
        return bool(OPEN_VSX_RE.match(package))
    if eco in {"go", "huggingface"}:
        return "/" in package and bool(GO_RE.match(package) or PACKAGIST_RE.match(package))
    return bool(package)


def _add_candidate(
    candidates: Dict[Tuple[str, str], Candidate],
    ecosystem: str,
    package: str,
    evidence: Evidence,
    *,
    requested_version: Optional[str] = None,
) -> None:
    eco = supply_chain.canonical_ecosystem(ecosystem)
    normalized = supply_chain.normalize_package_name(eco, package)
    if not _is_valid_package(eco, normalized):
        return
    key = (eco, normalized)
    if key not in candidates:
        candidates[key] = Candidate(eco, normalized)
    candidates[key].evidence.append(evidence)
    if requested_version and not candidates[key].requested_version:
        candidates[key].requested_version = requested_version


def _iter_dependency_object(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key in value:
            yield str(key)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                yield _versionless_requirement(item)


def _scan_package_json(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundledDependencies"):
        for package in _iter_dependency_object(payload.get(field)):
            _add_candidate(candidates, "npm", package, Evidence(_safe_rel(path, root), "manifest", f"package.json {field}"))


def _scan_package_lock(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    for package in _iter_dependency_object(payload.get("dependencies")):
        _add_candidate(candidates, "npm", package, Evidence(_safe_rel(path, root), "lockfile", "package-lock dependencies"))
    for item in (payload.get("packages") or {}).values() if isinstance(payload.get("packages"), dict) else []:
        for package in _iter_dependency_object((item or {}).get("dependencies")):
            _add_candidate(candidates, "npm", package, Evidence(_safe_rel(path, root), "lockfile", "package-lock nested dependency"))


def _scan_requirements(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    for lineno, line in enumerate(text.splitlines(), 1):
        package = _versionless_requirement(line)
        if package:
            _add_candidate(candidates, "pypi", package, Evidence(_safe_rel(path, root), "manifest", "requirements entry", lineno))


def _scan_pyproject(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    try:
        payload = tomllib.loads(text)
    except Exception:
        return
    project = payload.get("project") or {}
    for package in _iter_dependency_object(project.get("dependencies")):
        _add_candidate(candidates, "pypi", package, Evidence(_safe_rel(path, root), "manifest", "pyproject project.dependencies"))
    for group in (project.get("optional-dependencies") or {}).values():
        for package in _iter_dependency_object(group):
            _add_candidate(candidates, "pypi", package, Evidence(_safe_rel(path, root), "manifest", "pyproject optional dependency"))
    poetry = (((payload.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    for package in poetry:
        if str(package).lower() != "python":
            _add_candidate(candidates, "pypi", str(package), Evidence(_safe_rel(path, root), "manifest", "poetry dependency"))


def _scan_composer_json(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    for field in ("require", "require-dev"):
        for package in (payload.get(field) or {}):
            name = str(package)
            if name != "php" and not name.startswith("ext-"):
                _add_candidate(candidates, "packagist", name, Evidence(_safe_rel(path, root), "manifest", f"composer.json {field}"))


def _scan_composer_lock(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    for row in list(payload.get("packages") or []) + list(payload.get("packages-dev") or []):
        if isinstance(row, dict) and row.get("name"):
            _add_candidate(candidates, "packagist", str(row["name"]), Evidence(_safe_rel(path, root), "lockfile", "composer.lock package"), requested_version=str(row.get("version") or "") or None)


def _scan_go_mod(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("module ", "//")):
            continue
        if stripped.startswith("require "):
            stripped = stripped.removeprefix("require ").strip()
        if stripped.startswith("(") or stripped.startswith(")"):
            continue
        package = stripped.split()[0] if stripped.split() else ""
        _add_candidate(candidates, "go", package, Evidence(_safe_rel(path, root), "manifest", "go.mod require", lineno))


def _scan_cargo_toml(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    in_deps = False
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps = "dependencies" in stripped
            continue
        if in_deps and "=" in stripped and not stripped.startswith("#"):
            _add_candidate(candidates, "crates", stripped.split("=", 1)[0].strip().strip('"'), Evidence(_safe_rel(path, root), "manifest", "Cargo.toml dependency", lineno))


def _scan_ruby(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    for lineno, line in enumerate(text.splitlines(), 1):
        match = re.search(r"\bgem\s+['\"]([^'\"]+)['\"]", line)
        if match:
            _add_candidate(candidates, "rubygems", match.group(1), Evidence(_safe_rel(path, root), "manifest", "Gemfile gem", lineno))


def _scan_xml_packages(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    if path.name.endswith(".csproj") or path.name == "packages.config":
        for lineno, line in enumerate(text.splitlines(), 1):
            match = re.search(r'(?:PackageReference|package)\s+[^>]*(?:Include|id)=["\']([^"\']+)["\']', line, re.I)
            if match:
                _add_candidate(candidates, "nuget", match.group(1), Evidence(_safe_rel(path, root), "manifest", "NuGet package reference", lineno))
        return
    try:
        root_xml = ET.fromstring(text)
    except ET.ParseError:
        return
    for dep in root_xml.findall(".//{*}dependency"):
        group = dep.findtext("{*}groupId")
        artifact = dep.findtext("{*}artifactId")
        if group and artifact:
            _add_candidate(candidates, "maven", f"{group}:{artifact}", Evidence(_safe_rel(path, root), "manifest", "Maven dependency"))


def _scan_source_imports(path: Path, root: Path, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    suffix = path.suffix.lower()
    if suffix == ".py":
        for lineno, line in enumerate(text.splitlines(), 1):
            match = re.match(r"\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if match and match.group(1) not in PY_STDLIB_LIKE:
                _add_candidate(candidates, "pypi", match.group(1).replace("_", "-"), Evidence(_safe_rel(path, root), "source_import", "Python import", lineno))
    elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in re.finditer(r"(?:from\s+|require\(|import\()\s*['\"]([^'\"]+)['\"]", line):
                package = match.group(1)
                if package.startswith((".", "/", "node:")):
                    continue
                if package.startswith("@"):
                    parts = package.split("/")
                    package = "/".join(parts[:2])
                else:
                    package = package.split("/", 1)[0]
                _add_candidate(candidates, "npm", package, Evidence(_safe_rel(path, root), "source_import", "JavaScript import", lineno))


def _scan_command_text(path_label: str, source_type: str, text: str, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    patterns = [
        ("npm", r"\b(?:npm\s+(?:install|i)|pnpm\s+add|yarn\s+add)\s+([@A-Za-z0-9._/-][^\n;&|]*)"),
        ("pypi", r"\b(?:pip(?:3)?\s+install|uv\s+pip\s+install|poetry\s+add)\s+([A-Za-z0-9._/\[\]-][^\n;&|]*)"),
        ("packagist", r"\bcomposer\s+require\s+([A-Za-z0-9._/-][^\n;&|]*)"),
        ("go", r"\bgo\s+get\s+([A-Za-z0-9._~/-][^\n;&|]*)"),
        ("crates", r"\bcargo\s+add\s+([A-Za-z0-9._-][^\n;&|]*)"),
        ("rubygems", r"\bgem\s+install\s+([A-Za-z0-9._-][^\n;&|]*)"),
    ]
    for ecosystem, pattern in patterns:
        for match in re.finditer(pattern, text):
            raw = match.group(1)
            for token in raw.split():
                if token.startswith("-"):
                    continue
                package = _versionless_requirement(token)
                if package:
                    _add_candidate(candidates, ecosystem, package, Evidence(path_label, source_type, f"{ecosystem} install command"))


def collect_repo_candidates(path: str | Path, *, ecosystems: Optional[Sequence[str]] = None) -> Dict[Tuple[str, str], Candidate]:
    root = Path(path).expanduser().resolve()
    allowed = {supply_chain.canonical_ecosystem(item) for item in ecosystems or SUPPORTED_ECOSYSTEMS}
    candidates: Dict[Tuple[str, str], Candidate] = {}
    for file_path in _iter_repo_files(root):
        text = _read_text(file_path)
        if text is None:
            continue
        name = file_path.name
        suffix = file_path.suffix.lower()
        if name == "package.json":
            _scan_package_json(file_path, root, text, candidates)
        elif name == "package-lock.json":
            _scan_package_lock(file_path, root, text, candidates)
        elif name.startswith("requirements") and name.endswith(".txt"):
            _scan_requirements(file_path, root, text, candidates)
        elif name == "pyproject.toml":
            _scan_pyproject(file_path, root, text, candidates)
        elif name == "composer.json":
            _scan_composer_json(file_path, root, text, candidates)
        elif name == "composer.lock":
            _scan_composer_lock(file_path, root, text, candidates)
        elif name == "go.mod":
            _scan_go_mod(file_path, root, text, candidates)
        elif name == "Cargo.toml":
            _scan_cargo_toml(file_path, root, text, candidates)
        elif name in {"Gemfile", "Gemfile.lock"}:
            _scan_ruby(file_path, root, text, candidates)
        elif name == "pom.xml" or suffix == ".csproj" or name == "packages.config":
            _scan_xml_packages(file_path, root, text, candidates)
        if name.lower().startswith("dockerfile") or ".github/workflows" in _safe_rel(file_path, root):
            _scan_command_text(_safe_rel(file_path, root), "ci" if ".github/workflows" in _safe_rel(file_path, root) else "dockerfile", text, candidates)
        if suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            _scan_source_imports(file_path, root, text, candidates)
    return {key: value for key, value in candidates.items() if key[0] in allowed}


def _agent_text_files(root: Path, agent_source: str) -> Iterable[Tuple[str, str]]:
    source = agent_source.lower()
    roots: List[Path] = []
    if source in {"auto", "sessions"}:
        roots.extend([root / "data" / "sessions", root / "data" / "agent_jobs"])
    if source in {"auto", "openclaw"}:
        roots.append(root / "data" / "openclaw")
    for base in roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".md", ".txt", ".log"}:
                text = _read_text(path)
                if text:
                    yield (_safe_rel(path, root), text)


def collect_agent_candidates(path: str | Path, *, agent_source: str = "auto", ecosystems: Optional[Sequence[str]] = None) -> Dict[Tuple[str, str], Candidate]:
    root = Path(path).expanduser().resolve()
    allowed = {supply_chain.canonical_ecosystem(item) for item in ecosystems or SUPPORTED_ECOSYSTEMS}
    candidates: Dict[Tuple[str, str], Candidate] = {}
    for label, text in _agent_text_files(root, agent_source):
        _scan_command_text(label, "ai_agent_log", text, candidates)
        _scan_source_imports(Path(label), root, text, candidates)

    if agent_source in {"auto", "hermes"}:
        try:
            from adapters.hermes.adapter import HermesAdapter

            adapter = HermesAdapter({})
            for event in adapter.collect():
                normalized = adapter.normalize(event)
                text = json.dumps(normalized, sort_keys=True)
                label = f"hermes:{normalized.get('event_id') or normalized.get('path') or 'event'}"
                _scan_command_text(label, "ai_agent_log", text, candidates)
        except Exception:
            pass
    return {key: value for key, value in candidates.items() if key[0] in allowed}


def _metadata_url(ecosystem: str, package: str) -> Optional[str]:
    encoded = urllib.parse.quote(package, safe="@/")
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{encoded}"
    if ecosystem == "pypi":
        return supply_chain.PYPI_JSON.format(package=encoded)
    if ecosystem == "packagist":
        return f"https://repo.packagist.org/p2/{encoded}.json"
    return None


def fetch_registry_info(ecosystem: str, package: str, *, timeout: int = 8) -> RegistryInfo:
    eco = supply_chain.canonical_ecosystem(ecosystem)
    normalized = supply_chain.normalize_package_name(eco, package)
    try:
        if eco == "npm":
            metadata = supply_chain._http_json(f"{supply_chain.NPM_REGISTRY}/{urllib.parse.quote(normalized, safe='@/')}", timeout=timeout)
            times = metadata.get("time") or {}
            versions = metadata.get("versions") or {}
            return RegistryInfo(
                True,
                eco,
                normalized,
                created_at=times.get("created"),
                latest_version=((metadata.get("dist-tags") or {}).get("latest")),
                version_count=len(versions),
                metadata_url=_metadata_url(eco, normalized),
            )
        if eco == "pypi":
            metadata = supply_chain._http_json(supply_chain.PYPI_JSON.format(package=urllib.parse.quote(normalized)), timeout=timeout)
            releases = metadata.get("releases") or {}
            created = None
            for files in releases.values():
                for row in files or []:
                    stamp = row.get("upload_time_iso_8601") or row.get("upload_time")
                    if stamp and (created is None or stamp < created):
                        created = stamp
            return RegistryInfo(
                True,
                eco,
                normalized,
                created_at=created,
                latest_version=(metadata.get("info") or {}).get("version"),
                version_count=len(releases),
                metadata_url=_metadata_url(eco, normalized),
            )
        metadata = supply_chain._fetch_ecosystem_metadata(eco, normalized, timeout=timeout)
        rows = supply_chain._version_rows_from_metadata(eco, normalized, metadata if metadata is not None else {})
        rows_with_time = [row for row in rows if row.get("published_at")]
        created = min((str(row["published_at"]) for row in rows_with_time), default=None)
        latest = rows[-1]["version"] if rows else None
        return RegistryInfo(True, eco, normalized, created_at=created, latest_version=latest, version_count=len(rows), metadata_url=_metadata_url(eco, normalized))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return RegistryInfo(False, eco, normalized, error="not_found", metadata_url=_metadata_url(eco, normalized))
        return RegistryInfo(False, eco, normalized, error=f"http_{exc.code}", metadata_url=_metadata_url(eco, normalized))
    except Exception as exc:
        return RegistryInfo(False, eco, normalized, error=str(exc)[:180], metadata_url=_metadata_url(eco, normalized))


def _simple_name(package: str) -> str:
    if "/" in package:
        package = package.rsplit("/", 1)[-1]
    if ":" in package:
        package = package.rsplit(":", 1)[-1]
    return package.lower().replace("_", "-")


def _similar_trusted_package(package: str) -> Optional[Dict[str, Any]]:
    simple = _simple_name(package)
    if simple in COMMON_TRUSTED_NAMES or len(simple) < 4:
        return None
    best_name = ""
    best_score = 0.0
    for trusted in COMMON_TRUSTED_NAMES:
        score = difflib.SequenceMatcher(a=simple, b=trusted).ratio()
        if score > best_score:
            best_name = trusted
            best_score = score
    if best_score >= 0.86:
        return {"target": best_name, "score": round(best_score, 3)}
    return None


def _allowed_by_policy(candidate: Candidate) -> bool:
    policy = supply_chain.load_policy()
    return supply_chain._package_matches_policy(policy.get("allow", {}).get("packages", []), candidate.ecosystem, candidate.package)


def _check_advisory(candidate: Candidate) -> List[Dict[str, Any]]:
    version = candidate.requested_version or "0.0.0"
    try:
        payload = supply_chain.check_advisory(candidate.ecosystem, candidate.package, version)
    except Exception:
        return []
    return list(payload.get("matches") or [])


def classify_candidate(
    candidate: Candidate,
    *,
    registry_info: RegistryInfo,
    registration_window_days: int = DEFAULT_REGISTRATION_WINDOW_DAYS,
) -> Dict[str, Any]:
    advisory_matches = _check_advisory(candidate)
    similar = _similar_trusted_package(candidate.package)
    reasons: List[str] = []
    status = "needs_review"
    confidence = "low"
    severity = "info"
    score = 10

    if _allowed_by_policy(candidate):
        status = "local_only_or_private"
        confidence = "high"
        severity = "info"
        score = 0
        reasons.append("Package is allowed by local supply-chain policy.")
    elif advisory_matches:
        status = "advisory_matched"
        confidence = "high"
        severity = "critical"
        score = 95
        reasons.append("Existing SecOpsAI advisory matched this package/version context.")
    elif not registry_info.exists and registry_info.error == "not_found":
        status = "missing_or_hallucinated"
        confidence = "high" if candidate.ai_origin or candidate.manifest_origin else "medium"
        severity = "high" if candidate.ai_origin or candidate.manifest_origin else "medium"
        score = 78 if severity == "high" else 55
        reasons.append("Package was referenced locally but registry metadata returned not found.")
        if candidate.ai_origin:
            reasons.append("AI-agent evidence suggests this package may have been generated or recommended by an LLM.")
        if similar:
            status = "name_similarity_risk"
            severity = "high"
            score = max(score, 82)
            reasons.append(f"Name is similar to trusted package {similar['target']} (similarity {similar['score']}).")
    elif not registry_info.exists:
        status = "needs_review"
        confidence = "low"
        severity = "low"
        score = 25
        reasons.append(f"Registry metadata lookup failed: {registry_info.error or 'unknown error'}.")
    else:
        age_days = _days_since(registry_info.created_at)
        if age_days is not None and age_days <= registration_window_days:
            status = "newly_registered"
            confidence = "high" if candidate.ai_origin else "medium"
            severity = "high" if candidate.ai_origin or candidate.manifest_origin else "medium"
            score = 76 if severity == "high" else 55
            reasons.append(f"Package registry record appears newly created within {registration_window_days} days.")
        elif similar:
            status = "name_similarity_risk"
            confidence = "medium"
            severity = "medium"
            score = 58
            reasons.append(f"Name is similar to trusted package {similar['target']} (similarity {similar['score']}).")
        else:
            status = "verified_existing"
            confidence = "high" if registry_info.version_count > 1 else "medium"
            severity = "info"
            score = 5
            reasons.append("Package exists in registry metadata.")

    return {
        "ecosystem": candidate.ecosystem,
        "package": candidate.package,
        "requested_version": candidate.requested_version,
        "classification": status,
        "severity": severity,
        "confidence": confidence,
        "score": score,
        "ai_origin": candidate.ai_origin,
        "manifest_origin": candidate.manifest_origin,
        "registry": {
            "exists": registry_info.exists,
            "created_at": registry_info.created_at,
            "latest_version": registry_info.latest_version,
            "version_count": registry_info.version_count,
            "error": registry_info.error,
            "metadata_url": registry_info.metadata_url,
        },
        "advisory_matches": advisory_matches,
        "similar_to": similar,
        "evidence": [item.to_dict() for item in candidate.evidence[:12]],
        "reasons": reasons,
    }


def _finding_id(candidate: Dict[str, Any]) -> str:
    base = f"{candidate.get('ecosystem')}:{candidate.get('package')}:{candidate.get('classification')}"
    return "AIDG-" + hashlib.sha256(base.encode("utf-8")).hexdigest()[:16].upper()


def _finding_for_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    now = utc_now()
    title = f"AI Dependency Guard risk: {candidate['ecosystem']}:{candidate['package']}"
    evidence_bits = "; ".join(candidate.get("reasons") or []) or "AI dependency guard flagged this dependency for review."
    return {
        "finding_id": _finding_id(candidate),
        "title": title,
        "summary": evidence_bits[:500],
        "severity": candidate.get("severity") or "high",
        "severity_score": int(candidate.get("score") or 70),
        "status": "open",
        "disposition": "unreviewed",
        "first_seen": now,
        "last_seen": now,
        "event_ids": [f"ai-dependency-guard:{candidate['ecosystem']}:{candidate['package']}"],
        "rule_ids": ["AI-DEPENDENCY-GUARD", str(candidate.get("classification") or "needs_review")],
        "platform": "supply_chain",
        "source": SOURCE,
        "category": "supply_chain",
        "ecosystem": candidate.get("ecosystem"),
        "package": candidate.get("package"),
        "classification": candidate.get("classification"),
        "confidence": candidate.get("confidence"),
        "ai_origin": candidate.get("ai_origin"),
        "manifest_origin": candidate.get("manifest_origin"),
        "evidence": candidate.get("evidence", []),
        "registry": candidate.get("registry", {}),
        "advisory_matches": candidate.get("advisory_matches", []),
        "recommended_mitigation": [
            "Verify the package name against official project documentation before installing.",
            "If the package came from AI output, ask for a source-backed alternative and pin only after review.",
            "For newly registered packages, inspect metadata, maintainer identity, and artifacts in an isolated workflow.",
        ],
    }


def _persist_findings(findings: List[Dict[str, Any]]) -> Optional[str]:
    if not findings:
        return None
    db_path = soc_store.default_db_path()
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        for finding in findings:
            soc_store.upsert_finding(connection, finding, SOURCE)
        connection.commit()
    return db_path


def _summary(candidates: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total_candidates": len(candidates),
        "verified": sum(1 for item in candidates if item.get("classification") == "verified_existing"),
        "missing_or_hallucinated": sum(1 for item in candidates if item.get("classification") == "missing_or_hallucinated"),
        "newly_registered": sum(1 for item in candidates if item.get("classification") == "newly_registered"),
        "high_risk": sum(1 for item in candidates if item.get("severity") in {"high", "critical"}),
    }


def run_ai_dependency_guard(
    *,
    path: str | Path,
    include_agent_logs: bool = False,
    agent_source: str = "auto",
    ecosystems: Optional[Sequence[str]] = None,
    fail_on: Optional[str] = None,
    persist_findings: bool = False,
    report_path: Optional[str | Path] = None,
    timeout: int = 8,
    metadata_fetcher: Optional[Callable[[str, str], RegistryInfo]] = None,
) -> Dict[str, Any]:
    root = Path(path).expanduser().resolve()
    allowed = [supply_chain.canonical_ecosystem(item) for item in ecosystems] if ecosystems else list(SUPPORTED_ECOSYSTEMS)
    candidates = collect_repo_candidates(root, ecosystems=allowed)
    if include_agent_logs:
        for key, candidate in collect_agent_candidates(root, agent_source=agent_source, ecosystems=allowed).items():
            if key not in candidates:
                candidates[key] = candidate
            else:
                candidates[key].evidence.extend(candidate.evidence)

    fetcher = metadata_fetcher or (lambda eco, pkg: fetch_registry_info(eco, pkg, timeout=timeout))
    classified: List[Dict[str, Any]] = []
    for candidate in sorted(candidates.values(), key=lambda item: (item.ecosystem, item.package)):
        registry = fetcher(candidate.ecosystem, candidate.package)
        classified.append(classify_candidate(candidate, registry_info=registry))

    findings = [
        _finding_for_candidate(item)
        for item in classified
        if item.get("severity") in {"high", "critical"} and item.get("confidence") in {"medium", "high"}
    ]
    db_path = _persist_findings(findings) if persist_findings else None
    recommendations = []
    if any(item.get("classification") == "missing_or_hallucinated" for item in classified):
        recommendations.append("Review missing packages before install; ask the AI assistant for source-backed package names.")
    if any(item.get("classification") == "newly_registered" for item in classified):
        recommendations.append("Treat newly registered AI-suggested dependencies as untrusted until maintainer and artifact review is complete.")
    if any(item.get("classification") == "name_similarity_risk" for item in classified):
        recommendations.append("Check similarity-risk package names for slopsquatting or typosquatting before use.")

    payload: Dict[str, Any] = {
        "ok": True,
        "path": str(root),
        "included_agent_logs": bool(include_agent_logs),
        "agent_source": agent_source if include_agent_logs else None,
        "summary": _summary(classified),
        "candidates": classified,
        "findings": findings,
        "recommendations": recommendations,
        "db_path": db_path,
    }
    if fail_on in {"high", "critical"}:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        payload["would_fail"] = any(order.get(item.get("severity", "info"), 0) >= order[fail_on] for item in classified)
        payload["fail_on"] = fail_on
    else:
        payload["would_fail"] = False
        payload["fail_on"] = fail_on or "none"
    if report_path:
        output = Path(report_path).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        payload["report_path"] = str(output)
    return payload
