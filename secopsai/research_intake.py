"""Safe, non-executing package research intake.

The intake engine deliberately treats package archives as hostile data. It
fetches only from adapter-owned HTTPS hosts, keeps artifacts in quarantine,
and inspects archive members in memory without extracting or executing them.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from secopsai.research_cases import add_evidence, add_subject, get_case


MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
MAX_EXPANDED_BYTES = 250 * 1024 * 1024
MAX_INSPECTED_FILE_BYTES = 2 * 1024 * 1024
MAX_INSPECTED_TEXT_BYTES = 12 * 1024 * 1024
MAX_REDIRECTS = 3
DEFAULT_TIMEOUT = 20
USER_AGENT = "SecOpsAI-Research/1.0 (defensive static analysis)"

TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".html", ".java", ".js", ".json",
    ".jsx", ".md", ".mjs", ".py", ".rb", ".rs", ".sh", ".toml", ".ts",
    ".tsx", ".txt", ".xml", ".yaml", ".yml", ".lock", ".cfg", ".ini",
}
MANIFEST_NAMES = {
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "nuspec", "pom.xml", "gemspec", "composer.json", "go.mod", "extension.vsixmanifest",
}
LIFECYCLE_NAMES = {
    "preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishonly",
    "prepack", "postpack", "preversion", "version", "postversion",
}


class IntakeError(ValueError):
    """A user-safe, non-secret intake failure."""


@dataclass(frozen=True)
class RegistryMetadata:
    ecosystem: str
    package: str
    version: str
    metadata_url: str
    artifact_url: str
    publisher: str
    published_at: str
    dependencies: Dict[str, Any]
    integrity: Dict[str, Any]
    raw: Dict[str, Any]


def _text(value: Any, limit: int = 4096) -> str:
    value = str(value or "").strip()
    if "\x00" in value or len(value) > limit:
        raise IntakeError("input contains invalid characters or exceeds its limit")
    return value


def _safe_package(value: Any) -> str:
    package = _text(value, 512)
    if not package or package.startswith(".") or "\\" in package or ".." in package:
        raise IntakeError("package name is invalid")
    if not re.fullmatch(r"[A-Za-z0-9@._:/+\-]+", package):
        raise IntakeError("package name contains unsupported characters")
    return package


def _version(value: Any) -> str:
    value = _text(value, 160)
    if value and not re.fullmatch(r"[A-Za-z0-9.+:_~!*/\-]+", value):
        raise IntakeError("version contains unsupported characters")
    return value


def _is_prerelease(value: str) -> bool:
    return bool(re.search(r"(?i)(?:^|[._+\-])(alpha|beta|rc|preview|pre|dev|snapshot|nightly)(?:[._+\-]|\d|$)", str(value or "")))


def _safe_member_name(name: str) -> str:
    normalized = str(name or "").replace("\\", "/")
    if not normalized or normalized.startswith("/") or "\x00" in normalized:
        raise IntakeError("archive contains an unsafe member path")
    parts = [part for part in normalized.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise IntakeError("archive contains traversal path")
    return "/".join(parts)


def _is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise IntakeError("registry host did not resolve to an IP address") from exc
    return bool(ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_link_local)


def _validate_public_host(host: str) -> None:
    if not host or host.lower() in {"localhost", "metadata.google.internal"}:
        raise IntakeError("registry host is not allowed")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise IntakeError("registry host could not be resolved") from exc
    if not addresses or not all(_is_public_ip(address) for address in addresses):
        raise IntakeError("registry host resolves to a non-public address")


class SafeFetcher:
    """Bounded HTTP client with per-redirect host validation."""

    def __init__(self, *, timeout: int = DEFAULT_TIMEOUT, max_redirects: int = MAX_REDIRECTS,
                 fetch: Optional[Callable[[str, int], Tuple[int, Dict[str, str], bytes]]] = None) -> None:
        self.timeout = max(1, min(int(timeout), 120))
        self.max_redirects = max(0, min(int(max_redirects), 5))
        self._injected = fetch

    def get(self, url: str, *, allowed_hosts: Iterable[str], max_bytes: int,
            headers: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, str], bytes]:
        current = url
        hosts = {str(host).lower() for host in allowed_hosts}
        request_headers = {"Accept": "application/json, application/octet-stream", "User-Agent": USER_AGENT}
        if headers:
            request_headers.update(headers)
        for redirect_count in range(self.max_redirects + 1):
            parsed = urllib.parse.urlparse(current)
            if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.hostname:
                raise IntakeError("only credential-free HTTPS registry URLs are allowed")
            host = parsed.hostname.lower().rstrip(".")
            if host not in hosts:
                raise IntakeError(f"URL host is outside the adapter allowlist: {host}")
            if self._injected is None:
                _validate_public_host(host)
                request = urllib.request.Request(
                    current,
                    headers=request_headers,
                )
                opener = urllib.request.build_opener(_NoRedirectHandler())
                try:
                    with opener.open(request, timeout=self.timeout) as response:
                        status = int(response.status)
                        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
                        body = response.read(max_bytes + 1)
                except urllib.error.HTTPError as exc:
                    status = int(exc.code)
                    headers = {str(key).lower(): str(value) for key, value in exc.headers.items()}
                    body = exc.read(max_bytes + 1)
                except (urllib.error.URLError, TimeoutError, OSError) as exc:
                    raise IntakeError("registry request failed") from exc
            else:
                status, headers, body = self._injected(current, max_bytes)
                headers = {str(key).lower(): str(value) for key, value in headers.items()}
            if len(body) > max_bytes:
                raise IntakeError("registry response exceeded the safety limit")
            if status in {301, 302, 303, 307, 308}:
                location = headers.get("location", "")
                if not location or redirect_count >= self.max_redirects:
                    raise IntakeError("registry redirect chain exceeded the safety limit")
                current = urllib.parse.urljoin(current, location)
                continue
            if status < 200 or status >= 300:
                raise IntakeError(f"registry returned HTTP {status}")
            return current, headers, body
        raise IntakeError("registry redirect chain exceeded the safety limit")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class RegistryAdapter:
    ecosystem = ""
    metadata_hosts: Tuple[str, ...] = ()
    artifact_hosts: Tuple[str, ...] = ()

    def metadata_url(self, package: str) -> str:
        raise NotImplementedError

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        raise NotImplementedError

    def _json(self, url: str, fetcher: SafeFetcher) -> Tuple[str, Dict[str, Any]]:
        final_url, headers, body = fetcher.get(url, allowed_hosts=self.metadata_hosts, max_bytes=MAX_METADATA_BYTES)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntakeError("registry metadata was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise IntakeError("registry metadata was not an object")
        return final_url, payload

    @staticmethod
    def _pick_version(versions: Sequence[str], requested: str) -> str:
        requested = _version(requested)
        if requested:
            if requested not in versions:
                raise IntakeError("requested package version was not found")
            return requested
        if not versions:
            raise IntakeError("registry returned no package versions")
        stable = [str(item) for item in versions if not _is_prerelease(str(item))]
        return stable[-1] if stable else str(versions[-1])


class NpmAdapter(RegistryAdapter):
    ecosystem = "npm"
    metadata_hosts = ("registry.npmjs.org",)
    artifact_hosts = ("registry.npmjs.org",)

    def metadata_url(self, package: str) -> str:
        return "https://registry.npmjs.org/" + urllib.parse.quote(package, safe="@/")

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, payload = self._json(self.metadata_url(package), fetcher)
        versions = list((payload.get("versions") or {}).keys())
        version = self._pick_version(versions, requested_version or str((payload.get("dist-tags") or {}).get("latest", "")))
        item = payload.get("versions", {}).get(version) or {}
        dist = item.get("dist") or {}
        artifact = str(dist.get("tarball") or "")
        if not artifact:
            raise IntakeError("npm metadata did not include an official tarball")
        return RegistryMetadata(self.ecosystem, package, version, url, artifact,
                                str((payload.get("author") or {}).get("name") if isinstance(payload.get("author"), dict) else payload.get("author") or ""),
                                str(item.get("time") or payload.get("time", {}).get(version) or ""),
                                item.get("dependencies") or {},
                                {"integrity": dist.get("integrity", ""), "shasum": dist.get("shasum", "")}, payload)


class PyPiAdapter(RegistryAdapter):
    ecosystem = "pypi"
    metadata_hosts = ("pypi.org",)
    artifact_hosts = ("files.pythonhosted.org", "pypi.org")

    def metadata_url(self, package: str) -> str:
        return f"https://pypi.org/pypi/{urllib.parse.quote(package)}/json"

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, payload = self._json(self.metadata_url(package), fetcher)
        version = _version(requested_version) or str((payload.get("info") or {}).get("version") or "")
        release = (payload.get("releases") or {}).get(version) or []
        files = [item for item in release if isinstance(item, dict) and item.get("url")]
        if not files:
            raise IntakeError("PyPI metadata did not include an artifact for the selected version")
        chosen = next((item for item in files if item.get("packagetype") in {"bdist_wheel", "sdist"}), files[0])
        return RegistryMetadata(self.ecosystem, package, version, url, str(chosen["url"]),
                                str((payload.get("info") or {}).get("author") or ""),
                                str(chosen.get("upload_time_iso_8601") or ""),
                                (payload.get("info") or {}).get("requires_dist") or {},
                                {"digests": chosen.get("digests") or {}}, payload)


class NuGetAdapter(RegistryAdapter):
    ecosystem = "nuget"
    metadata_hosts = ("api.nuget.org",)
    artifact_hosts = ("api.nuget.org", "globalcdn.nuget.org")

    def metadata_url(self, package: str) -> str:
        return f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(package.lower())}/index.json"

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, payload = self._json(self.metadata_url(package), fetcher)
        versions = [str(item) for item in payload.get("versions", [])]
        version = self._pick_version(versions, requested_version)
        lower = package.lower()
        artifact = f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(lower)}/{urllib.parse.quote(version)}/{urllib.parse.quote(lower)}.{urllib.parse.quote(version)}.nupkg"
        return RegistryMetadata(self.ecosystem, package, version, url, artifact, "", "", {}, {}, payload)


class RubyGemsAdapter(RegistryAdapter):
    ecosystem = "rubygems"
    metadata_hosts = ("rubygems.org",)
    artifact_hosts = ("rubygems.org", "rubygems.global.ssl.fastly.net")

    def metadata_url(self, package: str) -> str:
        return f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(package)}.json"

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, payload = self._json(self.metadata_url(package), fetcher)
        version = _version(requested_version) or str(payload.get("version") or "")
        if not version:
            raise IntakeError("RubyGems metadata did not include a package version")
        artifact = f"https://rubygems.org/downloads/{urllib.parse.quote(package)}-{urllib.parse.quote(version)}.gem"
        return RegistryMetadata(self.ecosystem, package, version, url, artifact, str(payload.get("authors") or ""), str(payload.get("version_created_at") or ""), payload.get("dependencies") or {}, {"sha": payload.get("sha") or ""}, payload)


class PackagistAdapter(RegistryAdapter):
    ecosystem = "packagist"
    metadata_hosts = ("repo.packagist.org",)
    artifact_hosts = ("repo.packagist.org", "api.github.com", "github.com", "codeload.github.com")

    def metadata_url(self, package: str) -> str:
        encoded = urllib.parse.quote(package, safe="/")
        return f"https://repo.packagist.org/p2/{encoded}.json"

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, payload = self._json(self.metadata_url(package), fetcher)
        entries = (payload.get("packages") or {}).get(package) or []
        if not isinstance(entries, list):
            raise IntakeError("Packagist metadata did not contain a version list")
        versions = [str(item.get("version") or "") for item in entries if isinstance(item, dict) and item.get("version")]
        if requested_version:
            version = self._pick_version(versions, requested_version)
        else:
            version = next((item for item in versions if not _is_prerelease(item)), versions[0] if versions else "")
            version = self._pick_version(versions, version)
        item = next((entry for entry in entries if isinstance(entry, dict) and str(entry.get("version") or "") == version), {})
        dist = item.get("dist") or {}
        artifact = str(dist.get("url") or "")
        if not artifact:
            raise IntakeError("Packagist metadata did not include a distribution archive")
        return RegistryMetadata(self.ecosystem, package, version, url, artifact, str(item.get("authors") or ""), str(item.get("time") or ""), item.get("require") or {}, {"shasum": dist.get("shasum", "")}, payload)


class GoAdapter(RegistryAdapter):
    ecosystem = "go"
    metadata_hosts = ("proxy.golang.org",)
    artifact_hosts = ("proxy.golang.org",)

    def metadata_url(self, package: str) -> str:
        encoded = urllib.parse.quote(package, safe="/@")
        return f"https://proxy.golang.org/{encoded}/@v/list"

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, _, body = fetcher.get(self.metadata_url(package), allowed_hosts=self.metadata_hosts, max_bytes=MAX_METADATA_BYTES)
        versions = [line.strip() for line in body.decode("utf-8", "ignore").splitlines() if line.strip()]
        version = self._pick_version(versions, requested_version)
        encoded = urllib.parse.quote(package, safe="/@")
        artifact = f"https://proxy.golang.org/{encoded}/@v/{urllib.parse.quote(version)}.zip"
        return RegistryMetadata(self.ecosystem, package, version, url, artifact, "", "", {}, {}, {"versions": versions[-100:]})


class MavenAdapter(RegistryAdapter):
    ecosystem = "maven"
    metadata_hosts = ("repo.maven.apache.org", "repo1.maven.org")
    artifact_hosts = ("repo.maven.apache.org", "repo1.maven.org")

    def metadata_url(self, package: str) -> str:
        if ":" not in package:
            raise IntakeError("Maven package must use group:artifact notation")
        group, artifact = package.split(":", 1)
        path = f"{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
        return f"https://repo.maven.apache.org/maven2/{path}"

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, _, body = fetcher.get(self.metadata_url(package), allowed_hosts=self.metadata_hosts, max_bytes=MAX_METADATA_BYTES)
        versions = re.findall(rb"<version>([^<]+)</version>", body)
        release = re.search(rb"<release>([^<]+)</release>", body)
        advertised_release = release.group(1).decode("utf-8", "ignore") if release else ""
        preferred = requested_version or (advertised_release if not _is_prerelease(advertised_release) else "")
        version = self._pick_version([item.decode("utf-8", "ignore") for item in versions], preferred)
        group, artifact_name = package.split(":", 1)
        path = f"{group.replace('.', '/')}/{artifact_name}/{version}/{artifact_name}-{version}.jar"
        return RegistryMetadata(self.ecosystem, package, version, url, f"https://repo.maven.apache.org/maven2/{path}", "", "", {}, {}, {"metadata_sha256": hashlib.sha256(body).hexdigest()})


class OpenVSXAdapter(RegistryAdapter):
    ecosystem = "open-vsx"
    metadata_hosts = ("open-vsx.org",)
    artifact_hosts = ("open-vsx.org",)

    def metadata_url(self, package: str) -> str:
        if "/" not in package:
            raise IntakeError("Open VSX package must use namespace/name notation")
        encoded = urllib.parse.quote(package, safe="/")
        return f"https://open-vsx.org/api/{encoded}"

    def resolve(self, package: str, requested_version: str, fetcher: SafeFetcher) -> RegistryMetadata:
        package = _safe_package(package)
        url, payload = self._json(self.metadata_url(package), fetcher)
        version = _version(requested_version) or str(payload.get("version") or "")
        artifact = str((payload.get("files") or {}).get("download") or "")
        if not artifact:
            raise IntakeError("Open VSX metadata did not include a download URL")
        return RegistryMetadata(self.ecosystem, package, version, url, artifact, str(payload.get("namespace") or ""), str(payload.get("timestamp") or ""), {}, {}, payload)


ADAPTERS: Dict[str, RegistryAdapter] = {
    item.ecosystem: item for item in (
        NpmAdapter(), PyPiAdapter(), NuGetAdapter(), MavenAdapter(), RubyGemsAdapter(),
        PackagistAdapter(), GoAdapter(), OpenVSXAdapter(),
    )
}


def get_adapter(ecosystem: str) -> RegistryAdapter:
    key = _text(ecosystem, 40).lower()
    try:
        return ADAPTERS[key]
    except KeyError as exc:
        raise IntakeError(f"unsupported research ecosystem: {key}") from exc


def _read_text_member(name: str, data: bytes, text_budget: List[int]) -> Optional[str]:
    lower = name.lower()
    if not (lower in MANIFEST_NAMES or Path(lower).suffix in TEXT_SUFFIXES):
        return None
    if text_budget[0] >= MAX_INSPECTED_TEXT_BYTES:
        return None
    chunk = data[: min(len(data), MAX_INSPECTED_FILE_BYTES, MAX_INSPECTED_TEXT_BYTES - text_budget[0])]
    text_budget[0] += len(chunk)
    return chunk.decode("utf-8", "ignore")


def _static_indicators(files: Sequence[Tuple[str, str]]) -> List[Dict[str, Any]]:
    patterns = (
        ("install-hook", "lifecycle", re.compile(r"\b(preinstall|postinstall|install|prepare)\b", re.I), "medium"),
        ("process-execution", "execution", re.compile(r"\b(child_process|subprocess|os\.system|execSync|spawnSync|ProcessBuilder)\b", re.I), "medium"),
        ("dynamic-eval", "obfuscation", re.compile(r"\b(eval|Function\s*\(|exec\s*\(|compile\s*\()", re.I), "medium"),
        ("credential-access", "credential_access", re.compile(r"\b(password|passwd|api[_-]?key|access[_-]?token|authorization|secret)\b", re.I), "high"),
        ("browser-payment-access", "data_access", re.compile(r"\b(localStorage|sessionStorage|cookie|credit.?card|cardNumber|payment)\b", re.I), "high"),
        ("network-endpoint", "network", re.compile(r"https?://|socket|requests\.|urllib|http\.client", re.I), "low"),
        ("encoded-payload", "obfuscation", re.compile(r"\b(base64|atob|btoa|fromCharCode|marshal|pickle)\b", re.I), "medium"),
        ("persistence", "persistence", re.compile(r"launchagents?|systemd|cron|startup|registry\\run", re.I), "high"),
    )
    results: List[Dict[str, Any]] = []
    for name, text in files:
        for indicator_id, category, pattern, severity in patterns:
            matches = len(pattern.findall(text))
            if matches:
                results.append({"indicator_id": indicator_id, "category": category, "severity": severity, "path": name, "matches": min(matches, 50)})
    return results[:200]


def inspect_archive(data: bytes, filename: str) -> Dict[str, Any]:
    if len(data) > MAX_ARTIFACT_BYTES:
        raise IntakeError("artifact exceeds the safety limit")
    members: List[Dict[str, Any]] = []
    seen_names: set[str] = set()
    text_files: List[Tuple[str, str]] = []
    text_budget = [0]
    expanded = 0

    def add_member(name: str, size: int, kind: str, reader: Optional[Callable[[], bytes]] = None) -> None:
        nonlocal expanded
        safe_name = _safe_member_name(name)
        if len(members) >= MAX_ARCHIVE_ENTRIES:
            raise IntakeError("archive contains too many entries")
        if safe_name in seen_names:
            raise IntakeError("archive contains duplicate member paths")
        seen_names.add(safe_name)
        if size < 0 or size > MAX_EXPANDED_BYTES or expanded + size > MAX_EXPANDED_BYTES:
            raise IntakeError("archive expanded-size limit exceeded")
        expanded += size
        members.append({"path": safe_name, "bytes": size, "kind": kind})
        if reader and len(text_files) < 1000:
            text = _read_text_member(safe_name, reader(), text_budget)
            if text is not None:
                text_files.append((safe_name, text))

    is_zip = zipfile.is_zipfile(io.BytesIO(data))
    if is_zip:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                mode = (info.external_attr >> 16) & 0o170000
                if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode):
                    raise IntakeError("archive contains a link or device entry")
                if info.filename.endswith("/"):
                    add_member(info.filename, 0, "directory")
                else:
                    if info.compress_size and info.file_size / info.compress_size > 200:
                        raise IntakeError("archive compression ratio exceeds the safety limit")
                    add_member(info.filename, info.file_size, "file", lambda info=info: archive.read(info))
    else:
        try:
            archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except (tarfile.TarError, OSError) as exc:
            raise IntakeError("artifact is not a supported zip or tar archive") from exc
        with archive:
            for info in archive.getmembers():
                if info.issym() or info.islnk() or info.isdev() or not (info.isfile() or info.isdir()):
                    raise IntakeError("archive contains a link, device, or unsupported entry")
                if info.isdir():
                    add_member(info.name, 0, "directory")
                else:
                    extracted = archive.extractfile(info)
                    add_member(info.name, info.size, "file", lambda extracted=extracted: extracted.read(MAX_INSPECTED_FILE_BYTES) if extracted else b"")
    scripts: Dict[str, Any] = {}
    manifest_summary: Dict[str, Any] = {}
    for path, text in text_files:
        if Path(path).name.lower() == "package.json":
            try:
                package_json = json.loads(text)
                if isinstance(package_json, dict):
                    scripts = {key: str(value)[:500] for key, value in (package_json.get("scripts") or {}).items() if key in LIFECYCLE_NAMES}
                    manifest_summary = {key: package_json.get(key) for key in ("name", "version", "description", "license", "repository") if key in package_json}
            except json.JSONDecodeError:
                manifest_summary = {"package_json": "invalid_json"}
    return {
        "filename": _text(filename, 512),
        "archive_type": "zip" if is_zip else "tar",
        "member_count": len(members),
        "expanded_bytes": expanded,
        "members": members[:1000],
        "text_files_inspected": len(text_files),
        "lifecycle_scripts": scripts,
        "manifest_summary": manifest_summary,
        "indicators": _static_indicators(text_files),
        "execution_performed": False,
        "extracted_to_filesystem": False,
    }


def _quarantine_path(digest: str, filename: str) -> Path:
    root = Path(os.environ.get("SECOPSAI_RESEARCH_QUARANTINE", str(Path(__file__).resolve().parents[1] / "data" / "research" / "quarantine"))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    suffix = Path(filename).suffix.lower()
    path = root / f"{digest}{suffix}"
    if path.exists() and path.is_symlink():
        raise IntakeError("quarantine path is a symbolic link")
    return path


def _metadata_summary(metadata: RegistryMetadata) -> Dict[str, Any]:
    raw = metadata.raw
    return {
        "ecosystem": metadata.ecosystem,
        "package": metadata.package,
        "version": metadata.version,
        "metadata_url": metadata.metadata_url,
        "artifact_url": metadata.artifact_url,
        "publisher": metadata.publisher[:240],
        "published_at": metadata.published_at[:80],
        "dependencies": metadata.dependencies if isinstance(metadata.dependencies, (dict, list)) else {},
        "integrity": metadata.integrity,
        "raw_keys": sorted(str(key) for key in raw.keys())[:100],
    }


def collect_package_intake(
    *,
    ecosystem: str,
    package: str,
    version: str = "",
    fetcher: Optional[SafeFetcher] = None,
) -> Dict[str, Any]:
    """Collect one package into quarantine without requiring a research case."""
    adapter = get_adapter(ecosystem)
    fetcher = fetcher or SafeFetcher()
    metadata = adapter.resolve(package, version, fetcher)
    final_url, _headers, artifact = fetcher.get(metadata.artifact_url, allowed_hosts=adapter.artifact_hosts, max_bytes=MAX_ARTIFACT_BYTES)
    digest = hashlib.sha256(artifact).hexdigest()
    filename = Path(urllib.parse.urlparse(final_url).path).name or f"{metadata.package}-{metadata.version}.artifact"
    quarantine = _quarantine_path(digest, filename)
    if not quarantine.exists():
        quarantine.write_bytes(artifact)
        try:
            os.chmod(quarantine, 0o600)
        except OSError:
            pass
    analysis = inspect_archive(artifact, filename)
    package_summary = _metadata_summary(metadata)
    package_summary.update({"artifact_sha256": digest, "artifact_bytes": len(artifact), "artifact_url_final": final_url})
    return {
        "ok": True,
        "metadata": package_summary,
        "analysis": analysis,
        "quarantine": {"artifact_id": digest, "bytes": len(artifact), "locator": f"quarantine://{digest}"},
        "attached": False,
        "safety": {"execution_performed": False, "extracted_to_filesystem": False, "raw_artifact_sent_to_ai": False},
    }


def run_package_intake(
    *,
    case_id: str,
    ecosystem: str,
    package: str,
    version: str = "",
    db_path: Optional[str] = None,
    attach: bool = False,
    actor: str = "research-worker",
    fetcher: Optional[SafeFetcher] = None,
) -> Dict[str, Any]:
    """Collect and statically inspect one package; attach only when requested."""
    get_case(case_id, db_path=db_path)
    result = collect_package_intake(ecosystem=ecosystem, package=package, version=version, fetcher=fetcher)
    result["case_id"] = case_id
    result["evidence_ids"] = []
    if attach:
        result.update(attach_intake_result(result, db_path=db_path, actor=actor))
    return result


def attach_intake_result(result: Dict[str, Any], *, db_path: Optional[str] = None, actor: str = "analyst") -> Dict[str, Any]:
    """Attach a previously quarantined, operator-reviewed intake result."""
    case_id = _text(result.get("case_id"), 32)
    metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
    analysis = result.get("analysis") if isinstance(result.get("analysis"), dict) else {}
    quarantine = result.get("quarantine") if isinstance(result.get("quarantine"), dict) else {}
    digest = _text(metadata.get("artifact_sha256") or quarantine.get("artifact_id"), 64).lower()
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise IntakeError("intake result does not contain a valid artifact hash")
    path = _quarantine_path(digest, str(analysis.get("filename") or "artifact"))
    if not path.is_file() or path.is_symlink():
        raise IntakeError("quarantined artifact is unavailable")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        raise IntakeError("quarantined artifact hash changed")
    package = _safe_package(metadata.get("package"))
    ecosystem = _text(metadata.get("ecosystem"), 40).lower()
    version = _version(metadata.get("version"))
    subject_case = add_subject(case_id, subject_type="package", name=package, ecosystem=ecosystem,
                               version=version, publisher=_text(metadata.get("publisher"), 240), metadata=metadata,
                               db_path=db_path, actor=actor)
    metadata_payload = {key: metadata.get(key) for key in ("ecosystem", "package", "version", "publisher", "published_at", "integrity", "artifact_sha256", "artifact_bytes")}
    metadata_bytes = json.dumps(metadata_payload, sort_keys=True).encode()
    metadata_evidence = add_evidence(case_id, evidence_type="registry_metadata", title=f"{ecosystem} registry metadata: {package}@{version}",
                                     locator=_text(metadata.get("metadata_url"), 4000), provenance=f"official {ecosystem} registry metadata fetched by SecOpsAI", notes="Normalized metadata only; raw response is not sent to AI.",
                                     sha256=hashlib.sha256(metadata_bytes).hexdigest(), metadata=metadata_payload, db_path=db_path, actor=actor)
    artifact_evidence = add_evidence(case_id, evidence_type="package_artifact", title=f"Quarantined artifact: {package}@{version}",
                                     locator=f"quarantine://{digest}", sha256=digest, provenance=f"official {ecosystem} artifact fetched from an allowlisted host", notes="Stored in local quarantine. Never executed or extracted.",
                                     metadata={"bytes": int(metadata.get("artifact_bytes") or path.stat().st_size), "filename": analysis.get("filename"), "execution_performed": False, "extracted_to_filesystem": False}, db_path=db_path, actor=actor)
    analysis_bytes = json.dumps(analysis, sort_keys=True, separators=(",", ":")).encode()
    analysis_evidence = add_evidence(case_id, evidence_type="static_analysis", title=f"Static intake analysis: {package}@{version}",
                                      locator=f"quarantine-analysis://{digest}", sha256=hashlib.sha256(analysis_bytes).hexdigest(), provenance="SecOpsAI bounded archive inspection; no package code execution", notes=f"Indicators={len(analysis.get('indicators') or [])}; lifecycle_scripts={len(analysis.get('lifecycle_scripts') or {})}; execution=false.",
                                      metadata=analysis, db_path=db_path, actor=actor)
    return {
        "attached": True,
        "evidence_ids": [metadata_evidence["evidence"][-1]["evidence_id"], artifact_evidence["evidence"][-1]["evidence_id"], analysis_evidence["evidence"][-1]["evidence_id"]],
        "subject": subject_case["subjects"][-1] if subject_case.get("subjects") else None,
    }


def preview_package(*, ecosystem: str, package: str, version: str = "", fetcher: Optional[SafeFetcher] = None) -> Dict[str, Any]:
    adapter = get_adapter(ecosystem)
    metadata = adapter.resolve(package, version, fetcher or SafeFetcher())
    return {"ok": True, "preview": True, "metadata": _metadata_summary(metadata), "next_action": "run_intake_then_review_before_attach", "safety": {"execution_performed": False}}
