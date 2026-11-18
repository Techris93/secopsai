"""Does a published release match its source repository?

A hijacked release usually carries code that was never committed: the
agent-framework 1.26.1 start-up hook (2026-11-17) was in the PyPI wheel, not
in the project's GitHub repository. Legitimate packages that look alarming
(pirateface patches Hugging Face downloads from a .pth by design) ship the
same files their repository has at the release tag.

This module finds the project's GitHub repository from registry metadata
(untrusted: a malicious package can name any repository, so a match is a
signal, not proof), finds the tag for the version, and compares the release's
start-up/install files and flagged files with the same files at that tag.
Only raw.githubusercontent.com is read; nothing is cloned or executed.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

RAW_HOST = "raw.githubusercontent.com"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 8
TIME_BUDGET_SECONDS = 60.0
GITHUB_REPO = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$", re.IGNORECASE)
ARCHIVE_SUFFIX = re.compile(r"\.(tar\.gz|tgz|zip|whl|tar\.bz2)$", re.IGNORECASE)
# Files a build tool writes or rewrites; their absence from git means nothing.
GENERATED = re.compile(r"(^|/)(setup\.py|setup\.cfg|pyproject\.toml|package\.json|PKG-INFO|_version\.py|version\.py|\.npmignore)$|\.dist-info/|\.egg-info/")
INSTALL_SUFFIXES = (".pth",)
BUILD_FILES = ("setup.py", "pyproject.toml", "setup.cfg", "MANIFEST.in", "hatch_build.py", "build.py", "package.json")


def content_hash(data: bytes) -> str:
    """sha256 of the file with line endings and trailing whitespace normalized."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n").rstrip()).hexdigest()


def repository(ecosystem: str, metadata: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """(owner, repo) on GitHub named by the release metadata, or None."""
    found = repository_location(ecosystem, metadata)
    return (found[0], found[1]) if found else None


def repository_location(ecosystem: str, metadata: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
    """(owner, repo, subdirectory) on GitHub; the subdirectory comes from a
    monorepo link such as github.com/o/r/tree/main/python ('' otherwise)."""
    candidates: List[str] = []
    directory = ""
    if ecosystem == "pypi":
        info = metadata.get("info") or {}
        urls = info.get("project_urls") or {}
        # Source-like labels first, then the rest, then the home page.
        ordered = sorted(urls.items(), key=lambda kv: 0 if re.search(r"source|repo|code|github", str(kv[0]), re.IGNORECASE) else 1)
        candidates += [str(url) for _, url in ordered] + [str(info.get("home_page") or "")]
    elif ecosystem == "npm":
        repo = metadata.get("repository")
        url = repo.get("url") if isinstance(repo, dict) else repo
        if isinstance(url, str):
            if url.startswith("github:"):
                url = "github.com/" + url[len("github:"):]
            elif re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", url):
                url = "github.com/" + url
            candidates.append(url)
        directory = str(repo.get("directory") or "") if isinstance(repo, dict) else ""
    for url in candidates:
        url = url.strip().split()[0] if url.strip() else ""
        match = GITHUB_REPO.search(url)
        if match and match.group(2).lower() not in {"sponsors", "orgs"}:
            tree = re.search(r"/tree/[^/]+/([A-Za-z0-9_./-]+?)/?$", url)
            sub = (tree.group(1) if tree else directory or "").strip("/")
            return match.group(1), match.group(2), sub if ".." not in sub else ""
    return None


def candidate_tags(package: str, version: str, subdir: str = "") -> List[str]:
    name = package.rsplit("/", 1)[-1]
    tags = [f"v{version}", version, f"{name}-{version}", f"{name}@{version}", f"{package}@{version}", f"{name}-v{version}"]
    if subdir:
        leaf = subdir.rsplit("/", 1)[-1]
        tags += [f"{leaf}-{version}", f"{leaf}-v{version}", f"{leaf}/v{version}", f"{leaf}/{version}"]
    return list(dict.fromkeys(tags))


def repo_paths(archive_path: str, subdir: str = "") -> List[str]:
    """Where a file from the release archive would sit in the repository."""
    parts = archive_path.split("/")
    wheel = False
    if parts and ARCHIVE_SUFFIX.search(parts[0]):
        wheel = parts[0].lower().endswith(".whl")
        parts = parts[1:]
    if not wheel and len(parts) > 1:
        # sdist root (name-1.0/) or npm package/
        parts = parts[1:]
    path = "/".join(parts)
    if not path:
        return []
    paths = [path, f"src/{path}"] if wheel else [path]
    return [f"{subdir}/{item}" for item in paths] if subdir else paths


def _fetch(fetcher: Any, owner: str, repo: str, ref: str, path: str) -> Optional[bytes]:
    from secopsai.research_intake import RegistryHTTPError

    url = f"https://{RAW_HOST}/{owner}/{repo}/{ref}/{path}"
    try:
        _final, _headers, body = fetcher.get(url, allowed_hosts=(RAW_HOST,), max_bytes=MAX_FILE_BYTES)
        return body
    except RegistryHTTPError as exc:
        if exc.status == 404:
            return None
        raise


def _find_tag(fetcher: Any, owner: str, repo: str, package: str, version: str, anchors: Iterable[str], subdir: str = "") -> Tuple[str, str]:
    """(tag, anchor path found at it). The anchor is a file of this release
    known to be in git, which proves both the tag and the path layout."""
    anchors = list(anchors)
    for tag in candidate_tags(package, version, subdir):
        for anchor in anchors:
            if _fetch(fetcher, owner, repo, tag, anchor) is not None:
                return tag, anchor
    return "", ""


def compare(fetcher: Any, ecosystem: str, package: str, version: str, metadata: Dict[str, Any], scan: Dict[str, Any],
            *, budget_seconds: float = TIME_BUDGET_SECONDS) -> Dict[str, Any]:
    """Compare the release's install-time and flagged files with the repository.

    result: ``matches`` (every compared file is identical at the tag),
    ``differs`` (an install-time file is missing from, or different to, the
    repository; a strong warning), ``unknown`` (no repository, no tag or a
    layout that could not be mapped; says nothing either way).
    """
    deadline = time.monotonic() + budget_seconds
    found = repository_location(ecosystem, metadata)
    if not found:
        return {"result": "unknown", "reason": "no GitHub repository in the release metadata"}
    owner, repo, subdir = found
    hashes: Dict[str, str] = scan.get("file_hashes") or {}
    install = {str(item.get("path")) for item in scan.get("install_files") or []}
    files = [path for path in hashes if not GENERATED.search(path)][:MAX_FILES]
    if not files:
        return {"result": "unknown", "repository": f"{owner}/{repo}", "reason": "no comparable files"}
    # Any root file of the release proves the tag and the layout; try the
    # usual manifests from the release (they are in git, even if rewritten).
    manifests = [p for path in scan.get("root_manifests") or [] for p in repo_paths(str(path.get("path") if isinstance(path, dict) else path), subdir)]
    base = f"{subdir}/" if subdir else ""
    anchors = list(dict.fromkeys([*manifests, *(base + name for name in ("pyproject.toml", "setup.py", "package.json", "README.md"))]))[:6]
    try:
        tag, _anchor = _find_tag(fetcher, owner, repo, package, version, anchors, subdir)
    except Exception as exc:
        return {"result": "unknown", "repository": f"{owner}/{repo}", "reason": f"repository not readable: {type(exc).__name__}"}
    if not tag:
        return {"result": "unknown", "repository": f"{owner}/{repo}", "reason": f"no tag for {version}"}
    compared: List[Dict[str, str]] = []
    for path in files:
        if time.monotonic() > deadline:
            break
        outcome = "missing"
        for candidate in repo_paths(path, subdir):
            try:
                body = _fetch(fetcher, owner, repo, tag, candidate)
            except Exception:
                outcome = "unreadable"
                break
            if body is not None:
                outcome = "same" if content_hash(body) == hashes[path] else "differs"
                break
        startup = path in install or path.lower().endswith(INSTALL_SUFFIXES)
        compared.append({"path": path[:300], "outcome": outcome, "install_time": startup})
    # Build scripts write some start-up files (setuptools' and coverage's
    # .pth come from setup.py, 2026-11-18 check): a missing file the
    # repository's build files name at the tag is "built", not planted.
    missing = [item for item in compared if item["outcome"] == "missing" and item["install_time"]]
    if missing and time.monotonic() < deadline:
        build_text = b""
        for build in BUILD_FILES:
            try:
                build_text += _fetch(fetcher, owner, repo, tag, base + build) or b""
            except Exception:
                continue
        for item in missing:
            name = item["path"].rsplit("/", 1)[-1]
            stem = name.rsplit(".", 1)[0]
            # The whole name, or its stem in a build file that writes .pth
            # files (setuptools builds 'distutils-precedence' + '.pth'). A
            # planted hook named after the package still fails: the build
            # files of such a project never mention .pth.
            named = name.encode() in build_text or (name.endswith(".pth") and b".pth" in build_text and stem.encode() in build_text)
            if name and named:
                item["outcome"] = "built"
    # A built file (dist/, compiled JS) can be absent from git legitimately;
    # only install-time and start-up files missing or changed are a warning.
    bad = [item for item in compared if item["outcome"] == "differs" or (item["outcome"] == "missing" and item["install_time"])]
    if bad:
        result = "differs"
    elif compared and all(item["outcome"] in {"same", "built"} for item in compared):
        result = "matches"
    else:
        result = "unknown"
    return {"result": result, "repository": f"{owner}/{repo}" + (f" ({subdir})" if subdir else ""), "tag": tag, "files": compared,
            "note": "Repository named by untrusted package metadata: a match is a signal, not proof."}
