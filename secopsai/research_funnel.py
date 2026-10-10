"""Rules-first artifact funnel.

Fetch the published archive of many new releases concurrently, scan every
member's bytes with YARA-X in memory, and keep nothing unless a rule hits.
Hits move on to full static analysis and model triage; clean releases are
done.  This is what lets the worker look at every release instead of the
handful a metadata ranking would pick.
"""

from __future__ import annotations

import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from secopsai import yara_engine
from secopsai.research_intake import SafeFetcher

NPM_ARTIFACT_HOSTS = ("registry.npmjs.org",)
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
DEFAULT_WORKERS = 12
HIT_LEVELS = {"notice", "warning", "alert"}


def prescan_limit() -> int:
    return max(0, min(int(os.environ.get("SECOPSAI_NPM_PRESCAN_LIMIT", "150") or 0), 2000))


INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
DOC_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".adoc", ".html", ".htm"}


def manifest_summary(members: List[tuple]) -> Dict[str, Any]:
    """The parts of package.json that tell a reviewer what runs and when."""
    raw = next((data for path, data in members if path.lstrip("./").split("/", 1)[-1] == "package.json" and path.count("/") <= 1), b"")
    try:
        doc = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, ValueError):
        return {"parse_error": True}
    if not isinstance(doc, dict):
        return {"parse_error": True}
    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    repository = doc.get("repository")
    return {
        "name": str(doc.get("name") or "")[:214],
        "description": str(doc.get("description") or "")[:300],
        "install_scripts": {name: str(scripts[name])[:400] for name in INSTALL_SCRIPTS if name in scripts},
        "other_scripts": sorted(name for name in scripts if name not in INSTALL_SCRIPTS)[:20],
        "main": str(doc.get("main") or "")[:200],
        "bin": doc.get("bin") if isinstance(doc.get("bin"), (str, dict)) else "",
        "repository": (repository.get("url") if isinstance(repository, dict) else str(repository or ""))[:300],
        "dependency_count": len(doc.get("dependencies") or {}) if isinstance(doc.get("dependencies"), dict) else 0,
    }


def file_role(path: str, manifest: Dict[str, Any]) -> str:
    """Rough role of a file in the package, to help separate docs from code."""
    name = path.split("/", 1)[-1] if path.startswith("package/") else path
    lowered = name.lower()
    suffix = Path(lowered).suffix
    referenced = " ".join(list((manifest.get("install_scripts") or {}).values()))
    if name and name in referenced:
        return "install_script"
    if suffix == ".map":
        return "source_map"
    if suffix in DOC_SUFFIXES or Path(lowered).name.startswith(("readme", "changelog", "license")):
        return "documentation"
    bins = manifest.get("bin")
    bin_paths = [bins] if isinstance(bins, str) else list((bins or {}).values()) if isinstance(bins, dict) else []
    if any(str(item).lstrip("./") == name for item in bin_paths) or name == str(manifest.get("main") or "").lstrip("./"):
        return "entry_point"
    if lowered.endswith((".yar", ".yara", ".sigma", ".yml", ".yaml", ".json")):
        return "data_or_config"
    return "code"


def _scan_one(target: Dict[str, Any], fetcher: SafeFetcher) -> Dict[str, Any]:
    from secopsai.artifact_fleet import _safe_archive_files

    url = str(target.get("tarball") or "")
    result: Dict[str, Any] = {"key": target.get("key"), "package": target.get("package"), "version": target.get("version")}
    if not url.startswith("https://registry.npmjs.org/"):
        return {**result, "status": "skipped", "reason": "no registry tarball"}
    try:
        _final, _headers, body = fetcher.get(url, allowed_hosts=NPM_ARTIFACT_HOSTS, max_bytes=MAX_ARCHIVE_BYTES)
        members: List[tuple] = []
        with tempfile.TemporaryDirectory(prefix="secopsai-prescan-") as tmp:
            path = Path(tmp) / "artifact.tgz"
            path.write_bytes(body)
            _safe_archive_files(path, members)
        scanned = yara_engine.scan_files(members)
    except Exception as exc:  # one bad archive must not stop the batch
        return {**result, "status": "error", "reason": str(exc)[:300]}
    findings = [item for item in scanned.get("findings", []) if item.get("rule_id") != "YARA-SCAN-ERROR"]
    manifest = manifest_summary(members)
    for item in findings:
        item["file_role"] = file_role(str(item.get("file_path") or ""), manifest)
    return {
        **result,
        "status": "hit" if scanned.get("level") in HIT_LEVELS else "clean",
        "score": int(scanned.get("score") or 0),
        "level": scanned.get("level"),
        "rules_matched": scanned.get("rules_matched") or [],
        "findings": findings[:20],
        "manifest": manifest,
        "bytes": len(body),
        "files": len(members),
    }


def prescan(targets: Iterable[Dict[str, Any]], *, fetcher: Optional[SafeFetcher] = None, workers: int = DEFAULT_WORKERS) -> Dict[str, Dict[str, Any]]:
    """Scan targets ({key, package, version, tarball}); returns results by key."""
    items = list(targets)
    if not items or not yara_engine.status().get("available"):
        return {}
    fetcher = fetcher or SafeFetcher(timeout=30)
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), 32))) as pool:
        results = list(pool.map(lambda item: _scan_one(item, fetcher), items))
    return {str(item["key"]): item for item in results}
