"""Rules-first artifact funnel.

Fetch the published archive of many new releases concurrently, scan every
member's bytes with YARA-X in memory, and keep nothing unless a rule hits.
Hits move on to full static analysis and model triage; clean releases are
done.  This is what lets the worker look at every release instead of the
handful a metadata ranking would pick.
"""

from __future__ import annotations

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
    return {
        **result,
        "status": "hit" if scanned.get("level") in HIT_LEVELS else "clean",
        "score": int(scanned.get("score") or 0),
        "level": scanned.get("level"),
        "rules_matched": scanned.get("rules_matched") or [],
        "findings": findings[:20],
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
