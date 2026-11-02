"""Malware advisories on the dependencies a package declares.

A compromised release can keep its own code clean and add a malicious
dependency: npm @mastra/laminar 1.2.3 added easy-day-js (OSV MAL-2026-5979)
and was closed as benign in the third held-out test (2026-11-02).
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

from secopsai.research_intake import SafeFetcher

OSV_HOSTS = ("api.osv.dev",)
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
MAX_NAMES = 200
MAX_EXTRA_PAGES = 3
TIMEOUT_SECONDS = 10
# After a failed lookup, skip OSV for a while instead of retrying on every hit
# of the cycle; those hits are reported unchecked, so nothing closes on them.
COOLDOWN_SECONDS = 600
SLOW_LOOKUP_SECONDS = 5
_unavailable_until = 0.0
_stats = {"lookups": 0, "failures": 0, "seconds": 0.0}
_stats_lock = threading.Lock()


def take_stats() -> Dict[str, Any]:
    """OSV lookups since the last call (count, failures, seconds), for the cycle log."""
    with _stats_lock:
        taken = {**_stats, "seconds": round(_stats["seconds"], 1)}
        _stats.update(lookups=0, failures=0, seconds=0.0)
    return taken


def _record(seconds: float, failed: bool, names: int, error: str = "") -> None:
    with _stats_lock:
        _stats["lookups"] += 1
        _stats["failures"] += int(failed)
        _stats["seconds"] += seconds
    if failed or seconds >= SLOW_LOOKUP_SECONDS:  # a lost cycle must show whether OSV was the cause
        print(json.dumps({"component": "dependency_advisories", "event": "osv_lookup", "seconds": round(seconds, 1),
                          "names": names, "failed": failed, "error": error[:200]}), flush=True)


def _malicious(vulns: Iterable[Dict[str, Any]]) -> List[str]:
    return [str(item.get("id")) for item in vulns if str(item.get("id") or "").startswith("MAL-")]


def check(ecosystem: str, dependencies: Dict[str, Any], *, fetcher: Optional[SafeFetcher] = None) -> Dict[str, Any]:
    """OSV MAL- records for each declared dependency name.

    Anything that could not be checked is reported, never assumed clean."""
    names = [str(name) for name in dependencies.get("names") or [] if str(name).strip()]
    unverifiable = [str(name) for name in dependencies.get("unverifiable") or []][:20]
    result: Dict[str, Any] = {"status": "checked", "checked": 0, "malicious": [], "unverifiable": unverifiable}
    if dependencies.get("unparsed"):
        result["unparsed"] = [str(path) for path in dependencies["unparsed"]][:8]
    if not names:
        return result
    osv_ecosystem = OSV_ECOSYSTEMS.get(ecosystem)
    if not osv_ecosystem:
        return {**result, "status": "ecosystem_not_supported"}
    if len(names) > MAX_NAMES:
        return {**result, "status": "too_many_dependencies", "declared": len(names)}
    global _unavailable_until
    if time.monotonic() < _unavailable_until:
        return {**result, "status": "unavailable", "declared": names, "error": "OSV lookups paused after a recent failure"}
    fetcher = fetcher or SafeFetcher(timeout=TIMEOUT_SECONDS)
    started = time.monotonic()
    try:
        body = json.dumps({"queries": [{"package": {"name": name, "ecosystem": osv_ecosystem}} for name in names]}).encode()
        answers = json.loads(fetcher.get(OSV_BATCH_URL, allowed_hosts=OSV_HOSTS, max_bytes=8 << 20, data=body,
                                         headers={"Content-Type": "application/json"})[2]).get("results") or []
        if len(answers) != len(names):
            raise ValueError("OSV returned a different number of answers")
        malicious = []
        for name, answer in zip(names, answers):
            ids = _malicious(answer.get("vulns") or [])
            token, pages = answer.get("next_page_token"), 0
            while token and not ids:
                if pages >= MAX_EXTRA_PAGES:
                    raise ValueError(f"too many advisory pages for {name}")
                page = json.loads(fetcher.get(OSV_QUERY_URL, allowed_hosts=OSV_HOSTS, max_bytes=8 << 20, headers={"Content-Type": "application/json"},
                                              data=json.dumps({"package": {"name": name, "ecosystem": osv_ecosystem}, "page_token": token}).encode())[2])
                ids, token, pages = _malicious(page.get("vulns") or []), page.get("next_page_token"), pages + 1
            if ids:
                malicious.append({"name": name, "ids": ids[:5]})
    except Exception as exc:  # an unchecked dependency list must not count as clean
        _unavailable_until = time.monotonic() + COOLDOWN_SECONDS
        error = f"{type(exc).__name__}: {exc}"[:200]
        _record(time.monotonic() - started, True, len(names), error)
        return {**result, "status": "unavailable", "declared": names, "error": error}
    _record(time.monotonic() - started, False, len(names))
    return {**result, "checked": len(names), "malicious": malicious}
