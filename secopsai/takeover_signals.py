"""Account-takeover and provenance signals from registry metadata (frontier phase 2).

A hijacked release usually looks different from its predecessors before any
code is read: published by a different account, no longer through the
project's trusted publisher (GitHub OIDC), without the provenance attestation
earlier releases carried, with a new install script, after a long dormancy, or
just after a new maintainer was added. Each signal alone is ordinary; together
they mark a release for the diff-and-alert path even when the content prescan
was clean.

Weights are deliberately simple and fixed here; they were chosen before
measurement and are judged by the frontier scorecard and live alert outcomes.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

WEIGHTS = {
    "trusted_publishing_lost": 50,
    "provenance_lost": 40,
    "publisher_changed": 25,
    "install_script_added": 25,
    "maintainer_added": 20,
    "role_added_recently": 35,
    "dormant_republish": 20,
    "repository_changed": 15,
}
ESCALATE_SCORE = 60
DORMANT_DAYS = 365
ROLE_WINDOW_DAYS = 14
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


def _parse(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def score(signals: Iterable[str]) -> int:
    return sum(WEIGHTS.get(name, 0) for name in set(signals))


def _repo(meta: Dict[str, Any]) -> str:
    repository = meta.get("repository")
    url = repository.get("url") if isinstance(repository, dict) else repository
    return str(url or "").lower().replace("git+", "").replace(".git", "").rstrip("/")


def _previous(times: Dict[str, Any], versions: Dict[str, Any], version: str) -> Optional[str]:
    published = _parse(times.get(version))
    if published is None:
        return None
    earlier = [(stamp, name) for name, raw in times.items()
               if name in versions and name != version and (stamp := _parse(raw)) and stamp < published]
    return max(earlier)[1] if earlier else None


def npm_signals(doc: Dict[str, Any], version: str) -> Dict[str, Any]:
    """Signals for one version of an npm package document (the full packument)."""
    versions = doc.get("versions") or {}
    times = {key: value for key, value in (doc.get("time") or {}).items() if key not in {"created", "modified"}}
    current = versions.get(version)
    if not isinstance(current, dict):
        return {"metadata_available": False, "signals": [], "score": 0}
    previous_name = _previous(times, versions, version)
    previous = versions.get(previous_name) if previous_name else None
    signals: List[str] = []
    if isinstance(previous, dict):
        before_user, now_user = previous.get("_npmUser") or {}, current.get("_npmUser") or {}
        if before_user.get("trustedPublisher") and not now_user.get("trustedPublisher"):
            signals.append("trusted_publishing_lost")
        if (previous.get("dist") or {}).get("attestations") and not (current.get("dist") or {}).get("attestations"):
            signals.append("provenance_lost")
        if before_user.get("name") and now_user.get("name") and before_user["name"] != now_user["name"] \
                and not (before_user.get("trustedPublisher") and now_user.get("trustedPublisher")):
            signals.append("publisher_changed")
        before_scripts, now_scripts = previous.get("scripts") or {}, current.get("scripts") or {}
        if any(name in now_scripts and now_scripts.get(name) != before_scripts.get(name) for name in INSTALL_SCRIPTS):
            signals.append("install_script_added")
        before_names = {item.get("name") for item in previous.get("maintainers") or [] if isinstance(item, dict)}
        now_names = {item.get("name") for item in current.get("maintainers") or [] if isinstance(item, dict)}
        if before_names and now_names - before_names:
            signals.append("maintainer_added")
        if _repo(previous) and _repo(current) and _repo(previous) != _repo(current):
            signals.append("repository_changed")
        gap = (_parse(times.get(version)) or datetime.min.replace(tzinfo=timezone.utc)) - \
            (_parse(times.get(previous_name)) or datetime.max.replace(tzinfo=timezone.utc))
        if gap > timedelta(days=DORMANT_DAYS):
            signals.append("dormant_republish")
    return {"metadata_available": True, "previous_version": previous_name, "signals": sorted(signals), "score": score(signals)}


def pypi_signals(files_by_version: Dict[str, List[Dict[str, Any]]], version: str, *,
                 role_added_at: Optional[datetime] = None, published_at: Optional[datetime] = None) -> Dict[str, Any]:
    """Signals for one PyPI release from the JSON simple index (files grouped by version)."""
    current = files_by_version.get(version) or []
    if not current:
        return {"metadata_available": False, "signals": [], "score": 0}
    upload = min((_parse(item.get("upload-time")) for item in current if _parse(item.get("upload-time"))), default=None)
    published = published_at or upload
    earlier = sorted(((min((_parse(f.get("upload-time")) for f in files if _parse(f.get("upload-time"))), default=None), name)
                      for name, files in files_by_version.items() if name != version and files), key=lambda item: item[0] or datetime.min.replace(tzinfo=timezone.utc))
    earlier = [(stamp, name) for stamp, name in earlier if stamp and published and stamp < published]
    signals: List[str] = []
    previous_name = earlier[-1][1] if earlier else None
    if previous_name:
        if any(item.get("provenance") for item in files_by_version[previous_name]) and not any(item.get("provenance") for item in current):
            signals.append("provenance_lost")
        if published and published - earlier[-1][0] > timedelta(days=DORMANT_DAYS):
            signals.append("dormant_republish")
    if role_added_at and published and timedelta(0) <= published - role_added_at <= timedelta(days=ROLE_WINDOW_DAYS):
        signals.append("role_added_recently")
    return {"metadata_available": True, "previous_version": previous_name, "signals": sorted(signals), "score": score(signals)}


def pypi_files_by_version(simple: Dict[str, Any], version_of) -> Dict[str, List[Dict[str, Any]]]:
    """Group a JSON simple index's files by release version (``version_of(filename)``)."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in simple.get("files") or []:
        name = version_of(str(item.get("filename") or ""))
        if name:
            grouped.setdefault(name, []).append(item)
    return grouped


def pypi_version_of(filename: str) -> str:
    """Release version from a wheel or sdist filename; empty when it cannot be parsed."""
    from packaging.utils import InvalidSdistFilename, InvalidWheelFilename, parse_sdist_filename, parse_wheel_filename

    try:
        if filename.endswith(".whl"):
            return str(parse_wheel_filename(filename)[1])
        return str(parse_sdist_filename(filename)[1])
    except (InvalidSdistFilename, InvalidWheelFilename, ValueError):
        return ""
