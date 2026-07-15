"""Safe promotion of one ecosystem's package watchlist leads into cases.

This module deliberately stops at structured case creation. It does not fetch
registry metadata, download artifacts, unpack packages, or execute package
code. Those activities belong to later, isolated research stages.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from secopsai.research_cases import add_evidence, get_case, list_cases, start_package_case
from secopsai.supply_chain import campaign_watchlist_list


SUPPORTED_WATCHLIST_ECOSYSTEM = "npm"
_NPM_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+$")


def _package_name(value: Any, *, ecosystem: str) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    prefix, separator, name = raw.partition(":")
    if separator:
        if prefix.strip().lower() != ecosystem:
            return None
        raw = name.strip()
    if ecosystem == SUPPORTED_WATCHLIST_ECOSYSTEM:
        if not _NPM_PACKAGE_RE.fullmatch(raw.lower()):
            return None
        return raw
    return None


def select_watchlist_packages(
    watchlist: Dict[str, Any],
    *,
    ecosystem: str = SUPPORTED_WATCHLIST_ECOSYSTEM,
    packages: Optional[Iterable[str]] = None,
    select_all: bool = False,
) -> List[Dict[str, str]]:
    """Return normalized, explicitly selected package leads from a watchlist."""
    ecosystem_name = str(ecosystem or "").strip().lower()
    if ecosystem_name != SUPPORTED_WATCHLIST_ECOSYSTEM:
        raise ValueError("watchlist case promotion currently supports npm only")
    requested_values = list(packages or [])
    requested = [
        _package_name(value, ecosystem=ecosystem_name)
        for value in requested_values
    ]
    invalid = [str(value) for value, normalized in zip(requested_values, requested) if not normalized]
    if invalid:
        raise ValueError(f"invalid npm package in selection: {invalid[0]}")
    requested_names = list(dict.fromkeys(requested))
    if not select_all and not requested_names:
        raise ValueError("select a package with --package or use --all")
    if select_all and requested_names:
        raise ValueError("--all cannot be combined with --package")

    selected: List[Dict[str, str]] = []
    seen: set[str] = set()
    for raw in watchlist.get("packages", []) if isinstance(watchlist, dict) else []:
        name = _package_name(raw, ecosystem=ecosystem_name)
        if not name or name in seen:
            continue
        if not select_all and name not in requested_names:
            continue
        seen.add(name)
        selected.append({"ecosystem": ecosystem_name, "package": name, "watchlist_value": str(raw)})

    missing = [name for name in requested_names if name not in seen]
    if missing:
        raise ValueError(f"npm package is not present in the campaign watchlist: {missing[0]}")
    if not selected:
        raise ValueError("no matching npm packages found in the campaign watchlist")
    return selected


def _existing_case(package: str, *, db_path: Optional[str]) -> Optional[Dict[str, Any]]:
    for summary in list_cases(db_path=db_path, limit=1000):
        case_id = summary.get("case_id") if isinstance(summary, dict) else None
        if not case_id:
            continue
        detail = get_case(str(case_id), db_path=db_path)
        for subject in detail.get("subjects", []):
            if (
                subject.get("subject_type") == "package"
                and subject.get("ecosystem") == SUPPORTED_WATCHLIST_ECOSYSTEM
                and subject.get("name") == package
                and subject.get("status", "active") == "active"
            ):
                return {
                    "package": package,
                    "case_id": detail["case_id"],
                    "status": detail["status"],
                    "title": detail["title"],
                }
    return None


def promote_watchlist_packages(
    *,
    ecosystem: str = SUPPORTED_WATCHLIST_ECOSYSTEM,
    packages: Optional[Iterable[str]] = None,
    select_all: bool = False,
    create: bool = False,
    title_prefix: str = "Watchlist research",
    severity: str = "medium",
    owner: str = "",
    source_url: str = "",
    actor: str = "analyst",
    db_path: Optional[str] = None,
    watchlist_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Preview or idempotently create package cases from the npm watchlist."""
    watchlist = campaign_watchlist_list(Path(watchlist_path).expanduser() if watchlist_path else None)
    selected = select_watchlist_packages(
        watchlist,
        ecosystem=ecosystem,
        packages=packages,
        select_all=select_all,
    )
    result: Dict[str, Any] = {
        "ok": True,
        "ecosystem": SUPPORTED_WATCHLIST_ECOSYSTEM,
        "watchlist_path": watchlist.get("path"),
        "selected": selected,
        "dry_run": not create,
        "created": [],
        "existing": [],
    }
    if not create:
        return result

    for item in selected:
        package = item["package"]
        existing = _existing_case(package, db_path=db_path)
        if existing:
            result["existing"].append(existing)
            continue
        case = start_package_case(
            package=package,
            ecosystem=SUPPORTED_WATCHLIST_ECOSYSTEM,
            title=f"{title_prefix}: npm/{package}",
            summary=(
                f"Research lead promoted from the local npm campaign watchlist for {package}. "
                "No maliciousness has been established; validate public metadata and artifacts "
                "in an isolated research workflow."
            ),
            case_type="malicious_package",
            severity=severity,
            owner=owner,
            source_url=source_url,
            actor=actor,
            db_path=db_path,
        )
        case = add_evidence(
            case["case_id"],
            evidence_type="analyst_note",
            title="Campaign watchlist promotion",
            locator="local://secopsai/campaign-watchlist",
            provenance="local SecOpsAI campaign watchlist; promotion recorded without registry fetch",
            notes=(
                f"watchlist_value={item['watchlist_value']}; ecosystem=npm; "
                "registry_fetch=false; artifact_download=false; execution=false"
            ),
            actor=actor,
            db_path=db_path,
        )
        result["created"].append({
            "package": package,
            "case_id": case["case_id"],
            "status": case["status"],
            "title": case["title"],
        })
    return result
