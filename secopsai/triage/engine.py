from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import soc_store

from .disposition import VALID_DISPOSITIONS, require_closure_note, validate_disposition, validate_status
from .host import investigate_host
from .reporting import write_report
from .supply_chain import investigate_supply_chain, suggest_fp_action_for_supply_chain


def infer_category(finding: Dict[str, Any]) -> str:
    finding_id = str(finding.get("finding_id") or "")
    title = str(finding.get("title") or "").lower()
    source = str(finding.get("source") or "").lower()
    if finding_id.startswith("SCM-") or "supply-chain" in source or str(finding.get("platform") or "") == "supply_chain":
        return "supply_chain"
    if "policy denial" in title:
        return "policy_denial"
    if "exfil" in title:
        return "exfiltration"
    return "host"


def list_triage_findings(
    *,
    db_path: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    rows = soc_store.list_findings(db_path)
    if severity:
        rows = [row for row in rows if str(row.get("severity") or "").lower() == str(severity).lower()]
    if status:
        rows = [row for row in rows if str(row.get("status") or "").lower() == str(status).lower()]
    enriched = []
    for row in rows:
        detail = soc_store.get_finding(str(row["finding_id"]), db_path) or dict(row)
        triage_category = infer_category(detail)
        if category and triage_category != category:
            continue
        detail["category"] = triage_category
        enriched.append(detail)
    return enriched[:limit]


def start_finding(
    finding_id: str,
    *,
    author: Optional[str] = None,
    note: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    finding = soc_store.get_finding(finding_id, db_path)
    if not finding:
        raise ValueError(f"finding not found: {finding_id}")
    soc_store.set_finding_status(finding_id, validate_status("in_review"), db_path)
    if note:
        soc_store.add_note(finding_id, author or os.environ.get("USER", "analyst"), note.strip(), db_path)
    updated = soc_store.get_finding(finding_id, db_path) or finding
    updated["category"] = infer_category(updated)
    return updated


def investigate_finding(
    finding_id: str,
    *,
    db_path: Optional[str] = None,
    search_root: Optional[str] = None,
    report_dir: Optional[str] = None,
    author: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    finding = soc_store.get_finding(finding_id, db_path)
    if not finding:
        raise ValueError(f"finding not found: {finding_id}")

    category = infer_category(finding)
    search_path = Path(search_root or os.getcwd()).resolve()
    if category == "supply_chain":
        investigation = investigate_supply_chain(finding, search_root=search_path)
    else:
        investigation = investigate_host(finding)

    result: Dict[str, Any] = {
        "finding_id": finding_id,
        "category": category,
        "finding": finding,
        "investigation": investigation,
    }
    result.update(write_report(result, Path(report_dir).resolve() if report_dir else None))

    if note:
        soc_store.add_note(finding_id, author or os.environ.get("USER", "analyst"), note.strip(), db_path)
        refreshed = soc_store.get_finding(finding_id, db_path)
        if refreshed:
            result["finding"] = refreshed

    return result


def suggest_supply_chain_fp_action(
    finding_id: str,
    *,
    db_path: Optional[str] = None,
    search_root: Optional[str] = None,
) -> Dict[str, Any]:
    finding = soc_store.get_finding(finding_id, db_path)
    if not finding:
        raise ValueError(f"finding not found: {finding_id}")
    if infer_category(finding) != "supply_chain":
        raise ValueError(f"finding is not a supply-chain finding: {finding_id}")

    search_path = Path(search_root or os.getcwd()).resolve()
    suggestion = suggest_fp_action_for_supply_chain(finding, search_root=search_path)
    return {
        "finding_id": finding_id,
        "category": "supply_chain",
        "finding": finding,
        "suggestion": suggestion,
    }


def close_finding(
    finding_id: str,
    *,
    disposition: str,
    note: str,
    author: Optional[str] = None,
    status: str = "closed",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    finding = soc_store.get_finding(finding_id, db_path)
    if not finding:
        raise ValueError(f"finding not found: {finding_id}")

    final_disposition = validate_disposition(disposition)
    final_note = require_closure_note(final_disposition, note)
    final_status = validate_status(status, allowed={"triaged", "closed"})

    soc_store.set_finding_disposition(finding_id, final_disposition, db_path)
    soc_store.set_finding_status(finding_id, final_status, db_path)
    soc_store.add_note(finding_id, author or os.environ.get("USER", "analyst"), final_note, db_path)

    updated = soc_store.get_finding(finding_id, db_path)
    if not updated:
        raise ValueError(f"finding not found after closure update: {finding_id}")
    updated["category"] = infer_category(updated)
    return updated
