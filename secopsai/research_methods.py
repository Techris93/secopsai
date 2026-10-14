"""Non-executing release comparisons for the two initial research programs.

Differences are investigative leads. Publisher labels and MCP annotations
are untrusted declarations; neither establishes maliciousness or execution.
"""
from __future__ import annotations

import re

from secopsai.research_operation_store import append, canonical, digest, text, timestamp

PROGRAMS = {
    "software_supply_chain": ["Compare exact release bytes and install hooks against a known-good release", "Trace credential reads to destinations, including legitimate administration controls", "Compare publisher and dependency changes using attributable registry records", "Verify a patch and detection against affected and unaffected versions"],
    "ai_agent_security": ["Compare complete MCP tool catalogs and declared schemas between releases", "Test permission and credential boundaries with synthetic accounts in an authorized lab", "Reproduce injection attempts as untrusted input without permitting external side effects", "Compare agent behavior with a benign control and fixed model/prompt/tool versions"],
}


def _snapshot(value: dict) -> dict:
    if not isinstance(value, dict) or len(canonical(value).encode()) > 2 * 1024 * 1024:
        raise ValueError("comparison snapshot is missing or exceeds its budget")
    for field in ("package", "version", "origin"):
        text(value.get(field), field, limit=4000)
    timestamp(value.get("acquired_at", ""))
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value.get("artifact_sha256", "")):
        raise ValueError("comparison requires exact artifact hashes")
    return value


def compare_releases(payload: dict, *, actor: str, case_id: str = "", db_path=None) -> dict:
    from secopsai.research_assurance import person
    person(actor, role="researcher", db_path=db_path)
    before, after = _snapshot(payload.get("before")), _snapshot(payload.get("after"))
    if before["package"] != after["package"]:
        raise ValueError("release comparisons require the same package identity")
    program = payload.get("program")
    if program not in PROGRAMS:
        raise ValueError("unsupported initial research program")
    observations = []
    def observe(kind, path, previous, current):
        observations.append({"kind": kind, "location": path, "before": previous, "after": current,
                             "assessment": "metadata_difference", "requires_reproduction": True})
    if before.get("publisher") != after.get("publisher"):
        observe("publisher_declaration_changed", "/publisher", before.get("publisher"), after.get("publisher"))
    for field in ("install_hooks", "dependencies", "permissions"):
        left, right = before.get(field, {}), after.get(field, {})
        if not isinstance(left, dict) or not isinstance(right, dict) or len(left) + len(right) > 2000:
            raise ValueError(f"{field} comparison requires bounded normalized mappings")
        for name in sorted(set(left) | set(right)):
            if left.get(name) != right.get(name):
                observe(field + "_changed", f"/{field}/{name}", left.get(name), right.get(name))
    if program == "ai_agent_security":
        left, right = before.get("tools"), after.get("tools")
        if not isinstance(left, list) or not isinstance(right, list) or len(left) > 500 or len(right) > 500:
            raise ValueError("MCP comparison requires bounded complete tools/list snapshots")
        if before.get("catalog_complete") is not True or after.get("catalog_complete") is not True:
            raise ValueError("paginated or truncated tool catalogs cannot establish a complete release difference")
        for tools in (left, right):
            names = []
            for tool in tools:
                if not isinstance(tool, dict) or not isinstance(tool.get("inputSchema"), dict):
                    raise ValueError("each tool requires a name and a recorded input schema")
                name = text(tool.get("name"), "tool name", limit=128)
                if name in names:
                    raise ValueError("duplicate tool identity")
                names.append(name)
        indexed_left, indexed_right = {t["name"]: t for t in left}, {t["name"]: t for t in right}
        for name in sorted(set(indexed_left) | set(indexed_right)):
            old, new = indexed_left.get(name), indexed_right.get(name)
            if old != new:
                observe("tool_added" if old is None else "tool_removed" if new is None else "tool_contract_changed", f"/tools/{name}", old, new)
    value = {"program": program, "before_sha256": before["artifact_sha256"], "after_sha256": after["artifact_sha256"],
             "before_snapshot_hash": digest(before), "after_snapshot_hash": digest(after), "observations": observations,
             "next_experiments": PROGRAMS[program], "limitations": ["Declared metadata and tool annotations are untrusted. Differences do not prove execution, compromise, victim impact or attacker identity."]}
    return append("release_comparison", value, actor=actor, case_id=case_id, db_path=db_path)
