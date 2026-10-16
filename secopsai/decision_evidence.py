"""Budget evidence across categories and expose every loss of coverage."""
from __future__ import annotations
import json
from typing import Any

CATEGORIES = ("matched_strings", "flag_locations", "findings", "install_time_files", "decoded_payloads", "flagged_files", "binaries", "metadata_signals")
MAX_STATE_CHARS = 32_000


def build_evidence(context: dict[str, Any], limit: int = MAX_STATE_CHARS) -> tuple[str, dict[str, Any]]:
    if limit < 2048:
        raise ValueError("evidence budget must be at least 2048 characters")
    records: list[tuple[str, Any]] = []
    omitted: list[str] = []
    truncated: list[str] = []
    findings = context.get("findings") or []
    if not isinstance(findings, list):
        findings = [findings]
    matched_records = context.get("matched_strings") or []
    if not isinstance(matched_records, list):
        matched_records = [matched_records]
    location_records = context.get("flag_locations") or []
    if not isinstance(location_records, list):
        location_records = [location_records]
    normalized_findings = []
    for finding in findings[:64]:
        if not isinstance(finding, dict):
            normalized_findings.append(finding)
            continue
        match = {key: finding[key] for key in ("rule_id", "file_path", "matched_indicator", "matched_patterns", "matched_strings", "safe_context", "matched_regions_shown") if key in finding}
        if match and not (isinstance(matched_records, list) and any(item == match for item in matched_records)):
            matched_records.append(match)
        for location in finding.get("evidence_locations") or finding.get("evidence") or []:
            if isinstance(location, dict):
                normalized_location = {key: location[key] for key in ("rule_id", "flag", "file_path", "line", "code") if key in location}
                if normalized_location and normalized_location not in location_records:
                    location_records.append(normalized_location)
        normalized_findings.append({key: value for key, value in finding.items() if key not in {
            "matched_indicator", "matched_patterns", "matched_strings", "safe_context", "matched_regions_shown", "evidence", "evidence_locations",
        }})
    for category, items in (("matched_strings", matched_records), ("flag_locations", location_records)):
        records.extend((category, item) for item in items[:64])
        if len(items) > 64:
            omitted.append(category)
    for category in CATEGORIES:
        if category in {"matched_strings", "flag_locations"}:
            continue
        items = context.get(category) or []
        if category == "findings":
            items = normalized_findings
        if not isinstance(items, list):
            items = [items]
        records.extend((category, item) for item in items[:64])
        if len(items) > 64:
            omitted.append(category)
    for key in ("manifest", "actor_fingerprints"):
        if context.get(key):
            records.append((key, context[key]))
    meta = {key: context[key] for key in ("ecosystem", "package", "version", "artifact_id", "rule_score", "rule_level", "finding", "deterministic_assessment", "automation_policy") if key in context}
    # Allocate to each category first, then to its records: a large file cannot
    # consume the space reserved for rule matches or decoded payloads.
    counts = {category: sum(1 for c, _ in records if c == category) for category, _ in records}
    categories = max(1, len(counts) + 1)
    available = limit - 1800

    def bounded(value: Any, budget: int, label: str) -> Any:
        raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        if len(raw) <= budget:
            return value
        truncated.append(label)
        # Each record remains labelled, including the exact number omitted.
        keep = max(0, (budget - 160) // 2)
        return {"excerpt": raw[:keep], "tail": raw[-keep:] if keep else "", "truncated": True, "omitted_characters": max(0, len(raw) - 2 * keep)}

    state: dict[str, Any] = {"package": bounded(meta, available // categories, "package"), "evidence": {}}
    for index, (category, item) in enumerate(records):
        if isinstance(item, dict) and (item.get("truncated") or item.get("complete") is False):
            truncated.append(f"{category}:{item.get('path', index)}:source")
        budget = max(180, available // categories // counts[category])
        state["evidence"].setdefault(category, []).append(bounded(item, budget, f"{category}:{index}"))
    complete = bool(records) and not omitted and not truncated and not context.get("evidence_truncated")
    coverage = {"complete": complete, "included_categories": sorted(state["evidence"]), "omitted_categories": omitted, "truncated_records": truncated, "source_truncated": bool(context.get("evidence_truncated"))}
    state["coverage"] = coverage
    encoded = json.dumps(state, ensure_ascii=True, separators=(",", ":"))
    # Extremely many records can exceed the structural budget. Drop entire
    # labelled records, never silently truncate serialized JSON.
    while len(encoded) > limit and state["evidence"]:
        category = max(state["evidence"], key=lambda c: len(json.dumps(state["evidence"][c])))
        state["evidence"][category].pop()
        if category not in coverage["omitted_categories"]:
            coverage["omitted_categories"].append(category)
        coverage["complete"] = False
        if not state["evidence"][category]:
            del state["evidence"][category]
        coverage["included_categories"] = sorted(state["evidence"])
        encoded = json.dumps(state, ensure_ascii=True, separators=(",", ":"))
    if len(encoded) > limit:
        raise ValueError("evidence coverage metadata exceeds budget")
    return encoded, coverage


def evidence_identifiers(context: dict) -> list[str]:
    ids = []
    for category in CATEGORIES:
        for item in context.get(category) or []:
            if not isinstance(item, dict):
                continue
            for key in ("rule_id", "file_path", "path", "found_in"):
                value = item.get(key)
                if isinstance(value, str) and value and value not in ids:
                    ids.append(value)
    return ids[:200]
