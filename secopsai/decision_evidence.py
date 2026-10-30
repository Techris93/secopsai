"""Budget evidence across categories and expose every loss of coverage."""
from __future__ import annotations
import json
from typing import Any

CATEGORIES = ("matched_strings", "flag_locations", "findings", "install_time_files", "decoded_payloads", "flagged_files", "binaries", "metadata_signals")
MAX_STATE_CHARS = 32_000
# Contexts built before this contract carry no exact region counts, so they
# can never count as complete.
COVERAGE_CONTRACT = "context-v1"


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


def context_coverage(context: dict[str, Any]) -> dict[str, Any]:
    """Coverage for a model handed the whole context, as bridge models are.

    ``build_evidence`` measures Clef's smaller serialized state, so it reports
    cuts a bridge model never had. Complete here means every rule match can be
    read in what was supplied. A flagged file too large to send whole still
    counts when every matched region is in its excerpt: the rules scanned the
    rest. Anything the model cannot read is a gap, and a gap blocks closure.
    """
    gaps: list[str] = []
    if context.get("coverage_contract") != COVERAGE_CONTRACT:
        gaps.append("context_predates_coverage_contract")
    if context.get("evidence_truncated"):
        gaps.extend(f"omitted:{item}" for item in context.get("evidence_omissions") or ["evidence_truncated"])
    findings = [item for item in context.get("findings") or [] if isinstance(item, dict)]
    if not findings:
        gaps.append("no_findings")
    supplied: set[str] = set()
    for item in context.get("flagged_files") or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        cut = item.get("truncated") is True or item.get("complete") is False
        found, shown = item.get("regions_found"), item.get("regions_shown")
        supplied.add(path)
        if item.get("binary") or "content" not in item:
            gaps.append(f"flagged_file_not_readable:{path}")
        elif item.get("regions_trimmed") or (cut and not (isinstance(found, int) and found > 0 and shown == found)):
            gaps.append(f"flagged_file_regions:{path}")
    for item in context.get("install_time_files") or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        supplied.add(path)
        if item.get("truncated") is True or item.get("complete") is False:
            gaps.append(f"install_time_file:{path}")
    gaps.extend(f"decoded_payload:{item.get('found_in')}" for item in context.get("decoded_payloads") or [] if isinstance(item, dict) and item.get("truncated") is True)
    gaps.extend(f"binary_not_inspected:{item.get('path')}" for item in context.get("binaries") or [] if isinstance(item, dict))
    for item in findings:
        paths = [item.get("file_path")] + [found.get("file_path") for found in item.get("evidence_locations") or [] if isinstance(found, dict)]
        gaps.extend(f"finding_file_not_supplied:{path}" for path in paths if isinstance(path, str) and path and path not in supplied)
    gaps = list(dict.fromkeys(gaps))
    return {"contract": COVERAGE_CONTRACT, "complete": not gaps, "gaps": gaps[:50], "gap_count": len(gaps),
            "included_categories": sorted(key for key in CATEGORIES if context.get(key)), "omitted_categories": [],
            "truncated_records": gaps[:50], "source_truncated": bool(context.get("evidence_truncated"))}


def coverage_for_result(context: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Recheck a stored result with the measure that produced it."""
    reported = result.get("evidence_coverage")
    if isinstance(reported, dict) and reported.get("contract") == COVERAGE_CONTRACT:
        return context_coverage(context)
    return build_evidence(context)[1]


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


def missing_file_identifiers(context: dict) -> list[str]:
    """Exact absent-file choices; complete supplied files cannot be missing."""
    supplied = {
        item.get("path") or item.get("file_path")
        for category in ("flagged_files", "install_time_files")
        for item in context.get(category) or []
        if isinstance(item, dict) and item.get("truncated") is not True and item.get("complete") is not False
    }
    missing = context.get("missing_files")
    if not isinstance(missing, list):
        return []
    return list(dict.fromkeys(
        path for path in missing
        if isinstance(path, str) and path.strip() and path not in supplied
    ))[:200]


def artifact_decision_choices(context: dict) -> dict[str, Any]:
    """One choice set shared by prompts, schemas, formatters and validators."""
    dispositions = {"true_positive": "true_positive", "false_positive": "false_positive",
                    "benign_expected": "expected_behavior"}
    missing = missing_file_identifiers(context)
    if missing:
        dispositions["needs_more_evidence"] = "needs_review"
    return {"decision_evidence_refs": evidence_identifiers(context), "missing_evidence": missing,
            "verdict_dispositions": dispositions}
