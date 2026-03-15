"""
Generate local OpenClaw findings from replay data.

This script runs the detector against a replay bundle and groups hits by rule so
they can be reviewed without a separate SIEM or database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, UTC
from typing import Any, Dict, List

from detect import DETECTION_RULES, minutes_between, run_detection
import soc_store


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(ROOT_DIR, "data", "openclaw", "replay", "labeled", "sample_events.json")
DEFAULT_OUTPUT_DIR = os.path.join(ROOT_DIR, "data", "openclaw", "findings")
DEFAULT_DB_PATH = os.path.join(DEFAULT_OUTPUT_DIR, "openclaw_soc.db")

SEVERITY_SCORES = {
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate local OpenClaw findings")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Replay JSON file to analyze")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for findings bundle")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH, help="SQLite database path for persisted findings")
    return parser.parse_args()


def load_events(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("input replay file must be a JSON array")
    return payload


def rule_metadata() -> Dict[str, Dict[str, Any]]:
    return {rule["id"]: rule for rule in DETECTION_RULES}


def severity_score_from_events(events: List[Dict[str, Any]], rule_count: int = 1) -> int:
    base = max(SEVERITY_SCORES.get(str(event.get("severity_hint", "info")), 10) for event in events)
    attack_bonus = min(10, 2 * len({str(event.get("attack_type", "none")) for event in events if event.get("attack_type") not in {None, "none"}}))
    event_bonus = min(10, max(0, len(events) - 1))
    rule_bonus = min(10, max(0, rule_count - 1) * 3)
    return min(100, base + attack_bonus + event_bonus + rule_bonus)


def severity_label(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def stable_finding_id(event_ids: List[str], rule_ids: List[str]) -> str:
    digest = hashlib.sha1(
        "|".join(sorted(rule_ids) + sorted(event_ids)).encode("utf-8")
    ).hexdigest()[:16]
    return f"OCF-{digest.upper()}"


def build_candidate_finding(rule: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    attack_counts = Counter(str(event.get("attack_type", "none")) for event in events)
    session_keys = sorted({str(event.get("session_key", "")) for event in events if event.get("session_key")})
    sourcetypes = sorted({str(event.get("sourcetype", "")) for event in events if event.get("sourcetype")})
    severities = Counter(str(event.get("severity_hint", "info")) for event in events)

    score = severity_score_from_events(events)
    return {
        "finding_id": stable_finding_id([event["event_id"] for event in events], [rule["id"]]),
        "rule_id": rule["id"],
        "rule_ids": [rule["id"]],
        "rule_name": rule["name"],
        "rule_names": [rule["name"]],
        "mitre": rule["mitre"],
        "mitre_ids": [rule["mitre"]],
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "open",
        "disposition": "unreviewed",
        "title": rule["name"],
        "event_count": len(events),
        "attack_types": dict(sorted(attack_counts.items())),
        "severity_hints": dict(sorted(severities.items())),
        "severity_score": score,
        "severity": severity_label(score),
        "merged_from_rule_ids": [rule["id"]],
        "dedup_reason": "single-rule finding",
        "sourcetypes": sourcetypes,
        "session_keys": session_keys,
        "event_ids": [event["event_id"] for event in events],
        "first_seen": min(event["timestamp"] for event in events),
        "last_seen": max(event["timestamp"] for event in events),
        "summary": f"{rule['name']} matched {len(events)} events across {len(session_keys) or 1} session scopes.",
        "events": events,
    }


def findings_should_merge(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    if set(left["event_ids"]) & set(right["event_ids"]):
        return True

    shared_sessions = set(left.get("session_keys", [])) & set(right.get("session_keys", []))
    if not shared_sessions:
        return False

    left_attacks = {attack for attack in left.get("attack_types", {}).keys() if attack != "none"}
    right_attacks = {attack for attack in right.get("attack_types", {}).keys() if attack != "none"}
    if not (left_attacks & right_attacks):
        return False

    left_end = {"timestamp": left["last_seen"]}
    right_start = {"timestamp": right["first_seen"]}
    right_end = {"timestamp": right["last_seen"]}
    left_start = {"timestamp": left["first_seen"]}
    return minutes_between(left_end, right_start) <= 15 or minutes_between(right_end, left_start) <= 15


def merge_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    merged_events = {event["event_id"]: event for finding in findings for event in finding["events"]}
    event_list = sorted(merged_events.values(), key=lambda event: event["timestamp"])
    rule_ids = sorted({rule_id for finding in findings for rule_id in finding.get("rule_ids", [finding["rule_id"]])})
    rule_names = sorted({name for finding in findings for name in finding.get("rule_names", [finding["rule_name"]])})
    mitre_ids = sorted({mitre for finding in findings for mitre in finding.get("mitre_ids", [finding["mitre"]])})
    attack_counts = Counter(str(event.get("attack_type", "none")) for event in event_list)
    severity_hints = Counter(str(event.get("severity_hint", "info")) for event in event_list)
    session_keys = sorted({str(event.get("session_key", "")) for event in event_list if event.get("session_key")})
    sourcetypes = sorted({str(event.get("sourcetype", "")) for event in event_list if event.get("sourcetype")})
    score = severity_score_from_events(event_list, rule_count=len(rule_ids))
    dedup_reason = "shared event_ids"
    if len(rule_ids) > 1:
        dedup_reason = "shared session and attack type overlap"

    return {
        "finding_id": stable_finding_id([event["event_id"] for event in event_list], rule_ids),
        "rule_id": rule_ids[0],
        "rule_ids": rule_ids,
        "rule_name": rule_names[0],
        "rule_names": rule_names,
        "mitre": mitre_ids[0],
        "mitre_ids": mitre_ids,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "status": "open",
        "disposition": "unreviewed",
        "title": " / ".join(rule_names),
        "event_count": len(event_list),
        "attack_types": dict(sorted(attack_counts.items())),
        "severity_hints": dict(sorted(severity_hints.items())),
        "severity_score": score,
        "severity": severity_label(score),
        "merged_from_rule_ids": rule_ids,
        "dedup_reason": dedup_reason,
        "sourcetypes": sourcetypes,
        "session_keys": session_keys,
        "event_ids": [event["event_id"] for event in event_list],
        "first_seen": event_list[0]["timestamp"],
        "last_seen": event_list[-1]["timestamp"],
        "summary": f"Merged OpenClaw incident across {len(rule_ids)} rules and {len(event_list)} events.",
        "events": event_list,
    }


def deduplicate_findings(candidate_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ordered = sorted(candidate_findings, key=lambda finding: finding["first_seen"])
    deduplicated: List[Dict[str, Any]] = []
    for candidate in ordered:
        merged = False
        for index, existing in enumerate(deduplicated):
            if findings_should_merge(existing, candidate):
                deduplicated[index] = merge_findings([existing, candidate])
                merged = True
                break
        if not merged:
            deduplicated.append(candidate)

    deduplicated.sort(key=lambda finding: (-finding["severity_score"], finding["first_seen"]))
    return deduplicated


def build_bundle(source_path: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    result = run_detection(events)
    events_by_id = {event["event_id"]: event for event in events}
    metadata = rule_metadata()

    candidate_findings = []
    for rule_id, detected_ids in result["rule_results"].items():
        if not detected_ids:
            continue
        matched_events = [events_by_id[event_id] for event_id in detected_ids if event_id in events_by_id]
        if not matched_events:
            continue
        candidate_findings.append(build_candidate_finding(metadata[rule_id], matched_events))

    findings = deduplicate_findings(candidate_findings)

    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": source_path,
        "total_events": len(events),
        "total_detections": result["total_detections"],
        "total_candidate_findings": len(candidate_findings),
        "total_findings": len(findings),
        "findings": findings,
    }


def write_bundle(output_dir: str, bundle: Dict[str, Any]) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = os.path.join(output_dir, f"openclaw-findings-{ts}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
        handle.write("\n")
    return path


def main() -> int:
    args = parse_args()
    events = load_events(args.input)
    bundle = build_bundle(args.input, events)
    output_path = write_bundle(args.output_dir, bundle)
    db_path = soc_store.persist_findings(bundle["findings"], bundle["source"], args.db_path)

    print(f"findings_file={output_path}")
    print(f"findings_db={db_path}")
    print(f"total_candidate_findings={bundle['total_candidate_findings']}")
    print(f"total_findings={bundle['total_findings']}")
    print(f"total_detections={bundle['total_detections']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())