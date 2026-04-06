from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


def _sample_counts(values: List[str]) -> Dict[str, int]:
    return dict(Counter(value for value in values if value))


def _policy_denial_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    events = finding.get("events") or []
    statuses = _sample_counts([str(event.get("status") or "") for event in events if isinstance(event, dict)])
    actions = _sample_counts([str(event.get("action") or "") for event in events if isinstance(event, dict)])
    sessions = sorted(
        {
            str(event.get("session_key") or "")
            for event in events
            if isinstance(event, dict) and str(event.get("session_key") or "").strip()
        }
    )
    repeated_pattern = len(events) >= 20 and len(sessions) <= 3
    recommended_disposition = "tune_policy" if repeated_pattern else "needs_review"
    confidence = "medium" if repeated_pattern else "low"
    summary = (
        "Policy denials are repeating in a concentrated pattern, which suggests the policy may be too aggressive or needs an exception."
        if repeated_pattern
        else "Policy denial finding requires analyst review to determine whether this is intended enforcement or a noisy rule."
    )
    next_actions = [
        "Review the underlying detection rule and blocked action.",
        "Sample the associated events to confirm whether the same workflow is being denied repeatedly.",
    ]
    if repeated_pattern:
        next_actions.append("Consider tune_policy or exception_granted if the workflow is legitimate.")
    return {
        "summary": summary,
        "recommended_disposition": recommended_disposition,
        "confidence": confidence,
        "evidence": [
            f"Event count: {len(events)}",
            f"Distinct sessions: {len(sessions)}",
            f"Statuses: {statuses}" if statuses else "",
            f"Actions: {actions}" if actions else "",
        ],
        "next_actions": next_actions,
        "external_links": {},
        "event_analysis": {
            "event_count": len(events),
            "distinct_sessions": len(sessions),
            "statuses": statuses,
            "actions": actions,
        },
    }


def _exfil_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    destination_ip = finding.get("destination_ip")
    bytes_transferred = finding.get("bytes_transferred")
    suspicious_dest = bool(destination_ip) and destination_ip not in {"127.0.0.1", "::1"}
    large_transfer = isinstance(bytes_transferred, (int, float)) and float(bytes_transferred) >= 100_000_000
    escalated = suspicious_dest or large_transfer
    return {
        "summary": (
            "Potential exfiltration needs urgent review."
            if escalated
            else "Exfiltration-like behavior needs context before closure."
        ),
        "recommended_disposition": "needs_review",
        "confidence": "high" if escalated else "medium",
        "evidence": [
            f"Destination IP: {destination_ip}" if destination_ip else "",
            f"Bytes transferred: {bytes_transferred}" if bytes_transferred is not None else "",
        ],
        "next_actions": [
            "Confirm the initiating process, destination, and user context.",
            "Escalate immediately if the destination is unknown or sensitive data was accessed.",
        ],
        "external_links": {
            "ipinfo": f"https://ipinfo.io/{destination_ip}" if destination_ip else "",
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{destination_ip}" if destination_ip else "",
        },
    }


def investigate_host(finding: Dict[str, Any]) -> Dict[str, Any]:
    title = str(finding.get("title") or "").lower()
    if "policy denial" in title:
        return _policy_denial_summary(finding)
    if "exfil" in title:
        return _exfil_summary(finding)
    return {
        "summary": "Host-based finding needs analyst review.",
        "recommended_disposition": "needs_review",
        "confidence": "low",
        "evidence": [
            f"Rule IDs: {', '.join(finding.get('rule_ids') or [])}" if finding.get("rule_ids") else "",
            f"Event count: {len(finding.get('event_ids') or [])}",
        ],
        "next_actions": [
            "Review the full finding and associated events with `secopsai show <finding_id>`.",
            "Use finding context to decide whether this is true_positive, false_positive, or expected_behavior.",
        ],
        "external_links": {},
    }
