from __future__ import annotations

import json
from typing import Any, Dict, List


def fmt_list(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "No findings."

    lines: List[str] = []
    for r in rows:
        lines.append(
            f"{r['finding_id']} | {str(r.get('severity', 'info')).upper():8s} | "
            f"status={r.get('status')} | disposition={r.get('disposition')} | {r.get('title', '')}"
        )
    lines.append(f"total_findings={len(rows)}")
    return "\n".join(lines)


def fmt_finding(finding: Dict[str, Any]) -> str:
    """Pretty-print a single finding with key fields plus a short event tail."""

    lines: List[str] = []
    lines.append(f"FINDING: {finding.get('finding_id')}")
    lines.append(f"TITLE: {finding.get('title')}")
    lines.append(
        f"SEVERITY: {finding.get('severity')} (score={finding.get('severity_score')})"
    )
    lines.append(
        f"STATUS: {finding.get('status')} | DISPOSITION: {finding.get('disposition')}"
    )
    lines.append(
        f"FIRST_SEEN: {finding.get('first_seen')} | LAST_SEEN: {finding.get('last_seen')}"
    )
    rule_ids = finding.get("rule_ids") or [finding.get("rule_id", "")]
    lines.append(f"RULE_IDS: {', '.join(rule_ids)}")

    lines.append("")
    lines.append("SUMMARY:")
    lines.append(str(finding.get("summary", "")).strip())
    lines.append("")

    if finding.get("recommended_actions"):
        lines.append("RECOMMENDED_ACTIONS:")
        for action in finding["recommended_actions"]:
            lines.append(f"- {action}")
        lines.append("")

    events = finding.get("events") or []
    if events:
        lines.append(f"EVENTS (showing up to 10 of {len(events)}):")
        for ev in events[:10]:
            msg = ev.get("message") or ""
            cmd = ev.get("command")
            tail = f" | cmd={cmd}" if cmd else ""
            lines.append(
                f"- {ev.get('timestamp')} {ev.get('event_id')} {msg}{tail}"
            )

    return "\n".join(lines)


def to_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=False)
