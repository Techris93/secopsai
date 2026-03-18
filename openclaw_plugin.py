"""
OpenClaw plugin-style interface for security posture checks.

Purpose:
- Provide a stable local interface that OpenClaw can call now.
- Keep integrations (WhatsApp, Slack, API gateway) thin by routing them here.

Usage:
  python openclaw_plugin.py check --type malware
  python openclaw_plugin.py check --type exfil
  python openclaw_plugin.py check --type both --severity medium
  python openclaw_plugin.py list-high
  python openclaw_plugin.py show OCF-EXAMPLE
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

import soc_store


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

MALWARE_HINTS = (
    "dangerous exec",
    "powershell",
    "fileless",
    "malware",
    "blocked_policy_abuse",
    "t1059",
)

EXFIL_HINTS = (
    "data exfiltration",
    "dns exfiltration",
    "exfil",
    "t1048",
)

MITIGATION_BY_RULE: Dict[str, List[str]] = {
    # Dangerous execution / policy abuse
    "RULE-101": [
        "Review the exact exec commands and confirm they are expected.",
        "If any command is not expected, rotate any credentials exposed (API keys, tokens).",
        "Harden OpenClaw exec/tool permissions for the affected agent (reduce surface, add policy guards).",
        "Add detection rules or policy blocks for dangerous patterns like 'curl ... | bash'.",
    ],
    "RULE-109": [
        "Identify which agent or skill issued the dangerous execs and confirm business justification.",
        "If unauthorized, disable or restrict that skill/tool configuration in OpenClaw.",
        "Rotate any secrets used in the commands (tokens, SSH keys, API keys).",
        "Add stricter policy/approval requirements for high-risk exec operations.",
    ],
    # Sensitive Config
    "RULE-201": [
        "Review which OpenClaw config or environment values were accessed or modified.",
        "Confirm that only trusted operators/agents have access to those configuration paths.",
        "Restrict read/write of sensitive config to a small set of admin workflows.",
        "Audit recent config changes for unexpected keys (tokens, secret URLs, internal hostnames).",
    ],
    # Tool Burst
    "RULE-301": [
        "Check which skills/tools are being fanned out and whether that pattern is expected.",
        "Rate-limit or throttle high-risk tools to reduce blast radius.",
        "Add guardrails to prevent large unreviewed batches (e.g., require approval above N operations).",
        "Investigate the originating prompt/agent that triggered the burst for potential abuse.",
    ],
    # Pairing Churn
    "RULE-401": [
        "Review recent device pairing/unpairing events and confirm they match expected user actions.",
        "Disable or pause new pairings until suspicious activity is understood.",
        "Enforce MFA or explicit approval for new device pairings on OpenClaw.",
        "Check audit logs for access from newly paired devices and revoke any that look suspicious.",
    ],
    # Subagent Fanout
    "RULE-501": [
        "Inspect which root request caused the subagent fanout and whether that request was legitimate.",
        "Limit max subagents per request for untrusted surfaces (e.g., external chats).",
        "Add approval or rate limiting for fanout-heavy workflows (bulk edits, large repo scans).",
        "Review subagent results for signs of data exfiltration or unwanted mass changes.",
    ],
    # Restart Loop
    "RULE-601": [
        "Check service logs for recurring crashes or misconfigurations in the OpenClaw runtime or gateway.",
        "Temporarily disable non-essential skills/plugins to see if one is causing instability.",
        "Roll back recent configuration or code changes that align with the start of the restart loop.",
        "Add health checks and alerts so restart loops are caught early in staging, not production.",
    ],
    # Skill Source Drift
    "RULE-701": [
        "Review recent skill or plugin source changes for unreviewed code paths.",
        "Enforce code review and signed releases for skills before deployment into OpenClaw.",
        "Pin skills to known-good versions and avoid live editing in production.",
        "If drift is unexpected, roll back to the last verified skill version and diff the changes.",
    ],
    # Data Exfiltration
    "RULE-801": [
        "Inspect the events for which data was accessed and where it was sent (destination domains, IPs, buckets).",
        "If exfiltration is suspected, revoke tokens/credentials used for the data export.",
        "Add stricter egress controls (allow-list destinations, block generic paste/upload patterns).",
        "Search recent history for similar exfil patterns from the same agent, user, or IP.",
    ],
    # Malware Presence
    "RULE-901": [
        "Confirm whether the flagged behavior matches known malware techniques (e.g., fileless execution).",
        "Isolate the affected host or OpenClaw node if feasible to reduce lateral movement.",
        "Disable or sandbox risky tools that were used in the malware pattern.",
        "Schedule a deeper forensic review of the host's logs, processes, and network activity.",
    ],
}


@dataclass
class CheckResult:
    check_type: str
    findings_total: int
    matched_count: int
    high_or_above: int
    top_matches: List[Dict[str, Any]]


def _severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(threshold.lower(), 0)


def _haystack(finding: Dict[str, Any]) -> str:
    parts = [
        str(finding.get("title", "")),
        str(finding.get("summary", "")),
        str(finding.get("rule_name", "")),
        " ".join(str(x) for x in finding.get("rule_names", [])),
        " ".join(str(x) for x in finding.get("mitre_ids", [])),
        " ".join(str(x) for x in finding.get("attack_types", {}).keys()),
    ]
    return " ".join(parts).lower()


def _matches_type(finding: Dict[str, Any], check_type: str) -> bool:
    text = _haystack(finding)
    if check_type == "malware":
        return any(hint in text for hint in MALWARE_HINTS)
    if check_type == "exfil":
        return any(hint in text for hint in EXFIL_HINTS)
    if check_type == "both":
        return _matches_type(finding, "malware") or _matches_type(finding, "exfil")
    return False


def _top_rows(findings: Iterable[Dict[str, Any]], max_rows: int = 5) -> List[Dict[str, Any]]:
    rows = sorted(
        findings,
        key=lambda x: (
            -SEVERITY_ORDER.get(str(x.get("severity", "info")).lower(), 0),
            str(x.get("first_seen", "")),
        ),
    )
    return [
        {
            "finding_id": row.get("finding_id"),
            "severity": row.get("severity"),
            "status": row.get("status"),
            "disposition": row.get("disposition"),
            "title": row.get("title"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
        }
        for row in rows[:max_rows]
    ]


def _extract_rule_ids(finding: Dict[str, Any]) -> List[str]:
    ids: List[str] = []
    rule_id = finding.get("rule_id")
    if isinstance(rule_id, str):
        ids.append(rule_id)
    rule_ids = finding.get("rule_ids")
    if isinstance(rule_ids, list):
        ids.extend(str(r) for r in rule_ids)
    attack_types = finding.get("attack_types") or {}
    for key in attack_types.keys():
        if str(key).upper().startswith("RULE-"):
            ids.append(str(key).upper())
    seen: set = set()
    deduped: List[str] = []
    for rid in ids:
        if rid not in seen:
            seen.add(rid)
            deduped.append(rid)
    return deduped


def _mitigations_for_finding(finding: Dict[str, Any]) -> List[str]:
    if "recommended_actions" in finding and isinstance(finding["recommended_actions"], list):
        return [str(a) for a in finding["recommended_actions"]]
    rule_ids = _extract_rule_ids(finding)
    actions: List[str] = []
    for rid in rule_ids:
        actions.extend(MITIGATION_BY_RULE.get(rid, []))
    if not actions:
        actions = [
            "Review the associated events and confirm whether this behavior is expected.",
            "If not expected, rotate any exposed secrets and restrict relevant OpenClaw skills/tools.",
            "Add or tighten detection rules/policies so similar behavior is blocked or requires approval.",
        ]
    return actions


def check_presence(check_type: str, min_severity: str = "low") -> CheckResult:
    all_findings = soc_store.list_findings()
    enriched: List[Dict[str, Any]] = []
    for row in all_findings:
        detail = soc_store.get_finding(str(row["finding_id"])) or dict(row)
        detail.setdefault("severity", row.get("severity", "info"))
        detail.setdefault("status", row.get("status", "open"))
        detail.setdefault("disposition", row.get("disposition", "unreviewed"))
        detail.setdefault("title", row.get("title", ""))
        detail.setdefault("first_seen", row.get("first_seen", ""))
        detail.setdefault("last_seen", row.get("last_seen", ""))

        if not _severity_at_least(str(detail.get("severity", "info")), min_severity):
            continue
        if _matches_type(detail, check_type):
            enriched.append(detail)

    high_or_above = sum(1 for row in enriched if _severity_at_least(str(row.get("severity", "info")), "high"))
    return CheckResult(
        check_type=check_type,
        findings_total=len(all_findings),
        matched_count=len(enriched),
        high_or_above=high_or_above,
        top_matches=_top_rows(enriched, max_rows=5),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OpenClaw plugin interface")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Check malware/exfil presence from findings store")
    check.add_argument("--type", choices=["malware", "exfil", "both"], required=True)
    check.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"], default="low")

    sub.add_parser("list-high", help="List high+ findings")

    show = sub.add_parser("show", help="Show one finding")
    show.add_argument("finding_id")

    mitigate = sub.add_parser("mitigate", help="Show recommended mitigation steps for a finding")
    mitigate.add_argument("finding_id")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.command == "check":
        result = check_presence(args.type, args.severity)
        print(
            json.dumps(
                {
                    "check_type": result.check_type,
                    "findings_total": result.findings_total,
                    "matched_count": result.matched_count,
                    "high_or_above": result.high_or_above,
                    "top_matches": result.top_matches,
                },
                indent=2,
            )
        )
        return 0

    if args.command == "list-high":
        rows = [r for r in soc_store.list_findings() if _severity_at_least(str(r.get("severity", "info")), "high")]
        print(json.dumps(_top_rows(rows, max_rows=20), indent=2))
        return 0

    if args.command == "show":
        finding = soc_store.get_finding(args.finding_id)
        if not finding:
            print(json.dumps({"error": f"finding not found: {args.finding_id}"}, indent=2))
            return 1
        print(json.dumps(finding, indent=2))
        return 0

    if args.command == "mitigate":
        finding = soc_store.get_finding(args.finding_id)
        if not finding:
            print(json.dumps({"error": f"finding not found: {args.finding_id}"}, indent=2))
            return 1
        mitigations = _mitigations_for_finding(finding)
        output = {
            "finding_id": finding.get("finding_id", args.finding_id),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "disposition": finding.get("disposition"),
            "rule_id": finding.get("rule_id"),
            "rule_ids": finding.get("rule_ids"),
            "attack_types": finding.get("attack_types"),
            "recommended_actions": mitigations,
        }
        print(json.dumps(output, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
