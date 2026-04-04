#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

import soc_store


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FINDINGS_DIR = ROOT / ".sdd" / "secopsai" / "findings"
DEFAULT_PLAN_PATH = ROOT / ".sdd" / "plans" / "secopsai-remediation.yaml"

SEVERITY_PRIORITY = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Bernstein-compatible remediation plan files from SecOpsAI findings."
    )
    parser.add_argument("--db-path", default=None, help="Path to the SecOpsAI SOC SQLite database.")
    parser.add_argument(
        "--severity",
        default="high",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to include.",
    )
    parser.add_argument("--limit", type=int, default=10, help="Maximum findings to export.")
    parser.add_argument(
        "--status",
        default="open",
        choices=["open", "all"],
        help="Only export open findings by default.",
    )
    parser.add_argument(
        "--output-plan",
        default=str(DEFAULT_PLAN_PATH),
        help="Path to write the Bernstein plan YAML.",
    )
    parser.add_argument(
        "--findings-dir",
        default=str(DEFAULT_FINDINGS_DIR),
        help="Directory to write finding brief markdown files.",
    )
    return parser.parse_args()


def _severity_score(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(str(severity or "").lower(), 0)


def _include_row(row: Dict[str, Any], min_severity: str, status_mode: str) -> bool:
    if status_mode == "open" and str(row.get("status", "")).lower() != "open":
        return False
    return _severity_score(row.get("severity")) >= _severity_score(min_severity)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "finding"


def _role_for_finding(finding: Dict[str, Any]) -> str:
    platform = str(finding.get("platform", "")).lower()
    title = str(finding.get("title", "")).lower()
    summary = str(finding.get("summary", "")).lower()

    if platform == "supply_chain":
        return "security"
    if "dependency" in title or "package" in title or "dependency" in summary:
        return "security"
    if "plugin" in title or "cli" in title or "code" in summary:
        return "backend"
    return "security"


def _scope_for_finding(finding: Dict[str, Any]) -> str:
    severity = str(finding.get("severity", "")).lower()
    if severity == "critical":
        return "medium"
    if severity == "high":
        return "small"
    return "small"


def _complexity_for_finding(finding: Dict[str, Any]) -> str:
    severity = str(finding.get("severity", "")).lower()
    if severity in {"critical", "high"}:
        return "high"
    return "medium"


def _finding_brief(finding: Dict[str, Any]) -> str:
    lines = [
        f"# {finding.get('finding_id')}",
        "",
        f"- Title: {finding.get('title', 'Unknown')}",
        f"- Severity: {finding.get('severity', 'unknown')}",
        f"- Status: {finding.get('status', 'unknown')}",
        f"- Disposition: {finding.get('disposition', 'unknown')}",
        f"- Platform: {finding.get('platform', 'unknown')}",
        f"- Source: {finding.get('source', 'unknown')}",
        f"- First Seen: {finding.get('first_seen', 'unknown')}",
        f"- Last Seen: {finding.get('last_seen', 'unknown')}",
        "",
        "## Summary",
        "",
        str(finding.get("summary") or "No summary available."),
        "",
    ]

    if finding.get("analysis"):
        lines.extend(["## Analysis", "", str(finding["analysis"]), ""])

    if finding.get("package"):
        lines.extend(
            [
                "## Supply Chain Context",
                "",
                f"- Ecosystem: {finding.get('ecosystem', 'unknown')}",
                f"- Package: {finding.get('package')}",
                f"- Old Version: {finding.get('old_version', 'unknown')}",
                f"- New Version: {finding.get('new_version', 'unknown')}",
                f"- Report Path: {finding.get('report_path', 'unknown')}",
                "",
            ]
        )

    if finding.get("event_ids"):
        lines.extend(["## Event IDs", ""])
        for event_id in finding.get("event_ids", []):
            lines.append(f"- {event_id}")
        lines.append("")

    lines.extend(
        [
            "## Suggested Workflow",
            "",
            f"1. Inspect the finding with `secopsai show {finding.get('finding_id')}`.",
            "2. Confirm impact, affected asset or package, and whether remediation is code, config, or triage.",
            "3. If code changes are needed, implement and test them in a branch/worktree.",
            "4. Update triage in SecOpsAI after remediation or false-positive review.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_briefs(findings: Iterable[Dict[str, Any]], findings_dir: Path) -> Dict[str, Path]:
    findings_dir.mkdir(parents=True, exist_ok=True)
    out: Dict[str, Path] = {}
    for finding in findings:
        filename = f"{_slug(str(finding.get('finding_id', 'finding')))}.md"
        path = findings_dir / filename
        path.write_text(_finding_brief(finding), encoding="utf-8")
        out[str(finding.get("finding_id"))] = path
    return out


def _yaml_quote(text: str) -> str:
    return json.dumps(str(text))


def _render_plan(findings: List[Dict[str, Any]], brief_paths: Dict[str, Path], plan_path: Path) -> str:
    rel_context = sorted(str(path.relative_to(ROOT)) for path in brief_paths.values())
    lines = [
        'name: "SecOpsAI Remediation Queue"',
        'description: >',
        '  Investigate and remediate the highest-priority SecOpsAI findings exported',
        '  from the local SOC store. Treat SecOpsAI as the source of truth for findings',
        '  and use this plan to execute remediation tasks in Bernstein.',
        "",
        'cli: auto',
        'max_agents: 4',
        'budget: "$20"',
        'constraints:',
        '  - "Use secopsai show <finding_id> before deciding on remediation."',
        '  - "Preserve evidence and analyst notes; do not mutate SecOpsAI data directly except through supported workflows."',
        '  - "Run targeted tests for any code change."',
        'context_files:',
    ]
    for rel_path in rel_context:
        lines.append(f"  - {_yaml_quote(rel_path)}")

    lines.extend(["", "stages:", '  - name: "Investigate Findings"', "    steps:"])

    for finding in findings:
        fid = str(finding.get("finding_id"))
        severity = str(finding.get("severity", "unknown")).lower()
        rel_brief = brief_paths[fid].relative_to(ROOT)
        title = f"{finding.get('finding_id')} | {finding.get('title', 'Untitled finding')}"
        description = (
            f"Investigate {fid}. Read {rel_brief}. Confirm whether the finding is valid, "
            "identify impacted code, dependencies, or infrastructure, and produce either a remediation patch "
            "or a false-positive assessment with evidence."
        )
        lines.extend(
            [
                f"      - title: {_yaml_quote(title)}",
                f"        description: >",
                f"          {description}",
                f"        role: {_role_for_finding(finding)}",
                f"        scope: {_scope_for_finding(finding)}",
                f"        complexity: {_complexity_for_finding(finding)}",
                "        completion_signals:",
                "          - type: path_exists",
                f"            path: {_yaml_quote(str(rel_brief))}",
            ]
        )
        if severity in {"critical", "high"}:
            lines.extend(
                [
                    "          - type: file_contains",
                    f"            path: {_yaml_quote(str(rel_brief))}",
                    f"            contains: {_yaml_quote(fid)}",
                ]
            )

    lines.extend(
        [
            '  - name: "Verification and Triage"',
            '    depends_on: ["Investigate Findings"]',
            "    steps:",
            '      - title: "Validate remediation output and update SecOpsAI triage"',
            "        description: >",
            "          Review completed remediation work, run any required verification, and update the",
            "          corresponding finding status or disposition in SecOpsAI using the supported CLI.",
            "        role: qa",
            "        scope: medium",
            "        complexity: medium",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    rows = soc_store.list_findings(args.db_path)
    selected_rows = [row for row in rows if _include_row(row, args.severity, args.status)]
    selected_rows = sorted(
        selected_rows,
        key=lambda row: (
            SEVERITY_PRIORITY.get(str(row.get("severity", "")).lower(), 99),
            str(row.get("first_seen", "")),
        ),
    )[: args.limit]

    findings = []
    for row in selected_rows:
        finding = soc_store.get_finding(str(row["finding_id"]), args.db_path)
        if finding:
            findings.append(finding)

    findings_dir = Path(args.findings_dir).resolve()
    plan_path = Path(args.output_plan).resolve()
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    brief_paths = _write_briefs(findings, findings_dir)
    plan_text = _render_plan(findings, brief_paths, plan_path)
    plan_path.write_text(plan_text, encoding="utf-8")

    summary = {
        "exported_findings": len(findings),
        "plan_path": str(plan_path),
        "findings_dir": str(findings_dir),
        "finding_ids": [finding["finding_id"] for finding in findings],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
