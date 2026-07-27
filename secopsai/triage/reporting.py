from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_DIR = ROOT / "reports" / "triage"


def _slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip())
    return value.strip("-").lower() or "finding"


def report_paths(finding_id: str, report_dir: Path | None = None) -> tuple[Path, Path]:
    base_dir = (report_dir or DEFAULT_REPORT_DIR).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    stem = _slug(finding_id)
    return base_dir / f"{stem}.json", base_dir / f"{stem}.md"


def _render_list(items: Iterable[str]) -> list[str]:
    return [f"- {item}" for item in items if str(item or "").strip()]


def write_report(result: Dict[str, Any], report_dir: Path | None = None) -> Dict[str, str]:
    finding_id = str(result.get("finding", {}).get("finding_id") or result.get("finding_id") or "finding")
    json_path, md_path = report_paths(finding_id, report_dir)
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    finding = result.get("finding", {})
    investigation = result.get("investigation", {})
    lines = [
        f"# {finding.get('finding_id', finding_id)}",
        "",
        f"- Title: {finding.get('title', 'Unknown')}",
        f"- Severity: {finding.get('severity', 'unknown')}",
        f"- Status: {finding.get('status', 'unknown')}",
        f"- Disposition: {finding.get('disposition', 'unknown')}",
        f"- Category: {result.get('category', 'unknown')}",
        f"- Suggested Disposition: {investigation.get('recommended_disposition', 'needs_review')}",
        f"- Confidence: {investigation.get('confidence', 'unknown')}",
        "",
        "## Summary",
        "",
        str(investigation.get("summary") or finding.get("summary") or "No summary available."),
        "",
        "## Evidence",
        "",
    ]
    lines.extend(_render_list(investigation.get("evidence") or []))
    if lines[-1] != "":
        lines.append("")
    threat = investigation.get("threat_assessment") or {}
    exposure = investigation.get("exposure_assessment") or {}
    if threat:
        lines.extend(
            [
                "## Package Threat Assessment",
                "",
                f"- Verdict: {threat.get('verdict', 'unknown')}",
                f"- Confidence: {threat.get('confidence', 'unknown')}",
                f"- Basis: {threat.get('basis', 'No basis recorded.')}",
                "",
            ]
        )
    if exposure:
        lines.extend(
            [
                "## Environment Exposure Assessment",
                "",
                f"- Status: {exposure.get('status', 'unknown')}",
                f"- Scope: {exposure.get('scope', 'unknown')}",
            ]
        )
        lines.extend(_render_list(exposure.get("limitations") or []))
        lines.append("")
    lines.extend(
        [
            "## Next Actions",
            "",
        ]
    )
    lines.extend(_render_list(investigation.get("next_actions") or []))
    lines.append("")
    links = investigation.get("external_links") or {}
    if links:
        lines.extend(["## External Links", ""])
        for label, url in links.items():
            if str(url or "").strip():
                lines.append(f"- {label}: {url}")
        lines.append("")
    md_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return {"json_report": str(json_path), "markdown_report": str(md_path)}
