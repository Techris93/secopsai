#!/usr/bin/env python3
"""Create a blog draft from a SecOpsAI emergency advisory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable

ROOT = Path(__file__).resolve().parents[1]
ADVISORIES_DIR = ROOT / "data" / "advisories"
BLOG_DRAFTS_DIR = ROOT / "blog" / "drafts"


def iter_advisories() -> Iterable[Dict[str, Any]]:
    for path in sorted(ADVISORIES_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            yield from (item for item in payload if isinstance(item, dict))
        elif isinstance(payload, dict):
            yield payload


def find_advisory(campaign: str) -> Dict[str, Any]:
    for advisory in iter_advisories():
        if campaign in {advisory.get("campaign_id"), advisory.get("advisory_id")}:
            return advisory
    raise SystemExit(f"No advisory found for campaign/advisory id: {campaign}")


def affected_table(advisory: Dict[str, Any]) -> str:
    rows = ["| Ecosystem | Package | Versions |", "|---|---|---|"]
    for item in advisory.get("affected", []):
        versions = ", ".join(str(version) for version in item.get("versions", []))
        ranges = ", ".join(json.dumps(spec, sort_keys=True) for spec in item.get("version_ranges", []))
        rows.append(f"| {item.get('ecosystem', '')} | `{item.get('package', '')}` | {versions or ranges} |")
    return "\n".join(rows)


def bullet_list(items: Iterable[Any]) -> str:
    return "\n".join(f"- {item}" for item in items) or "- Pending analyst detail"


def render_draft(advisory: Dict[str, Any]) -> str:
    iocs = advisory.get("iocs", {})
    ioc_lines = []
    for key, values in iocs.items():
        if values:
            ioc_lines.append(f"- {key}: {', '.join(str(value) for value in values)}")
    sources = advisory.get("source_urls", [])
    return f"""# {advisory.get('title', 'SecOpsAI advisory')}

Severity: {advisory.get('severity', 'unknown')}
Confidence: {advisory.get('confidence', 'unknown')}
Campaign: {advisory.get('campaign_id', 'unknown')}
Updated: {advisory.get('updated_at', 'unknown')}

## Executive Summary

{advisory.get('summary', 'Add concise executive summary.')}

## Affected Artifacts

{affected_table(advisory)}

## Detection Rationale

{bullet_list(advisory.get('detection_rationale', []))}

## IOCs

{chr(10).join(ioc_lines) if ioc_lines else '- Pending IOCs'}

## Recommended Actions

{bullet_list(advisory.get('remediation', []))}

## SecOpsAI Commands

```bash
secopsai supply-chain advisory list
secopsai supply-chain reconcile-history --include-advisories
```

## References

{bullet_list(sources)}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True, help="Campaign id or advisory id")
    parser.add_argument("--output", help="Override output path")
    args = parser.parse_args()

    advisory = find_advisory(args.campaign)
    BLOG_DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    target = Path(args.output) if args.output else BLOG_DRAFTS_DIR / f"{args.campaign}.md"
    target.write_text(render_draft(advisory), encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
