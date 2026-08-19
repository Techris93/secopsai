#!/usr/bin/env python3
"""Fail CI only for HIGH/CRITICAL Grype matches that have an available fix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


HIGH_SEVERITIES = {"High", "Critical", "HIGH", "CRITICAL"}


def has_available_fix(vulnerability: dict[str, Any]) -> bool:
    fix = vulnerability.get("fix") or {}
    versions = [str(item).strip() for item in (fix.get("versions") or []) if str(item).strip()]
    if versions:
        return True
    return str(fix.get("state") or "").strip().lower() == "fixed"


def collect_blocking_findings(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for match in report.get("matches") or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        if vulnerability.get("severity") not in HIGH_SEVERITIES:
            continue
        if not has_available_fix(vulnerability):
            continue
        failures.append(
            f"{vulnerability.get('id')} {artifact.get('name')}@{artifact.get('version')} "
            f"path={artifact.get('locations') or []}"
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("container-security/grype-results.json"),
    )
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    failures = collect_blocking_findings(report)
    if failures:
        print("\n".join(f"::error title=Grype container vulnerability::{item}" for item in failures))
        raise SystemExit(f"Grype found {len(failures)} HIGH/CRITICAL vulnerabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
