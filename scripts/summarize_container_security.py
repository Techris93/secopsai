#!/usr/bin/env python3
"""Normalize Trivy JSON into a concise, auditable container security report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "secopsai.container-security-evidence.v1"


def summarize(report: dict[str, Any], *, image_digest: str, trivy_version: str, database_metadata: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for vulnerability in result.get("Vulnerabilities") or []:
            layer = vulnerability.get("Layer") or {}
            identifier = vulnerability.get("PkgIdentifier") or {}
            finding = {
                "vulnerability_id": vulnerability.get("VulnerabilityID", ""),
                "severity": vulnerability.get("Severity", "UNKNOWN"),
                "package_name": vulnerability.get("PkgName", ""),
                "installed_version": vulnerability.get("InstalledVersion", ""),
                "fixed_version": vulnerability.get("FixedVersion", ""),
                "package_path": vulnerability.get("PkgPath", ""),
                "package_identifier": identifier.get("PURL", "") if isinstance(identifier, dict) else str(identifier),
                "target": target,
                "class": result.get("Class", ""),
                "type": result.get("Type", ""),
                "layer_digest": layer.get("Digest", ""),
                "layer_diff_id": layer.get("DiffID", ""),
                "data_source": vulnerability.get("DataSource") or {},
                "dependency_relationship": vulnerability.get("Relationship", ""),
            }
            findings.append(finding)
    findings.sort(key=lambda item: (item["severity"], item["package_name"], item["vulnerability_id"], item["package_path"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_name": report.get("ArtifactName", ""),
        "artifact_type": report.get("ArtifactType", ""),
        "image_digest": image_digest,
        "trivy_version": trivy_version,
        "vulnerability_database": database_metadata,
        "finding_count": len(findings),
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-digest", default="")
    parser.add_argument("--trivy-version", default="")
    parser.add_argument("--db-metadata", type=Path)
    parser.add_argument("--gate", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    database_metadata = {}
    if args.db_metadata and args.db_metadata.exists():
        database_metadata = json.loads(args.db_metadata.read_text(encoding="utf-8"))
    payload = summarize(
        report,
        image_digest=args.image_digest,
        trivy_version=args.trivy_version,
        database_metadata=database_metadata,
    )
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    high_or_critical = [finding for finding in payload["findings"] if finding["severity"] in {"HIGH", "CRITICAL"}]
    for finding in high_or_critical:
        print(
            "::error title=Container vulnerability::"
            f"{finding['vulnerability_id']} affects {finding['package_name']}@{finding['installed_version']} "
            f"at {finding['package_path'] or finding['target']} layer={finding['layer_digest'] or 'unknown'} "
            f"fixed={finding['fixed_version'] or 'unavailable'}"
        )
    return 1 if args.gate and high_or_critical else 0


if __name__ == "__main__":
    raise SystemExit(main())
