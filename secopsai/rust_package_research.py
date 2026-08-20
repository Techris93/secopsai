"""Approval-gated, source-first Rust package research orchestration.

This module composes the existing bounded registry intake, Artifact Fleet
static scanner, Research Case ledger, and Intelligence bridge. It never runs
Cargo, build scripts, package imports, binaries, or downloaded payloads.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import soc_store

from secopsai.artifact_fleet import DEFAULT_DB_PATH as DEFAULT_ARTIFACT_DB_PATH
from secopsai.artifact_fleet import enqueue_model_triage, scan_artifact
from secopsai.research_analysis import compare_intakes
from secopsai.research_cases import (
    add_evidence,
    add_ioc,
    create_case,
    draft_case_blog,
    get_case,
    link_finding,
    publication_readiness,
)
from secopsai.research_workflow import build_evidence_matrix
from secopsai.research_intake import (
    IntakeError,
    SafeFetcher,
    attach_intake_result,
    collect_package_intake,
    preview_package,
)


RUST_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:_~!*/-]{0,159}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
CRATES_SOURCE_HOSTS = {"crates.io", "www.crates.io"}
REFERENCE_HOSTS = {
    "crates.io", "static.crates.io", "github.com", "docs.rs", "doc.rust-lang.org",
    "rust-lang.org", "img.shields.io", "apache.org",
}
KNOWN_TLDS = {
    "com", "net", "org", "info", "io", "co", "ru", "cn", "xyz", "site", "dev", "app",
    "online", "top", "biz", "me", "tv", "ai", "cloud", "pro", "tech", "live", "store",
    "pw", "cc", "link", "mobi", "name", "su", "eu", "uk", "de", "fr", "ca", "au",
}
STRONG_RULE_IDS = {
    "OSS-DOWNLOAD-EXECUTE", "OSS-CREDENTIAL-DISCOVERY", "OSS-POWERSHELL-STAGING",
    "OSS-WINDOWS-PERSISTENCE", "OSS-BROWSER-DATA", "OSS-C2-DGA", "OSS-C2-IP-PORT",
    "OSS-RUST-PROC-MACRO",
}
MAX_EVIDENCE_ITEMS = 100


def _text(value: Any, limit: int = 4096) -> str:
    text = str(value or "").strip()
    if "\x00" in text or len(text) > limit:
        raise ValueError("value contains invalid characters or exceeds its limit")
    return text


def _package(value: Any) -> str:
    package = _text(value, 128)
    if not RUST_PACKAGE_RE.fullmatch(package):
        raise ValueError("Rust package name is invalid")
    return package


def _version(value: Any) -> str:
    version = _text(value, 160)
    if not VERSION_RE.fullmatch(version):
        raise ValueError("Rust package version is invalid")
    return version


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _artifact_db_path(value: str | Path | None = None) -> str:
    return str(Path(value or os.environ.get("SECOPSAI_ARTIFACT_FLEET_DB_PATH") or DEFAULT_ARTIFACT_DB_PATH).expanduser().resolve())


def _source_repository(metadata: dict[str, Any]) -> str:
    value = str(metadata.get("source_repository") or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or parsed.hostname not in {"github.com", "gitlab.com"}:
        return value[:1000]
    return value[:1000]


def _validate_crates_metadata(metadata: dict[str, Any], package: str, version: str) -> None:
    if metadata.get("package") != package or metadata.get("version") != version:
        raise IntakeError("crates.io returned metadata for a different package or version")
    metadata_url = str(metadata.get("metadata_url") or "")
    artifact_url = str(metadata.get("artifact_url") or "")
    metadata_host = (urlsplit(metadata_url).hostname or "").lower()
    artifact_host = (urlsplit(artifact_url).hostname or "").lower()
    if metadata_host not in CRATES_SOURCE_HOSTS:
        raise IntakeError("metadata URL is outside the crates.io allowlist")
    if artifact_host not in {"crates.io", "static.crates.io"}:
        raise IntakeError("artifact URL is outside the crates.io allowlist")
    if urlsplit(metadata_url).scheme != "https" or urlsplit(artifact_url).scheme != "https":
        raise IntakeError("crates.io URLs must use HTTPS")
    repository = str(metadata.get("source_repository") or "").strip()
    if repository:
        parsed_repository = urlsplit(repository)
        if parsed_repository.scheme != "https" or parsed_repository.username or parsed_repository.password or not parsed_repository.hostname:
            raise IntakeError("crate source repository must be a credential-free HTTPS URL")


def _verify_checksum(result: dict[str, Any]) -> None:
    metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
    integrity = metadata.get("integrity") if isinstance(metadata.get("integrity"), dict) else {}
    expected = str(integrity.get("checksum") or "").strip().lower()
    actual = str(metadata.get("artifact_sha256") or "").strip().lower()
    if expected and (not SHA256_RE.fullmatch(expected) or expected != actual):
        raise IntakeError("crates.io checksum does not match the downloaded artifact")
    if not SHA256_RE.fullmatch(actual):
        raise IntakeError("downloaded artifact did not produce a valid SHA-256")


def _case_key(package: str, version: str, artifact_sha256: str, source_revision: str) -> str:
    value = f"crates:{package.lower()}:{version}:{artifact_sha256.lower()}:{source_revision}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _find_case(case_key: str, *, db_path: str | None = None) -> str | None:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT case_id, payload_json FROM research_cases ORDER BY updated_at DESC").fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("rust_package_research_key") == case_key:
            return str(row["case_id"])
    return None


def _latest_evidence_id(case: dict[str, Any], title: str) -> str | None:
    for item in reversed(case.get("evidence") or []):
        if item.get("title") == title and item.get("status", "active") == "active":
            return str(item.get("evidence_id"))
    return None


def _evidence_ids(case: dict[str, Any], title_prefix: str) -> list[str]:
    return [
        str(item.get("evidence_id"))
        for item in case.get("evidence") or []
        if item.get("status", "active") == "active" and str(item.get("title") or "").startswith(title_prefix)
    ]


def _public_iocs(scan: dict[str, Any]) -> list[dict[str, str]]:
    iocs = scan.get("iocs") if isinstance(scan.get("iocs"), dict) else {}
    output: list[dict[str, str]] = []
    for value in iocs.get("urls") or []:
        value = str(value).strip()
        host = (urlsplit(value).hostname or "").lower()
        if urlsplit(value).scheme == "https" and host and host not in REFERENCE_HOSTS:
            output.append({"ioc_type": "url", "value": value})
    for value in iocs.get("ips") or []:
        value = str(value).split(":", 1)[0].strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global:
            output.append({"ioc_type": "ipv4" if address.version == 4 else "ipv6", "value": value})
    for value in iocs.get("domains") or []:
        value = str(value).strip().lower().rstrip(".")
        labels = value.split(".")
        tld = labels[-1] if labels else ""
        if (
            len(labels) >= 2
            and all(re.fullmatch(r"[a-z0-9-]{1,63}", label or "") for label in labels)
            and tld in KNOWN_TLDS
            and not any(value == host or value.endswith(f".{host}") for host in REFERENCE_HOSTS)
        ):
            output.append({"ioc_type": "domain", "value": value})
    for value in iocs.get("hashes") or []:
        value = str(value).strip().lower()
        if SHA256_RE.fullmatch(value):
            output.append({"ioc_type": "sha256", "value": value})
    unique: dict[tuple[str, str], dict[str, str]] = {}
    for item in output:
        unique[(item["ioc_type"], item["value"])] = item
    return list(unique.values())[:MAX_EVIDENCE_ITEMS]


def _finding_from_scan(scan: dict[str, Any], *, source_reference: str = "") -> dict[str, Any]:
    package = str(scan.get("package") or "")
    version = str(scan.get("version") or "")
    token = f"crates:{package.lower()}:{version}:{scan.get('sha256')}"
    finding_id = "SCM-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16].upper()
    findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []
    high_count = sum(1 for item in findings if str(item.get("severity") or "").lower() in {"high", "critical"})
    return {
        "finding_id": finding_id,
        "title": f"Suspicious crates package release: {package}@{version}",
        "summary": "Static Artifact Fleet analysis identified suspicious Rust package behavior; no package code was executed.",
        "severity": "critical" if high_count else "high",
        "severity_score": 98 if high_count else 85,
        "status": "open",
        "disposition": "unreviewed",
        "first_seen": soc_store.utc_now(),
        "last_seen": soc_store.utc_now(),
        "event_ids": [f"rust-package-research:{package}:{version}"],
        "rule_ids": sorted({str(item.get("rule_id")) for item in findings if item.get("rule_id")}),
        "platform": "supply_chain",
        "source": "secopsai-rust-package-research",
        "ecosystem": "crates",
        "package": package,
        "new_version": version,
        "confidence": "high" if high_count else "medium",
        "analysis": " ".join(str(item.get("matched_indicator") or "") for item in findings[:20]).strip(),
        "artifact_urls": [source_reference] if source_reference else [],
        "matched_rules": findings[:100],
        "supply_chain_metadata": {"artifact_id": scan.get("artifact_id"), "sha256": scan.get("sha256"), "execution_performed": False},
        "iocs": [scan.get("iocs") or {}],
        "remediation": [["Quarantine the package, block the exact version, inspect CI/build logs, and rotate credentials if installation or execution is confirmed."]],
    }


def _high_confidence_scan(scan: dict[str, Any]) -> bool:
    findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []
    return any(str(item.get("rule_id") or "") in STRONG_RULE_IDS for item in findings)


def _persist_finding(finding: dict[str, Any], *, db_path: str | None = None) -> str:
    soc_store.init_db(db_path)
    from secopsai.sqlite_writer_lock import sqlite_writer_lock

    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            soc_store.upsert_finding(connection, finding, source=finding.get("source") or "secopsai-rust-package-research")
            connection.commit()
    return str(finding["finding_id"])


def run_rust_package_research(
    *,
    package: str,
    version: str,
    compare_package: str = "",
    compare_version: str = "",
    case_id: str = "",
    source_reference: str = "",
    owner: str = "SecOpsAI Research",
    model: str = "",
    persist_findings: bool = False,
    draft_blog: bool = False,
    create_research_case: bool = True,
    dry_run: bool = False,
    db_path: str | None = None,
    artifact_db_path: str | Path | None = None,
    actor: str = "operator",
    fetcher: SafeFetcher | None = None,
) -> dict[str, Any]:
    package = _package(package)
    version = _version(version)
    compare_package = _package(compare_package) if compare_package else ""
    compare_version = _version(compare_version) if compare_version else ""
    source_reference = _text(source_reference, 4000)
    if source_reference:
        parsed_source = urlsplit(source_reference)
        if parsed_source.scheme != "https" or parsed_source.username or parsed_source.password or not parsed_source.hostname:
            raise ValueError("source_reference must be a credential-free HTTPS URL")
    if dry_run:
        primary = preview_package(ecosystem="crates", package=package, version=version, fetcher=fetcher)
        comparison = preview_package(ecosystem="crates", package=compare_package, version=compare_version, fetcher=fetcher) if compare_package else None
        _validate_crates_metadata(primary["metadata"], package, primary["metadata"]["version"])
        if comparison:
            _validate_crates_metadata(comparison["metadata"], compare_package, comparison["metadata"]["version"])
        return {"ok": True, "dry_run": True, "metadata": primary["metadata"], "comparison_metadata": comparison.get("metadata") if comparison else None, "safety": {"execution_performed": False, "downloaded": False}, "next_action": "run_without_dry_run_after_review"}

    intake = collect_package_intake(ecosystem="crates", package=package, version=version, fetcher=fetcher)
    _validate_crates_metadata(intake["metadata"], package, version)
    _verify_checksum(intake)
    artifact_path = str((intake.get("quarantine") or {}).get("path") or "")
    if not artifact_path or not Path(artifact_path).is_file():
        raise IntakeError("quarantined Rust artifact path is unavailable")
    artifact_db = _artifact_db_path(artifact_db_path)
    scan = scan_artifact(ecosystem="crates", package=package, version=version, artifact=artifact_path, source_reference=source_reference or intake["metadata"].get("metadata_url", ""), db_path=artifact_db)
    comparison_intake = None
    comparison_result = None
    if compare_package:
        comparison_intake = collect_package_intake(ecosystem="crates", package=compare_package, version=compare_version, fetcher=fetcher)
        _validate_crates_metadata(comparison_intake["metadata"], compare_package, comparison_intake["metadata"]["version"])
        _verify_checksum(comparison_intake)
        comparison_result = compare_intakes(intake, comparison_intake, db_path=db_path)

    finding = _finding_from_scan(scan, source_reference=source_reference)
    case_key = _case_key(package, version, str(intake["metadata"]["artifact_sha256"]), str(intake["metadata"].get("source_repository") or intake["metadata"].get("artifact_url") or ""))
    resolved_case_id = _text(case_id, 32).upper() if case_id else _find_case(case_key, db_path=db_path)
    if resolved_case_id:
        get_case(resolved_case_id, db_path=db_path)
    elif create_research_case and _high_confidence_scan(scan):
        case = create_case(
            title=f"Rust package research: {package}@{version}",
            summary=f"Automated source-first research for {package}@{version}. Static evidence is recorded without executing the crate.",
            case_type="malicious_package",
            severity="critical" if finding["severity"] == "critical" else "high",
            confidence=80 if finding["severity"] == "critical" else 60,
            owner=owner,
            db_path=db_path,
            metadata={"rust_package_research_key": case_key, "artifact_id": scan.get("artifact_id"), "execution_performed": False},
        )
        resolved_case_id = case["case_id"]

    evidence_ids: list[str] = []
    model_job = None
    draft = None
    validated_iocs = _public_iocs(scan)
    evidence_matrix = None
    if resolved_case_id:
        intake["case_id"] = resolved_case_id
        existing_case = get_case(resolved_case_id, db_path=db_path)
        if not _evidence_ids(existing_case, f"{intake['metadata']['ecosystem']} registry metadata: {package}"):
            attached = attach_intake_result(intake, db_path=db_path, actor=actor, metadata_extra={"artifact_fleet_artifact_id": scan.get("artifact_id"), "execution_performed": False})
            evidence_ids.extend(attached.get("evidence_ids") or [])
        else:
            evidence_ids.extend(_evidence_ids(existing_case, f"{intake['metadata']['ecosystem']} registry metadata: {package}"))
        scan_title = f"Artifact Fleet static analysis: {package}@{version}"
        scan_case = get_case(resolved_case_id, db_path=db_path)
        if not _evidence_ids(scan_case, scan_title):
            add_evidence(resolved_case_id, evidence_type="static_analysis", title=scan_title, locator=f"artifact-fleet://{scan.get('artifact_id')}", sha256=str(scan.get("sha256") or ""), provenance="SecOpsAI Artifact Fleet deterministic static rules", notes="No package code was executed; review rule hits, safe contexts, and limitations before making runtime claims.", metadata={"findings": scan.get("findings", [])[:100], "iocs": scan.get("iocs") or {}, "execution_performed": False}, db_path=db_path, actor=actor)
            scan_case = get_case(resolved_case_id, db_path=db_path)
        scan_evidence_id = _latest_evidence_id(scan_case, scan_title)
        if scan_evidence_id:
            evidence_ids.append(scan_evidence_id)
        if source_reference:
            source_title = f"Operator source reference for {package}@{version}"
            if not _evidence_ids(get_case(resolved_case_id, db_path=db_path), source_title):
                add_evidence(resolved_case_id, evidence_type="source", title=source_title, locator=source_reference, provenance="Operator-supplied public source reference", notes="Source context only; source content is not treated as attacker infrastructure.", db_path=db_path, actor=actor)
            scan_case = get_case(resolved_case_id, db_path=db_path)
            source_evidence_id = _latest_evidence_id(scan_case, source_title)
        else:
            source_evidence_id = None
        for item in validated_iocs:
            add_ioc(resolved_case_id, ioc_type=item["ioc_type"], value=item["value"], confidence=85, source_evidence_id=scan_evidence_id or source_evidence_id, tags=["rust-package-static"], db_path=db_path, actor=actor)
        if comparison_result:
            comparison_title = f"Static comparison: {package}@{version} vs {compare_package}@{comparison_intake['metadata']['version']}"
            if not _evidence_ids(get_case(resolved_case_id, db_path=db_path), comparison_title):
                add_evidence(resolved_case_id, evidence_type="static_analysis", title=comparison_title, locator=f"comparison://{comparison_result.get('comparison_id')}", sha256=_sha256_json(comparison_result), provenance="SecOpsAI bounded static package comparison", notes="Comparison does not execute either package and does not prove attribution.", metadata={"comparison": comparison_result}, db_path=db_path, actor=actor)
        if persist_findings and _high_confidence_scan(scan):
            finding_id = _persist_finding(finding, db_path=db_path)
            link_finding(resolved_case_id, finding_id, relationship="supports", db_path=db_path, actor=actor)
        evidence_matrix = build_evidence_matrix(resolved_case_id, persist=True, actor=actor, db_path=db_path)
        if _high_confidence_scan(scan):
            model_job = enqueue_model_triage(scan["artifact_id"], model=model, db_path=artifact_db, job_db_path=db_path, requested_by=actor)
        if draft_blog:
            readiness = publication_readiness(get_case(resolved_case_id, db_path=db_path))
            if readiness["ready"]:
                draft = draft_case_blog(resolved_case_id, db_path=db_path)
            else:
                draft = {"status": "blocked", "publication_readiness": readiness}

    return {
        "ok": True,
        "dry_run": False,
        "package": intake["metadata"],
        "artifact": {"path": artifact_path, "sha256": intake["metadata"]["artifact_sha256"], "artifact_id": scan.get("artifact_id"), "execution_performed": False},
        "scan": {key: scan.get(key) for key in ("artifact_id", "status", "sha256", "findings", "iocs", "execution_performed", "duration_ms")},
        "comparison": comparison_result,
        "comparison_package": comparison_intake["metadata"] if comparison_intake else None,
        "validated_iocs": validated_iocs,
        "rejected_ioc_reasons": ["registry, source, documentation, and non-domain code tokens are excluded from attacker IOC persistence."],
        "case_id": resolved_case_id,
        "case_key": case_key,
        "finding": finding if persist_findings and _high_confidence_scan(scan) else None,
        "evidence_ids": evidence_ids,
        "evidence_matrix": evidence_matrix,
        "model_job": model_job,
        "draft": draft,
        "blockers": (draft or {}).get("publication_readiness", {}).get("blockers", []) if isinstance(draft, dict) else [],
        "next_action": "review_static_evidence_and_model_queue" if _high_confidence_scan(scan) else "review_expected_build_behavior_or_close_as_not_substantiated",
        "safety": {"execution_performed": False, "raw_artifact_sent_to_ai": False, "sandbox_submitted": False, "auto_publish": False},
    }
