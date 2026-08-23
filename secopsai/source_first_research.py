"""Universal source-first, static-only security research orchestration.

This module is the canonical package/artifact research entry point.  Registry
adapters and Artifact Fleet remain the implementation details; callers receive
one normalized result regardless of ecosystem.  Nothing in this module
installs, imports, activates, or executes an artifact.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import soc_store

from secopsai.artifact_fleet import DEFAULT_DB_PATH as DEFAULT_ARTIFACT_DB_PATH
from secopsai.artifact_fleet import enqueue_model_triage, scan_artifact
from secopsai.research_analysis import compare_intakes
from secopsai.research_cases import (
    add_evidence,
    add_ioc,
    add_subject,
    create_case,
    draft_case_blog,
    get_case,
    link_finding,
    publication_readiness,
)
from secopsai.research_intake import (
    ADAPTERS,
    IntakeError,
    SafeFetcher,
    attach_intake_result,
    collect_package_intake,
    inspect_archive,
    preview_package,
)
from secopsai.research_workflow import build_evidence_matrix


ECOSYSTEM_ALIASES = {
    "crate": "crates",
    "crates.io": "crates",
    "rust": "crates",
    "composer": "packagist",
    "packagist.org": "packagist",
    "pypi.org": "pypi",
    "python": "pypi",
    "golang": "go",
    "gomod": "go",
    "go-modules": "go",
    "maven-central": "maven",
    "gem": "rubygems",
    "rubygems.org": "rubygems",
    "vscode": "open-vsx",
    "vs-code": "open-vsx",
    "openvsx": "open-vsx",
    "hugging-face": "huggingface",
    "hf": "huggingface",
    "github-repository": "github",
    "github-repo": "github",
    "repo": "github",
    "container-image": "container",
    "oci": "container",
}

SUPPORTED_ECOSYSTEMS = tuple(sorted(set(ADAPTERS) | {
    "container", "github", "huggingface", "chrome-web-store",
}))

RESEARCH_TYPES = (
    "malicious_package", "package_compromise", "typosquatting",
    "dependency_confusion", "slopsquatting", "lifecycle_behavior",
    "vulnerability_advisory", "github_token_breach", "extension_compromise",
    "credential_theft", "malware_apt_c2", "cloud_kubernetes_abuse",
    "cross_ecosystem_campaign", "general_threat_intel", "package_artifact",
)

CASE_TYPE_BY_RESEARCH = {
    "malicious_package": "malicious_package",
    "package_compromise": "malicious_package",
    "typosquatting": "typosquatting",
    "dependency_confusion": "dependency_confusion",
    "slopsquatting": "dependency_confusion",
    "vulnerability_advisory": "vulnerability_research",
    "credential_theft": "credential_theft",
    "malware_apt_c2": "malware",
    "cloud_kubernetes_abuse": "infrastructure_cluster",
    "cross_ecosystem_campaign": "supply_chain_campaign",
    "extension_compromise": "malicious_package",
}

REFERENCE_HOSTS = {
    "npmjs.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "crates.io", "static.crates.io", "packagist.org", "repo.packagist.org",
    "proxy.golang.org", "repo.maven.apache.org", "repo1.maven.org",
    "nuget.org", "api.nuget.org", "rubygems.org", "open-vsx.org",
    "github.com", "api.github.com", "huggingface.co", "docs.rs",
}
KNOWN_TLDS = {
    "com", "net", "org", "info", "io", "co", "ru", "cn", "xyz", "site",
    "dev", "app", "online", "top", "biz", "me", "tv", "ai", "cloud",
    "pro", "tech", "live", "store", "pw", "cc", "link", "mobi", "name",
    "su", "eu", "uk", "de", "fr", "ca", "au",
}
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9@._:/+\-]{1,512}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9.+:_~!*/\-]{1,160}$")
CASE_ID_RE = re.compile(r"^RSC-[A-F0-9]{12}$")


def normalize_ecosystem(value: Any) -> str:
    key = str(value or "").strip().lower()
    return ECOSYSTEM_ALIASES.get(key, key)


def _text(value: Any, limit: int = 4096) -> str:
    text = str(value or "").strip()
    if "\x00" in text or len(text) > limit:
        raise ValueError("value contains invalid characters or exceeds its limit")
    return text


def _package(value: Any) -> str:
    value = _text(value, 512)
    if not value or not PACKAGE_RE.fullmatch(value) or ".." in value or "\\" in value:
        raise ValueError("package or artifact identifier is invalid")
    return value


def _version(value: Any) -> str:
    value = _text(value, 160)
    if value and not VERSION_RE.fullmatch(value):
        raise ValueError("version or revision is invalid")
    return value


def _source_url(value: Any) -> str:
    value = _text(value, 4000)
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("source reference must be a credential-free HTTPS URL")
    return value


def _artifact_db_path(value: str | Path | None) -> str:
    return str(Path(value or os.environ.get("SECOPSAI_ARTIFACT_FLEET_DB_PATH") or DEFAULT_ARTIFACT_DB_PATH).expanduser().resolve())


def _case_id(value: Any) -> str:
    value = _text(value, 32).upper()
    if value and not CASE_ID_RE.fullmatch(value):
        raise ValueError("case_id must use the RSC-XXXXXXXXXXXX format")
    return value


def _case_key(ecosystem: str, package: str, version: str, digest: str, source: str) -> str:
    return hashlib.sha256(f"{ecosystem}:{package.lower()}:{version}:{digest}:{source}".encode()).hexdigest()


def _find_case(key: str, *, db_path: str | None) -> str | None:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT case_id, payload_json FROM research_cases ORDER BY updated_at DESC").fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("source_first_research_key") == key:
            return str(row["case_id"])
    return None


def _high_confidence(scan: dict[str, Any]) -> bool:
    findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []
    return any(str(item.get("severity") or "").lower() in {"high", "critical"} for item in findings)


def _validated_iocs(scan: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    raw = scan.get("iocs") if isinstance(scan.get("iocs"), dict) else {}
    accepted: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []

    def add(kind: str, value: Any) -> None:
        value = str(value or "").strip().lower() if kind == "domain" else str(value or "").strip()
        if not value:
            return
        if kind == "url":
            parsed = urlsplit(value)
            host = (parsed.hostname or "").lower()
            if parsed.scheme != "https" or not host or any(host == ref or host.endswith("." + ref) for ref in REFERENCE_HOSTS):
                rejected.append({"value": value, "reason": "source or non-HTTPS reference"})
                return
        elif kind == "domain":
            labels = value.rstrip(".").split(".")
            if len(labels) < 2 or labels[-1] not in KNOWN_TLDS or any(value == ref or value.endswith("." + ref) for ref in REFERENCE_HOSTS):
                rejected.append({"value": value, "reason": "registry or source domain"})
                return
        elif kind in {"ipv4", "ipv6"}:
            candidate = value
            host = value
            if kind == "ipv4" and value.count(":") == 1 and "." in value:
                host, port = value.rsplit(":", 1)
                if not port.isdigit() or not 1 <= int(port) <= 65535:
                    rejected.append({"value": value, "reason": "invalid port"})
                    return
            try:
                if not ipaddress.ip_address(host).is_global:
                    rejected.append({"value": value, "reason": "non-public address"})
                    return
            except ValueError:
                rejected.append({"value": value, "reason": "invalid IP address"})
                return
            value = candidate
        elif kind == "sha256" and not SHA256_RE.fullmatch(value):
            rejected.append({"value": value, "reason": "invalid SHA-256"})
            return
        accepted.append({"ioc_type": kind, "value": value})

    for value in raw.get("urls") or []:
        add("url", value)
    for value in raw.get("domains") or []:
        add("domain", value)
    for value in raw.get("ips") or []:
        # Artifact Fleet emits bare addresses. Keep IPv6 intact; splitting on
        # a colon would turn a valid address into an invalid partial IOC.
        address = str(value or "").strip()
        kind = "ipv4" if ":" not in address or (address.count(":") == 1 and "." in address) else "ipv6"
        add(kind, address)
    for value in raw.get("hashes") or []:
        add("sha256", value)
    unique = {(item["ioc_type"], item["value"]): item for item in accepted}
    return list(unique.values())[:100], rejected[:100]


def _finding(scan: dict[str, Any], ecosystem: str, package: str, version: str, source_reference: str) -> dict[str, Any]:
    findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []
    high = _high_confidence(scan)
    fid = "SCM-" + hashlib.sha256(f"{ecosystem}:{package}:{version}:{scan.get('sha256')}".encode()).hexdigest()[:16].upper()
    return {
        "finding_id": fid,
        "title": f"Suspicious {ecosystem} artifact: {package}@{version}",
        "summary": "Static Artifact Fleet analysis identified suspicious artifact behavior; no package code was executed.",
        "severity": "critical" if any(str(item.get("severity")).lower() == "critical" for item in findings) else ("high" if high else "medium"),
        "severity_score": 98 if high else 60,
        "status": "open", "disposition": "unreviewed",
        "first_seen": soc_store.utc_now(), "last_seen": soc_store.utc_now(),
        "event_ids": [f"source-first-research:{ecosystem}:{package}:{version}"],
        "rule_ids": sorted({str(item.get("rule_id")) for item in findings if item.get("rule_id")}),
        "platform": "supply_chain", "source": "secopsai-source-first-research",
        "ecosystem": ecosystem, "package": package, "new_version": version,
        "confidence": "high" if high else "medium",
        "analysis": " ".join(str(item.get("matched_indicator") or "") for item in findings[:20]).strip(),
        "artifact_urls": [source_reference] if source_reference else [],
        "matched_rules": findings[:100],
        "supply_chain_metadata": {"artifact_id": scan.get("artifact_id"), "sha256": scan.get("sha256"), "execution_performed": False},
        "iocs": [scan.get("iocs") or {}],
        "remediation": [["Quarantine the artifact, block the exact version, inspect build/import logs, and rotate credentials if installation or execution is confirmed."]],
    }


def _local_usage(*, package: str, version: str, search_root: str = "", lockfile: str = "") -> dict[str, Any]:
    """Check bounded local manifests/lockfiles without importing or executing code."""
    requested = str(search_root or lockfile or "").strip()
    if not requested:
        return {"status": "not_requested", "matches": [], "scanned_files": 0}
    target = Path(lockfile or search_root).expanduser().resolve()
    if not target.exists() or target.is_symlink():
        return {"status": "unavailable", "matches": [], "scanned_files": 0, "reason": "local search path is unavailable"}
    roots = [target] if target.is_file() else [path for path in target.rglob("*") if path.is_file() and not path.is_symlink()]
    ignored = {".git", ".venv", "node_modules", "dist", "build", "site-packages", "__pycache__"}
    package_pattern = re.compile(re.escape(package), re.IGNORECASE)
    version_pattern = re.compile(re.escape(version), re.IGNORECASE) if version else None
    allowed_names = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "pyproject.toml", "poetry.lock", "setup.py", "composer.json", "composer.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "packages.config", "packages.lock.json", "Gemfile", "Gemfile.lock", "Dockerfile"}
    allowed_suffixes = {".json", ".lock", ".toml", ".yaml", ".yml", ".txt", ".xml", ".mod", ".sum", ".gemspec"}
    matches: list[dict[str, Any]] = []
    scanned = 0
    total_bytes = 0
    for path in roots:
        if scanned >= 500 or total_bytes >= 25 * 1024 * 1024:
            break
        try:
            relative_parts = set(path.relative_to(target if target.is_dir() else path.parent).parts)
            if relative_parts.intersection(ignored):
                continue
            if path.name not in allowed_names and path.suffix.lower() not in allowed_suffixes:
                continue
            size = path.stat().st_size
            if size > 2 * 1024 * 1024:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeError, ValueError):
            continue
        scanned += 1
        total_bytes += size
        if not package_pattern.search(text):
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if not package_pattern.search(line):
                continue
            matches.append({"path": str(path), "line": line_number, "summary": " ".join(line.split())[:400], "version_present": bool(version_pattern and version_pattern.search(text))})
            if len(matches) >= 50:
                break
        if len(matches) >= 50:
            break
    return {"status": "confirmed" if matches else "not_found", "matches": matches, "scanned_files": scanned}


def _persist_finding(finding: dict[str, Any], *, db_path: str | None) -> None:
    from secopsai.sqlite_writer_lock import sqlite_writer_lock
    soc_store.init_db(db_path)
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            soc_store.upsert_finding(connection, finding, source=finding.get("source") or "secopsai-source-first-research")
            connection.commit()


def _local_scan(*, ecosystem: str, package: str, version: str, artifact: str, source_reference: str, artifact_db_path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    path = Path(artifact).expanduser().resolve()
    if not path.is_file() or path.is_symlink():
        raise ValueError("artifact must be an existing regular file")
    scan = scan_artifact(ecosystem=ecosystem, package=package, version=version, artifact=path, source_reference=source_reference, db_path=artifact_db_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    raw_artifact = path.read_bytes()
    try:
        analysis = inspect_archive(raw_artifact, path.name)
    except IntakeError:
        # Binary artifacts are still safely hashed and scanned by Artifact
        # Fleet. Archive-only inspection is optional evidence, not a reason to
        # discard a PE/ELF/Mach-O result or force execution.
        analysis = {
            "filename": path.name,
            "archive_type": "binary",
            "member_count": 1,
            "expanded_bytes": len(raw_artifact),
            "members": [{"path": path.name, "bytes": len(raw_artifact), "kind": "binary"}],
            "text_files_inspected": 0,
            "lifecycle_scripts": {},
            "manifest_summary": {},
            "indicators": {},
            "execution_performed": False,
            "extracted_to_filesystem": False,
        }
    metadata = {
        "ecosystem": ecosystem, "package": package, "version": version,
        "metadata_url": "", "artifact_url": "", "artifact_sha256": digest,
        "artifact_bytes": path.stat().st_size, "publisher": "", "published_at": "",
        "source_repository": "", "integrity": {}, "contacts": {},
    }
    intake = {"ok": True, "metadata": metadata, "analysis": analysis, "quarantine": {"artifact_id": digest, "bytes": path.stat().st_size, "path": str(path)}, "safety": {"execution_performed": False, "extracted_to_filesystem": False, "raw_artifact_sent_to_ai": False}}
    return scan, intake


def investigate_package(
    *,
    ecosystem: str,
    package: str,
    version: str = "",
    research_type: str = "package_artifact",
    namespace: str = "",
    source_reference: str = "",
    source_repository: str = "",
    compare_ecosystem: str = "",
    compare_package: str = "",
    compare_version: str = "",
    artifact: str = "",
    search_root: str = "",
    lockfile: str = "",
    case_id: str = "",
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
    ecosystem = normalize_ecosystem(ecosystem)
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        raise ValueError(f"unsupported research ecosystem: {ecosystem}")
    package = _package(package)
    version = _version(version)
    compare_ecosystem = normalize_ecosystem(compare_ecosystem or ecosystem)
    compare_package = _package(compare_package) if compare_package else ""
    compare_version = _version(compare_version) if compare_version else ""
    source_reference = _source_url(source_reference)
    source_repository = _source_url(source_repository) if source_repository else ""
    research_type = _text(research_type or "package_artifact", 80).lower()
    if research_type not in RESEARCH_TYPES:
        raise ValueError(f"unsupported research type: {research_type}")
    case_id = _case_id(case_id)
    if compare_package and not compare_version:
        raise ValueError("comparison version is required with comparison package")
    if dry_run:
        if artifact:
            return {"ok": True, "dry_run": True, "research": {"research_type": research_type, "ecosystem": ecosystem, "package": package, "version": version}, "metadata": None, "safety": {"execution_performed": False, "downloaded": False}, "next_action": "run_without_dry_run_after_review"}
        if ecosystem not in ADAPTERS:
            return {"ok": True, "dry_run": True, "research": {"research_type": research_type, "ecosystem": ecosystem, "package": package, "version": version}, "metadata": {"status": "metadata_only", "message": f"{ecosystem} is metadata-only until a reviewed artifact is supplied."}, "safety": {"execution_performed": False, "downloaded": False}, "next_action": "supply_a_reviewed_artifact_or_source_fixture"}
        primary = preview_package(ecosystem=ecosystem, package=package, version=version, fetcher=fetcher)
        comparison = preview_package(ecosystem=compare_ecosystem, package=compare_package, version=compare_version, fetcher=fetcher) if compare_package else None
        return {"ok": True, "dry_run": True, "research": {"research_type": research_type, "ecosystem": ecosystem, "package": package, "version": version, "namespace": namespace}, "metadata": primary["metadata"], "comparison_metadata": comparison.get("metadata") if comparison else None, "safety": {"execution_performed": False, "downloaded": False}, "next_action": "run_without_dry_run_after_review"}

    artifact_db = _artifact_db_path(artifact_db_path)
    if artifact:
        scan, intake = _local_scan(ecosystem=ecosystem, package=package, version=version, artifact=artifact, source_reference=source_reference, artifact_db_path=artifact_db)
        comparison_intake = None
        comparison_result = None
    else:
        if ecosystem not in ADAPTERS:
            raise IntakeError(f"{ecosystem} metadata is available only; provide --artifact for static research")
        intake = collect_package_intake(ecosystem=ecosystem, package=package, version=version, fetcher=fetcher)
        scan_path = str((intake.get("quarantine") or {}).get("path") or "")
        if not scan_path or not Path(scan_path).is_file():
            raise IntakeError("quarantined artifact path is unavailable")
        scan = scan_artifact(ecosystem=ecosystem, package=package, version=version, artifact=scan_path, source_reference=source_reference or intake["metadata"].get("metadata_url", ""), db_path=artifact_db)
        comparison_intake = None
        comparison_result = None
        if compare_package:
            comparison_intake = collect_package_intake(ecosystem=compare_ecosystem, package=compare_package, version=compare_version, fetcher=fetcher)
            comparison_result = compare_intakes(intake, comparison_intake, db_path=db_path)

    local_usage = _local_usage(package=package, version=version, search_root=search_root, lockfile=lockfile)
    finding = _finding(scan, ecosystem, package, version, source_reference)
    finding["environment_impact"] = local_usage.get("status")
    finding["supply_chain_metadata"]["local_usage"] = local_usage
    digest = str((intake.get("metadata") or {}).get("artifact_sha256") or scan.get("sha256") or "")
    source_key = str((intake.get("metadata") or {}).get("source_repository") or source_repository or (intake.get("metadata") or {}).get("artifact_url") or "")
    key = _case_key(ecosystem, package, version, digest, source_key)
    resolved_case_id = case_id or _find_case(key, db_path=db_path)
    high_confidence = _high_confidence(scan)
    if resolved_case_id:
        get_case(resolved_case_id, db_path=db_path)
    elif create_research_case and (high_confidence or scan.get("status") == "flagged"):
        case = create_case(
            title=f"Source-first {ecosystem} research: {package}@{version}",
            summary=f"Static source-first research for {ecosystem} artifact {package}@{version}. The artifact was inspected without execution.",
            case_type=CASE_TYPE_BY_RESEARCH.get(research_type, "malicious_package" if high_confidence else "other"),
            severity=finding["severity"], confidence=80 if high_confidence else 60, owner=owner, db_path=db_path,
            metadata={"source_first_research_key": key, "research_type": research_type, "artifact_id": scan.get("artifact_id"), "execution_performed": False, "source_reference": source_reference, "source_repository": source_repository},
        )
        resolved_case_id = case["case_id"]

    validated_iocs, rejected_iocs = _validated_iocs(scan)
    evidence_ids: list[str] = []
    evidence_matrix = None
    model_job = None
    draft = None
    if resolved_case_id:
        if artifact:
            add_subject(resolved_case_id, subject_type="package", name=package, ecosystem=ecosystem, version=version, metadata={"artifact_sha256": digest, "artifact_path_supplied": True}, db_path=db_path, actor=actor)
            add_evidence(resolved_case_id, evidence_type="package_artifact", title=f"Reviewed local artifact: {package}@{version}", locator=f"local-artifact://{digest}", sha256=digest, provenance="Operator-supplied local artifact; static inspection only", notes="The artifact was not executed or installed.", metadata={"execution_performed": False, "research_type": research_type}, db_path=db_path, actor=actor)
            evidence_ids.append(digest)
        else:
            intake["case_id"] = resolved_case_id
            attached = attach_intake_result(intake, db_path=db_path, actor=actor, metadata_extra={"artifact_fleet_artifact_id": scan.get("artifact_id"), "execution_performed": False, "research_type": research_type})
            evidence_ids.extend(attached.get("evidence_ids") or [])
        add_evidence(resolved_case_id, evidence_type="static_analysis", title=f"Artifact Fleet static analysis: {package}@{version}", locator=f"artifact-fleet://{scan.get('artifact_id')}", sha256=str(scan.get("sha256") or ""), provenance="SecOpsAI deterministic static rules", notes="Static observations are not runtime proof; no package code was executed.", metadata={"findings": scan.get("findings", [])[:100], "iocs": scan.get("iocs") or {}, "execution_performed": False}, db_path=db_path, actor=actor)
        if source_reference:
            add_evidence(resolved_case_id, evidence_type="source", title=f"Source reference for {package}@{version}", locator=source_reference, provenance="Operator-supplied public source reference", notes="Source context only; reporting domains are not attacker IOCs.", db_path=db_path, actor=actor)
        if source_repository:
            add_evidence(resolved_case_id, evidence_type="source", title=f"Source repository for {package}@{version}", locator=source_repository, provenance="Operator-supplied source repository", notes="Repository reference only; commit behavior remains subject to static evidence.", db_path=db_path, actor=actor)
        if local_usage.get("status") in {"confirmed", "not_found"}:
            add_evidence(resolved_case_id, evidence_type="other", title=f"Local usage review: {package}@{version}", locator="local-usage://bounded-search", provenance="SecOpsAI bounded manifest and lockfile search", notes="Local usage checks inspect text only; no dependency is installed or imported.", metadata={"local_usage": local_usage, "execution_performed": False}, db_path=db_path, actor=actor)
        case = get_case(resolved_case_id, db_path=db_path)
        scan_evidence = next((item.get("evidence_id") for item in reversed(case.get("evidence") or []) if item.get("evidence_type") == "static_analysis"), None)
        for item in validated_iocs:
            add_ioc(resolved_case_id, ioc_type=item["ioc_type"], value=item["value"], confidence=85, source_evidence_id=scan_evidence, tags=["source-first", ecosystem], db_path=db_path, actor=actor)
        if comparison_result:
            add_evidence(resolved_case_id, evidence_type="static_analysis", title=f"Static comparison: {package}@{version} vs {compare_package}@{comparison_intake['metadata']['version']}", locator=f"comparison://{comparison_result.get('comparison_id')}", sha256=hashlib.sha256(json.dumps(comparison_result, sort_keys=True).encode()).hexdigest(), provenance="SecOpsAI bounded static package comparison", notes="Comparison does not execute either artifact or prove intent.", metadata={"comparison": comparison_result, "execution_performed": False}, db_path=db_path, actor=actor)
        if persist_findings and high_confidence:
            _persist_finding(finding, db_path=db_path)
            link_finding(resolved_case_id, finding["finding_id"], relationship="supports", db_path=db_path, actor=actor)
        evidence_matrix = build_evidence_matrix(resolved_case_id, persist=True, actor=actor, db_path=db_path)
        if high_confidence:
            model_job = enqueue_model_triage(scan["artifact_id"], model=model, db_path=artifact_db, job_db_path=db_path, requested_by=actor)
        if draft_blog:
            readiness = publication_readiness(get_case(resolved_case_id, db_path=db_path))
            draft = draft_case_blog(resolved_case_id, db_path=db_path) if readiness["ready"] else {"status": "blocked", "publication_readiness": readiness}

    metadata = intake.get("metadata") if isinstance(intake.get("metadata"), dict) else {}
    artifact_url = str(metadata.get("artifact_url_final") or metadata.get("artifact_url") or "")
    artifact_format = Path(str((intake.get("analysis") or {}).get("filename") or artifact_url)).suffix.lower().lstrip(".")
    behavior_indicators = sorted({str(item.get("category") or item.get("rule_id") or "") for item in (scan.get("findings") or []) if str(item.get("category") or item.get("rule_id") or "")})
    source_repository_value = source_repository or str(metadata.get("source_repository") or "")
    missing_evidence = []
    if not source_reference and not source_repository_value:
        missing_evidence.append("source repository or public source reference")
    if not scan.get("findings"):
        missing_evidence.append("suspicious static indicator or corroborating source evidence")
    if research_type == "vulnerability_advisory":
        route = "vulnerability_tracking"
    elif research_type == "github_token_breach" or ecosystem == "github":
        route = "github_security_review"
    elif research_type == "extension_compromise" or ecosystem in {"open-vsx", "chrome-web-store"}:
        route = "extension_security_review"
    elif research_type in {"malware_apt_c2", "credential_theft", "cloud_kubernetes_abuse", "general_threat_intel"}:
        route = "threat_intel_review"
    elif ecosystem in ADAPTERS and (research_type in {"malicious_package", "package_compromise", "package_artifact", "cross_ecosystem_campaign", "lifecycle_behavior", "typosquatting", "dependency_confusion", "slopsquatting"} or high_confidence):
        route = "campaign_research"
    else:
        route = "needs_human_review"
    return {
        "ok": True, "dry_run": False,
        "research": {"research_id": "RSR-" + hashlib.sha256(key.encode()).hexdigest()[:16].upper(), "case_id": resolved_case_id, "research_type": research_type, "ecosystem": ecosystem, "package_or_artifact": package, "namespace": namespace, "version": version, "source_repository": source_repository_value, "source_reference": source_reference, "comparison_subject": {"ecosystem": compare_ecosystem, "package": compare_package, "version": compare_version} if compare_package else None},
        "metadata": metadata,
        "artifact": {"path": (intake.get("quarantine") or {}).get("path", ""), "url": artifact_url, "sha256": digest, "artifact_id": scan.get("artifact_id"), "size": metadata.get("artifact_bytes"), "format": artifact_format, "execution_performed": False},
        "scan": {key: scan.get(key) for key in ("artifact_id", "status", "sha256", "findings", "iocs", "execution_performed", "duration_ms")},
        "comparison": comparison_result,
        "validated_iocs": validated_iocs, "rejected_iocs": rejected_iocs, "local_usage": local_usage,
        "source_references": [value for value in [source_reference, source_repository_value, metadata.get("metadata_url")] if value],
        "source_evidence": {"source_reference": source_reference, "source_repository": source_repository_value, "registry_metadata_url": metadata.get("metadata_url", ""), "artifact_url": artifact_url},
        "static_findings": scan.get("findings") or [], "comparison_findings": comparison_result or {},
        "behavior_indicators": behavior_indicators,
        "advisory_ids": metadata.get("advisory_ids") or [], "cve_ids": metadata.get("cve_ids") or [], "ghsa_ids": metadata.get("ghsa_ids") or [],
        "extension_ids": [package] if ecosystem in {"open-vsx", "chrome-web-store"} else [], "github_repositories": [source_repository_value] if source_repository_value and "github.com/" in source_repository_value else [],
        "actors": [], "publishers": [metadata.get("publisher")] if metadata.get("publisher") else [], "malware_names": [],
        "case_id": resolved_case_id, "case_key": key, "finding": finding if persist_findings and high_confidence else None,
        "evidence_ids": evidence_ids, "evidence_matrix": evidence_matrix, "model_job": model_job, "draft": draft,
        "route": route, "severity": finding["severity"], "confidence": finding["confidence"],
        "verdict": "suspicious" if scan.get("findings") else "not_substantiated", "missing_evidence": missing_evidence,
        "allowed_actions": ["build_evidence_matrix", "queue_selected_model", "open_research_case", "create_review_only_draft"],
        "blocked_actions": ["execute_artifact", "publish", "deploy", "external_disclosure"],
        "execution_performed": False, "model_review": model_job, "publication_readiness": (draft or {}).get("publication_readiness") if isinstance(draft, dict) else (publication_readiness(get_case(resolved_case_id, db_path=db_path)) if resolved_case_id else None),
        "safety": {"execution_performed": False, "raw_artifact_sent_to_ai": False, "sandbox_submitted": False, "auto_publish": False},
        "next_action": "review_static_evidence_and_model_queue" if high_confidence else "review_evidence_or_close_as_not_substantiated",
    }


def investigate(**kwargs: Any) -> dict[str, Any]:
    """Alias used by CLI/API callers so future research types share one API."""
    return investigate_package(**kwargs)


__all__ = ["ECOSYSTEM_ALIASES", "SUPPORTED_ECOSYSTEMS", "RESEARCH_TYPES", "normalize_ecosystem", "investigate", "investigate_package"]
