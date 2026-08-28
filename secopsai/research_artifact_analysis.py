"""Bounded, non-executing analysis for quarantined research artifacts."""
from __future__ import annotations

import gzip
import hashlib
import io
import ipaddress
import json
import os
import secrets
import re
import tarfile
import zipfile
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlsplit

import soc_store
from secopsai import research_artifacts
from secopsai.research_analysis import inspect_nuget_archive
from secopsai.research_cases import add_ioc
from secopsai.research_signal_analysis import (
    TOOL_NAME as SIGNAL_TOOL_NAME,
    TOOL_VERSION as SIGNAL_TOOL_VERSION,
    analyze_text_files,
    classify_path,
    classify_url,
    evidence_quality_summary,
)

URL_RE = re.compile(r"https?://[^\s\"'<>]{4,2048}", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
SCRIPT_NAMES = {"install.ps1", "install.sh"}
MAX_STRINGS = 5000
MAX_ARCHIVE_ENTRIES = 10_000
MAX_MEMBER_BYTES = 50 * 1024 * 1024
MAX_EXPANDED_BYTES = 250 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
BENIGN_IOC_HOSTS = (
    "nuget.org", "npmjs.com", "npmjs.org", "pypi.org", "rubygems.org",
    "packagist.org", "maven.org", "golang.org", "open-vsx.org", "crates.io",
    "w3.org", "json.schemastore.org",
)


def _safe_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_private or address.is_loopback or address.is_reserved or address.is_link_local)
    except ValueError:
        return False


def _strings(data: bytes) -> list[str]:
    values = re.findall(rb"[ -~]{8,}", data)
    return [item.decode("ascii", "ignore")[:2048] for item in values[:MAX_STRINGS]]


def _capped_gunzip(data: bytes, cap: int = 50 * 1024 * 1024) -> bytes:
    """Decompress a gzip member in memory with a hard output cap."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            return handle.read(cap + 1)[:cap]
    except (OSError, EOFError):
        return b""


def _is_benign_ioc_url(value: str) -> bool:
    try:
        host = (urlsplit(value).hostname or "").lower()
    except ValueError:
        return False
    return any(host == domain or host.endswith(f".{domain}") for domain in BENIGN_IOC_HOSTS)


def _process_member(name: str, data: bytes, result: Dict[str, Any]) -> None:
    lower = name.lower()
    if lower.endswith((".dll", ".exe")):
        result["assemblies"].append({
            "path": name, "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data), "loaded": False, "executed": False,
            "analysis": "metadata-only; Mono.Cecil worker not invoked",
        })
    if any(lower.endswith(script) or lower == script for script in SCRIPT_NAMES):
        result["lifecycle_scripts"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest()})
    if lower.endswith((".dll", ".exe", ".json", ".xml", ".nuspec", ".cs", ".ps1", ".sh", ".py", ".js", ".ts", ".txt", ".md")):
        result["strings"].extend(_strings(data))
        if len(data) <= 2 * 1024 * 1024:
            result["text_files"].append((name, data.decode("utf-8", "ignore")))


def inspect_artifact(artifact_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    artifact = research_artifacts.get_artifact(artifact_id, db_path=db_path)
    if not artifact.get("available"):
        raise ValueError("artifact is missing or failed hash verification")
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT quarantine_path FROM research_artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
    path = Path(row["quarantine_path"])
    result: Dict[str, Any] = {
        "schema_version": "secopsai.research.analysis-result.v1",
        "artifact_id": artifact_id,
        "sha256": artifact["sha256"],
        "tool": "secopsai-bounded-archive-inspector",
        "tool_version": "2",
        "execution_performed": False,
        "loaded": False,
        "assemblies": [],
        "archive_members": [],
        "lifecycle_scripts": [],
        "strings": [],
        "text_files": [],
        "urls": [],
        "url_observations": [],
        "ipv4": [],
        "sha256_candidates": [],
        "indicators": [],
        "limitations": [],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            members = []
            expanded_bytes = 0
            for index, info in enumerate(infos):
                if index >= MAX_ARCHIVE_ENTRIES:
                    result["limitations"].append(
                        f"archive contains more than {MAX_ARCHIVE_ENTRIES} entries; remaining entries were not inspected"
                    )
                    break
                name = info.filename.replace("\\", "/")
                if info.is_dir():
                    continue
                if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
                    result["limitations"].append(
                        f"archive member {name} exceeds the {MAX_MEMBER_BYTES} byte member limit; content was not read"
                    )
                    members.append({"name": name, "size": info.file_size, "sha256": None, "skipped": "member_size_limit"})
                    continue
                if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    result["limitations"].append(
                        f"archive member {name} exceeds the {MAX_COMPRESSION_RATIO}:1 compression-ratio limit; content was not read"
                    )
                    members.append({"name": name, "size": info.file_size, "sha256": None, "skipped": "compression_ratio_limit"})
                    continue
                if expanded_bytes + info.file_size > MAX_EXPANDED_BYTES:
                    result["limitations"].append(
                        f"archive expanded content exceeds the {MAX_EXPANDED_BYTES} byte limit; remaining entries were not inspected"
                    )
                    break
                # All limits are checked before opening the member. This keeps
                # hostile compressed entries from allocating unbounded memory.
                data = archive.read(info)
                expanded_bytes += len(data)
                members.append({"name": name, "size": info.file_size, "sha256": hashlib.sha256(data).hexdigest()})
                _process_member(name, data, result)
            result["archive_members"] = members
            result["archive_format"] = "zip"
    except zipfile.BadZipFile:
        try:
            with tarfile.open(path) as archive:
                members = []
                expanded_bytes = 0
                for index, info in enumerate(archive.getmembers()):
                    if index >= MAX_ARCHIVE_ENTRIES:
                        result["limitations"].append(
                            f"archive contains more than {MAX_ARCHIVE_ENTRIES} entries; remaining entries were not inspected"
                        )
                        break
                    if not info.isfile():
                        continue
                    name = info.name.replace("\\", "/")
                    data = b""
                    if info.size < 0 or info.size > MAX_MEMBER_BYTES:
                        result["limitations"].append(
                            f"archive member {name} exceeds the {MAX_MEMBER_BYTES} byte member limit; content was not read"
                        )
                        members.append({"name": name, "size": info.size, "sha256": None, "skipped": "member_size_limit"})
                        continue
                    if expanded_bytes + info.size > MAX_EXPANDED_BYTES:
                        result["limitations"].append(
                            f"archive expanded content exceeds the {MAX_EXPANDED_BYTES} byte limit; remaining entries were not inspected"
                        )
                        break
                    extracted = archive.extractfile(info)
                    if extracted is not None:
                        data = extracted.read(MAX_MEMBER_BYTES + 1)
                    if len(data) > MAX_MEMBER_BYTES:
                        result["limitations"].append(
                            f"archive member {name} exceeded the {MAX_MEMBER_BYTES} byte read limit; content was not analyzed"
                        )
                        members.append({"name": name, "size": info.size, "sha256": None, "skipped": "member_read_limit"})
                        continue
                    expanded_bytes += len(data)
                    members.append({"name": name, "size": info.size, "sha256": hashlib.sha256(data).hexdigest() if data else None})
                    if data:
                        _process_member(name, data, result)
                        if name.lower().endswith(".gz"):
                            decompressed = _capped_gunzip(data)
                            if decompressed:
                                result["strings"].extend(_strings(decompressed))
                result["archive_members"] = members
                result["archive_format"] = "tar"
        except tarfile.TarError:
            result["limitations"].append("artifact is not a supported ZIP or TAR package; only hash metadata is available")
    strings = list(dict.fromkeys(result["strings"]))[:MAX_STRINGS]
    result["strings"] = strings
    contextual_observations = analyze_text_files(result["text_files"], artifact_sha256=result["sha256"])
    result["observations"] = contextual_observations
    result["observation_summary"] = evidence_quality_summary(contextual_observations)
    declared_sources = [
        str(artifact.get("provenance", {}).get("metadata_url") or ""),
        str(artifact.get("provenance", {}).get("artifact_url") or ""),
    ]
    # Package metadata is source provenance too. Treat repository, homepage,
    # and issue URLs declared by a manifest as references rather than IOCs.
    for member_path, member_text in result["text_files"]:
        if classify_path(member_path)["context_classification"] != "manifest":
            continue
        try:
            manifest = json.loads(member_text)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(manifest, dict):
            continue
        for key in ("homepage", "bugs", "repository", "source", "funding"):
            value = manifest.get(key)
            values = value if isinstance(value, list) else [value]
            for item in values:
                if isinstance(item, str):
                    declared_sources.extend(URL_RE.findall(item))
                elif isinstance(item, dict):
                    for candidate in item.values():
                        if isinstance(candidate, str):
                            declared_sources.extend(URL_RE.findall(candidate))
    url_rows: list[Dict[str, Any]] = []
    for member_path, member_text in result["text_files"]:
        network_evidence = any(
            item.get("path") == member_path and item.get("category") == "network"
            for item in contextual_observations
        )
        for match in URL_RE.findall(member_text):
            classified = classify_url(
                match,
                path=member_path,
                declared_source_urls=declared_sources,
                network_call_evidence=network_evidence,
            )
            classified["path"] = member_path
            classified["context_classification"] = classify_path(member_path)["context_classification"]
            url_rows.append(classified)
    classified_values = {item["value"] for item in url_rows}
    for value in sorted({match for current in strings for match in URL_RE.findall(current)}):
        classified = classify_url(value)
        if classified["value"] not in classified_values:
            classified["path"] = ""
            classified["context_classification"] = "binary_or_unknown"
            url_rows.append(classified)
    deduped_urls: Dict[str, Dict[str, Any]] = {}
    for item in url_rows:
        existing = deduped_urls.get(item["value"])
        if existing is None or int(item.get("confidence") or 0) > int(existing.get("confidence") or 0):
            deduped_urls[item["value"]] = item
    result["url_observations"] = list(deduped_urls.values())[:500]
    urls = sorted(deduped_urls)
    result["urls"] = urls[:500]
    result["ipv4"] = sorted({match for value in strings for match in IP_RE.findall(value) if _safe_ip(match)})[:500]
    result["sha256_candidates"] = sorted({match.lower() for value in strings for match in HASH_RE.findall(value)})[:500]
    result["indicators"] = [
        *[{
            "type": "url",
            "value": item["value"],
            "source": "bounded_strings",
            "classification": item["classification"],
            "classification_reason": item["classification_reason"],
            "confidence": item["confidence"],
            "eligible_for_ioc_review": item["eligible_for_ioc_review"],
            "path": item.get("path", ""),
        } for item in result["url_observations"]],
        *[{"type": "ipv4", "value": value, "source": "bounded_strings"} for value in result["ipv4"]],
        *[{"type": "sha256", "value": value, "source": "bounded_strings"} for value in result["sha256_candidates"]],
    ]
    result["analysis_tool"] = SIGNAL_TOOL_NAME
    result["analysis_tool_version"] = SIGNAL_TOOL_VERSION
    if result["assemblies"]:
        result["limitations"].append("assembly metadata requires the optional isolated Mono.Cecil worker for namespaces, methods, P/Invoke, and resources")
        if artifact.get("ecosystem") == "nuget" and os.environ.get("SECOPSAI_NUGET_ANALYZER_IMAGE", "").strip():
            deep = inspect_nuget_archive(path.read_bytes(), artifact.get("filename") or "package.nupkg")
            result["dotnet"] = deep.get("dotnet", {})
            result["limitations"] = [item for item in result["limitations"] if "optional isolated Mono.Cecil" not in item]
            result["tool"] = result["dotnet"].get("tool", result["tool"])
    result["complete"] = not bool(result["limitations"])
    result.pop("text_files", None)
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("UPDATE research_artifacts SET analysis_json = ?, updated_at = ? WHERE artifact_id = ?", (json.dumps(result, sort_keys=True), soc_store.utc_now(), artifact_id))
        connection.commit()
    return result


def compare_artifacts(left_id: str, right_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    left = inspect_artifact(left_id, db_path=db_path)
    right = inspect_artifact(right_id, db_path=db_path)
    left_members = {item["name"]: item for item in left["archive_members"]}
    right_members = {item["name"]: item for item in right["archive_members"]}
    return {
        "schema_version": "secopsai.research.comparison.v2",
        "mode": "local_artifact_local_artifact",
        "left_artifact_id": left_id,
        "right_artifact_id": right_id,
        "left_sha256": left["sha256"],
        "right_sha256": right["sha256"],
        "added_members": sorted(set(right_members) - set(left_members)),
        "removed_members": sorted(set(left_members) - set(right_members)),
        "changed_members": sorted(name for name in set(left_members) & set(right_members) if left_members[name]["sha256"] != right_members[name]["sha256"]),
        "lifecycle_script_diff": {"left": left["lifecycle_scripts"], "right": right["lifecycle_scripts"]},
        "indicator_diff": {"left": left["indicators"], "right": right["indicators"]},
        "assembly_diff": {"left": left["assemblies"], "right": right["assemblies"]},
        "limitations": sorted(set(left["limitations"] + right["limitations"])),
        "execution_performed": False,
    }


def extract_ioc_candidates(case_id: str, *, artifact_id: Optional[str] = None, db_path: Optional[str] = None, actor: str = "analyst") -> Dict[str, Any]:
    artifacts = [artifact_id] if artifact_id else []
    if not artifacts:
        with closing(soc_store.connect(db_path)) as connection:
            artifacts = [str(row["artifact_id"]) for row in connection.execute("SELECT artifact_id FROM research_case_artifacts WHERE case_id = ?", (case_id,)).fetchall()]
    candidates = []
    for current in artifacts:
        result = inspect_artifact(current, db_path=db_path)
        for indicator in result["indicators"]:
            value = indicator["value"]
            classification = str(indicator.get("classification") or "")
            if indicator["type"] == "url" and (
                _is_benign_ioc_url(value)
                or classification in {"source_reference", "documentation_url", "shared_legitimate_service"}
            ):
                continue
            stable = hashlib.sha256(f"{case_id}|{indicator['type']}|{value}".encode()).hexdigest()[:16].upper()
            candidate_id = f"IOC-C-{stable}"
            with closing(soc_store.connect(db_path)) as connection:
                confidence = int(indicator.get("confidence") or 50)
                reason = str(indicator.get("classification_reason") or f"Extracted from bounded static evidence in {current}")
                connection.execute("""INSERT INTO research_ioc_candidates
                    (candidate_id, case_id, ioc_type, value, confidence, reason,
                     source_evidence_id, status, created_at, classification, classification_reason)
                    VALUES (?, ?, ?, ?, ?, ?, NULL, 'pending', ?, ?, ?)
                    ON CONFLICT(case_id, ioc_type, value) DO UPDATE SET
                      confidence=excluded.confidence, reason=excluded.reason,
                      classification=excluded.classification,
                      classification_reason=excluded.classification_reason""",
                    (candidate_id, case_id, indicator["type"], value, confidence, reason,
                     soc_store.utc_now(), classification or "ioc_candidate", reason))
                connection.commit()
            candidates.append({
                "candidate_id": candidate_id,
                "ioc_type": indicator["type"],
                "value": value,
                "status": "pending",
                "classification": classification or "ioc_candidate",
                "classification_reason": reason,
                "artifact_id": current,
            })
    return {"case_id": case_id, "candidates": candidates, "execution_performed": False}


def review_ioc_candidate(candidate_id: str, *, decision: str, db_path: Optional[str] = None, actor: str = "analyst") -> Dict[str, Any]:
    if decision not in {"approved", "rejected"}:
        raise ValueError("decision must be approved or rejected")
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_ioc_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
        if row is None:
            raise ValueError(f"IOC candidate not found: {candidate_id}")
        connection.execute("UPDATE research_ioc_candidates SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE candidate_id = ?", (decision, soc_store.utc_now(), actor, candidate_id))
        connection.commit()
    if decision == "approved":
        add_ioc(row["case_id"], ioc_type=row["ioc_type"], value=row["value"], confidence=row["confidence"], db_path=db_path, actor=actor)
    return {"candidate_id": candidate_id, "case_id": row["case_id"], "status": decision}


def queue_artifact_analysis(case_id: str, artifact_id: str, *, requested_by: str = "mission-control", db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    job_id = "ARJ-" + secrets.token_hex(7).upper()
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("""INSERT INTO research_artifact_jobs
            (job_id, case_id, artifact_id, status, requested_by, queued_at, result_json)
            VALUES (?, ?, ?, 'queued', ?, ?, '{}')
            ON CONFLICT(case_id, artifact_id) DO UPDATE SET status='queued', requested_by=excluded.requested_by, queued_at=excluded.queued_at, error_message=NULL""", (job_id, case_id, artifact_id, requested_by, now))
        row = connection.execute("SELECT job_id, status, queued_at FROM research_artifact_jobs WHERE case_id = ? AND artifact_id = ?", (case_id, artifact_id)).fetchone()
        connection.commit()
    return {"job_id": row["job_id"], "case_id": case_id, "artifact_id": artifact_id, "status": row["status"], "queued_at": row["queued_at"]}


def run_artifact_job(job_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_artifact_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise ValueError(f"artifact analysis job not found: {job_id}")
        connection.execute("UPDATE research_artifact_jobs SET status='running', started_at=? WHERE job_id=?", (soc_store.utc_now(), job_id))
        connection.commit()
    try:
        result = inspect_artifact(row["artifact_id"], db_path=db_path)
    except Exception as exc:
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute("UPDATE research_artifact_jobs SET status='failed', completed_at=?, error_message=? WHERE job_id=?", (soc_store.utc_now(), str(exc)[:2000], job_id))
            connection.commit()
        raise
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("UPDATE research_artifact_jobs SET status='succeeded', completed_at=?, result_json=? WHERE job_id=?", (soc_store.utc_now(), json.dumps(result, sort_keys=True), job_id))
        connection.commit()
    return {"job_id": job_id, "status": "succeeded", "result": result}


def run_artifact_worker_once(*, db_path: Optional[str] = None, limit: int = 5) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        jobs = connection.execute("SELECT job_id FROM research_artifact_jobs WHERE status='queued' ORDER BY queued_at LIMIT ?", (max(1, min(limit, 25)),)).fetchall()
    results = []
    for item in jobs:
        try:
            results.append(run_artifact_job(item["job_id"], db_path=db_path))
        except Exception as exc:
            results.append({"job_id": item["job_id"], "status": "failed", "error": str(exc)})
    return {"processed": len(results), "jobs": results}
