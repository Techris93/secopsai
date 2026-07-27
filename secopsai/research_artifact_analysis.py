"""Bounded, non-executing analysis for quarantined research artifacts."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import zipfile
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import soc_store
from secopsai import research_artifacts
from secopsai.research_analysis import inspect_nuget_archive
from secopsai.research_cases import add_ioc

URL_RE = re.compile(r"https?://[^\s\"'<>]{4,2048}", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
SCRIPT_NAMES = {"install.ps1", "install.sh", "setup.py", "setup.cfg", "pyproject.toml", "package.json", ".nuspec"}
MAX_STRINGS = 5000


def _safe_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_private or address.is_loopback or address.is_reserved or address.is_link_local)
    except ValueError:
        return False


def _strings(data: bytes) -> list[str]:
    values = re.findall(rb"[ -~]{8,}", data)
    return [item.decode("ascii", "ignore")[:2048] for item in values[:MAX_STRINGS]]


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
        "tool_version": "1",
        "execution_performed": False,
        "loaded": False,
        "assemblies": [],
        "archive_members": [],
        "lifecycle_scripts": [],
        "strings": [],
        "urls": [],
        "ipv4": [],
        "sha256_candidates": [],
        "indicators": [],
        "limitations": [],
    }
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            result["archive_members"] = [
                {"name": info.filename.replace("\\", "/"), "size": info.file_size, "sha256": hashlib.sha256(archive.read(info)).hexdigest()}
                for info in infos[:10000] if not info.is_dir()
            ]
            for info in infos[:10000]:
                name = info.filename.replace("\\", "/")
                lower = name.lower()
                if info.is_dir() or info.file_size > 50 * 1024 * 1024:
                    continue
                data = archive.read(info)
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
    except zipfile.BadZipFile:
        result["limitations"].append("artifact is not a supported ZIP package; only hash metadata is available")
    strings = list(dict.fromkeys(result["strings"]))[:MAX_STRINGS]
    result["strings"] = strings
    urls = sorted({match.rstrip(".,);") for value in strings for match in URL_RE.findall(value)})
    result["urls"] = urls[:500]
    result["ipv4"] = sorted({match for value in strings for match in IP_RE.findall(value) if _safe_ip(match)})[:500]
    result["sha256_candidates"] = sorted({match.lower() for value in strings for match in HASH_RE.findall(value)})[:500]
    result["indicators"] = [
        *[{"type": "url", "value": value, "source": "bounded_strings"} for value in result["urls"]],
        *[{"type": "ipv4", "value": value, "source": "bounded_strings"} for value in result["ipv4"]],
        *[{"type": "sha256", "value": value, "source": "bounded_strings"} for value in result["sha256_candidates"]],
    ]
    if result["assemblies"]:
        result["limitations"].append("assembly metadata requires the optional isolated Mono.Cecil worker for namespaces, methods, P/Invoke, and resources")
        if artifact.get("ecosystem") == "nuget" and os.environ.get("SECOPSAI_NUGET_ANALYZER_IMAGE", "").strip():
            deep = inspect_nuget_archive(path.read_bytes(), artifact.get("filename") or "package.nupkg")
            result["dotnet"] = deep.get("dotnet", {})
            result["limitations"] = [item for item in result["limitations"] if "optional isolated Mono.Cecil" not in item]
            result["tool"] = result["dotnet"].get("tool", result["tool"])
    result["complete"] = not bool(result["limitations"])
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
            if indicator["type"] == "url" and ("nuget.org" in value or "npmjs.com" in value or "pypi.org" in value):
                continue
            stable = hashlib.sha256(f"{case_id}|{indicator['type']}|{value}".encode()).hexdigest()[:16].upper()
            candidate_id = f"IOC-C-{stable}"
            with closing(soc_store.connect(db_path)) as connection:
                connection.execute("""INSERT INTO research_ioc_candidates
                    (candidate_id, case_id, ioc_type, value, confidence, reason, source_evidence_id, status, created_at)
                    VALUES (?, ?, ?, ?, 50, ?, NULL, 'pending', ?)
                    ON CONFLICT(case_id, ioc_type, value) DO UPDATE SET reason=excluded.reason""",
                    (candidate_id, case_id, indicator["type"], value, f"Extracted from bounded static evidence in {current}", soc_store.utc_now()))
                connection.commit()
            candidates.append({"candidate_id": candidate_id, "ioc_type": indicator["type"], "value": value, "status": "pending", "artifact_id": current})
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
