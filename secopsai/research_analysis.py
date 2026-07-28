"""Static package comparison and campaign correlation helpers.

The functions in this module accept normalized intake results or archive bytes.
They never import, install, load, or execute package code.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import subprocess
import tempfile
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import soc_store
from secopsai.research_intake import IntakeError, collect_package_intake, inspect_archive


ANALYSIS_SCHEMA = "secopsai.research.analysis-result.v1"
CORRELATION_VERSION = "correlation-1"


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _read_json(value: Any, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, ValueError):
        return default


def _set_diff(left: Iterable[str], right: Iterable[str]) -> Dict[str, List[str]]:
    a, b = set(str(item) for item in left), set(str(item) for item in right)
    return {"added": sorted(b - a), "removed": sorted(a - b), "common": sorted(a & b)}


def compare_intakes(left: Dict[str, Any], right: Dict[str, Any], *, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Compare two normalized intake payloads and persist the comparison."""
    left_meta = left.get("metadata") if isinstance(left.get("metadata"), dict) else {}
    right_meta = right.get("metadata") if isinstance(right.get("metadata"), dict) else {}
    left_analysis = left.get("analysis") if isinstance(left.get("analysis"), dict) else {}
    right_analysis = right.get("analysis") if isinstance(right.get("analysis"), dict) else {}
    left_members = [item.get("path") for item in left_analysis.get("members", []) if isinstance(item, dict) and item.get("path")]
    right_members = [item.get("path") for item in right_analysis.get("members", []) if isinstance(item, dict) and item.get("path")]
    left_scripts = left_analysis.get("lifecycle_scripts") or {}
    right_scripts = right_analysis.get("lifecycle_scripts") or {}
    result = {
        "schema_version": "secopsai.research.package-comparison.v1",
        "left": {key: left_meta.get(key, "") for key in ("ecosystem", "package", "version", "publisher", "artifact_sha256")},
        "right": {key: right_meta.get(key, "") for key in ("ecosystem", "package", "version", "publisher", "artifact_sha256")},
        "metadata": {
            "publisher_changed": left_meta.get("publisher", "") != right_meta.get("publisher", ""),
            "package_changed": left_meta.get("package", "") != right_meta.get("package", ""),
            "ecosystem_changed": left_meta.get("ecosystem", "") != right_meta.get("ecosystem", ""),
        },
        "members": _set_diff(left_members, right_members),
        "lifecycle_scripts": {"left": left_scripts, "right": right_scripts, "changed": left_scripts != right_scripts},
        "indicators": {
            "left": left_analysis.get("indicators", []),
            "right": right_analysis.get("indicators", []),
            "added": _set_diff([item.get("indicator_id") for item in left_analysis.get("indicators", [])], [item.get("indicator_id") for item in right_analysis.get("indicators", [])])["added"],
        },
        "safety": {
            "execution_performed": False,
            "raw_package_sent_to_ai": False,
            "comparison_is_static_only": True,
        },
    }
    left_key = (str(left_meta.get("ecosystem")), str(left_meta.get("package")), str(left_meta.get("version")))
    right_key = (str(right_meta.get("ecosystem")), str(right_meta.get("package")), str(right_meta.get("version")))
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        comparison_id = _id("CMP")
        connection.execute(
            """INSERT INTO research_comparisons
            (comparison_id, left_ecosystem, left_package, left_version, right_ecosystem, right_package, right_version, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(left_ecosystem, left_package, left_version, right_ecosystem, right_package, right_version)
            DO UPDATE SET result_json=excluded.result_json, created_at=excluded.created_at""",
            (comparison_id, *left_key, *right_key, _json(result), _now()),
        )
        row = connection.execute("SELECT comparison_id FROM research_comparisons WHERE left_ecosystem=? AND left_package=? AND left_version=? AND right_ecosystem=? AND right_package=? AND right_version=?", (*left_key, *right_key)).fetchone()
        connection.commit()
    result["comparison_id"] = row["comparison_id"] if row else comparison_id
    return result


def compare_packages(*, left_ecosystem: str, left_package: str, left_version: str = "", right_ecosystem: str, right_package: str, right_version: str = "", db_path: Optional[str] = None) -> Dict[str, Any]:
    """Collect and compare two exact package targets using static-only intake."""
    left = collect_package_intake(ecosystem=left_ecosystem, package=left_package, version=left_version)
    right = collect_package_intake(ecosystem=right_ecosystem, package=right_package, version=right_version)
    result = compare_intakes(left, right, db_path=db_path)
    result["collection"] = {
        "left": {"package": left_package, "version": left.get("metadata", {}).get("version"), "artifact_sha256": left.get("metadata", {}).get("artifact_sha256")},
        "right": {"package": right_package, "version": right.get("metadata", {}).get("version"), "artifact_sha256": right.get("metadata", {}).get("artifact_sha256")},
        "execution_performed": False,
    }
    return result


def inspect_nuget_archive(data: bytes, filename: str = "package.nupkg") -> Dict[str, Any]:
    """Inspect NuGet package members and .NET-like artifacts without loading them."""
    base = inspect_archive(data, filename)
    if base["archive_type"] != "zip":
        raise IntakeError("NuGet package must be a ZIP-compatible .nupkg archive")
    assemblies: List[Dict[str, Any]] = []
    suspicious_references: List[Dict[str, str]] = []
    byte_patterns = {
        "process": rb"System\.Diagnostics\.Process|ProcessStartInfo",
        "network": rb"HttpClient|WebClient|System\.Net|Sockets",
        "credentials": rb"Credential|Password|AccessToken|ApiKey|Secret",
        "reflection": rb"System\.Reflection|Assembly\.Load|Type\.GetType",
        "native": rb"DllImport|LoadLibrary|GetProcAddress",
    }
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            lower = info.filename.lower()
            if not lower.endswith((".dll", ".exe")):
                continue
            raw = archive.read(info)
            digest = hashlib.sha256(raw).hexdigest()
            signals = []
            for name, pattern in byte_patterns.items():
                if re.search(pattern, raw, re.I):
                    signals.append(name)
                    suspicious_references.append({"path": info.filename, "indicator": name})
            assemblies.append({"path": info.filename, "bytes": len(raw), "sha256": digest, "static_signals": signals, "loaded": False, "executed": False})
    result = {
        "schema_version": ANALYSIS_SCHEMA,
        "archive": base,
        "dotnet": {
            "assembly_count": len(assemblies),
            "assemblies": assemblies,
            "references": suspicious_references,
            "tool": "bounded-byte-metadata-inspector",
            "tool_version": "1",
            "decompiler_available": False,
            "limitations": ["Assembly metadata is inspected without loading code; runtime behavior is unproven.", "Install a separately pinned Mono.Cecil/ILSpy worker for full symbol and API extraction."],
        },
        "safety": {"execution_performed": False, "assemblies_loaded": False, "raw_artifact_sent_to_ai": False},
    }
    analyzer_image = os.environ.get("SECOPSAI_NUGET_ANALYZER_IMAGE", "").strip()
    if analyzer_image:
        tag_pinned = re.fullmatch(r"[A-Za-z0-9._/-]{1,180}:[A-Za-z0-9._-]{1,80}", analyzer_image)
        digest_pinned = re.fullmatch(r"[A-Za-z0-9._/-]{1,180}@sha256:[a-f0-9]{64}", analyzer_image)
        if not (tag_pinned or digest_pinned):
            raise IntakeError("NuGet analyzer image must be a pinned image reference (immutable tag or sha256 digest)")
        with tempfile.TemporaryDirectory(prefix="secopsai-nuget-") as temp_dir:
            package_path = os.path.join(temp_dir, "package.nupkg")
            with open(package_path, "wb") as handle:
                handle.write(data)
            completed = subprocess.run([
                "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "512m",
                "-v", f"{temp_dir}:/input:ro", analyzer_image, "/input/package.nupkg",
            ], capture_output=True, text=True, timeout=120, check=False)
        if completed.returncode != 0:
            raise IntakeError("configured NuGet analyzer failed")
        try:
            deep = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise IntakeError("configured NuGet analyzer returned invalid JSON") from exc
        if not isinstance(deep, dict) or deep.get("execution_performed") is not False:
            raise IntakeError("NuGet analyzer did not provide a non-executing result")
        result["dotnet"]["deep_analysis"] = deep
        result["dotnet"]["tool"] = deep.get("tool") or "configured-analyzer"
        result["dotnet"]["tool_version"] = deep.get("tool_version") or "unknown"
        result["dotnet"]["decompiler_available"] = True
        result["dotnet"]["limitations"] = ["Metadata analysis does not establish runtime behavior or malicious intent."]
    return result


def correlate_candidates(*, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Create stable campaign links for exact shared evidence only."""
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        candidates = [dict(row) for row in connection.execute("SELECT * FROM research_candidates WHERE status IN ('new', 'review', 'promoted') ORDER BY package, version").fetchall()]
    campaigns: List[Dict[str, Any]] = []
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for candidate in candidates:
        evidence = _read_json(candidate.get("evidence_json"), {})
        key = str(evidence.get("publisher") or "").strip().casefold()
        if key:
            groups.setdefault(f"publisher:{key}", []).append(candidate)
    for group_key, items in groups.items():
        if len(items) < 2:
            continue
        campaign_id = _id("CMPG")
        now = _now()
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute("INSERT INTO research_campaigns (campaign_id, title, status, confidence, attribution, summary, created_at, updated_at) VALUES (?, ?, 'candidate', ?, 'none', ?, ?, ?)", (campaign_id, f"Potential package campaign: {group_key.split(':', 1)[1]}", 40, "Candidates share a publisher field; this is not attribution.", now, now))
            for item in items:
                connection.execute("INSERT INTO research_campaign_links (campaign_id, left_type, left_id, right_type, right_id, relationship, confidence, evidence_json, algorithm_version, human_state, created_at) VALUES (?, 'campaign', ?, 'candidate', ?, 'shared_publisher', 40, ?, ?, 'unreviewed', ?)", (campaign_id, campaign_id, item["candidate_id"], _json({"publisher": _read_json(item.get("evidence_json"), {}).get("publisher", "")}), CORRELATION_VERSION, now))
            connection.commit()
        campaigns.append({"campaign_id": campaign_id, "candidate_ids": [item["candidate_id"] for item in items], "relationship": "shared_publisher", "confidence": 40})
    return campaigns


def list_campaigns(*, db_path: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """List persisted campaign clusters without implying attribution."""
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute("SELECT * FROM research_campaigns ORDER BY updated_at DESC LIMIT ?", (max(1, min(int(limit), 500)),)).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            links = connection.execute("SELECT * FROM research_campaign_links WHERE campaign_id = ? ORDER BY created_at", (item["campaign_id"],)).fetchall()
            item["links"] = [dict(link) | {"evidence": _read_json(link["evidence_json"], {})} for link in links]
            output.append(item)
    return output
