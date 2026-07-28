"""Local-only artifact catalog and bounded quarantine operations.

Artifacts never leave the Core host.  This module records hashes and normalized
metadata in SQLite while keeping package bytes in an owner-only quarantine.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tarfile
import zipfile
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Optional

import soc_store

MAX_ARTIFACT_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10000
MAX_ENTRY_BYTES = 50 * 1024 * 1024
ALLOWED_STATES = {"collected", "missing", "externally_supplied", "purged"}
ZIP_SUFFIXES = {".nupkg", ".zip", ".vsix", ".whl"}
TAR_SUFFIXES = {".gem"}
ATTACHMENT_ROLES = {"subject", "reference", "comparison", "baseline"}


def quarantine_root() -> Path:
    root = Path(os.environ.get("SECOPSAI_RESEARCH_QUARANTINE", "data/research/quarantine")).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _hash_and_validate(path: Path, max_bytes: int = MAX_ARTIFACT_BYTES) -> tuple[str, int]:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("artifact must be a regular file")
    if st.st_size > max_bytes:
        raise ValueError(f"artifact exceeds {max_bytes} bytes")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"artifact exceeds {max_bytes} bytes")
            digest.update(chunk)
    return digest.hexdigest(), size


def _validate_member_name(name: str) -> None:
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if (
        normalized.startswith("/")
        or ".." in parts
        or (parts and re.fullmatch(r"[A-Za-z]:", parts[0]))
    ):
        raise ValueError("archive contains a path traversal entry")


def _validate_zip(path: Path) -> Dict[str, Any]:
    entries = 0
    expanded = 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("archive contains too many entries")
        for info in infos:
            entries += 1
            _validate_member_name(info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
                raise ValueError("archive contains a symlink or device entry")
            if info.is_dir():
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                raise ValueError("archive entry exceeds safety limit")
            expanded += info.file_size
            if expanded > MAX_ARTIFACT_BYTES * 4:
                raise ValueError("archive expanded size exceeds safety limit")
    return {"archive": True, "format": "zip", "entries": entries, "expanded_bytes": expanded, "unsafe": False}


def _validate_tar(path: Path) -> Dict[str, Any]:
    entries = 0
    expanded = 0
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("archive contains too many entries")
        for info in members:
            entries += 1
            _validate_member_name(info.name)
            if info.issym() or info.islnk() or info.isdev() or info.isfifo():
                raise ValueError("archive contains a symlink, hardlink, or device entry")
            if info.isdir():
                continue
            if info.size > MAX_ENTRY_BYTES:
                raise ValueError("archive entry exceeds safety limit")
            expanded += info.size
            if expanded > MAX_ARTIFACT_BYTES * 4:
                raise ValueError("archive expanded size exceeds safety limit")
    return {"archive": True, "format": "tar", "entries": entries, "expanded_bytes": expanded, "unsafe": False}


def _validate_archive(path: Path) -> Dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in ZIP_SUFFIXES:
        return _validate_zip(path)
    if suffix in TAR_SUFFIXES:
        return _validate_tar(path)
    return {"archive": False, "entries": 0, "unsafe": False}


def import_artifact(
    source_path: str,
    *,
    ecosystem: str = "nuget",
    package_name: str = "",
    version: str = "",
    provenance: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    """Copy an authorized local artifact into hash-addressed quarantine."""
    if not isinstance(provenance, dict) or not str(provenance.get("source", "")).strip():
        raise ValueError("provenance requires a non-empty 'source' describing lawful origin and authorization")
    soc_store.init_db(db_path)
    source = Path(source_path).expanduser()
    digest, size = _hash_and_validate(source)
    archive = _validate_archive(source)
    destination = quarantine_root() / f"{digest}{source.suffix.lower()}"
    if not destination.exists():
        tmp = destination.with_name(f".{destination.name}.{secrets.token_hex(4)}.tmp")
        shutil.copyfile(source, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, destination)
    now = soc_store.utc_now()
    artifact_id = f"ART-{digest[:16].upper()}"
    metadata = {"archive": archive, "source_filename": source.name}
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_artifacts
            (artifact_id, sha256, filename, ecosystem, package_name, version,
             size_bytes, quarantine_path, state, provenance_json, analysis_json,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'collected', ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              filename=excluded.filename, ecosystem=excluded.ecosystem,
              package_name=excluded.package_name, version=excluded.version,
              size_bytes=excluded.size_bytes, quarantine_path=excluded.quarantine_path,
              state='collected', provenance_json=excluded.provenance_json,
              updated_at=excluded.updated_at""",
            (artifact_id, digest, source.name, ecosystem.lower().strip(), package_name.strip(),
             version.strip(), size, str(destination), json.dumps(provenance or {}, sort_keys=True),
             json.dumps(metadata, sort_keys=True), now, now),
        )
        connection.commit()
    return {
        "artifact_id": artifact_id,
        "sha256": digest,
        "filename": source.name,
        "ecosystem": ecosystem.lower().strip(),
        "package_name": package_name.strip(),
        "version": version.strip(),
        "size_bytes": size,
        "state": "collected",
        "archive": archive,
        "provenance": provenance or {},
    }


def list_artifacts(*, db_path: Optional[str] = None, ecosystem: str = "") -> list[Dict[str, Any]]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        query = "SELECT artifact_id, sha256, filename, ecosystem, package_name, version, size_bytes, state, created_at, updated_at FROM research_artifacts"
        args: tuple[Any, ...] = ()
        if ecosystem:
            query += " WHERE ecosystem = ?"
            args = (ecosystem.lower().strip(),)
        query += " ORDER BY updated_at DESC"
        return [dict(row) for row in connection.execute(query, args).fetchall()]


def get_artifact(artifact_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
    if row is None:
        raise ValueError(f"artifact not found: {artifact_id}")
    result = dict(row)
    path = Path(result["quarantine_path"])
    result["available"] = path.is_file() and _hash_and_validate(path)[0] == result["sha256"] if path.exists() else False
    result["provenance"] = json.loads(result.pop("provenance_json") or "{}")
    result["analysis"] = json.loads(result.pop("analysis_json") or "{}")
    result.pop("quarantine_path", None)
    return result


def verify_artifact(artifact_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT sha256, quarantine_path, state FROM research_artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
        if row is None:
            raise ValueError(f"artifact not found: {artifact_id}")
        path = Path(row["quarantine_path"])
        valid = path.is_file() and _hash_and_validate(path)[0] == row["sha256"] if path.exists() else False
        current = str(row["state"])
        if current == "purged":
            state = "purged"
        elif valid:
            state = "externally_supplied" if current == "externally_supplied" else "collected"
        else:
            state = "missing"
        connection.execute("UPDATE research_artifacts SET state = ?, updated_at = ? WHERE artifact_id = ?", (state, soc_store.utc_now(), artifact_id))
        connection.commit()
    return {"artifact_id": artifact_id, "valid": valid, "state": state}


def attach_to_case(case_id: str, artifact_id: str, *, role: str = "subject", db_path: Optional[str] = None, actor: str = "analyst") -> Dict[str, Any]:
    if role not in ATTACHMENT_ROLES:
        raise ValueError(f"role must be one of {sorted(ATTACHMENT_ROLES)}")
    soc_store.init_db(db_path)
    artifact = get_artifact(artifact_id, db_path=db_path)
    if not artifact.get("available"):
        raise ValueError("artifact is not available in local quarantine")
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute("INSERT OR IGNORE INTO research_case_artifacts (case_id, artifact_id, role, created_at) VALUES (?, ?, ?, ?)", (case_id, artifact_id, role, soc_store.utc_now()))
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (soc_store.utc_now(), case_id))
        connection.commit()
    return {"case_id": case_id, "artifact_id": artifact_id, "role": role}
