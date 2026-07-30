#!/usr/bin/env python3
"""Produce a bounded inventory of Python package metadata in a container image."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "secopsai.container-package-provenance.v1"
DEFAULT_PACKAGES = ("msgpack", "setuptools")
SKIP_PARTS = {"dev", "proc", "sys", "run", ".git", "node_modules"}
ARCHIVE_SUFFIXES = {".egg", ".whl", ".zip"}
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _metadata_record(text: str, *, path: str, source_type: str, archive_member: str = "") -> dict[str, Any] | None:
    parsed = Parser().parsestr(text)
    name = parsed.get("Name", "").strip()
    version = parsed.get("Version", "").strip()
    if not name or not version:
        return None
    return {
        "name": name,
        "normalized_name": _normalize(name),
        "version": version,
        "path": path,
        "source_type": source_type,
        "archive_member": archive_member,
    }


def _iter_files(root: Path) -> Iterable[Path]:
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        names[:] = [name for name in names if name not in SKIP_PARTS and not (current / name).is_symlink()]
        for filename in files:
            path = current / filename
            if not path.is_symlink():
                yield path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(root: Path, package_names: Iterable[str]) -> dict[str, Any]:
    wanted = {_normalize(name) for name in package_names}
    records: list[dict[str, Any]] = []
    archives: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for path in _iter_files(root):
        relative = "/" + str(path.relative_to(root)) if root != Path("/") else str(path)
        if path.name in {"METADATA", "PKG-INFO"}:
            try:
                record = _metadata_record(path.read_text(encoding="utf-8", errors="replace"), path=relative, source_type="filesystem_metadata")
                if record and record["normalized_name"] in wanted:
                    record["sha256"] = _sha256(path)
                    records.append(record)
            except OSError as exc:
                errors.append({"path": relative, "error": type(exc).__name__})
            continue

        if path.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
            if size > MAX_ARCHIVE_BYTES or not zipfile.is_zipfile(path):
                continue
            archive = {"path": relative, "size": size, "sha256": _sha256(path)}
            matches = 0
            with zipfile.ZipFile(path) as handle:
                members = handle.infolist()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    archive["skipped"] = "member_limit"
                    archives.append(archive)
                    continue
                for member in members:
                    if not member.filename.endswith((".dist-info/METADATA", ".egg-info/PKG-INFO")):
                        continue
                    if member.file_size > 4 * 1024 * 1024:
                        continue
                    text = handle.read(member).decode("utf-8", errors="replace")
                    record = _metadata_record(text, path=relative, source_type="embedded_archive", archive_member=member.filename)
                    if record and record["normalized_name"] in wanted:
                        record["archive_sha256"] = archive["sha256"]
                        records.append(record)
                        matches += 1
            if matches:
                archive["matching_metadata_records"] = matches
                archives.append(archive)
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            errors.append({"path": relative, "error": type(exc).__name__})

    active: list[dict[str, str]] = []
    if root == Path("/"):
        for distribution in importlib.metadata.distributions():
            name = distribution.metadata.get("Name", "")
            if _normalize(name) in wanted:
                active.append(
                    {
                        "name": name,
                        "normalized_name": _normalize(name),
                        "version": distribution.version,
                        "path": str(distribution.locate_file("")),
                    }
                )

    records.sort(key=lambda item: (item["normalized_name"], item["version"], item["path"], item["archive_member"]))
    active.sort(key=lambda item: (item["normalized_name"], item["version"], item["path"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "packages": sorted(wanted),
        "active_distributions": active,
        "metadata_records": records,
        "matching_archives": archives,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--package", action="append", dest="packages")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = collect(args.root.resolve(), args.packages or DEFAULT_PACKAGES)
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
