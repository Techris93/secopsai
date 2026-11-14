"""Blocklist of known-malicious package versions for the install firewall (frontier phase 5).

Built from ossf/malicious-packages OSV reports (and SecOpsAI's own confirmed
verdicts when supplied) into 256 small shards per ecosystem, keyed by the
first byte of the SHA-256 of the normalized package name, so the firewall
reads one small object per request. A report whose range starts at version 0
with no fix blocks every version of the package.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi"}


def normalize(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.strip().lower()


def shard_of(ecosystem: str, name: str) -> str:
    return hashlib.sha256(normalize(ecosystem, name).encode("utf-8")).hexdigest()[:2]


def _all_versions(affected: Dict[str, Any]) -> bool:
    for item in affected.get("ranges") or []:
        events = item.get("events") or []
        introduced = [event.get("introduced") for event in events if "introduced" in event]
        fixed = [event for event in events if "fixed" in event or "last_affected" in event]
        if "0" in introduced and not fixed:
            return True
    return False


def add_record(blocks: Dict[str, Dict[str, Dict[str, Any]]], record: Dict[str, Any], *, source: str = "osv") -> None:
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = ECOSYSTEMS.get(str(package.get("ecosystem") or ""))
        name = str(package.get("name") or "")
        if not ecosystem or not name:
            continue
        entry = blocks.setdefault(ecosystem, {}).setdefault(normalize(ecosystem, name), {"all": False, "versions": [], "ids": []})
        entry["all"] = entry["all"] or _all_versions(affected)
        entry["versions"] = sorted(set(entry["versions"]) | {str(version) for version in affected.get("versions") or []})
        if record.get("id") and record["id"] not in entry["ids"] and len(entry["ids"]) < 5:
            entry["ids"].append(str(record["id"]))
        entry.setdefault("sources", [])
        if source not in entry["sources"]:
            entry["sources"].append(source)


def from_osv(directories: Iterable[Path], blocks: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Dict[str, Any]]]:
    blocks = blocks if blocks is not None else {}
    for directory in directories:
        for path in Path(directory).rglob("*.json"):
            try:
                add_record(blocks, json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
    return blocks


def shards(blocks: Dict[str, Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """``{"npm/3f": {name: entry}, ...}``, every shard present (empty ones too, so stale entries are replaced)."""
    out: Dict[str, Dict[str, Dict[str, Any]]] = {f"{eco}/{index:02x}": {} for eco in ECOSYSTEMS.values() for index in range(256)}
    for ecosystem, names in blocks.items():
        for name, entry in names.items():
            out[f"{ecosystem}/{shard_of(ecosystem, name)}"][name] = entry
    return out


def blocked(blocks: Dict[str, Dict[str, Dict[str, Any]]], ecosystem: str, name: str, version: str) -> bool:
    entry = (blocks.get(ecosystem) or {}).get(normalize(ecosystem, name))
    return bool(entry) and (entry["all"] or version in entry["versions"])
