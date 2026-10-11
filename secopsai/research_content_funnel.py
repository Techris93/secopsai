"""Content scanning for registries beyond npm (PyPI, Open VSX, crates.io).

The collectors already record every new PyPI release and Open VSX extension
version, but only npm releases had their contents inspected.  Each cycle this
downloads the newest unscanned releases (bounded, newest first), scans them
in memory with the YARA rules and behaviour rules, and:

- marks each event ``content_prescan`` = clean / hit / error / skipped;
- for hits, raises a ``registry_release_anomaly`` research alert and queues
  model triage through the operator's bridge, exactly as npm hits do.

Nothing is executed; archives are read with the same safe extractor as npm.
"""

from __future__ import annotations

import json
import os
import re
import zlib
import secrets
import tempfile
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import soc_store
from secopsai import actor_fingerprint, package_features, version_diff, yara_engine
from secopsai.research_intake import SafeFetcher

ECOSYSTEMS: Tuple[str, ...] = ("pypi", "open-vsx", "crates", "vscode-marketplace", "mcp-registry")
MCP_PACKAGE_REGISTRIES = {"npm": "npm", "pypi": "pypi"}
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
OPENVSX_HOSTS = ("open-vsx.org", "openvsx.eclipsecontent.org")
PYPI_HOSTS = ("pypi.org",)
PYPI_FILE_HOSTS = ("files.pythonhosted.org",)
CRATES_FILE_HOSTS = ("static.crates.io",)
VSCODE_HOSTS = ("marketplace.visualstudio.com",)
MAX_DECOMPRESSED_BYTES = 100 * 1024 * 1024
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HIT_LEVELS = {"notice", "warning", "alert"}
SEVERITY = {"alert": "high", "warning": "medium", "notice": "low"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def limit_per_ecosystem() -> int:
    return max(0, min(int(os.environ.get("SECOPSAI_CONTENT_PRESCAN_LIMIT", "60") or 0), 500))


def resolve_artifact(fetcher: SafeFetcher, ecosystem: str, package: str, version: str) -> Tuple[str, Tuple[str, ...], str]:
    """(download url, allowed hosts, filename) for one release."""
    if ecosystem == "pypi":
        _u, _h, body = fetcher.get(f"https://pypi.org/pypi/{package}/{version}/json", allowed_hosts=PYPI_HOSTS, max_bytes=4 * 1024 * 1024)
        files = [item for item in json.loads(body).get("urls") or [] if int(item.get("size") or 0) <= MAX_ARTIFACT_BYTES]
        # sdists carry setup.py, where most PyPI malware runs.
        files.sort(key=lambda item: {"sdist": 0, "bdist_wheel": 1}.get(item.get("packagetype"), 2))
        if not files:
            raise LookupError("no artifact under the size limit")
        return str(files[0]["url"]), PYPI_FILE_HOSTS, str(files[0].get("filename") or "artifact")
    if ecosystem == "open-vsx":
        namespace, _, name = package.partition("/")
        if not namespace or not name:
            raise LookupError("Open VSX package must be namespace/name")
        _u, _h, body = fetcher.get(f"https://open-vsx.org/api/{namespace}/{name}/{version}", allowed_hosts=OPENVSX_HOSTS, max_bytes=2 * 1024 * 1024)
        url = str((json.loads(body).get("files") or {}).get("download") or "")
        if not url.startswith("https://open-vsx.org/"):
            raise LookupError("no Open VSX download link")
        return url, OPENVSX_HOSTS, f"{namespace}.{name}-{version}.vsix"
    if ecosystem == "vscode-marketplace":
        publisher, _, name = package.partition("/")
        if not SAFE_NAME.match(publisher) or not SAFE_NAME.match(name) or not SAFE_NAME.match(version):
            raise LookupError("Marketplace package must be publisher/name")
        return (f"https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisher}/vsextensions/{name}/{version}/vspackage",
                VSCODE_HOSTS, f"{publisher}.{name}-{version}.vsix")
    if ecosystem == "crates":
        quoted = urllib.parse.quote(package, safe="")
        return (f"https://static.crates.io/crates/{quoted}/{quoted}-{urllib.parse.quote(version, safe='')}.crate",
                CRATES_FILE_HOSTS, f"{package}-{version}.crate")
    raise LookupError(f"unsupported ecosystem {ecosystem}")


def _gunzip(raw: bytes) -> bytes:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    data = decompressor.decompress(raw, MAX_DECOMPRESSED_BYTES + 1)
    if len(data) > MAX_DECOMPRESSED_BYTES or decompressor.unconsumed_tail:
        raise ValueError("decompressed artifact exceeds the safety limit")
    return data


def _resolve_npm(fetcher: SafeFetcher, package: str, version: str) -> Tuple[str, Tuple[str, ...], str]:
    _u, _h, body = fetcher.get(f"https://registry.npmjs.org/{package.replace('/', '%2F')}/{version}", allowed_hosts=("registry.npmjs.org",), max_bytes=4 * 1024 * 1024)
    tarball = str((json.loads(body).get("dist") or {}).get("tarball") or "")
    if not tarball.startswith("https://registry.npmjs.org/"):
        raise LookupError("no npm tarball")
    return tarball, ("registry.npmjs.org",), "package.tgz"


def scan_release(fetcher: SafeFetcher, ecosystem: str, package: str, version: str, *, rules_ecosystem: str = "") -> Dict[str, Any]:
    from secopsai.artifact_fleet import _safe_archive_files

    try:
        url, hosts, filename = _resolve_npm(fetcher, package, version) if ecosystem == "npm" else resolve_artifact(fetcher, ecosystem, package, version)
    except LookupError as exc:
        return {"status": "skipped", "reason": str(exc)[:200]}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)[:200]}
    try:
        _u, headers, raw = fetcher.get(url, allowed_hosts=hosts, max_bytes=MAX_ARTIFACT_BYTES)
        if "gzip" in str(headers.get("content-encoding") or "").lower() and raw[:2] == b"\x1f\x8b":
            raw = _gunzip(raw)  # the Marketplace serves .vsix gzip-encoded
        members: List[Tuple[str, bytes]] = []
        with tempfile.TemporaryDirectory(prefix="secopsai-content-") as tmp:
            path = Path(tmp) / Path(filename).name
            path.write_bytes(raw)
            _safe_archive_files(path, members)
        flags = package_features.profile(members, version=version)
        flags, diff = version_diff.with_diff(fetcher, ecosystem, package, version, flags)
        scanned = package_features.combine(yara_engine.scan_files(members), flags, rules_ecosystem or ecosystem, members)
    except Exception as exc:  # one bad archive must not stop the batch
        reason = str(exc)[:200]
        return {"status": "skipped" if "safety limit" in reason or "maximum size" in reason or "too many" in reason else "error", "reason": reason}
    findings = [item for item in scanned.get("findings") or [] if item.get("rule_id") != "YARA-SCAN-ERROR"]
    level = str(scanned.get("level") or "none")
    return {"fingerprints": actor_fingerprint.from_members(members) if level in HIT_LEVELS else {},
            "status": "hit" if level in HIT_LEVELS else "clean", "score": int(scanned.get("score") or 0), "level": level,
            "rules_matched": scanned.get("rules_matched") or [], "findings": findings[:20], "features": flags, "files": len(members), "bytes": len(raw), "diff": diff}


def _scan_mcp(fetcher: SafeFetcher, metadata: Dict[str, Any], scan: Callable[..., Dict[str, Any]]) -> Dict[str, Any]:
    """Scan the npm/PyPI package an MCP server ships, with MCP rules applied."""
    for item in metadata.get("packages") or []:
        registry = MCP_PACKAGE_REGISTRIES.get(str(item.get("registry") or "").lower())
        if registry and item.get("identifier") and item.get("version"):
            result = scan(fetcher, registry, str(item["identifier"]), str(item["version"]), rules_ecosystem="mcp-registry")
            return {**result, "scanned_package": f"{registry}:{item['identifier']}@{item['version']}"}
    return {"status": "skipped", "reason": "remote-only server or no npm/PyPI package"}


def _pending(db_path: Optional[str], ecosystem: str, limit: int) -> List[Dict[str, Any]]:
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            """SELECT feed_event_id, ecosystem, package, version, registry_timestamp, metadata_json FROM registry_feed_events
               WHERE ecosystem = ? AND version <> '' AND event_type NOT LIKE '%removed%'
                 AND json_extract(metadata_json, '$.content_prescan') IS NULL
               ORDER BY registry_timestamp DESC LIMIT ?""",
            (ecosystem, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def _raise_alert(event: Dict[str, Any], result: Dict[str, Any], db_path: Optional[str]) -> str:
    key = f"{event['ecosystem']}:{event['package']}@{event['version']}"
    now = _now()
    evidence = {
        "source": "content_funnel", "ecosystem": event["ecosystem"], "package": event["package"], "version": event["version"],
        "registry_timestamp": event.get("registry_timestamp"), "score": result["score"], "level": result["level"],
        "rules": result["rules_matched"][:20], "behaviours": result.get("features", [])[:30],
        "findings": [{field: item.get(field) for field in ("rule_id", "file_path", "matched_indicator", "rule_author", "rule_reference")} for item in result["findings"][:10]],
    }
    reason = f"Content scan flagged {key}: {', '.join(result['rules_matched'][:5])} (score {result['score']})"
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_alerts (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
                   reason, evidence_json, status, owner, created_at, updated_at)
               VALUES (?, 'registry_release_anomaly', ?, NULL, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
               ON CONFLICT(dedupe_key) DO NOTHING""",
            (f"RAL-{secrets.token_hex(8).upper()}", SEVERITY.get(result["level"], "low"), f"content-funnel:{key}", reason, json.dumps(evidence, sort_keys=True), now, now),
        )
        connection.commit()
    return key


def run(*, db_path: Optional[str] = None, fetcher: Optional[SafeFetcher] = None, limit: Optional[int] = None,
        scanner: Optional[Callable[[SafeFetcher, str, str, str], Dict[str, Any]]] = None, workers: int = 8) -> Dict[str, Any]:
    """Scan the newest unscanned PyPI and Open VSX releases.  Safe to call every cycle."""
    from secopsai import research_ai_triage

    if not yara_engine.status().get("available"):
        return {"enabled": False, "reason": "YARA rules unavailable"}
    per_ecosystem = limit_per_ecosystem() if limit is None else limit
    fetcher = fetcher or SafeFetcher(timeout=30)
    scan = scanner or scan_release
    stats: Dict[str, Any] = {"enabled": True}
    for ecosystem in ECOSYSTEMS:
        events = _pending(db_path, ecosystem, per_ecosystem)
        with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as pool:
            if ecosystem == "mcp-registry":
                results = list(pool.map(lambda event: _scan_mcp(fetcher, json.loads(event.get("metadata_json") or "{}"), scan), events))
            else:
                results = list(pool.map(lambda event: scan(fetcher, ecosystem, event["package"], event["version"]), events))
        counts = {"scanned": len(events), "hits": 0, "clean": 0, "errors": 0, "skipped": 0, "rules_matched": {}}
        now = _now()
        for event, result in zip(events, results):
            status = result.get("status", "error")
            counts["hits" if status == "hit" else "clean" if status == "clean" else "skipped" if status == "skipped" else "errors"] += 1
            record = {"status": status, "at": now, **{key: result[key] for key in ("score", "level", "rules_matched", "files", "scanned_package") if key in result}}
            if result.get("reason"):
                record["reason"] = result["reason"]
            with closing(soc_store.connect(db_path)) as connection:
                connection.execute("UPDATE registry_feed_events SET metadata_json = json_set(metadata_json, '$.content_prescan', json(?)) WHERE feed_event_id = ?",
                                   (json.dumps(record), event["feed_event_id"]))
                connection.commit()
            if status == "hit":
                for rule in result.get("rules_matched") or []:
                    counts["rules_matched"][rule] = counts["rules_matched"].get(rule, 0) + 1
                _raise_alert(event, result, db_path)
                research_ai_triage.record_hit(ecosystem=ecosystem, package=event["package"], version=event["version"], prescan=result,
                                              metadata_signals=[{"id": "behaviours", "flags": result.get("features", [])[:30]}], db_path=db_path)
        stats[ecosystem] = counts
    return stats
