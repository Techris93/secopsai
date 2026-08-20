"""Nextron-style OSS artifact funnel for SecOpsAI.

The implementation is intentionally safe-by-default: metadata indexing never
downloads artifacts, static scanning never executes code, and model triage
receives only minimized rule-hit context. The local SQLite queue is also the
fixture backend for a hosted worker implementation.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import tarfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from secopsai.supply_chain import analyze_ecosystem_files


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = ROOT / "data" / "artifact_fleet" / "artifact_fleet.db"
RULE_DIR = ROOT / "rules" / "yara"
MAX_PAGE = 500
MAX_ARCHIVE_FILES = 5_000
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
CONTEXT_BYTES = 2_048
ARTIFACT_ID_RE = re.compile(r"^ART-[A-F0-9]{16}$")
URL_RE = re.compile(r"https?://[^\s\"'<>]{4,500}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
HASH_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.IGNORECASE)

REGISTRY_SOURCES = (
    "npm", "pypi", "crates", "nuget", "packagist", "go", "maven", "rubygems",
    "open-vsx", "visual-studio-marketplace", "chrome-web-store", "edge-addons",
    "firefox-addons", "clawhub",
)

GENERIC_RULES: tuple[dict[str, Any], ...] = (
    {"rule_id": "OSS-BUILD-HOOK", "pattern": r"(?i)(build\.rs|postinstall|preinstall|setup\.py|composer\.json.*autoload\.files)", "severity": "medium", "description": "Build or install hook present."},
    {"rule_id": "OSS-DOWNLOAD-EXECUTE", "pattern": r"(?i)(curl|wget|Invoke-WebRequest|DownloadString|fetch\s*\(|requests\.(get|post)|ureq|reqwest).{0,240}(exec|spawn|powershell|bash|sh\s+-c|Command::new)", "severity": "high", "description": "Network retrieval is combined with execution behavior."},
    {"rule_id": "OSS-CREDENTIAL-DISCOVERY", "pattern": r"(?i)(\.ssh|\.npmrc|\.pypirc|\.aws/credentials|\.config/gcloud|\.kube/config|GITHUB_TOKEN|AWS_SECRET|GOOGLE_APPLICATION_CREDENTIALS|/proc/.*/environ|/var/run/secrets)", "severity": "high", "description": "Credential or cloud-secret discovery indicator."},
    {"rule_id": "OSS-POWERSHELL-STAGING", "pattern": r"(?i)(powershell(?:\.exe)?|pwsh).{0,200}(enc|download|invoke|start-process|iex|frombase64string)", "severity": "high", "description": "PowerShell download, decoding, or execution indicator."},
    {"rule_id": "OSS-WINDOWS-PERSISTENCE", "pattern": r"(?i)(CurrentVersion\\Run|RunOnce|HKCU|registry.*startup)", "severity": "high", "description": "Windows startup persistence indicator."},
    {"rule_id": "OSS-BROWSER-DATA", "pattern": r"(?i)(Chrome|Chromium|Brave|Edge).{0,180}(login|credential|cookie|extension|history)", "severity": "high", "description": "Browser credential or extension enumeration indicator."},
    {"rule_id": "OSS-C2-DGA", "pattern": r"(?i)(domain.?generation|DGA|fallback.{0,80}domain|dns.{0,80}random|five.?day)", "severity": "high", "description": "DGA or generated fallback C2 indicator."},
    {"rule_id": "OSS-RUST-PROC-MACRO", "pattern": r"(?i)(proc_macro|proc-macro|build\.rs).{0,260}(std::process|Command::new|std::env|reqwest|ureq|curl|wget|std::fs)", "severity": "high", "description": "Rust proc-macro/build script has process, network, filesystem, or environment behavior."},
    {"rule_id": "OSS-C2-IP-PORT", "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", "severity": "high", "description": "Hard-coded IP and port indicator."},
)


@dataclass(frozen=True)
class ArtifactMetadata:
    ecosystem: str
    package: str
    version: str
    publisher: str = ""
    published_at: str = ""
    dist_url: str = ""
    source_url: str = ""
    source_ref: str = ""
    source_revision: str = ""
    advisory_ids: tuple[str, ...] = ()
    size_bytes: int | None = None
    sha256: str = ""
    trust: str = "registry"

    def as_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "advisory_ids": list(self.advisory_ids)}


def _db_path(value: str | Path | None = None) -> Path:
    return Path(value or os.environ.get("SECOPSAI_ARTIFACT_FLEET_DB_PATH") or DEFAULT_DB_PATH).expanduser().resolve()


def _connect(path: str | Path | None = None) -> sqlite3.Connection:
    target = _db_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        pass
    conn = sqlite3.connect(target, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(path: str | Path | None = None) -> Path:
    target = _db_path(path)
    with _connect(target) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifact_metadata (
                artifact_id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                publisher TEXT NOT NULL,
                published_at TEXT NOT NULL,
                dist_url TEXT NOT NULL,
                source_url TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                source_revision TEXT NOT NULL,
                advisory_ids_json TEXT NOT NULL,
                size_bytes INTEGER,
                sha256 TEXT NOT NULL,
                trust TEXT NOT NULL,
                status TEXT NOT NULL,
                indexed_at TEXT NOT NULL,
                UNIQUE(ecosystem, package, version, source_revision)
            );
            CREATE INDEX IF NOT EXISTS idx_artifact_metadata_published ON artifact_metadata(published_at DESC, artifact_id DESC);
            CREATE INDEX IF NOT EXISTS idx_artifact_metadata_status ON artifact_metadata(status, indexed_at DESC);
            CREATE TABLE IF NOT EXISTS artifact_queue (
                queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT NOT NULL,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(artifact_id, stage)
            );
            CREATE INDEX IF NOT EXISTS idx_artifact_queue_stage_status ON artifact_queue(stage, status, created_at ASC);
            CREATE TABLE IF NOT EXISTS artifact_scans (
                scan_id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                status TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                files_json TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                duration_ms REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifact_scans_artifact ON artifact_scans(artifact_id, scanned_at DESC);
            CREATE TABLE IF NOT EXISTS artifact_triage (
                triage_id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                model TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 0,
                context_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                analyst_required INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_sources (
                source TEXT PRIMARY KEY,
                cursor_value TEXT NOT NULL,
                status TEXT NOT NULL,
                last_success_at TEXT NOT NULL,
                last_error_at TEXT NOT NULL,
                indexed_count INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_dead_letters (
                dead_letter_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                retryable INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                stage TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _artifact_id(eco: str, package: str, version: str, source_revision: str = "") -> str:
    token = "|".join((eco, package, version, source_revision))
    return f"ART-{hashlib.sha256(token.encode()).hexdigest()[:16].upper()}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _text(value: Any, limit: int = 1000) -> str:
    return str(value or "").strip()[:limit]


def _validate_metadata(item: dict[str, Any]) -> ArtifactMetadata:
    ecosystem = _text(item.get("ecosystem"), 50).lower()
    if ecosystem not in REGISTRY_SOURCES and ecosystem not in {"chrome-web-store", "open-vsx"}:
        raise ValueError(f"unsupported artifact ecosystem: {ecosystem}")
    package = _text(item.get("package") or item.get("name"), 260)
    version = _text(item.get("version") or item.get("revision"), 160)
    if not package or not version:
        raise ValueError("artifact package and version are required")
    advisory_ids = tuple(_text(value, 160) for value in (item.get("advisory_ids") or []) if _text(value, 160))
    return ArtifactMetadata(
        ecosystem=ecosystem, package=package, version=version,
        publisher=_text(item.get("publisher") or item.get("maintainer"), 240),
        published_at=_text(item.get("published_at") or item.get("publish_time"), 40),
        dist_url=_text(item.get("dist_url") or item.get("artifact_url"), 600),
        source_url=_text(item.get("source_url"), 600), source_ref=_text(item.get("source_ref"), 300),
        source_revision=_text(item.get("source_revision") or item.get("commit") or item.get("tag"), 300),
        advisory_ids=advisory_ids, size_bytes=item.get("size_bytes"), sha256=_text(item.get("sha256"), 64),
        trust=_text(item.get("trust") or "registry", 60),
    )


def index_records(records: Iterable[dict[str, Any]], *, source: str, cursor: str = "", db_path: str | Path | None = None) -> dict[str, Any]:
    target = init_db(db_path)
    indexed = 0
    duplicates = 0
    dead = 0
    now = _now()
    with _connect(target) as conn:
        for raw in list(records)[:MAX_PAGE * 20]:
            try:
                metadata = _validate_metadata(raw)
                artifact_id = _artifact_id(metadata.ecosystem, metadata.package, metadata.version, metadata.source_revision)
                conn.execute(
                    """INSERT INTO artifact_metadata
                    (artifact_id, ecosystem, package, version, publisher, published_at, dist_url, source_url,
                     source_ref, source_revision, advisory_ids_json, size_bytes, sha256, trust, status, indexed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'indexed', ?)
                    ON CONFLICT(ecosystem, package, version, source_revision) DO UPDATE SET publisher=excluded.publisher,
                    published_at=excluded.published_at, dist_url=excluded.dist_url, source_url=excluded.source_url,
                    advisory_ids_json=excluded.advisory_ids_json, size_bytes=excluded.size_bytes, sha256=excluded.sha256,
                    trust=excluded.trust, indexed_at=excluded.indexed_at""",
                    (artifact_id, metadata.ecosystem, metadata.package, metadata.version, metadata.publisher, metadata.published_at, metadata.dist_url, metadata.source_url, metadata.source_ref, metadata.source_revision, _json(list(metadata.advisory_ids)), metadata.size_bytes, metadata.sha256, metadata.trust, now),
                )
                if conn.execute("SELECT changes()").fetchone()[0]:
                    indexed += 1
                queue_payload = {**metadata.as_dict(), "artifact_id": artifact_id, "artifact_path": _text(raw.get("artifact_path"), 800)}
                conn.execute("INSERT OR IGNORE INTO artifact_queue(artifact_id, stage, status, payload_json, created_at, updated_at) VALUES (?, 'scan', 'pending', ?, ?, ?)", (artifact_id, _json(queue_payload), now, now))
            except Exception as exc:
                dead += 1
                conn.execute("INSERT INTO artifact_dead_letters(dead_letter_id, source, artifact_id, reason, retryable, payload_json, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)", (_artifact_id("dead", source, str(dead), now), source, "", _text(exc, 1000), _json(raw), now))
        conn.execute("INSERT INTO artifact_sources(source, cursor_value, status, last_success_at, last_error_at, indexed_count, metadata_json, updated_at) VALUES (?, ?, 'healthy', ?, '', ?, ?, ?) ON CONFLICT(source) DO UPDATE SET cursor_value=excluded.cursor_value, status='healthy', last_success_at=excluded.last_success_at, indexed_count=artifact_sources.indexed_count+excluded.indexed_count, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at", (source, _text(cursor, 400), now, indexed, _json({"duplicates": duplicates, "dead_letters": dead}), now))
        conn.commit()
    return {"source": source, "cursor": cursor, "indexed": indexed, "duplicates": duplicates, "dead_letters": dead, "status": "healthy", "db_path": str(target)}


def index_live_sources(*, since: str = "24h", limit: int = 1000, sources: Iterable[str] | None = None, db_path: str | Path | None = None) -> dict[str, Any]:
    """Bridge existing bounded registry collectors into the artifact index.

    Sources without a safe global metadata adapter remain explicitly
    ``not_configured``. This keeps the index stage honest and prevents a
    package-scoped watcher from being presented as a full-registry census.
    """
    try:
        from secopsai.research_surveillance import COLLECTOR_DEFINITIONS, list_feed_events, run_registry_collector
    except ImportError as exc:
        return {"status": "degraded", "error": str(exc), "sources": []}
    selected = list(sources or REGISTRY_SOURCES)
    results: list[dict[str, Any]] = []
    for source in selected:
        if source not in COLLECTOR_DEFINITIONS:
            results.append({"source": source, "status": "not_configured", "indexed": 0, "message": "No global metadata collector is configured for this source."})
            continue
        try:
            collector_result = run_registry_collector(ecosystem=source, since=None, max_pages=max(1, min(int(limit // 100 or 1), 50)), fetch_leaves=False, db_path=db_path)
            collector_id = COLLECTOR_DEFINITIONS[source]["collector_id"]
            events = list_feed_events(collector_id=collector_id, limit=max(1, min(int(limit), MAX_PAGE)), db_path=db_path)
            records = []
            for event in events:
                records.append({"ecosystem": source, "package": event.get("package"), "version": event.get("version") or "unknown", "published_at": event.get("registry_timestamp") or event.get("observed_at"), "source_url": event.get("source_url") or "", "source_revision": event.get("idempotency_key") or "", "advisory_ids": [], "trust": "registry"})
            indexed = index_records(records, source=source, cursor=str(collector_result.get("cursor_after") or ""), db_path=db_path)
            results.append({"source": source, "status": "healthy", "collector": collector_result, "index": indexed})
        except Exception as exc:
            results.append({"source": source, "status": "degraded", "error": str(exc)[:1000]})
    return {"status": "completed", "since": since, "limit": limit, "sources": results, "configured_sources": sum(1 for item in results if item.get("status") == "healthy")}


def scan_pending(*, limit: int = 100, workers: int = 4, db_path: str | Path | None = None) -> dict[str, Any]:
    """Scan pending fixture-backed rows with bounded worker concurrency.

    A hosted worker may replace the fixture path with a verified registry
    download implementation. Rows without an authorized local artifact remain
    pending instead of silently downloading or executing anything.
    """
    target = init_db(db_path)
    bounded = max(1, min(int(limit), MAX_PAGE))
    with _connect(target) as conn:
        rows = conn.execute("SELECT * FROM artifact_queue WHERE stage='scan' AND status='pending' ORDER BY created_at ASC LIMIT ?", (bounded,)).fetchall()
    jobs = []
    for row in rows:
        payload = json.loads(row["payload_json"])
        if payload.get("artifact_path"):
            jobs.append(payload)
    completed = 0
    pending = len(rows) - len(jobs)
    errors = []
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), 32))) as pool:
        futures = {
            pool.submit(scan_artifact, ecosystem=job["ecosystem"], package=job["package"], version=job["version"], artifact=job["artifact_path"], source_reference=job.get("source_url") or job.get("dist_url") or "", db_path=target): job
            for job in jobs
        }
        for future in as_completed(futures):
            job = futures[future]
            try:
                result = future.result()
                with _connect(target) as conn:
                    conn.execute("UPDATE artifact_queue SET status='complete', updated_at=? WHERE artifact_id=? AND stage='scan'", (_now(), job["artifact_id"]))
                    conn.commit()
                completed += 1
            except Exception as exc:
                errors.append({"artifact_id": job.get("artifact_id"), "error": str(exc)[:1000]})
                with _connect(target) as conn:
                    conn.execute("UPDATE artifact_queue SET status='failed', attempts=attempts+1, updated_at=? WHERE artifact_id=? AND stage='scan'", (_now(), job["artifact_id"]))
                    conn.commit()
    return {"status": "completed", "processed": completed, "pending_artifacts": pending, "errors": errors, "workers": max(1, min(int(workers), 32))}


def list_artifacts(*, status: str = "", limit: int = 100, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    target = init_db(db_path)
    bounded = max(1, min(int(limit), MAX_PAGE))
    where = ""
    params: list[Any] = []
    if status:
        where = "WHERE status=?"
        params.append(_text(status, 40))
    params.append(bounded)
    with _connect(target) as conn:
        rows = conn.execute(f"SELECT * FROM artifact_metadata {where} ORDER BY indexed_at DESC, artifact_id DESC LIMIT ?", params).fetchall()
    return [dict(row) for row in rows]


def _safe_archive_files(path: Path) -> tuple[dict[str, str], list[dict[str, Any]], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("artifact exceeds the maximum size")
    files: dict[str, str] = {}
    metadata: list[dict[str, Any]] = []
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_FILES:
                raise ValueError("artifact contains too many files")
            total = 0
            for member in members:
                name = member.filename.replace("\\", "/")
                if name.startswith("/") or ".." in Path(name).parts or member.is_dir() or member.external_attr >> 16 & 0o170000 == 0o120000:
                    raise ValueError("artifact contains an unsafe path or link")
                total += member.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("expanded artifact exceeds the safety limit")
                data = archive.read(member)
                metadata.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                if len(data) <= MAX_FILE_BYTES:
                    try:
                        files[name] = data.decode("utf-8")
                    except UnicodeDecodeError:
                        pass
    elif tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_FILES:
                raise ValueError("artifact contains too many files")
            total = 0
            for member in members:
                name = member.name.replace("\\", "/")
                if name.startswith("/") or ".." in Path(name).parts or member.issym() or member.islnk() or not member.isfile():
                    raise ValueError("artifact contains an unsafe path or link")
                total += member.size
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("expanded artifact exceeds the safety limit")
                handle = archive.extractfile(member)
                data = handle.read(MAX_FILE_BYTES + 1) if handle else b""
                if len(data) > MAX_FILE_BYTES:
                    data = data[:MAX_FILE_BYTES]
                metadata.append({"path": name, "size": member.size, "sha256": hashlib.sha256(data).hexdigest()})
                try:
                    files[name] = data.decode("utf-8")
                except UnicodeDecodeError:
                    pass
    else:
        data = raw[:MAX_FILE_BYTES]
        try:
            files[path.name] = data.decode("utf-8")
        except UnicodeDecodeError:
            metadata.append({"path": path.name, "size": len(raw), "sha256": digest, "format": _binary_format(raw)})
    return files, metadata, digest


def _binary_format(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"\xcf\xfa\xed\xfe") or data.startswith(b"\xfe\xed\xfa\xcf"):
        return "Mach-O"
    return "unknown"


def _rule_pack_findings(files: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path, source in files.items():
        searchable = f"{path}\n{source}"
        for rule in GENERIC_RULES:
            for match in re.finditer(rule["pattern"], searchable):
                source_start = max(0, match.start() - len(path))
                start = max(0, source_start - CONTEXT_BYTES // 2)
                end = min(len(source), source_start + CONTEXT_BYTES // 2)
                findings.append({"rule_id": rule["rule_id"], "severity": rule["severity"], "confidence": "high" if rule["severity"] == "high" else "medium", "file_path": path, "matched_indicator": rule["description"], "safe_context": source[start:end][:CONTEXT_BYTES], "recommended_mitigation": "Quarantine and review the artifact before installation."})
    return _dedupe_findings(findings)


def validate_rule_pack(rule_dir: str | Path | None = None) -> dict[str, Any]:
    directory = Path(rule_dir or RULE_DIR)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "secopsai.artifact-rule-pack.v1":
        raise ValueError("unsupported artifact rule-pack schema")
    rule_ids = {str(item.get("rule_id")) for item in manifest.get("rules") or []}
    if not rule_ids or any(not re.fullmatch(r"[A-Z0-9-]{3,120}", value) for value in rule_ids):
        raise ValueError("rule-pack metadata contains an invalid rule ID")
    yara_files = []
    compiler = "structural"
    try:
        import yara  # type: ignore
    except ImportError:
        yara = None
    for path in sorted(directory.glob("*.yar")):
        source = path.read_text(encoding="utf-8")
        if source.count("{") != source.count("}") or not re.search(r"(?m)^rule\s+[A-Za-z0-9_]+", source):
            raise ValueError(f"invalid YARA structure: {path.name}")
        if yara is not None:
            yara.compile(source=source)
            compiler = "yara-python"
        yara_files.append(path.name)
    return {"status": "valid", "pack_id": manifest.get("pack_id"), "version": manifest.get("version"), "rule_count": len(rule_ids), "yara_files": yara_files, "compiler": compiler}


def _dedupe_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for item in findings:
        key = (_text(item.get("rule_id"), 120), _text(item.get("file_path"), 500))
        result.setdefault(key, item)
    return list(result.values())


def _extract_iocs(files: dict[str, str]) -> dict[str, list[str]]:
    text = "\n".join(files.values())
    urls = sorted(set(URL_RE.findall(text)))[:100]
    ips = sorted(set(IP_RE.findall(text)))[:100]
    hashes = sorted(set(HASH_RE.findall(text)))[:100]
    domains = sorted(set(DOMAIN_RE.findall(text)) - {"example.com", "example.test"})[:100]
    return {"urls": urls, "ips": ips, "hashes": hashes, "domains": domains}


def scan_artifact(*, ecosystem: str, package: str, version: str, artifact: str | Path, source_reference: str = "", db_path: str | Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    target = init_db(db_path)
    path = Path(artifact).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(str(path))
    files, file_metadata, digest = _safe_archive_files(path)
    deterministic = analyze_ecosystem_files(ecosystem, files)
    findings = _rule_pack_findings(files)
    for detail in deterministic.get("findings", []) if isinstance(deterministic, dict) else []:
        findings.append({"rule_id": "SECOPSAI-ECOSYSTEM", "severity": "high" if "credential" in str(detail).lower() or "network" in str(detail).lower() else "medium", "confidence": "high", "file_path": str(detail).split(":", 1)[0], "matched_indicator": str(detail)[:1000], "safe_context": str(detail)[:CONTEXT_BYTES], "recommended_mitigation": "Quarantine and review the artifact before installation."})
    findings = _dedupe_findings(findings)
    artifact_id = _artifact_id(ecosystem, package, version, digest)
    for item in findings:
        item.update({"artifact_id": artifact_id, "ecosystem": ecosystem, "package": package, "version": version, "sha256": digest, "source_reference": source_reference})
    result = {"artifact_id": artifact_id, "ecosystem": ecosystem, "package": package, "version": version, "sha256": digest, "status": "flagged" if findings else "clean", "findings": findings, "iocs": _extract_iocs(files), "files": file_metadata[:MAX_ARCHIVE_FILES], "source_reference": source_reference, "execution_performed": False, "duration_ms": round((time.perf_counter() - started) * 1000, 2)}
    now = _now()
    with _connect(target) as conn:
        conn.execute("INSERT OR IGNORE INTO artifact_metadata(artifact_id, ecosystem, package, version, publisher, published_at, dist_url, source_url, source_ref, source_revision, advisory_ids_json, size_bytes, sha256, trust, status, indexed_at) VALUES (?, ?, ?, ?, '', '', '', '', ?, ?, '[]', ?, ?, 'local-artifact', ?, ?)", (artifact_id, ecosystem, package, version, source_reference, "", path.stat().st_size, digest, result["status"], now))
        conn.execute("INSERT OR REPLACE INTO artifact_scans(scan_id, artifact_id, status, sha256, findings_json, files_json, scanned_at, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (_artifact_id("SCN", artifact_id, now), artifact_id, result["status"], digest, _json(findings), _json(file_metadata), now, result["duration_ms"]))
        conn.execute("UPDATE artifact_metadata SET status=?, sha256=? WHERE artifact_id=?", (result["status"], digest, artifact_id))
        if findings:
            context = build_triage_context(result)
            conn.execute("INSERT OR REPLACE INTO artifact_triage(triage_id, artifact_id, status, model, verdict, confidence, context_json, result_json, analyst_required, created_at, updated_at) VALUES (?, ?, 'awaiting_model', '', 'pending', 0, ?, '{}', 0, ?, ?)", (_artifact_id("TRI", artifact_id, now), artifact_id, _json(context), now, now))
            conn.execute("INSERT OR IGNORE INTO artifact_queue(artifact_id, stage, status, payload_json, created_at, updated_at) VALUES (?, 'triage', 'pending', ?, ?, ?)", (artifact_id, _json(context), now, now))
        conn.commit()
    return result


def build_triage_context(result: dict[str, Any]) -> dict[str, Any]:
    if not result.get("findings"):
        raise ValueError("clean artifacts must not enter model triage")
    return {"artifact_id": result.get("artifact_id"), "ecosystem": result.get("ecosystem"), "package": result.get("package"), "version": result.get("version"), "sha256": result.get("sha256"), "source_reference": result.get("source_reference"), "findings": [{key: item.get(key) for key in ("rule_id", "severity", "confidence", "file_path", "matched_indicator", "safe_context", "recommended_mitigation")} for item in result.get("findings", [])[:100]], "iocs": result.get("iocs") or {}, "execution_performed": False}


def triage_artifact(artifact_id: str, *, model: str = "", model_call: Callable[[dict[str, Any]], dict[str, Any]] | None = None, db_path: str | Path | None = None) -> dict[str, Any]:
    target = init_db(db_path)
    with _connect(target) as conn:
        row = conn.execute("SELECT * FROM artifact_triage WHERE artifact_id=?", (artifact_id,)).fetchone()
        if not row:
            raise ValueError("artifact is not queued for triage")
        context = json.loads(row["context_json"])
    if model_call is None:
        return {"artifact_id": artifact_id, "status": "awaiting_model", "model": model, "context": context, "analyst_required": False}
    response = model_call(context)
    verdict = _text(response.get("verdict"), 40).lower()
    if verdict not in {"benign", "likely_benign", "suspicious", "inconclusive"}:
        raise ValueError("model verdict is invalid")
    confidence = max(0, min(int(response.get("confidence") or 0), 100))
    analyst_required = verdict in {"suspicious", "inconclusive"}
    status = "analyst_review" if analyst_required else "resolved"
    now = _now()
    with _connect(target) as conn:
        conn.execute("UPDATE artifact_triage SET status=?, model=?, verdict=?, confidence=?, result_json=?, analyst_required=?, updated_at=? WHERE artifact_id=?", (status, _text(model, 200), verdict, confidence, _json(response), int(analyst_required), now, artifact_id))
        conn.execute("UPDATE artifact_queue SET status='complete', updated_at=? WHERE artifact_id=? AND stage='triage'", (now, artifact_id))
        conn.commit()
    return {"artifact_id": artifact_id, "status": status, "model": model, "verdict": verdict, "confidence": confidence, "analyst_required": analyst_required, "result": response}


def enqueue_model_triage(
    artifact_id: str,
    *,
    model: str = "",
    db_path: str | Path | None = None,
    job_db_path: str | Path | None = None,
    requested_by: str = "artifact-fleet",
) -> dict[str, Any]:
    """Queue one minimized artifact context for the configured model bridge."""
    triage = triage_show(artifact_id, db_path=db_path)
    from secopsai.intelligence_jobs import enqueue_job

    job = enqueue_job(
        action="triage_artifact",
        target_id=artifact_id,
        inputs={"artifact_id": artifact_id, "selected_model": model, "artifact_db_path": str(_db_path(db_path))},
        requested_by=requested_by,
        idempotency_key=f"artifact-triage:{artifact_id}:{model}",
        db_path=job_db_path or db_path,
    )
    target = init_db(db_path)
    with _connect(target) as conn:
        conn.execute("UPDATE artifact_triage SET status='awaiting_model', model=?, updated_at=? WHERE artifact_id=?", (_text(model, 200), _now(), artifact_id))
        conn.commit()
    return {"artifact_id": artifact_id, "status": "awaiting_model", "job": job, "context": triage.get("context")}


def record_model_result(artifact_id: str, response: dict[str, Any], *, model: str = "", db_path: str | Path | None = None) -> dict[str, Any]:
    raw_verdict = _text(response.get("artifact_verdict") or response.get("finding_verdict") or response.get("verdict_recommendation"), 60).lower()
    verdict_map = {"true_positive": "suspicious", "needs_more_evidence": "inconclusive", "benign_expected": "benign", "false_positive": "likely_benign"}
    verdict = verdict_map.get(raw_verdict, raw_verdict)
    if verdict not in {"benign", "likely_benign", "suspicious", "inconclusive"}:
        verdict = "inconclusive"
    confidence = max(0, min(int(response.get("artifact_confidence") or response.get("finding_confidence") or response.get("verdict_confidence") or 0), 100))
    analyst_required = verdict in {"suspicious", "inconclusive"}
    status = "analyst_review" if analyst_required else "resolved"
    target = init_db(db_path)
    now = _now()
    with _connect(target) as conn:
        conn.execute("UPDATE artifact_triage SET status=?, model=?, verdict=?, confidence=?, result_json=?, analyst_required=?, updated_at=? WHERE artifact_id=?", (status, _text(model, 200), verdict, confidence, _json(response), int(analyst_required), now, artifact_id))
        conn.execute("UPDATE artifact_queue SET status='complete', updated_at=? WHERE artifact_id=? AND stage='triage'", (now, artifact_id))
        conn.commit()
    return {"artifact_id": artifact_id, "status": status, "verdict": verdict, "confidence": confidence, "analyst_required": analyst_required}


def triage_show(artifact_id: str, *, db_path: str | Path | None = None) -> dict[str, Any]:
    target = init_db(db_path)
    with _connect(target) as conn:
        row = conn.execute("SELECT * FROM artifact_triage WHERE artifact_id=?", (artifact_id,)).fetchone()
    if not row:
        raise ValueError("artifact is not queued for triage")
    result = dict(row)
    for key in ("context_json", "result_json"):
        result[key[:-5]] = json.loads(result[key])
    return result


def triage_pending(*, limit: int = 500, db_path: str | Path | None = None) -> dict[str, Any]:
    target = init_db(db_path)
    bounded = max(1, min(int(limit), MAX_PAGE))
    with _connect(target) as conn:
        rows = conn.execute("SELECT artifact_id, status, model, verdict, confidence, context_json, updated_at FROM artifact_triage WHERE status='awaiting_model' ORDER BY updated_at ASC LIMIT ?", (bounded,)).fetchall()
    return {"status": "awaiting_model", "artifacts": [{"artifact_id": row["artifact_id"], "status": row["status"], "model": row["model"], "verdict": row["verdict"], "confidence": row["confidence"], "context": json.loads(row["context_json"]), "updated_at": row["updated_at"]} for row in rows], "model_calls": 0}


def queue_model_triage(*, limit: int = 500, model: str = "", db_path: str | Path | None = None, requested_by: str = "artifact-fleet-dashboard") -> dict[str, Any]:
    """Enqueue bounded, minimized contexts for the configured model bridge.

    This only creates intelligence jobs. It never invokes a model directly and
    never executes an artifact. The bridge remains responsible for honoring the
    selected model and the analyst-review guardrails.
    """
    pending = triage_pending(limit=limit, db_path=db_path)
    queued: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for item in pending.get("artifacts", []):
        artifact_id = str(item.get("artifact_id") or "")
        try:
            queued.append(enqueue_model_triage(artifact_id, model=model, db_path=db_path, requested_by=requested_by))
        except Exception as exc:
            errors.append({"artifact_id": artifact_id, "error": str(exc)[:500]})
    return {"status": "queued", "model": model, "queued": queued, "errors": errors, "requested": len(pending.get("artifacts", []))}


def analyst_queue(*, limit: int = 100, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    target = init_db(db_path)
    bounded = max(1, min(int(limit), MAX_PAGE))
    with _connect(target) as conn:
        rows = conn.execute("SELECT * FROM artifact_triage WHERE status='analyst_review' OR (status='awaiting_model' AND analyst_required=1) ORDER BY updated_at DESC LIMIT ?", (bounded,)).fetchall()
    return [dict(row) for row in rows]


def fleet_status(*, db_path: str | Path | None = None) -> dict[str, Any]:
    target = init_db(db_path)
    with _connect(target) as conn:
        queue = {f"{row['stage']}_{row['status']}": int(row["count"]) for row in conn.execute("SELECT stage, status, COUNT(*) count FROM artifact_queue GROUP BY stage, status")}
        sources = [dict(row) for row in conn.execute("SELECT * FROM artifact_sources ORDER BY updated_at DESC LIMIT 100")]
        counts = {str(row["status"]): int(row["count"]) for row in conn.execute("SELECT status, COUNT(*) count FROM artifact_metadata GROUP BY status")}
        triage = {str(row["status"]): int(row["count"]) for row in conn.execute("SELECT status, COUNT(*) count FROM artifact_triage GROUP BY status")}
        dead = int(conn.execute("SELECT COUNT(*) FROM artifact_dead_letters").fetchone()[0])
    return {"db_path": str(target), "artifacts": counts, "queue": queue, "triage": triage, "dead_letters": dead, "sources": sources, "supported_sources": list(REGISTRY_SOURCES)}


def source_health(*, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    return fleet_status(db_path=db_path)["sources"]


def fleet_metrics(*, db_path: str | Path | None = None) -> dict[str, Any]:
    target = init_db(db_path)
    with _connect(target) as conn:
        rows = conn.execute("SELECT stage, metric, SUM(value) value, COUNT(*) samples FROM artifact_metrics GROUP BY stage, metric").fetchall()
    return {"metrics": [dict(row) for row in rows], "status": fleet_status(db_path=target)}


def benchmark(*, artifacts: int = 1000, workers: int = 4, fixture_mode: bool = True) -> dict[str, Any]:
    count = max(1, min(int(artifacts), 250_000))
    worker_count = max(1, min(int(workers), 64))
    started = time.perf_counter()
    flagged = 0
    def classify(index: int) -> bool:
        return fixture_mode and index % 25 == 0
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        for value in pool.map(classify, range(count)):
            flagged += int(value)
    elapsed = max(time.perf_counter() - started, 0.000001)
    rate = count / elapsed
    target_rate = 114_000 / 86_400
    return {"mode": "synthetic_fixture" if fixture_mode else "metadata_only", "artifacts": count, "workers": worker_count, "elapsed_seconds": round(elapsed, 4), "artifacts_per_second": round(rate, 2), "artifacts_per_day_equivalent": round(rate * 86_400), "target_artifacts_per_day": 114_000, "synthetic_sustains_target": rate >= target_rate, "production_sustainable": None, "synthetic_flagged": flagged, "note": "Benchmark is synthetic and does not prove live registry throughput."}


def run_cycle(*, since: str = "24h", limit: int = 1000, workers: int = 4, fixture_path: str | Path | None = None, db_path: str | Path | None = None) -> dict[str, Any]:
    """Run the safe automated funnel up to (but not through) model execution."""
    if fixture_path:
        records = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError("artifact cycle fixture must be a JSON array")
        indexed = index_records(records[:limit], source="fixture", cursor=since, db_path=db_path)
    else:
        indexed = index_live_sources(since=since, limit=limit, db_path=db_path)
    scanned = scan_pending(limit=limit, workers=workers, db_path=db_path)
    pending = triage_pending(limit=limit, db_path=db_path)
    return {"status": "completed", "index": indexed, "scan": scanned, "triage": pending, "metrics": fleet_metrics(db_path=db_path), "model_execution": "not_started", "next_action": "artifact-fleet triage --enqueue-model"}


def artifact_research_handoff(artifact_id: str, *, db_path: str | Path | None = None) -> dict[str, Any]:
    target = init_db(db_path)
    with _connect(target) as conn:
        scan = conn.execute("SELECT * FROM artifact_scans WHERE artifact_id=? ORDER BY scanned_at DESC LIMIT 1", (artifact_id,)).fetchone()
        artifact = conn.execute("SELECT * FROM artifact_metadata WHERE artifact_id=?", (artifact_id,)).fetchone()
        triage = conn.execute("SELECT * FROM artifact_triage WHERE artifact_id=?", (artifact_id,)).fetchone()
    if not artifact or not scan:
        raise ValueError("artifact scan not found")
    return {"artifact_id": artifact_id, "package": dict(artifact), "scan": dict(scan), "triage": dict(triage) if triage else None, "publication": {"status": "review_only", "approval_required": True, "auto_publish": False}}


def draft_artifact_blog(artifact_id: str, *, db_path: str | Path | None = None, paths: Any = None) -> dict[str, Any]:
    handoff = artifact_research_handoff(artifact_id, db_path=db_path)
    package = handoff["package"]
    scan = handoff["scan"]
    findings = json.loads(scan.get("findings_json") or "[]")
    iocs = {"urls": [], "ips": [], "domains": [], "hashes": [scan.get("sha256")]}
    campaign = {
        "campaign_id": artifact_id.lower(),
        "title": f"Artifact review: {package.get('ecosystem')} {package.get('package')} {package.get('version')}",
        "summary": "SecOpsAI generated a review-only artifact research draft from deterministic static evidence.",
        "severity": "high" if findings else "medium",
        "confidence": "medium",
        "source_urls": [value for value in (package.get("source_url"), package.get("dist_url")) if value],
        "packages": [{"ecosystem": package.get("ecosystem"), "package": package.get("package"), "version": package.get("version"), "publisher": package.get("publisher", "")}],
        "iocs": iocs,
        "behavioral_indicators": [item.get("matched_indicator") for item in findings if item.get("matched_indicator")],
        "references": [package.get("source_url")] if package.get("source_url") else [],
    }
    from secopsai import blog
    draft = blog.draft_campaign(campaign_data=campaign, paths=paths)
    return {"artifact_id": artifact_id, "draft": draft, "publication": {"status": "review_only", "approval_required": True, "auto_publish": False}}
