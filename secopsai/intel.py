from __future__ import annotations

"""Threat-intelligence (IOC) pipeline for secopsai.

Design goals:
- Local-first: all IOC data is stored locally under data/intel/
- Zero new dependencies: use stdlib only
- Safe defaults: no external enrichment APIs by default

This module:
1) Downloads open-source IOC feeds
2) Normalizes + de-duplicates indicators
3) Performs lightweight local enrichment (DNS resolution)
4) Matches IOCs against the latest OpenClaw replay events
5) Persists matches as findings into soc_store (source="secopsai-intel")
"""

import csv
import hashlib
import json
import re
import socket
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import openclaw_prepare
import soc_store


REPO_ROOT = Path(__file__).resolve().parents[1]
INTEL_DIR = REPO_ROOT / "data" / "intel"
IOC_STORE = INTEL_DIR / "iocs.json"
ENRICH_STORE = INTEL_DIR / "enriched.json"

DEFAULT_TIMEOUT_SECONDS = 20


def _curated_supply_chain_iocs() -> List["IOC"]:
    first_seen = "2026-03-31T00:00:00Z"
    entries = [
        ("domain", "sfrclak.com", "elastic-curated", ["axios-compromise", "c2", "supply-chain"], 95),
        ("ip", "142.11.206.73", "elastic-curated", ["axios-compromise", "c2", "supply-chain"], 95),
        ("url", "http://sfrclak.com:8000/6202033", "elastic-curated", ["axios-compromise", "stage2", "supply-chain"], 98),
        ("hash", "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09", "elastic-curated", ["axios-compromise", "setup.js", "supply-chain"], 95),
        ("hash", "6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7", "elastic-curated", ["axios-compromise", "linux-rat", "supply-chain"], 95),
        ("hash", "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c", "elastic-curated", ["axios-compromise", "powershell-rat", "supply-chain"], 95),
        ("hash", "e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff", "elastic-curated", ["axios-compromise", "persistence", "supply-chain"], 92),
        ("hash", "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a", "elastic-curated", ["axios-compromise", "macos-backdoor", "supply-chain"], 95),
        ("artifact", "axios@1.14.1", "elastic-curated", ["axios-compromise", "package-version", "supply-chain"], 88),
        ("artifact", "axios@0.30.4", "elastic-curated", ["axios-compromise", "package-version", "supply-chain"], 88),
        ("artifact", "plain-crypto-js@4.2.1", "elastic-curated", ["axios-compromise", "dependency", "postinstall"], 92),
        ("artifact", "@shadanai/openclaw@2026.3.28-2", "elastic-curated", ["openclaw-ecosystem", "package-version", "supply-chain"], 90),
        ("artifact", "@shadanai/openclaw@2026.3.28-3", "elastic-curated", ["openclaw-ecosystem", "package-version", "supply-chain"], 90),
        ("artifact", "@shadanai/openclaw@2026.3.31-1", "elastic-curated", ["openclaw-ecosystem", "package-version", "supply-chain"], 90),
        ("artifact", "@shadanai/openclaw@2026.3.31-2", "elastic-curated", ["openclaw-ecosystem", "package-version", "supply-chain"], 90),
        ("artifact", "node_modules/plain-crypto-js/setup.js", "elastic-curated", ["axios-compromise", "filesystem", "postinstall"], 85),
        ("artifact", "/tmp/ld.py", "elastic-curated", ["axios-compromise", "filesystem", "linux"], 90),
        ("artifact", "programdata\\wt.exe", "elastic-curated", ["axios-compromise", "filesystem", "windows"], 90),
        ("artifact", "programdata\\system.bat", "elastic-curated", ["axios-compromise", "filesystem", "windows"], 88),
        ("artifact", "currentversion\\run\\microsoftupdate", "elastic-curated", ["axios-compromise", "registry", "persistence"], 92),
        ("artifact", "/Library/Caches/com.apple.act.mond", "elastic-curated", ["axios-compromise", "filesystem", "macos"], 92),
        ("artifact", ".scpt", "elastic-curated", ["axios-compromise", "applescript", "macos"], 82),
    ]
    return [
        IOC(
            ioc_type=ioc_type,
            value=value,
            source=source,
            tags=tags,
            first_seen=first_seen,
            last_seen=first_seen,
            score=score,
        )
        for ioc_type, value, source, tags, score in entries
    ]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def _fetch_text(url: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "secopsai-intel/0.1 (local-first)",
            "Accept": "text/plain, text/csv, application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return raw.decode("utf-8", errors="replace")


@dataclass
class IOC:
    ioc_type: str  # ip|domain|url|hash
    value: str
    source: str
    tags: List[str]
    first_seen: str
    last_seen: str
    score: int

    def key(self) -> str:
        return f"{self.ioc_type}:{self.value}".lower()


def _normalize_domain(host: str) -> str:
    host = host.strip().lower().strip(".")
    return host


def _extract_host_from_url(url: str) -> Optional[str]:
    # simple/robust enough for IOC matching
    m = re.match(r"^[a-zA-Z]+://([^/]+)", url.strip())
    if not m:
        return None
    host = m.group(1)
    # strip creds and port
    if "@" in host:
        host = host.split("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]
    return _normalize_domain(host)


def _csv_lines_with_header(text: str) -> List[str]:
    """Return CSV lines including a header, even if the header is commented out."""
    lines = [line for line in text.splitlines() if line]

    header = None
    for line in lines:
        if not line.startswith("#"):
            continue
        stripped = line.lstrip("#").strip()
        # Heuristic: header lines are comma-separated and contain common keys.
        if "," in stripped and ("dateadded" in stripped or "ioc_value" in stripped or "url_status" in stripped):
            header = stripped
            break

    data_lines = [line for line in lines if not line.startswith("#")]
    if header:
        return [header] + data_lines
    return data_lines


def _parse_urlhaus_csv(text: str) -> List[IOC]:
    """Parse URLhaus CSV feeds (csv_online)."""

    rows: List[IOC] = []
    data_lines = _csv_lines_with_header(text)
    if not data_lines:
        return rows

    reader = csv.DictReader(data_lines)
    for r in reader:
        url = (r.get("url") or r.get("URL") or "").strip()
        if not url:
            continue
        date_added = (r.get("dateadded") or r.get("date_added") or r.get("date") or utc_now()).strip()
        threat = (r.get("threat") or r.get("threat_type") or "").strip()
        tags_raw = (r.get("tags") or "").strip()
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        if threat and threat not in tags:
            tags.append(threat)

        rows.append(
            IOC(
                ioc_type="url",
                value=url,
                source="urlhaus",
                tags=tags,
                first_seen=date_added,
                last_seen=date_added,
                score=70,
            )
        )

    return rows


def _parse_threatfox_csv(text: str) -> List[IOC]:
    """Parse ThreatFox CSV exports (e.g. /export/csv/recent/)."""

    rows: List[IOC] = []
    data_lines = _csv_lines_with_header(text)
    if not data_lines:
        return rows

    reader = csv.DictReader(data_lines)
    for r in reader:
        ioc_val = (r.get("ioc_value") or r.get("ioc") or r.get("ioc_value ") or "").strip()
        ioc_type = (r.get("ioc_type") or "").strip().lower()
        confidence = (r.get("confidence_level") or r.get("confidence") or "").strip()
        first_seen = (r.get("first_seen_utc") or r.get("first_seen") or utc_now()).strip()
        last_seen = (r.get("last_seen_utc") or r.get("last_seen") or first_seen).strip()
        threat_type = (r.get("threat_type") or "").strip()
        tags_raw = (r.get("tags") or "").strip()

        if not ioc_val:
            continue

        mapped = None
        if ioc_type in {"ip", "ip:port"}:
            mapped = "ip"
            if ":" in ioc_val:
                ioc_val = ioc_val.split(":", 1)[0]
        elif ioc_type == "domain":
            mapped = "domain"
            ioc_val = _normalize_domain(ioc_val)
        elif ioc_type == "url":
            mapped = "url"
        elif ioc_type in {"md5", "sha1", "sha256"}:
            mapped = "hash"
            ioc_val = ioc_val.lower()
        else:
            continue

        try:
            conf_int = int(confidence)
        except Exception:
            conf_int = 50

        score = 50 + min(max(conf_int, 0), 50)

        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        if threat_type and threat_type not in tags:
            tags.append(threat_type)

        rows.append(
            IOC(
                ioc_type=mapped,
                value=ioc_val,
                source="threatfox",
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                score=score,
            )
        )

    return rows


def refresh_iocs(*, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """Download and persist normalized IOC list to data/intel/iocs.json."""
    INTEL_DIR.mkdir(parents=True, exist_ok=True)

    feeds = {
        # URLhaus provides multiple downloads; csv_online is plain text (not zip).
        "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_online/",
        # ThreatFox recent export is plain CSV (no auth-key required).
        "threatfox": "https://threatfox.abuse.ch/export/csv/recent/",
    }

    all_iocs: List[IOC] = _curated_supply_chain_iocs()
    errors: Dict[str, str] = {}

    for name, url in feeds.items():
        try:
            text = _fetch_text(url, timeout=timeout)
            if name == "urlhaus":
                all_iocs.extend(_parse_urlhaus_csv(text))
            elif name == "threatfox":
                all_iocs.extend(_parse_threatfox_csv(text))
        except Exception as e:
            errors[name] = repr(e)

    # de-dup by key, keep max score and widen first/last seen.
    merged: Dict[str, IOC] = {}
    for ioc in all_iocs:
        k = ioc.key()
        existing = merged.get(k)
        if not existing:
            merged[k] = ioc
            continue
        existing.score = max(existing.score, ioc.score)
        existing.tags = sorted(set(existing.tags + ioc.tags))
        existing.first_seen = min(existing.first_seen, ioc.first_seen)
        existing.last_seen = max(existing.last_seen, ioc.last_seen)

    persisted = [ioc.__dict__ for ioc in sorted(merged.values(), key=lambda x: x.score, reverse=True)]
    payload = {
        "generated_at": utc_now(),
        "total": len(persisted),
        "feeds": ["elastic-curated", *list(feeds.keys())],
        "errors": errors,
        "iocs": persisted,
    }
    IOC_STORE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"path": str(IOC_STORE), "total": len(persisted), "errors": errors}


def load_iocs() -> List[IOC]:
    if not IOC_STORE.exists():
        return []
    data = json.loads(IOC_STORE.read_text(encoding="utf-8"))
    iocs = []
    for row in data.get("iocs", []):
        iocs.append(
            IOC(
                ioc_type=row["ioc_type"],
                value=row["value"],
                source=row["source"],
                tags=list(row.get("tags", [])),
                first_seen=row.get("first_seen", utc_now()),
                last_seen=row.get("last_seen", utc_now()),
                score=int(row.get("score", 50)),
            )
        )
    return iocs


def enrich_iocs(iocs: Iterable[IOC], *, max_items: int = 500) -> Dict[str, Any]:
    """Lightweight local enrichment: resolve domains to IPs (best-effort)."""
    INTEL_DIR.mkdir(parents=True, exist_ok=True)

    enriched: Dict[str, Any] = {
        "generated_at": utc_now(),
        "items": {},
    }

    count = 0
    for ioc in iocs:
        if count >= max_items:
            break
        if ioc.ioc_type not in {"domain", "url"}:
            continue
        host = ioc.value if ioc.ioc_type == "domain" else (_extract_host_from_url(ioc.value) or "")
        if not host:
            continue
        try:
            # returns (hostname, aliaslist, ipaddrlist)
            res = socket.gethostbyname_ex(host)
            enriched["items"][ioc.key()] = {
                "host": host,
                "ips": res[2],
                "ts": utc_now(),
            }
        except Exception:
            # ignore resolution failures
            continue
        count += 1

    ENRICH_STORE.write_text(json.dumps(enriched, indent=2), encoding="utf-8")
    return {"path": str(ENRICH_STORE), "enriched": len(enriched["items"])}


def _load_latest_replay_events(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []


def _event_text(event: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("command", "message", "tool_name", "skill_key", "url", "host"):
        v = event.get(key)
        if v:
            parts.append(str(v))
    # Include a small slice of the dict for robustness.
    parts.append(json.dumps(event, sort_keys=True)[:4000])
    return "\n".join(parts).lower()


def match_iocs_against_replay(
    iocs: List[IOC],
    *,
    replay_path: Optional[Path] = None,
    max_iocs: int = 2000,
) -> Dict[str, Any]:
    """Match IOCs against latest replay events and persist matches as soc_store findings."""

    replay_path = replay_path or (REPO_ROOT / "data" / "openclaw" / "replay" / "labeled" / "current.json")
    events = _load_latest_replay_events(replay_path)

    # Precompute event texts
    indexed: List[Tuple[str, Dict[str, Any]]] = [(_event_text(ev), ev) for ev in events]

    matches: List[Dict[str, Any]] = []

    for ioc in iocs[:max_iocs]:
        needle = ioc.value.lower()
        if not needle or len(needle) < 4:
            continue

        hit_events = []
        for text, ev in indexed:
            if needle in text:
                # Use event_id if present, else a stable hash
                event_id = ev.get("event_id") or ev.get("collector", {}).get("record_id") or f"evt-{_sha1(text)[:12]}"
                hit_events.append(str(event_id))

        if not hit_events:
            continue

        severity = "medium"
        if ioc.score >= 90:
            severity = "high"
        elif ioc.score >= 75:
            severity = "medium"
        else:
            severity = "low"

        finding_id = f"TI-{_sha1(ioc.key())[:16].upper()}"
        title = f"Threat Intel IOC match ({ioc.ioc_type})"
        summary = f"Matched {ioc.ioc_type} IOC from {ioc.source}: {ioc.value}"

        finding = {
            "finding_id": finding_id,
            "title": title,
            "summary": summary,
            "severity": severity,
            "severity_score": 90 if severity == "high" else 60 if severity == "medium" else 30,
            "status": "open",
            "disposition": "unreviewed",
            "source": "secopsai-intel",
            "first_seen": ioc.first_seen,
            "last_seen": ioc.last_seen,
            "rule_ids": ["TI-IOC-MATCH"],
            "ioc": ioc.__dict__,
            "event_ids": hit_events,
            "recommended_actions": [
                "Review the matching OpenClaw events for context and legitimacy.",
                "If unexpected, block the IOC at the appropriate control point (DNS, egress proxy, firewall).",
                "Rotate secrets if the IOC suggests credential exposure or exfiltration.",
            ],
        }

        matches.append(finding)

    # Persist as findings under dedicated source.
    db_path = soc_store.persist_findings(matches, source="secopsai-intel", db_path=None)
    return {
        "replay_path": str(replay_path),
        "events_total": len(events),
        "iocs_considered": min(len(iocs), max_iocs),
        "matched_findings": len(matches),
        "db_path": db_path,
    }
