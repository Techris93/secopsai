from __future__ import annotations

import hashlib
import json
import re
import secrets
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import soc_store


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_DIR = ROOT / "reports" / "research" / "cases"

CASE_TYPES = {
    "malicious_package",
    "typosquatting",
    "dependency_confusion",
    "supply_chain_campaign",
    "credential_theft",
    "malware",
    "infrastructure_cluster",
    "vulnerability_research",
    "other",
}
CASE_STATUSES = {
    "draft",
    "investigating",
    "validation",
    "disclosure_pending",
    "ready_to_publish",
    "published",
    "closed",
}
DISCLOSURE_STATUSES = {
    "not_started",
    "not_required",
    "preparing",
    "reported",
    "coordinating",
    "disclosed",
    "closed",
}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
SUBJECT_TYPES = {"package", "extension", "repository", "publisher", "brand", "infrastructure", "other"}
EVIDENCE_TYPES = {
    "source",
    "package_artifact",
    "static_analysis",
    "sandbox_analysis",
    "registry_metadata",
    "screenshot",
    "analyst_note",
    "other",
}
IOC_TYPES = {"domain", "url", "ipv4", "ipv6", "sha256", "sha1", "md5", "email", "wallet", "file_path", "other"}
CONFIDENCE_LEVELS = {"low": 25, "medium": 55, "high": 80, "confirmed": 100}
CASE_ID_RE = re.compile(r"^RSC-[A-F0-9]{12}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(6).upper()}"


def _clean(value: Any, *, field: str, required: bool = False, limit: int = 4096) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{field} is required")
    if "\x00" in text or "\r" in text:
        raise ValueError(f"{field} contains invalid control characters")
    if len(text) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    return text


def _choice(value: Any, *, field: str, allowed: Iterable[str], default: Optional[str] = None) -> str:
    text = _clean(value if value is not None else default, field=field, required=True, limit=80).lower()
    allowed_set = set(allowed)
    if text not in allowed_set:
        raise ValueError(f"invalid {field}: {text}; expected one of {', '.join(sorted(allowed_set))}")
    return text


def _confidence(value: Any) -> int:
    if isinstance(value, str) and value.lower() in CONFIDENCE_LEVELS:
        return CONFIDENCE_LEVELS[value.lower()]
    try:
        confidence = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("confidence must be 0-100 or low/medium/high/confirmed") from exc
    if not 0 <= confidence <= 100:
        raise ValueError("confidence must be between 0 and 100")
    return confidence


def _case_id(value: str) -> str:
    case_id = _clean(value, field="case_id", required=True, limit=32).upper()
    if not CASE_ID_RE.match(case_id):
        raise ValueError("case_id must use the RSC-XXXXXXXXXXXX format")
    return case_id


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: Any, default: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _record_event(
    connection: Any,
    case_id: str,
    event_type: str,
    message: str,
    *,
    actor: str = "secopsai",
    data: Optional[Dict[str, Any]] = None,
) -> None:
    connection.execute(
        """
        INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            _clean(event_type, field="event_type", required=True, limit=80),
            _clean(actor, field="actor", required=True, limit=160),
            _clean(message, field="message", required=True, limit=4096),
            _json(data or {}),
            soc_store.utc_now(),
        ),
    )


def create_case(
    *,
    title: str,
    summary: str = "",
    case_type: str = "other",
    severity: str = "medium",
    confidence: Any = 0,
    owner: str = "",
    db_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    soc_store.init_db(db_path)
    case_id = _id("RSC")
    now = soc_store.utc_now()
    values = {
        "title": _clean(title, field="title", required=True, limit=240),
        "summary": _clean(summary, field="summary", limit=8000),
        "case_type": _choice(case_type, field="case_type", allowed=CASE_TYPES),
        "severity": _choice(severity, field="severity", allowed=SEVERITIES),
        "confidence": _confidence(confidence),
        "owner": _clean(owner, field="owner", limit=160),
    }
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO research_cases (
                case_id, title, summary, case_type, severity, confidence, status,
                owner, disclosure_status, embargo_until, created_at, updated_at,
                closed_at, published_at, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, 'not_started', NULL, ?, ?, NULL, NULL, ?)
            """,
            (
                case_id,
                values["title"],
                values["summary"],
                values["case_type"],
                values["severity"],
                values["confidence"],
                values["owner"],
                now,
                now,
                _json(metadata or {}),
            ),
        )
        _record_event(connection, case_id, "case_created", "Research case created.", data=values)
        connection.commit()
    return get_case(case_id, db_path=db_path)


def list_cases(
    *,
    db_path: Optional[str] = None,
    status: Optional[str] = None,
    case_type: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    soc_store.init_db(db_path)
    if limit <= 0:
        return []
    clauses: List[str] = []
    params: List[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(_choice(status, field="status", allowed=CASE_STATUSES))
    if case_type:
        clauses.append("case_type = ?")
        params.append(_choice(case_type, field="case_type", allowed=CASE_TYPES))
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(int(limit), 1000))
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"""
            SELECT case_id, title, summary, case_type, severity, confidence, status,
                   owner, disclosure_status, embargo_until, created_at, updated_at,
                   closed_at, published_at
            FROM research_cases{where}
            ORDER BY updated_at DESC, created_at DESC LIMIT ?
            """,
            tuple(params),
        ).fetchall()
        counts = {
            str(row["case_id"]): dict(row)
            for row in connection.execute(
                """
                SELECT c.case_id,
                       (SELECT COUNT(*) FROM research_subjects s WHERE s.case_id = c.case_id AND s.status = 'active') AS subject_count,
                       (SELECT COUNT(*) FROM research_evidence e WHERE e.case_id = c.case_id AND e.status = 'active') AS evidence_count,
                       (SELECT COUNT(*) FROM research_iocs i WHERE i.case_id = c.case_id AND i.status = 'active') AS ioc_count,
                       (SELECT COUNT(*) FROM research_case_findings f WHERE f.case_id = c.case_id) AS finding_count
                FROM research_cases c
                """
            ).fetchall()
        }
    output: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item.update({key: value for key, value in counts.get(str(row["case_id"]), {}).items() if key != "case_id"})
        output.append(item)
    return output


def get_case(case_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_cases WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise ValueError(f"research case not found: {case_id}")
        result = dict(row)
        result["metadata"] = _decode(result.pop("payload_json", "{}"), {})
        result["subjects"] = [
            {**dict(item), "metadata": _decode(item["metadata_json"], {})}
            for item in connection.execute(
                "SELECT * FROM research_subjects WHERE case_id = ? ORDER BY created_at, subject_id", (case_id,)
            ).fetchall()
        ]
        for item in result["subjects"]:
            item.pop("metadata_json", None)
        result["evidence"] = [
            {**dict(item), "metadata": _decode(item["metadata_json"], {})}
            for item in connection.execute(
                "SELECT * FROM research_evidence WHERE case_id = ? ORDER BY collected_at, evidence_id", (case_id,)
            ).fetchall()
        ]
        for item in result["evidence"]:
            item.pop("metadata_json", None)
        result["iocs"] = []
        for item in connection.execute(
            "SELECT * FROM research_iocs WHERE case_id = ? ORDER BY ioc_type, value", (case_id,)
        ).fetchall():
            value = dict(item)
            value["tags"] = _decode(value.pop("tags_json", "[]"), [])
            result["iocs"].append(value)
        result["findings"] = [
            dict(item)
            for item in connection.execute(
                "SELECT * FROM research_case_findings WHERE case_id = ? ORDER BY created_at", (case_id,)
            ).fetchall()
        ]
        result["timeline"] = []
        for item in connection.execute(
            "SELECT event_id, event_type, actor, message, data_json, created_at FROM research_case_events WHERE case_id = ? ORDER BY event_id",
            (case_id,),
        ).fetchall():
            value = dict(item)
            value["data"] = _decode(value.pop("data_json", "{}"), {})
            result["timeline"].append(value)
    result["publication_readiness"] = publication_readiness(result)
    return result


def update_case(
    case_id: str,
    *,
    db_path: Optional[str] = None,
    actor: str = "analyst",
    **changes: Any,
) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    current = get_case(case_id, db_path=db_path)
    validators = {
        "title": lambda value: _clean(value, field="title", required=True, limit=240),
        "summary": lambda value: _clean(value, field="summary", limit=8000),
        "case_type": lambda value: _choice(value, field="case_type", allowed=CASE_TYPES),
        "severity": lambda value: _choice(value, field="severity", allowed=SEVERITIES),
        "confidence": _confidence,
        "status": lambda value: _choice(value, field="status", allowed=CASE_STATUSES),
        "owner": lambda value: _clean(value, field="owner", limit=160),
        "disclosure_status": lambda value: _choice(value, field="disclosure_status", allowed=DISCLOSURE_STATUSES),
        "embargo_until": lambda value: _clean(value, field="embargo_until", limit=64) or None,
    }
    normalized: Dict[str, Any] = {}
    for key, value in changes.items():
        if value is None:
            continue
        if key not in validators:
            raise ValueError(f"unsupported case field: {key}")
        normalized[key] = validators[key](value)
    if not normalized:
        return current
    changed = {key: value for key, value in normalized.items() if current.get(key) != value}
    if not changed:
        return current
    now = soc_store.utc_now()
    if changed.get("status") == "published":
        changed["published_at"] = current.get("published_at") or now
    if changed.get("status") == "closed":
        changed["closed_at"] = current.get("closed_at") or now
    assignments = ", ".join(f"{key} = ?" for key in changed)
    values = [*changed.values(), now, case_id]
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(f"UPDATE research_cases SET {assignments}, updated_at = ? WHERE case_id = ?", tuple(values))
        _record_event(
            connection,
            case_id,
            "case_updated",
            "Research case fields updated.",
            actor=actor,
            data={"changes": changed},
        )
        connection.commit()
    return get_case(case_id, db_path=db_path)


def add_subject(
    case_id: str,
    *,
    subject_type: str,
    name: str,
    ecosystem: str = "",
    version: str = "",
    publisher: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    get_case(case_id, db_path=db_path)
    subject_type = _choice(subject_type, field="subject_type", allowed=SUBJECT_TYPES)
    name = _clean(name, field="name", required=True, limit=512)
    ecosystem = _clean(ecosystem, field="ecosystem", limit=80).lower()
    version = _clean(version, field="version", limit=160)
    publisher = _clean(publisher, field="publisher", limit=240)
    stable = hashlib.sha256(f"{case_id}|{subject_type}|{ecosystem}|{name}|{version}".encode()).hexdigest()[:16].upper()
    subject_id = f"SUB-{stable}"
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO research_subjects (
                subject_id, case_id, subject_type, ecosystem, name, version,
                publisher, status, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
            ON CONFLICT(case_id, subject_type, ecosystem, name, version) DO UPDATE SET
                publisher = excluded.publisher, status = 'active', metadata_json = excluded.metadata_json
            """,
            (subject_id, case_id, subject_type, ecosystem, name, version, publisher, _json(metadata or {}), now),
        )
        _record_event(connection, case_id, "subject_added", f"Added research subject {name}.", actor=actor, data={"subject_id": subject_id})
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def add_evidence(
    case_id: str,
    *,
    evidence_type: str,
    title: str,
    locator: str = "",
    sha256: str = "",
    provenance: str = "",
    notes: str = "",
    collected_at: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    get_case(case_id, db_path=db_path)
    evidence_type = _choice(evidence_type, field="evidence_type", allowed=EVIDENCE_TYPES)
    title = _clean(title, field="title", required=True, limit=500)
    locator = _clean(locator, field="locator", limit=4000)
    sha256 = _clean(sha256, field="sha256", limit=64).lower()
    if sha256 and not SHA256_RE.match(sha256):
        raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
    evidence_id = _id("EVD")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO research_evidence (
                evidence_id, case_id, evidence_type, title, locator, sha256,
                provenance, notes, status, collected_at, created_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                evidence_id,
                case_id,
                evidence_type,
                title,
                locator,
                sha256,
                _clean(provenance, field="provenance", limit=1000),
                _clean(notes, field="notes", limit=12000),
                _clean(collected_at or now, field="collected_at", required=True, limit=64),
                now,
                _json(metadata or {}),
            ),
        )
        _record_event(connection, case_id, "evidence_added", f"Added evidence: {title}.", actor=actor, data={"evidence_id": evidence_id, "type": evidence_type})
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def add_ioc(
    case_id: str,
    *,
    ioc_type: str,
    value: str,
    confidence: Any = 50,
    source_evidence_id: Optional[str] = None,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    get_case(case_id, db_path=db_path)
    ioc_type = _choice(ioc_type, field="ioc_type", allowed=IOC_TYPES)
    value = _clean(value, field="value", required=True, limit=4096)
    confidence_value = _confidence(confidence)
    source_evidence_id = _clean(source_evidence_id, field="source_evidence_id", limit=32) or None
    normalized_tags = sorted({_clean(tag, field="tag", required=True, limit=80) for tag in (tags or [])})
    stable = hashlib.sha256(f"{case_id}|{ioc_type}|{value}".encode()).hexdigest()[:16].upper()
    ioc_id = f"IOC-{stable}"
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        if source_evidence_id:
            exists = connection.execute(
                "SELECT 1 FROM research_evidence WHERE evidence_id = ? AND case_id = ? AND status = 'active'",
                (source_evidence_id, case_id),
            ).fetchone()
            if exists is None:
                raise ValueError(f"source evidence does not belong to case: {source_evidence_id}")
        connection.execute(
            """
            INSERT INTO research_iocs (
                ioc_id, case_id, ioc_type, value, confidence, first_seen,
                last_seen, source_evidence_id, tags_json, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            ON CONFLICT(case_id, ioc_type, value) DO UPDATE SET
                confidence = excluded.confidence,
                first_seen = COALESCE(excluded.first_seen, research_iocs.first_seen),
                last_seen = COALESCE(excluded.last_seen, research_iocs.last_seen),
                source_evidence_id = COALESCE(excluded.source_evidence_id, research_iocs.source_evidence_id),
                tags_json = excluded.tags_json,
                status = 'active'
            """,
            (
                ioc_id,
                case_id,
                ioc_type,
                value,
                confidence_value,
                _clean(first_seen, field="first_seen", limit=64) or None,
                _clean(last_seen, field="last_seen", limit=64) or None,
                source_evidence_id,
                _json(normalized_tags),
                now,
            ),
        )
        _record_event(connection, case_id, "ioc_added", f"Added {ioc_type} indicator.", actor=actor, data={"ioc_id": ioc_id})
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def link_finding(
    case_id: str,
    finding_id: str,
    *,
    relationship: str = "supports",
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    get_case(case_id, db_path=db_path)
    finding_id = _clean(finding_id, field="finding_id", required=True, limit=128)
    if soc_store.get_finding(finding_id, db_path) is None:
        raise ValueError(f"finding not found: {finding_id}")
    relationship = _choice(relationship, field="relationship", allowed={"supports", "related", "derived_from", "impacts"})
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO research_case_findings (case_id, finding_id, relationship, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(case_id, finding_id) DO UPDATE SET relationship = excluded.relationship
            """,
            (case_id, finding_id, relationship, now),
        )
        _record_event(connection, case_id, "finding_linked", f"Linked finding {finding_id}.", actor=actor, data={"finding_id": finding_id, "relationship": relationship})
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def add_case_note(
    case_id: str,
    note: str,
    *,
    actor: str = "analyst",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    get_case(case_id, db_path=db_path)
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        _record_event(connection, case_id, "analyst_note", _clean(note, field="note", required=True, limit=12000), actor=actor)
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def retract_item(
    case_id: str,
    *,
    item_type: str,
    item_id: str,
    reason: str,
    actor: str = "analyst",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    case_id = _case_id(case_id)
    get_case(case_id, db_path=db_path)
    item_type = _choice(item_type, field="item_type", allowed={"subject", "evidence", "ioc"})
    item_id = _clean(item_id, field="item_id", required=True, limit=40).upper()
    reason = _clean(reason, field="reason", required=True, limit=2000)
    table, id_column, prefix = {
        "subject": ("research_subjects", "subject_id", "SUB-"),
        "evidence": ("research_evidence", "evidence_id", "EVD-"),
        "ioc": ("research_iocs", "ioc_id", "IOC-"),
    }[item_type]
    if not item_id.startswith(prefix):
        raise ValueError(f"invalid {item_type} item id")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        cursor = connection.execute(
            f"UPDATE {table} SET status = 'retracted' WHERE {id_column} = ? AND case_id = ? AND status = 'active'",
            (item_id, case_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"active {item_type} item not found in case: {item_id}")
        _record_event(
            connection,
            case_id,
            f"{item_type}_retracted",
            f"Retracted {item_type} {item_id}: {reason}",
            actor=actor,
            data={"item_type": item_type, "item_id": item_id, "reason": reason},
        )
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def publication_readiness(case: Dict[str, Any]) -> Dict[str, Any]:
    blockers: List[str] = []
    warnings: List[str] = []
    summary = str(case.get("summary") or "").strip()
    subjects = [item for item in (case.get("subjects") or []) if item.get("status", "active") == "active"]
    evidence = [item for item in (case.get("evidence") or []) if item.get("status", "active") == "active"]
    source_evidence = [item for item in evidence if item.get("evidence_type") in {"source", "registry_metadata"} and item.get("locator")]
    active_evidence_ids = {item.get("evidence_id") for item in evidence}
    active_iocs = [item for item in (case.get("iocs") or []) if item.get("status", "active") == "active"]
    if len(str(case.get("title") or "").strip()) < 12:
        blockers.append("title must clearly identify the research subject")
    if len(summary) < 80:
        blockers.append("summary must contain at least 80 characters")
    if not subjects:
        blockers.append("at least one structured research subject is required")
    if len(evidence) < 2:
        blockers.append("at least two evidence records are required")
    if not source_evidence:
        blockers.append("at least one source or registry-metadata record with a locator is required")
    if int(case.get("confidence") or 0) < 60:
        blockers.append("confidence must be at least 60 before publication")
    if case.get("disclosure_status") not in {"not_required", "disclosed", "closed"}:
        blockers.append("responsible disclosure must be completed or marked not required")
    if case.get("status") not in {"ready_to_publish", "published"}:
        blockers.append("case status must be ready_to_publish or published")
    if any(item.get("source_evidence_id") and item.get("source_evidence_id") not in active_evidence_ids for item in active_iocs):
        blockers.append("an active IOC references retracted or missing evidence")
    if not active_iocs:
        warnings.append("no structured IOCs are attached; explicitly state that none were found in the article")
    if not case.get("findings"):
        warnings.append("no SecOpsAI SOC findings are linked to this case")
    return {
        "ready": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "checked_at": soc_store.utc_now(),
    }


def _case_markdown(case: Dict[str, Any]) -> str:
    readiness = publication_readiness(case)
    lines = [
        f"# {case['title']}",
        "",
        f"- Case: `{case['case_id']}`",
        f"- Type: `{case['case_type']}`",
        f"- Status: `{case['status']}`",
        f"- Severity: `{case['severity']}`",
        f"- Confidence: `{case['confidence']}`",
        f"- Disclosure: `{case['disclosure_status']}`",
        f"- Updated: `{case['updated_at']}`",
        "",
        "## Executive Summary",
        "",
        case.get("summary") or "Summary pending.",
        "",
        "## Affected Subjects",
        "",
    ]
    for subject in [item for item in (case.get("subjects") or []) if item.get("status", "active") == "active"]:
        target = ":".join(filter(None, [subject.get("ecosystem"), subject.get("name")]))
        version = f"@{subject['version']}" if subject.get("version") else ""
        lines.append(f"- `{subject.get('subject_type')}`: `{target or subject.get('name')}{version}`")
    if not [item for item in (case.get("subjects") or []) if item.get("status", "active") == "active"]:
        lines.append("- No structured subjects recorded.")
    lines.extend(["", "## Evidence", ""])
    for item in [value for value in (case.get("evidence") or []) if value.get("status", "active") == "active"]:
        locator = f" - {item['locator']}" if item.get("locator") else ""
        lines.append(f"- **{item['title']}** (`{item['evidence_type']}`){locator}")
        if item.get("sha256"):
            lines.append(f"  - SHA-256: `{item['sha256']}`")
        if item.get("notes"):
            lines.append(f"  - {item['notes']}")
    if not [item for item in (case.get("evidence") or []) if item.get("status", "active") == "active"]:
        lines.append("- No evidence recorded.")
    lines.extend(["", "## Indicators of Compromise", ""])
    for item in [value for value in (case.get("iocs") or []) if value.get("status", "active") == "active"]:
        lines.append(f"- `{item['ioc_type']}`: `{item['value']}` (confidence {item['confidence']})")
    if not [item for item in (case.get("iocs") or []) if item.get("status", "active") == "active"]:
        lines.append("- No structured IOCs recorded.")
    lines.extend(["", "## Related SecOpsAI Findings", ""])
    for item in case.get("findings") or []:
        lines.append(f"- `{item['finding_id']}` ({item['relationship']})")
    if not case.get("findings"):
        lines.append("- No findings linked.")
    lines.extend(["", "## Timeline", ""])
    for item in case.get("timeline") or []:
        lines.append(f"- {item['created_at']} - **{item['event_type']}** - {item['message']}")
    lines.extend(["", "## Publication Readiness", ""])
    lines.append(f"- Ready: `{'yes' if readiness['ready'] else 'no'}`")
    for blocker in readiness["blockers"]:
        lines.append(f"- Blocker: {blocker}")
    for warning in readiness["warnings"]:
        lines.append(f"- Warning: {warning}")
    return "\n".join(lines).rstrip() + "\n"


def export_case(
    case_id: str,
    *,
    output_dir: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    case = get_case(case_id, db_path=db_path)
    target = Path(output_dir).expanduser().resolve() if output_dir else DEFAULT_REPORT_DIR
    target.mkdir(parents=True, exist_ok=True)
    stem = f"{case['case_id'].lower()}-{re.sub(r'[^a-z0-9]+', '-', case['title'].lower()).strip('-')[:80]}"
    json_path = target / f"{stem}.json"
    markdown_path = target / f"{stem}.md"
    json_path.write_text(json.dumps(case, indent=2, sort_keys=True), encoding="utf-8")
    markdown_path.write_text(_case_markdown(case), encoding="utf-8")
    return {
        "case_id": case["case_id"],
        "json_report": str(json_path),
        "markdown_report": str(markdown_path),
        "publication_readiness": case["publication_readiness"],
    }


def campaign_payload(case: Dict[str, Any]) -> Dict[str, Any]:
    packages = []
    publishers = []
    behaviors = [item.get("notes") for item in case.get("evidence") or [] if item.get("status", "active") == "active" and item.get("notes")]
    for subject in [item for item in (case.get("subjects") or []) if item.get("status", "active") == "active"]:
        if subject.get("subject_type") in {"package", "extension"}:
            packages.append(
                {
                    "ecosystem": subject.get("ecosystem") or "unknown",
                    "package": subject.get("name"),
                    "version": subject.get("version") or "",
                    "publisher": subject.get("publisher") or "",
                    "package_verdict": "confirmed_malicious" if int(case.get("confidence") or 0) >= 90 else "likely_malicious",
                    "behavioral_indicators": [
                        value
                        for value in [(subject.get("metadata") or {}).get("behavior_notes", "")]
                        if value
                    ],
                }
            )
        if subject.get("publisher"):
            publishers.append(subject["publisher"])
        if subject.get("subject_type") == "publisher":
            publishers.append(subject.get("name"))
    iocs: Dict[str, List[str]] = {}
    for item in [value for value in (case.get("iocs") or []) if value.get("status", "active") == "active"]:
        if item.get("value"):
            iocs.setdefault(str(item.get("ioc_type") or "other"), []).append(str(item["value"]))
    return {
        "campaign_id": case["case_id"],
        "title": case["title"],
        "summary": case["summary"],
        "campaign_verdict": "confirmed" if int(case.get("confidence") or 0) >= 90 else "likely_malicious",
        "severity": case.get("severity") or "medium",
        "confidence": case.get("confidence") or 0,
        "packages": packages,
        "publishers": sorted({item for item in publishers if item}),
        "iocs": iocs,
        "references": [item.get("locator") for item in case.get("evidence") or [] if item.get("status", "active") == "active" and item.get("locator")],
        "behavioral_indicators": behaviors,
        "recommended_mitigation": [
            "Block confirmed malicious packages or infrastructure in applicable controls.",
            "Review dependency manifests, lockfiles, caches, and build logs for exposure.",
            "Rotate credentials when installation or execution is confirmed.",
        ],
        "disclosure_status": case.get("disclosure_status"),
    }


def draft_case_blog(case_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    from secopsai.blog import draft_research_case

    case = get_case(case_id, db_path=db_path)
    readiness = publication_readiness(case)
    if not readiness["ready"]:
        raise ValueError("research case is not publication-ready: " + "; ".join(readiness["blockers"]))
    result = draft_research_case(case)
    with closing(soc_store.connect(db_path)) as connection:
        _record_event(
            connection,
            case["case_id"],
            "blog_draft_created",
            "Created a review-only research blog draft.",
            data={"draft_path": result.get("draft_path")},
        )
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (soc_store.utc_now(), case["case_id"]))
        connection.commit()
    return {"case_id": case["case_id"], "publication_readiness": readiness, **result}
