from __future__ import annotations

import hashlib
import json
import re
import secrets
import stat
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import soc_store

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by minimal system Python
    yaml = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_DIR = ROOT / "reports" / "research" / "cases"
RESEARCH_EXPORT_SCHEMA_VERSION = "secopsai.research.case.v1"
RESEARCH_EXPORT_MANIFEST_VERSION = "secopsai.research.export-manifest.v1"
LOCAL_ARTIFACT_MAX_BYTES = 250 * 1024 * 1024
RULE_MAX_BYTES = 512 * 1024

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
POTENTIAL_IMPACTS = SEVERITIES
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
RULE_TYPES = {"yara", "sigma", "semgrep"}
RULE_STATUSES = {"active", "retracted"}
RULE_VALIDATION_STATUSES = {"passed", "failed"}
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


def _sha256_file(path: Path, *, max_bytes: int = LOCAL_ARTIFACT_MAX_BYTES) -> tuple[str, int]:
    """Hash a local regular file without executing, unpacking, or retaining it."""
    if path.is_symlink():
        raise ValueError("artifact must not be a symbolic link")
    try:
        file_stat = path.stat()
    except FileNotFoundError as exc:
        raise ValueError(f"artifact not found: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("artifact must be a regular file")
    if file_stat.st_size > max_bytes:
        raise ValueError(f"artifact exceeds the {max_bytes} byte safety limit")

    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"artifact exceeds the {max_bytes} byte safety limit")
                digest.update(chunk)
    except OSError as exc:
        raise ValueError(f"could not read artifact: {exc}") from exc
    return digest.hexdigest(), total


def load_rule_file(path_value: str, *, max_bytes: int = RULE_MAX_BYTES) -> str:
    """Read a local rule file without executing or interpreting it as code."""
    raw_path = _clean(path_value, field="rule_path", required=True, limit=4096)
    path = Path(raw_path).expanduser()
    if path.is_symlink():
        raise ValueError("rule file must not be a symbolic link")
    try:
        file_stat = path.stat()
    except FileNotFoundError as exc:
        raise ValueError(f"rule file not found: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("rule file must be a regular file")
    if file_stat.st_size > max_bytes:
        raise ValueError(f"rule file exceeds the {max_bytes} byte safety limit")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"could not read rule file: {exc}") from exc


def validate_rule(rule_type: str, content: str) -> Dict[str, Any]:
    """Perform bounded structural checks; never execute a submitted rule."""
    rule_type = _choice(rule_type, field="rule_type", allowed=RULE_TYPES)
    content = _clean(content, field="content", required=True, limit=RULE_MAX_BYTES)
    errors: List[str] = []
    validator = "structural"
    try:
        if rule_type == "yara":
            if not re.search(r"\brule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", content):
                errors.append("YARA rule declaration is missing")
            if content.count("{") != content.count("}"):
                errors.append("YARA braces are unbalanced")
            if not re.search(r"\bcondition\s*:", content):
                errors.append("YARA condition section is missing")
        else:
            if yaml is None:
                errors.append("PyYAML is required for Sigma and Semgrep validation")
                parsed = None
            else:
                parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                errors.append(f"{rule_type} document must be a mapping")
            elif rule_type == "sigma":
                for field in ("title", "logsource", "detection"):
                    if field not in parsed:
                        errors.append(f"Sigma field is missing: {field}")
                if "detection" in parsed and not isinstance(parsed["detection"], dict):
                    errors.append("Sigma detection must be a mapping")
            else:
                rules = parsed.get("rules") if isinstance(parsed, dict) else None
                if not isinstance(rules, list) or not rules:
                    errors.append("Semgrep document must contain a non-empty rules list")
                else:
                    for index, item in enumerate(rules):
                        if not isinstance(item, dict):
                            errors.append(f"Semgrep rule {index + 1} must be a mapping")
                            continue
                        if not item.get("id"):
                            errors.append(f"Semgrep rule {index + 1} is missing id")
                        pattern_keys = {"pattern", "patterns", "pattern-either", "pattern-regex", "metavariable-regex", "paths"}
                        if not pattern_keys.intersection(item):
                            errors.append(f"Semgrep rule {index + 1} has no supported pattern selector")
    except Exception as exc:
        if yaml is not None and isinstance(exc, yaml.YAMLError):
            errors.append(f"{rule_type} YAML could not be parsed: {exc.__class__.__name__}")
        else:
            raise
    return {
        "status": "passed" if not errors else "failed",
        "validator": validator,
        "errors": errors,
    }


def _decode(value: Any, default: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _pipeline_step_summary(step_key: str, value: Any) -> Dict[str, Any]:
    """Return the bounded case-detail view; full pipeline results remain Core-local."""
    result = value if isinstance(value, dict) else {}
    if result.get("message"):
        return {
            "message": _clean(result.get("message"), field="pipeline message", limit=1000),
            **({"required_input": str(result.get("required_input"))[:80]} if result.get("required_input") else {}),
        }
    if step_key in {"collect_subject", "collect_reference"}:
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        analysis = result.get("analysis") if isinstance(result.get("analysis"), dict) else {}
        return {
            "package": str(metadata.get("package") or "")[:512],
            "version": str(metadata.get("version") or "")[:160],
            "artifact_sha256": str(metadata.get("artifact_sha256") or "")[:64],
            "artifact_bytes": int(metadata.get("artifact_bytes") or 0),
            "indicator_count": len(analysis.get("indicators") or []),
            "member_count": int(analysis.get("member_count") or 0),
            "execution_performed": False,
        }
    if step_key == "compare_packages":
        return {"comparison_ready": bool(result), "execution_performed": False}
    if step_key == "evidence_matrix":
        return {"summary": result.get("summary") if isinstance(result.get("summary"), dict) else {}}
    if step_key in {"analyze_research_case", "generate_analyst_brief", "review_publication_safety"}:
        return {"message": "Structured analysis is available in the pipeline review queue."} if result else {}
    if step_key == "validate_subject":
        return {"assumptions_made": bool(result.get("assumptions_made", False))}
    return {}


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
    potential_impact: Optional[str] = None,
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
        "potential_impact": _choice(
            potential_impact if potential_impact is not None else severity,
            field="potential_impact",
            allowed=POTENTIAL_IMPACTS,
        ),
        "potential_impact_explicit": int(potential_impact is not None),
        "confidence": _confidence(confidence),
        "owner": _clean(owner, field="owner", limit=160),
    }
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO research_cases (
                case_id, title, summary, case_type, severity, confidence, status,
                potential_impact, potential_impact_explicit, owner, disclosure_status, embargo_until, created_at, updated_at,
                closed_at, published_at, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, 'not_started', NULL, ?, ?, NULL, NULL, ?)
            """,
            (
                case_id,
                values["title"],
                values["summary"],
                values["case_type"],
                values["severity"],
                values["confidence"],
                values["potential_impact"],
                values["potential_impact_explicit"],
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
                   CASE WHEN COALESCE(potential_impact_explicit, 0) = 0
                             AND severity IN ('high', 'critical')
                        THEN severity ELSE potential_impact END AS potential_impact,
                   investigation_priority, detection_confidence,
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
                       (SELECT COUNT(*) FROM research_rules r WHERE r.case_id = c.case_id AND r.status = 'active') AS rule_count,
                       (SELECT COUNT(*) FROM research_rule_proposals p WHERE p.case_id = c.case_id AND p.status = 'review_required') AS rule_proposal_count,
                       (SELECT COUNT(*) FROM research_case_findings f WHERE f.case_id = c.case_id) AS finding_count,
                       (SELECT COUNT(*) FROM research_sandbox_requests s WHERE s.case_id = c.case_id) AS sandbox_count,
                       (SELECT COUNT(*) FROM research_sandbox_requests s WHERE s.case_id = c.case_id
                          AND s.status IN ('pending_approval', 'approved', 'submitted')) AS sandbox_pending_count
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


def reconcile_subject_artifact_state(case_id: str, *, db_path: Optional[str] = None, actor: str = "state-reconciler") -> Dict[str, Any]:
    """Keep subject lifecycle state aligned with the canonical artifact catalog.

    The catalog is authoritative for whether a hash-verified artifact is
    collected. Reconciliation is idempotent and records an audit event only
    when a visible subject state actually changes.
    """
    case_id = _case_id(case_id)
    soc_store.init_db(db_path)
    changed: list[dict[str, Any]] = []
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        subjects = connection.execute(
            """SELECT subject_id, subject_type, ecosystem, name, version, artifact_state
               FROM research_subjects WHERE case_id = ? AND status = 'active'""",
            (case_id,),
        ).fetchall()
        for subject in subjects:
            artifact = connection.execute(
                """SELECT a.artifact_id, a.state, a.sha256
                   FROM research_case_artifacts ca
                   JOIN research_artifacts a ON a.artifact_id = ca.artifact_id
                   WHERE ca.case_id = ? AND lower(a.ecosystem) = lower(?)
                     AND a.package_name = ? AND a.version = ?
                   ORDER BY a.updated_at DESC LIMIT 1""",
                (case_id, subject["ecosystem"], subject["name"], subject["version"]),
            ).fetchone()
            if artifact is None:
                continue
            catalog_state = str(artifact["state"] or "missing")
            desired = catalog_state if catalog_state in {"collected", "externally_supplied", "missing"} else "missing"
            current = str(subject["artifact_state"] or "missing")
            if current == desired:
                continue
            reason = f"Reconciled from artifact catalog {artifact['artifact_id']} ({desired}; sha256={artifact['sha256']})."
            connection.execute(
                """UPDATE research_subjects
                   SET artifact_state = ?, state_reason = ?, state_checked_at = ?
                   WHERE subject_id = ?""",
                (desired, reason, now, subject["subject_id"]),
            )
            changed.append({"subject_id": subject["subject_id"], "artifact_id": artifact["artifact_id"], "from": current, "to": desired})
        if changed:
            _record_event(
                connection,
                case_id,
                "subject_state_reconciled",
                f"Reconciled {len(changed)} subject artifact state(s) from the artifact catalog.",
                actor=actor,
                data={"changes": changed},
            )
            connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return {"case_id": case_id, "changed": changed, "checked_at": now}


def calibrate_case_assessment(
    case_id: str,
    *,
    db_path: Optional[str] = None,
    actor: str = "signal-calibrator",
    persist: bool = True,
) -> Dict[str, Any]:
    """Calculate calibrated fields, optionally persisting the assessment.

    Read paths use ``persist=False`` so rendering a case never changes its
    state or creates audit events. Explicit workflow actions keep the default
    persistent behavior.
    """
    case_id = _case_id(case_id)
    soc_store.init_db(db_path)
    from secopsai.research_signal_analysis import collect_observations, deduplicate_observations, evidence_quality_summary

    with closing(soc_store.connect(db_path)) as connection:
        case_row = connection.execute(
            "SELECT status, severity, confidence, assessment, investigation_priority, detection_confidence, potential_impact, potential_impact_explicit, local_exposure, evidence_quality, publication_readiness FROM research_cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case_row is None:
            raise ValueError(f"research case not found: {case_id}")
        evidence_rows = connection.execute(
            "SELECT evidence_id, evidence_type, metadata_json, occurrence_count FROM research_evidence WHERE case_id = ? AND status = 'active'",
            (case_id,),
        ).fetchall()
        subjects = connection.execute(
            "SELECT metadata_json FROM research_subjects WHERE case_id = ? AND status = 'active'",
            (case_id,),
        ).fetchall()
        observations: list[dict[str, Any]] = []
        for row in evidence_rows:
            metadata = _decode(row["metadata_json"], {})
            if isinstance(metadata, dict):
                observations.extend(collect_observations(metadata))
        deduped = deduplicate_observations(observations)
        quality = evidence_quality_summary(deduped["observations"])
        high_signal = [
            item for item in deduped["observations"]
            if item.get("contributes_to_score") and int(item.get("confidence") or 0) >= 80
        ]
        detection_confidence = max((int(item.get("confidence") or 0) for item in high_signal), default=0)
        categories = {str(item.get("category") or "") for item in high_signal}
        priority = "high" if len(high_signal) >= 3 or {"execution", "network"}.issubset(categories) else "medium" if high_signal else "normal"
        severity = str(case_row["severity"] or "medium").lower()
        impact = str(case_row["potential_impact"] or severity or "medium").lower()
        # Legacy rows had a medium database default with no way to distinguish
        # an explicit override. Never understate a high/critical case during
        # migration; new explicit overrides remain respected.
        if not bool(case_row["potential_impact_explicit"] or 0) and severity in {"high", "critical"}:
            impact = severity
        if impact not in {"info", "low", "medium", "high", "critical"}:
            impact = "medium"
        assessment = str(case_row["assessment"] or "unconfirmed")
        verdict_row = connection.execute(
            "SELECT verdict, confidence FROM research_verdicts WHERE case_id = ? ORDER BY created_at DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        if verdict_row is not None:
            assessment = str(verdict_row["verdict"] or "unconfirmed")
        elif high_signal:
            assessment = "unconfirmed_static_lead"
        usage_states: list[str] = []
        for subject in subjects:
            metadata = _decode(subject["metadata_json"], {})
            usage = metadata.get("local_usage")
            if isinstance(usage, dict) and usage.get("present") is True:
                usage_states.append("observed")
            elif isinstance(usage, dict) and usage.get("present") is False:
                usage_states.append("not_observed")
            else:
                usage_states.append("unknown")
        if "observed" in usage_states:
            local_exposure = "observed"
        elif usage_states and all(state == "not_observed" for state in usage_states):
            local_exposure = "not_observed"
        elif any(state == "not_observed" for state in usage_states):
            local_exposure = "partially_checked"
        else:
            local_exposure = "unknown"
        readiness = "ready" if str(case_row["status"]) == "ready_to_publish" else "blocked"
        changed = {
            "investigation_priority": priority,
            "detection_confidence": detection_confidence,
            "assessment": assessment,
            "potential_impact": impact,
            "local_exposure": local_exposure,
            "evidence_quality": quality["label"],
            "publication_readiness": readiness,
        }
        previous = {key: case_row[key] for key in changed}
        if persist and previous != changed:
            now = soc_store.utc_now()
            assignments = ", ".join(f"{key} = ?" for key in changed)
            connection.execute(
                f"UPDATE research_cases SET {assignments}, updated_at = ? WHERE case_id = ?",
                (*changed.values(), now, case_id),
            )
            _record_event(
                connection,
                case_id,
                "case_assessment_calibrated",
                "Recalibrated priority, confidence, impact, exposure, evidence quality, and publication readiness.",
                actor=actor,
                data={"before": previous, "after": changed, "unique_observations": deduped["unique_observations"], "repeat_observations": deduped["repeat_observations"]},
            )
            connection.commit()
        return {
            "case_id": case_id,
            **changed,
            "unique_observations": deduped["unique_observations"],
            "repeat_observations": deduped["repeat_observations"],
            "independent_sources": quality["independent_sources"],
        }


def reclassify_ioc_candidates(case_id: str, *, db_path: Optional[str] = None, actor: str = "ioc-classifier") -> Dict[str, Any]:
    """Reclassify legacy URL candidates without deleting their audit trail.

    Older artifact analyses persisted every URL-like string as a pending IOC.
    Current extraction separates registry/reporting/documentation references
    from attacker candidates. This repair applies the same deterministic
    classifier to existing rows and marks non-IOC references rejected with an
    explicit reason, preserving the original candidate for audit review.
    """
    case_id = _case_id(case_id)
    soc_store.init_db(db_path)
    from secopsai.research_signal_analysis import classify_url

    changed: list[dict[str, Any]] = []
    with closing(soc_store.connect(db_path)) as connection:
        artifact_classifications: dict[str, tuple[str, str]] = {}
        for artifact in connection.execute(
            """SELECT a.analysis_json FROM research_case_artifacts ca
               JOIN research_artifacts a ON a.artifact_id = ca.artifact_id
               WHERE ca.case_id = ?""",
            (case_id,),
        ).fetchall():
            analysis = _decode(artifact["analysis_json"], {})
            observations = analysis.get("url_observations", []) if isinstance(analysis, dict) else []
            for item in observations:
                if isinstance(item, dict) and item.get("value"):
                    artifact_classifications[str(item["value"])] = (
                        str(item.get("classification") or "ioc_candidate"),
                        str(item.get("classification_reason") or "Artifact URL classification."),
                    )
        rows = connection.execute(
            """SELECT candidate_id, ioc_type, value, status, classification, classification_reason
               FROM research_ioc_candidates WHERE case_id = ? ORDER BY created_at, candidate_id""",
            (case_id,),
        ).fetchall()
        for row in rows:
            value = str(row["value"] or "").strip()
            # Automatic provenance repair is limited to unresolved legacy
            # candidates. Never rewrite a human-approved or human-rejected
            # row, even if its older value contains punctuation or lacks the
            # new classification fields.
            if str(row["status"] or "pending") not in {"pending", "needs_review"}:
                continue
            if not value or (row["ioc_type"] not in {"url", "domain"} and "://" not in value):
                continue
            probe = value if "://" in value else f"https://{value}"
            artifact_classification = artifact_classifications.get(value)
            if artifact_classification is None:
                artifact_classification = artifact_classifications.get(value.rstrip("*).,;:"))
            if artifact_classification is not None:
                classification, reason = artifact_classification
                classified = {"classification": classification, "classification_reason": reason, "value": value.rstrip("*).,;:")}
            else:
                classified = classify_url(probe)
            classification = str(classified.get("classification") or "ioc_candidate")
            reason = str(classified.get("classification_reason") or "Deterministic URL classification.")
            normalized_value = str(classified.get("value") or value)
            status = str(row["status"] or "pending")
            if classification in {"source_reference", "documentation_url", "shared_legitimate_service"} and status in {"pending", "needs_review"}:
                status = "rejected"
            if (
                str(row["value"] or "") == normalized_value
                and str(row["classification"] or "ioc_candidate") == classification
                and str(row["classification_reason"] or "") == reason
                and str(row["status"] or "") == status
            ):
                continue
            connection.execute(
                """UPDATE research_ioc_candidates
                   SET value = ?, classification = ?, classification_reason = ?, status = ?
                   WHERE candidate_id = ?""",
                (normalized_value, classification, reason, status, row["candidate_id"]),
            )
            changed.append({
                "candidate_id": row["candidate_id"],
                "value": normalized_value,
                "previous_value": value if value != normalized_value else None,
                "classification": classification,
                "status": status,
                "reason": reason,
            })
        if changed:
            _record_event(
                connection,
                case_id,
                "ioc_candidates_reclassified",
                f"Reclassified {len(changed)} legacy IOC candidate(s) using source and documentation provenance rules.",
                actor=actor,
                data={"changes": changed},
            )
            connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (soc_store.utc_now(), case_id))
        connection.commit()
    return {"case_id": case_id, "changed": changed}


def get_case(case_id: str, *, db_path: Optional[str] = None, repair: bool = False) -> Dict[str, Any]:
    """Return a case without mutating it unless an explicit repair is requested."""
    case_id = _case_id(case_id)
    soc_store.init_db(db_path)
    ioc_reclassification = reclassify_ioc_candidates(case_id, db_path=db_path) if repair else {"case_id": case_id, "changed": []}
    reconciliation = reconcile_subject_artifact_state(case_id, db_path=db_path) if repair else {"case_id": case_id, "changed": []}
    calibration = calibrate_case_assessment(case_id, db_path=db_path, persist=False)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_cases WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise ValueError(f"research case not found: {case_id}")
        result = dict(row)
        # Keep read payloads/export reports deterministic; the persisted
        # subject state and audit event retain the reconciliation timestamp.
        result["ioc_reclassification"] = ioc_reclassification
        result["state_reconciliation"] = {"case_id": case_id, "changed": reconciliation.get("changed", [])}
        result["assessment_calibration"] = calibration
        for key in ("investigation_priority", "detection_confidence", "assessment", "potential_impact", "local_exposure", "evidence_quality"):
            if key in calibration:
                result[key] = calibration[key]
        result["metadata"] = _decode(result.pop("payload_json", "{}"), {})
        result["subjects"] = [
            {**dict(item), "metadata": _decode(item["metadata_json"], {})}
            for item in connection.execute(
                "SELECT * FROM research_subjects WHERE case_id = ? ORDER BY created_at, subject_id", (case_id,)
            ).fetchall()
        ]
        for item in result["subjects"]:
            item.pop("metadata_json", None)
        result["artifacts"] = [
            dict(item) for item in connection.execute(
                """SELECT a.artifact_id, a.sha256, a.filename, a.ecosystem,
                          a.package_name, a.version, a.size_bytes, a.state,
                          ca.role, ca.created_at
                   FROM research_case_artifacts ca
                   JOIN research_artifacts a ON a.artifact_id = ca.artifact_id
                   WHERE ca.case_id = ? ORDER BY ca.created_at, a.artifact_id""", (case_id,)
            ).fetchall()
        ]
        result["ioc_candidates"] = [
            dict(item) for item in connection.execute(
                "SELECT * FROM research_ioc_candidates WHERE case_id = ? ORDER BY created_at, candidate_id", (case_id,)
            ).fetchall()
        ]
        result["partner_requests"] = [
            dict(item) for item in connection.execute(
                "SELECT * FROM research_partner_requests WHERE case_id = ? ORDER BY updated_at DESC", (case_id,)
            ).fetchall()
        ]
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
        result["rules"] = []
        for item in connection.execute(
            "SELECT * FROM research_rules WHERE case_id = ? ORDER BY rule_type, name, rule_id", (case_id,)
        ).fetchall():
            value = dict(item)
            value["validation"] = _decode(value.pop("validation_json", "{}"), {})
            result["rules"].append(value)
        result["rule_proposals"] = []
        for item in connection.execute(
            "SELECT * FROM research_rule_proposals WHERE case_id = ? ORDER BY created_at, proposal_id", (case_id,)
        ).fetchall():
            value = dict(item)
            value["validation"] = _decode(value.pop("validation_json", "{}"), {})
            value["test"] = _decode(value.pop("test_json", "{}"), {})
            result["rule_proposals"].append(value)
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
        result["jobs"] = []
        for item in connection.execute(
            "SELECT job_id, action, status, requested_by, attempt, queued_at, started_at, completed_at, updated_at, error_code, error_message, config_json, result_json FROM research_jobs WHERE case_id = ? ORDER BY updated_at DESC",
            (case_id,),
        ).fetchall():
            value = dict(item)
            value["config"] = _decode(value.pop("config_json", "{}"), {})
            value["result"] = _decode(value.pop("result_json", "{}"), {})
            result["jobs"].append(value)
        result["pipelines"] = []
        for pipeline_row in connection.execute(
            "SELECT * FROM research_pipeline_runs WHERE case_id = ? ORDER BY updated_at DESC",
            (case_id,),
        ).fetchall():
            pipeline = dict(pipeline_row)
            pipeline["config"] = _decode(pipeline.pop("config_json", "{}"), {})
            pipeline["summary"] = _decode(pipeline.pop("summary_json", "{}"), {})
            pipeline["steps"] = []
            for step_row in connection.execute(
                "SELECT * FROM research_pipeline_steps WHERE pipeline_id = ? ORDER BY step_order",
                (pipeline["pipeline_id"],),
            ).fetchall():
                step = dict(step_row)
                step["result"] = _pipeline_step_summary(
                    str(step.get("step_key") or ""),
                    _decode(step.pop("result_json", "{}"), {}),
                )
                pipeline["steps"].append(step)
            pipeline["review_items"] = []
            for review_row in connection.execute(
                "SELECT * FROM research_review_items WHERE pipeline_id = ? ORDER BY created_at, item_id",
                (pipeline["pipeline_id"],),
            ).fetchall():
                review = dict(review_row)
                review["evidence_refs"] = _decode(review.pop("evidence_refs_json", "[]"), [])
                review["metadata"] = _decode(review.pop("metadata_json", "{}"), {})
                pipeline["review_items"].append(review)
            pipeline["review_summary"] = {
                status: sum(item["status"] == status for item in pipeline["review_items"])
                for status in ("pending", "applying", "accepted", "rejected", "superseded")
            }
            result["pipelines"].append(pipeline)
        intelligence_jobs = {
            str(item["job_id"]): dict(item)
            for item in connection.execute(
                """SELECT DISTINCT j.job_id, j.action, j.status, j.attempt, j.provider,
                          j.queued_at, j.started_at, j.completed_at, j.updated_at,
                          j.error_code, j.error_message
                   FROM intelligence_jobs j
                   JOIN research_pipeline_steps s ON s.intelligence_job_id = j.job_id
                   JOIN research_pipeline_runs p ON p.pipeline_id = s.pipeline_id
                   WHERE p.case_id = ?""",
                (case_id,),
            ).fetchall()
        }
        for pipeline in result["pipelines"]:
            for step in pipeline["steps"]:
                job_id = str(step.get("intelligence_job_id") or "")
                if job_id and job_id in intelligence_jobs:
                    step["intelligence_job"] = intelligence_jobs[job_id]
        result["claims"] = []
        for item in connection.execute(
            "SELECT * FROM research_claims WHERE case_id = ? ORDER BY updated_at DESC",
            (case_id,),
        ).fetchall():
            value = dict(item)
            for key in ("supporting_evidence_json", "contradicting_evidence_json", "missing_evidence_json", "limitations_json"):
                value[key[:-5]] = _decode(value.pop(key, "[]"), [])
            result["claims"].append(value)
        result["verdicts"] = []
        for item in connection.execute(
            "SELECT * FROM research_verdicts WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,),
        ).fetchall():
            value = dict(item)
            value["evidence_ids"] = _decode(value.pop("evidence_ids_json", "[]"), [])
            result["verdicts"].append(value)
        result["disclosures"] = []
        for item in connection.execute(
            "SELECT * FROM research_disclosures WHERE case_id = ? ORDER BY updated_at DESC",
            (case_id,),
        ).fetchall():
            value = dict(item)
            value["affected_scope"] = _decode(value.pop("affected_scope_json", "[]"), [])
            value["attachments"] = _decode(value.pop("attachments_json", "[]"), [])
            result["disclosures"].append(value)
        result["publication_reviews"] = []
        for item in connection.execute(
            "SELECT * FROM research_publication_reviews WHERE case_id = ? ORDER BY updated_at DESC",
            (case_id,),
        ).fetchall():
            value = dict(item)
            for key in ("blockers_json", "warnings_json", "checks_json", "waivers_json"):
                value[key[:-5]] = _decode(value.pop(key, "[]"), {})
            result["publication_reviews"].append(value)
        result["sandbox_requests"] = []
        for item in connection.execute(
            "SELECT * FROM research_sandbox_requests WHERE case_id = ? ORDER BY updated_at DESC",
            (case_id,),
        ).fetchall():
            value = dict(item)
            value["requested_behaviors"] = _decode(value.pop("requested_behaviors_json", "[]"), [])
            value["result"] = _decode(value.pop("result_json", "{}"), {})
            result["sandbox_requests"].append(value)
    readiness = publication_readiness(result)
    result["publication_readiness"] = readiness
    result["publication_readiness_state"] = "ready" if readiness["ready"] else "blocked"
    # Dynamic-analysis guidance is a pure, read-only policy decision. Keep it
    # alongside the case payload so the CLI and dashboard use the same result.
    from secopsai.research_sandbox import recommend_dynamic_analysis

    result["sandbox_recommendation"] = recommend_dynamic_analysis(result)
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
        "potential_impact": lambda value: _choice(value, field="potential_impact", allowed=POTENTIAL_IMPACTS),
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
    derived_impact = False
    if "severity" in changed and not bool(current.get("potential_impact_explicit") or 0) and "potential_impact" not in changed:
        changed["potential_impact"] = changed["severity"]
        derived_impact = True
    if "potential_impact" in changed:
        changed["potential_impact_explicit"] = 0 if derived_impact else 1
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
    registry_state: str = "unknown",
    artifact_state: str = "missing",
    validation_state: str = "unverified",
    state_reason: str = "",
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
    registry_state = _choice(registry_state, field="registry_state", allowed={"available", "unlisted", "removed", "unavailable", "unknown"})
    artifact_state = _choice(artifact_state, field="artifact_state", allowed={"collected", "missing", "externally_supplied"})
    validation_state = _choice(validation_state, field="validation_state", allowed={"unverified", "static_confirmed", "sandbox_confirmed"})
    state_reason = _clean(state_reason, field="state_reason", limit=2000)
    stable = hashlib.sha256(f"{case_id}|{subject_type}|{ecosystem}|{name}|{version}".encode()).hexdigest()[:16].upper()
    subject_id = f"SUB-{stable}"
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO research_subjects (
                subject_id, case_id, subject_type, ecosystem, name, version,
                publisher, status, registry_state, artifact_state, validation_state,
                state_reason, state_checked_at, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, subject_type, ecosystem, name, version) DO UPDATE SET
                publisher = excluded.publisher, metadata_json = excluded.metadata_json,
                registry_state = excluded.registry_state, artifact_state = excluded.artifact_state,
                validation_state = excluded.validation_state, state_reason = excluded.state_reason,
                state_checked_at = excluded.state_checked_at
            """,
            (subject_id, case_id, subject_type, ecosystem, name, version, publisher,
             registry_state, artifact_state, validation_state, state_reason, now,
             _json(metadata or {}), now),
        )
        _record_event(connection, case_id, "subject_added", f"Added research subject {name}.", actor=actor, data={"subject_id": subject_id})
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def update_subject_state(
    subject_id: str,
    *,
    registry_state: Optional[str] = None,
    artifact_state: Optional[str] = None,
    validation_state: Optional[str] = None,
    reason: str = "",
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    """Update lifecycle facts without changing the case-record status."""
    soc_store.init_db(db_path)
    allowed = {
        "registry_state": {"available", "unlisted", "removed", "unavailable", "unknown"},
        "artifact_state": {"collected", "missing", "externally_supplied"},
        "validation_state": {"unverified", "static_confirmed", "sandbox_confirmed"},
    }
    changes: Dict[str, Any] = {}
    for key, value in (("registry_state", registry_state), ("artifact_state", artifact_state), ("validation_state", validation_state)):
        if value is not None:
            value = _choice(value, field=key, allowed=allowed[key])
            changes[key] = value
    if reason:
        changes["state_reason"] = _clean(reason, field="reason", limit=2000)
    if not changes:
        raise ValueError("at least one subject state is required")
    changes["state_checked_at"] = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT case_id FROM research_subjects WHERE subject_id = ?", (subject_id,)).fetchone()
        if row is None:
            raise ValueError(f"subject not found: {subject_id}")
        assignments = ", ".join(f"{key} = ?" for key in changes)
        connection.execute(f"UPDATE research_subjects SET {assignments} WHERE subject_id = ?", (*changes.values(), subject_id))
        _record_event(connection, row["case_id"], "subject_state_updated", f"Updated lifecycle state for {subject_id}.", actor=actor, data={"subject_id": subject_id, "changes": changes})
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (soc_store.utc_now(), row["case_id"]))
        connection.commit()
    return get_case(row["case_id"], db_path=db_path)


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
    now = soc_store.utc_now()
    metadata_payload = dict(metadata or {})
    fingerprint_payload = {
        "case_id": case_id,
        "evidence_type": evidence_type,
        "locator": locator,
        "sha256": sha256,
        "tool": str(metadata_payload.get("analysis_tool") or metadata_payload.get("tool") or ""),
        "tool_version": str(metadata_payload.get("analysis_tool_version") or metadata_payload.get("tool_version") or ""),
        "artifact_sha256": str(metadata_payload.get("artifact_sha256") or ""),
    }
    fingerprint = hashlib.sha256(_json(fingerprint_payload).encode()).hexdigest()
    source_key = hashlib.sha256(f"{provenance}|{locator}".encode()).hexdigest()[:24]
    with closing(soc_store.connect(db_path)) as connection:
        existing = connection.execute(
            """SELECT evidence_id, occurrence_count, metadata_json
               FROM research_evidence
               WHERE case_id = ? AND fingerprint = ? AND status = 'active'
               ORDER BY created_at LIMIT 1""",
            (case_id, fingerprint),
        ).fetchone()
        if existing is not None:
            evidence_id = str(existing["evidence_id"])
            occurrence_count = int(existing["occurrence_count"] or 1) + 1
            existing_metadata = _decode(existing["metadata_json"], {})
            merged_metadata = {**existing_metadata, **metadata_payload}
            merged_metadata["repeat_observations"] = occurrence_count - 1
            connection.execute(
                """UPDATE research_evidence
                   SET occurrence_count = ?, last_observed_at = ?, metadata_json = ?
                   WHERE evidence_id = ?""",
                (occurrence_count, now, _json(merged_metadata), evidence_id),
            )
            _record_event(
                connection,
                case_id,
                "evidence_reobserved",
                f"Reobserved existing evidence: {title}.",
                actor=actor,
                data={"evidence_id": evidence_id, "fingerprint": fingerprint, "occurrence_count": occurrence_count},
            )
            connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
            connection.commit()
            return get_case(case_id, db_path=db_path)
        evidence_id = _id("EVD")
        connection.execute(
            """
            INSERT INTO research_evidence (
                evidence_id, case_id, evidence_type, title, locator, sha256,
                provenance, notes, status, collected_at, created_at, metadata_json,
                fingerprint, occurrence_count, first_observed_at, last_observed_at,
                independent_source_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, 1, ?, ?, ?)
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
                _json(metadata_payload),
                fingerprint,
                now,
                now,
                source_key,
            ),
        )
        _record_event(connection, case_id, "evidence_added", f"Added evidence: {title}.", actor=actor, data={"evidence_id": evidence_id, "type": evidence_type})
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def add_local_artifact(
    case_id: str,
    *,
    artifact_path: str,
    title: str = "",
    locator: str = "",
    provenance: str = "",
    notes: str = "",
    max_bytes: int = LOCAL_ARTIFACT_MAX_BYTES,
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    """Attach a local artifact as hash-only evidence.

    The file is read as bytes solely to calculate a SHA-256 digest. This helper
    deliberately does not execute, unpack, import, or otherwise inspect the
    artifact contents.
    """
    raw_path = _clean(artifact_path, field="artifact_path", required=True, limit=4096)
    path = Path(raw_path).expanduser()
    digest, size = _sha256_file(path, max_bytes=max_bytes)
    filename = path.name or "artifact"
    safe_locator = locator.strip() or f"local-artifact:{filename}"
    safe_provenance = provenance.strip() or "local artifact hashed without execution or unpacking"
    size_note = f"filename={filename}; bytes={size}; collection=hash_only; execution=false; unpacking=false"
    combined_notes = "; ".join(value for value in [size_note, notes.strip()] if value)
    return add_evidence(
        case_id,
        evidence_type="package_artifact",
        title=title.strip() or f"Local artifact: {filename}",
        locator=safe_locator,
        sha256=digest,
        provenance=safe_provenance,
        notes=combined_notes,
        metadata={
            "collection_mode": "hash_only",
            "analysis_executed": False,
            "unpacked": False,
            "filename": filename,
            "bytes": size,
        },
        db_path=db_path,
        actor=actor,
    )


def add_rule(
    case_id: str,
    *,
    rule_type: str,
    name: str,
    content: str,
    purpose: str = "",
    source_evidence_id: Optional[str] = None,
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    """Attach a defensive detection rule after bounded structural validation."""
    case_id = _case_id(case_id)
    get_case(case_id, db_path=db_path)
    rule_type = _choice(rule_type, field="rule_type", allowed=RULE_TYPES)
    name = _clean(name, field="name", required=True, limit=240)
    content = _clean(content, field="content", required=True, limit=RULE_MAX_BYTES)
    purpose = _clean(purpose, field="purpose", limit=2000)
    source_evidence_id = _clean(source_evidence_id, field="source_evidence_id", limit=32) or None
    validation = validate_rule(rule_type, content)
    stable = hashlib.sha256(f"{case_id}|{rule_type}|{name}".encode()).hexdigest()[:16].upper()
    rule_id = f"RUL-{stable}"
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
            INSERT INTO research_rules (
                rule_id, case_id, rule_type, name, purpose, content,
                validation_status, validation_json, source_evidence_id,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
            ON CONFLICT(case_id, rule_type, name) DO UPDATE SET
                purpose = excluded.purpose,
                content = excluded.content,
                validation_status = excluded.validation_status,
                validation_json = excluded.validation_json,
                source_evidence_id = excluded.source_evidence_id,
                status = 'active',
                updated_at = excluded.updated_at
            """,
            (
                rule_id,
                case_id,
                rule_type,
                name,
                purpose,
                content,
                validation["status"],
                _json(validation),
                source_evidence_id,
                now,
                now,
            ),
        )
        _record_event(
            connection,
            case_id,
            "rule_added",
            f"Attached {rule_type} detection rule {name} ({validation['status']}).",
            actor=actor,
            data={"rule_id": rule_id, "rule_type": rule_type, "validation": validation},
        )
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return get_case(case_id, db_path=db_path)


def start_package_case(
    *,
    package: str,
    ecosystem: str,
    version: str = "",
    title: str = "",
    summary: str = "",
    case_type: str = "malicious_package",
    severity: str = "medium",
    potential_impact: Optional[str] = None,
    confidence: Any = 0,
    owner: str = "",
    publisher: str = "",
    source_url: str = "",
    artifact_path: str = "",
    artifact_title: str = "",
    db_path: Optional[str] = None,
    actor: str = "analyst",
) -> Dict[str, Any]:
    """Create a package research case with a safe, structured starting point.

    This command records analyst-supplied metadata and optional public source
    references. It never fetches a registry, executes a package, or unpacks a
    local artifact. Local artifacts are hash-only evidence when supplied.
    """
    package_name = _clean(package, field="package", required=True, limit=512)
    ecosystem_name = _clean(ecosystem, field="ecosystem", required=True, limit=80).lower()
    package_version = _clean(version, field="version", limit=160)
    generated_title = title.strip() or f"Package research: {ecosystem_name}/{package_name}"
    generated_summary = summary.strip() or (
        f"Initial structured research case for the {ecosystem_name} package {package_name}"
        + (f" version {package_version}" if package_version else "")
        + ". No maliciousness has been established; validation remains open."
    )

    # Preflight the artifact before creating any case records so a bad path
    # cannot leave a guided start half-complete.
    artifact_digest: Optional[str] = None
    artifact_size: Optional[int] = None
    artifact_name = ""
    if artifact_path:
        artifact_file = Path(_clean(artifact_path, field="artifact_path", required=True, limit=4096)).expanduser()
        artifact_digest, artifact_size = _sha256_file(artifact_file)
        artifact_name = artifact_file.name or "artifact"

    case = create_case(
        title=generated_title,
        summary=generated_summary,
        case_type=case_type,
        severity=severity,
        potential_impact=potential_impact,
        confidence=confidence,
        owner=owner,
        db_path=db_path,
    )
    case = add_subject(
        case["case_id"],
        subject_type="package",
        name=package_name,
        ecosystem=ecosystem_name,
        version=package_version,
        publisher=publisher,
        actor=actor,
        db_path=db_path,
    )
    if source_url:
        case = add_evidence(
            case["case_id"],
            evidence_type="registry_metadata",
            title="Analyst-supplied public package source",
            locator=source_url,
            provenance="analyst-supplied public source; not fetched by case start",
            notes="Recorded as a research lead. Validate the source before publication.",
            actor=actor,
            db_path=db_path,
        )
    if artifact_digest:
        case = add_evidence(
            case["case_id"],
            evidence_type="package_artifact",
            title=artifact_title.strip() or f"Local artifact: {artifact_name}",
            locator=f"local-artifact:{artifact_name}",
            sha256=artifact_digest,
            provenance="local artifact hashed without execution or unpacking",
            notes=(
                f"filename={artifact_name}; bytes={artifact_size}; collection=hash_only; "
                "execution=false; unpacking=false"
            ),
            metadata={
                "collection_mode": "hash_only",
                "analysis_executed": False,
                "unpacked": False,
                "filename": artifact_name,
                "bytes": artifact_size,
            },
            actor=actor,
            db_path=db_path,
        )
    return case


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
    item_type = _choice(item_type, field="item_type", allowed={"subject", "evidence", "ioc", "rule"})
    item_id = _clean(item_id, field="item_id", required=True, limit=40).upper()
    reason = _clean(reason, field="reason", required=True, limit=2000)
    table, id_column, prefix = {
        "subject": ("research_subjects", "subject_id", "SUB-"),
        "evidence": ("research_evidence", "evidence_id", "EVD-"),
        "ioc": ("research_iocs", "ioc_id", "IOC-"),
        "rule": ("research_rules", "rule_id", "RUL-"),
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
    active_rules = [item for item in (case.get("rules") or []) if item.get("status", "active") == "active"]
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
    if any(item.get("validation_status") != "passed" for item in active_rules):
        blockers.append("every active detection rule must pass structural validation")
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


def _case_markdown(case: Dict[str, Any], *, readiness: Optional[Dict[str, Any]] = None) -> str:
    readiness = readiness or publication_readiness(case)
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
    lines.extend(["", "## Detection Rules", ""])
    active_rules = [item for item in (case.get("rules") or []) if item.get("status", "active") == "active"]
    if not active_rules:
        lines.append("- No detection rules recorded.")
    for item in active_rules:
        lines.append(
            f"### {item['name']} (`{item['rule_type']}`, validation `{item['validation_status']}`)"
        )
        if item.get("purpose"):
            lines.extend(["", item["purpose"]])
        content = str(item.get("content") or "")
        longest_fence = max((len(match.group(0)) for match in re.finditer(r"`+", content)), default=2)
        fence = "`" * max(3, longest_fence + 1)
        lines.extend(["", fence + item["rule_type"], content, fence, ""])
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
    # A readiness check is useful in the exported report, but its wall-clock
    # evaluation time must not make identical case snapshots differ.
    readiness = dict(case["publication_readiness"])
    readiness["checked_at"] = case.get("updated_at")
    export_payload = {
        "schema_version": RESEARCH_EXPORT_SCHEMA_VERSION,
        **{key: value for key, value in case.items() if key != "publication_readiness"},
        "publication_readiness": readiness,
    }
    json_path.write_text(json.dumps(export_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_case_markdown(export_payload, readiness=readiness), encoding="utf-8")
    manifest_files = []
    for report_path in (json_path, markdown_path):
        report_bytes = report_path.read_bytes()
        manifest_files.append(
            {
                "name": report_path.name,
                "bytes": len(report_bytes),
                "sha256": hashlib.sha256(report_bytes).hexdigest(),
            }
        )
    manifest = {
        "schema_version": RESEARCH_EXPORT_MANIFEST_VERSION,
        "case_id": case["case_id"],
        "case_updated_at": case.get("updated_at"),
        "files": manifest_files,
    }
    manifest_path = target / f"{stem}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "case_id": case["case_id"],
        "json_report": str(json_path),
        "markdown_report": str(markdown_path),
        "manifest": str(manifest_path),
        "manifest_payload": manifest,
        "publication_readiness": readiness,
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
    publication_reviews = case.get("publication_reviews") or []
    if publication_reviews and publication_reviews[0].get("status") != "approved":
        raise ValueError("latest publication safety review is not approved")
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
