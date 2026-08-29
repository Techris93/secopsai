"""Approval-gated external sandbox connector primitives."""

from __future__ import annotations

import json
import os
import hashlib
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import soc_store


MAX_SUBMISSION_BYTES = 50 * 1024 * 1024
SANDBOX_RECOMMENDATION_POLICY_VERSION = "secopsai.sandbox-recommendation.v1"
SANDBOX_RUNTIME_CATEGORIES = {
    "execution",
    "lifecycle",
    "network",
    "credential_access",
    "credential",
    "persistence",
    "obfuscation",
}
SANDBOX_NON_CODE_CONTEXTS = {"documentation", "test", "example"}
SANDBOX_ACTIVE_STATUSES = {"pending_approval", "approved", "submitted"}
SANDBOX_TERMINAL_VERDICTS = {"benign", "not_substantiated", "retracted"}


class SandboxProviderError(RuntimeError):
    pass


def _decode(value: Any, default: Any) -> Any:
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _allowed_provider_hosts() -> set[str]:
    hosts = {"tria.ge", "www.tria.ge", "api.tria.ge"}
    hosts.update(item.strip().lower() for item in os.environ.get("TRIAGE_API_ALLOWED_HOSTS", "").split(",") if item.strip())
    return hosts


def provider_status(*, verify: bool = False) -> Dict[str, Any]:
    """Return safe Tria.ge configuration state, optionally using a read-only probe.

    The default path never contacts Tria.ge, which keeps frequent dashboard
    status polling cheap. ``verify=True`` calls the documented ``/resources``
    endpoint and returns only bounded health metadata; tokens and raw responses
    are never returned.
    """
    token = os.environ.get("TRIAGE_API_TOKEN", "").strip()
    base_url = os.environ.get("TRIAGE_API_BASE_URL", "https://tria.ge/api/v0").strip().rstrip("/")
    payload: Dict[str, Any] = {
        "provider": "tria.ge",
        "configured": bool(token),
        "mode": "public" if token else "manual-result-import",
        "base_url": base_url,
        "public_submission": True,
        "verified": False,
        "health": "not_checked" if token else "not_configured",
        "checked_at": None,
        "resource_count": None,
        "warning": "Tria.ge public submissions are visible to the public and must not contain confidential data.",
    }
    if not verify or not token:
        return payload

    parsed = urllib.parse.urlparse(f"{base_url}/resources")
    if parsed.scheme != "https" or parsed.hostname not in _allowed_provider_hosts():
        payload.update({"health": "invalid_configuration", "verification_error": "endpoint_not_allowed"})
        return payload

    request = urllib.request.Request(
        f"{base_url}/resources",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "SecOpsAI/Tria.ge-configuration-check",
        },
    )
    payload["checked_at"] = soc_store.utc_now()
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                payload.update({"health": "invalid_response", "verification_error": "response_too_large"})
                return payload
            decoded = json.loads(body.decode("utf-8"))
            resources = decoded.get("resources") if isinstance(decoded, dict) else decoded
            payload.update({
                "verified": response.status == 200 and isinstance(decoded, (dict, list)),
                "health": "ready" if response.status == 200 and isinstance(decoded, (dict, list)) else "invalid_response",
                "resource_count": len(resources) if isinstance(resources, (dict, list)) else None,
            })
            if response.status != 200:
                payload["verification_error"] = "unexpected_status"
    except urllib.error.HTTPError as exc:
        payload.update({
            "health": "unauthorized" if exc.code in {401, 403} else "unavailable",
            "verification_error": "authentication_failed" if exc.code in {401, 403} else "http_error",
            "http_status": exc.code,
        })
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        payload.update({"health": "unavailable", "verification_error": "connection_error"})
    return payload


def _normalized_category(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _case_observations(case: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Collect high-signal observations from static evidence without mutation."""
    from secopsai.research_signal_analysis import collect_observations, deduplicate_observations

    observations: list[dict[str, Any]] = []
    for evidence in case.get("evidence") or []:
        if not isinstance(evidence, Mapping):
            continue
        evidence_type = str(evidence.get("evidence_type") or "")
        if evidence_type not in {"static_analysis", "package_artifact"}:
            continue
        metadata = evidence.get("metadata")
        if not isinstance(metadata, Mapping):
            continue
        observations.extend({**dict(item), "_evidence_type": evidence_type} for item in collect_observations(metadata))
        nested = metadata.get("analysis")
        if isinstance(nested, Mapping):
            observations.extend({**dict(item), "_evidence_type": evidence_type} for item in collect_observations(nested))
    return deduplicate_observations(observations).get("observations", [])


def _valid_sha256(value: Any) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", str(value or "").strip()))


def _timestamp_for_sort(value: Any) -> float:
    """Return a stable UTC timestamp for latest-first queue ordering."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _runtime_gap(case: Mapping[str, Any]) -> bool:
    for claim in case.get("claims") or []:
        if not isinstance(claim, Mapping):
            continue
        missing = claim.get("missing_evidence") or claim.get("missing_evidence_json") or []
        if isinstance(missing, str):
            missing = [missing]
        text = " ".join(str(item) for item in missing if item)
        statement = str(claim.get("statement") or "")
        if re.search(r"\b(?:sandbox|dynamic|runtime|execution)\b", f"{text} {statement}", re.IGNORECASE):
            return True
    return False


def recommend_dynamic_analysis(case: Mapping[str, Any]) -> Dict[str, Any]:
    """Evaluate whether a case needs isolated runtime evidence.

    This is deliberately a pure policy function. It never creates a request,
    uploads an artifact, changes a verdict, or contacts an external provider.
    """
    observations = _case_observations(case)
    high_signal = [
        item for item in observations
        if bool(item.get("contributes_to_score"))
        and int(item.get("confidence") or 0) >= 80
        and _normalized_category(item.get("category")) in SANDBOX_RUNTIME_CATEGORIES
        and _normalized_category(item.get("context_classification")) not in SANDBOX_NON_CODE_CONTEXTS
    ]
    categories = {_normalized_category(item.get("category")) for item in high_signal}
    runtime_gap = _runtime_gap(case)
    verdicts = case.get("verdicts") or []
    latest_verdict = verdicts[0] if verdicts and isinstance(verdicts[0], Mapping) else {}
    verdict = str(latest_verdict.get("verdict") or "").strip().lower()

    artifacts = [
        item for item in case.get("artifacts") or []
        if isinstance(item, Mapping)
        and str(item.get("state") or "").lower() in {"collected", "externally_supplied"}
        and _valid_sha256(item.get("sha256"))
    ]
    artifacts.sort(key=lambda item: (0 if str(item.get("role") or "") == "subject" else 1, str(item.get("created_at") or ""), str(item.get("artifact_id") or "")))
    artifact = artifacts[0] if artifacts else {}
    artifact_sha256 = str(artifact.get("sha256") or "").lower()

    sandbox_requests = [item for item in case.get("sandbox_requests") or [] if isinstance(item, Mapping)]
    sandbox_evidence = [
        item for item in case.get("evidence") or []
        if isinstance(item, Mapping)
        and str(item.get("evidence_type") or "").lower() == "sandbox_analysis"
        and str(item.get("status") or "active").lower() == "active"
    ]
    if sandbox_evidence:
        return {
            "policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION,
            "recommended": False,
            "status": "completed",
            "priority": "normal",
            "score": 0,
            "artifact_sha256": artifact_sha256,
            "requested_behaviors": [],
            "reasons": ["Reviewed sandbox evidence is already attached to this case."],
            "blockers": [],
            "next_action": "Review the sanitized sandbox result and update the case verdict if needed.",
            "allowed_actions": [],
            "blocked_actions": [],
        }

    if any(str(item.get("status") or "").lower() == "completed" for item in sandbox_requests):
        return {
            "policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION,
            "recommended": False,
            "status": "completed_unlinked",
            "priority": "high" if len(categories) >= 2 else "medium",
            "score": min(100, 40 + len(categories) * 15),
            "artifact_sha256": artifact_sha256,
            "requested_behaviors": [],
            "reasons": ["A sandbox request is marked completed, but no linked sandbox_analysis evidence record is present."],
            "blockers": ["Record a valid sanitized report URL, submission ID, and behavior summary before relying on the result."],
            "next_action": "Refresh the case or record the sanitized result again; do not create a duplicate sandbox request.",
            "allowed_actions": [],
            "blocked_actions": ["request_sandbox_approval", "publish_research"],
        }

    if any(str(item.get("status") or "").lower() in SANDBOX_ACTIVE_STATUSES for item in sandbox_requests):
        return {
            "policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION,
            "recommended": False,
            "status": "already_requested",
            "priority": "high" if len(categories) >= 2 else "medium",
            "score": min(100, 40 + len(categories) * 15),
            "artifact_sha256": artifact_sha256,
            "requested_behaviors": [],
            "reasons": ["A sandbox request is already pending, approved, or submitted; a duplicate request is not needed."],
            "blockers": [],
            "next_action": "Review the existing request and refresh its result.",
            "allowed_actions": [],
            "blocked_actions": ["request_sandbox_approval"],
        }

    if verdict in SANDBOX_TERMINAL_VERDICTS:
        return {
            "policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION,
            "recommended": False,
            "status": "not_recommended",
            "priority": "normal",
            "score": 0,
            "artifact_sha256": artifact_sha256,
            "requested_behaviors": [],
            "reasons": [f"The latest human verdict is {verdict}; reopen the case only if new evidence contradicts it."],
            "blockers": [],
            "next_action": "Continue normal case review; do not submit a sample automatically.",
            "allowed_actions": [],
            "blocked_actions": ["request_sandbox_approval"],
        }

    runtime_reasons = {
        "execution": ("high-confidence process execution evidence", "process behavior"),
        "lifecycle": ("high-confidence lifecycle or build-time execution evidence", "process behavior"),
        "network": ("high-confidence outbound network evidence", "network behavior"),
        "credential_access": ("high-confidence credential access evidence", "credential access indicators"),
        "credential": ("high-confidence credential access evidence", "credential access indicators"),
        "persistence": ("high-confidence persistence evidence", "persistence behavior"),
        "obfuscation": ("high-confidence obfuscation evidence", "process behavior"),
    }
    reasons = [runtime_reasons[item][0] for item in sorted(categories) if item in runtime_reasons]
    requested_behaviors = sorted({runtime_reasons[item][1] for item in categories if item in runtime_reasons})
    if runtime_gap:
        reasons.append("the evidence matrix has an unresolved runtime or execution question")
    if not reasons:
        return {
            "policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION,
            "recommended": False,
            "status": "not_recommended",
            "priority": "normal",
            "score": 0,
            "artifact_sha256": artifact_sha256,
            "requested_behaviors": [],
            "reasons": ["No high-confidence executable behavior or material runtime evidence gap was found."],
            "blockers": [],
            "next_action": "Continue static evidence review; dynamic analysis is not currently justified.",
            "allowed_actions": [],
            "blocked_actions": ["request_sandbox_approval"],
        }

    score = min(100, 40 + len(categories) * 12 + (12 if {"execution", "lifecycle", "obfuscation"} & categories and {"network", "credential_access", "credential", "persistence"} & categories else 0) + (10 if runtime_gap else 0))
    priority = "high" if score >= 80 else "medium" if score >= 60 else "normal"
    if not artifact_sha256:
        return {
            "policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION,
            "recommended": True,
            "status": "blocked",
            "priority": priority,
            "score": score,
            "artifact_sha256": "",
            "requested_behaviors": requested_behaviors,
            "reasons": reasons,
            "blockers": ["Attach one exact hash-verified artifact before requesting dynamic analysis."],
            "next_action": "Collect or attach the exact authorized artifact, then request sandbox approval.",
            "allowed_actions": [],
            "blocked_actions": ["request_sandbox_approval", "submit_sandbox_artifact"],
        }

    return {
        "policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION,
        "recommended": True,
        "status": "recommended",
        "priority": priority,
        "score": score,
        "artifact_sha256": artifact_sha256,
        "requested_behaviors": requested_behaviors,
        "reasons": reasons,
        "blockers": [],
        "next_action": "Request sandbox approval for the exact artifact; approval and submission remain separate human actions.",
        "allowed_actions": ["request_sandbox_approval"],
        "blocked_actions": ["submit_sandbox_artifact", "publish_research"],
    }


def list_sandbox_recommendations(*, db_path: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    """Return a bounded, read-only queue of cases needing dynamic evidence."""
    soc_store.init_db(db_path)
    bounded_limit = max(1, min(int(limit), 500))
    with soc_store.connect(db_path) as connection:
        case_rows = connection.execute(
            """SELECT case_id, title, summary, severity, confidence, status, assessment, updated_at
               FROM research_cases ORDER BY updated_at DESC, created_at DESC LIMIT ?""",
            (bounded_limit,),
        ).fetchall()
        if not case_rows:
            return {"policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION, "recommendations": [], "summary": {"scanned": 0, "recommended": 0, "blocked": 0, "already_requested": 0, "completed": 0}}
        case_ids = [str(row["case_id"]) for row in case_rows]
        placeholders = ",".join("?" for _ in case_ids)
        artifacts_by_case: dict[str, list[dict[str, Any]]] = {case_id: [] for case_id in case_ids}
        for row in connection.execute(
            f"""SELECT ca.case_id, a.artifact_id, a.sha256, a.filename, a.ecosystem,
                      a.package_name, a.version, a.size_bytes, a.state, ca.role, ca.created_at
               FROM research_case_artifacts ca JOIN research_artifacts a ON a.artifact_id = ca.artifact_id
               WHERE ca.case_id IN ({placeholders})""",
            case_ids,
        ).fetchall():
            artifacts_by_case[str(row["case_id"])].append(dict(row))
        evidence_by_case: dict[str, list[dict[str, Any]]] = {case_id: [] for case_id in case_ids}
        for row in connection.execute(
            f"SELECT case_id, evidence_id, evidence_type, metadata_json FROM research_evidence WHERE case_id IN ({placeholders}) AND status = 'active'",
            case_ids,
        ).fetchall():
            evidence_by_case[str(row["case_id"])].append({
                "evidence_id": row["evidence_id"],
                "evidence_type": row["evidence_type"],
                "metadata": _decode(row["metadata_json"], {}),
            })
        requests_by_case: dict[str, list[dict[str, Any]]] = {case_id: [] for case_id in case_ids}
        for row in connection.execute(
            f"SELECT case_id, request_id, status, artifact_sha256 FROM research_sandbox_requests WHERE case_id IN ({placeholders})",
            case_ids,
        ).fetchall():
            requests_by_case[str(row["case_id"])].append(dict(row))
        verdicts_by_case: dict[str, list[dict[str, Any]]] = {case_id: [] for case_id in case_ids}
        for row in connection.execute(
            f"SELECT case_id, verdict, confidence, created_at FROM research_verdicts WHERE case_id IN ({placeholders}) ORDER BY created_at DESC",
            case_ids,
        ).fetchall():
            verdicts_by_case[str(row["case_id"])].append(dict(row))
        claims_by_case: dict[str, list[dict[str, Any]]] = {case_id: [] for case_id in case_ids}
        for row in connection.execute(
            f"SELECT case_id, statement, missing_evidence_json FROM research_claims WHERE case_id IN ({placeholders})",
            case_ids,
        ).fetchall():
            claims_by_case[str(row["case_id"])].append({
                "statement": row["statement"],
                "missing_evidence": _decode(row["missing_evidence_json"], []),
            })

    rows: list[dict[str, Any]] = []
    for row in case_rows:
        case_id = str(row["case_id"])
        case = {
            **dict(row),
            "artifacts": artifacts_by_case[case_id],
            "evidence": evidence_by_case[case_id],
            "sandbox_requests": requests_by_case[case_id],
            "verdicts": verdicts_by_case[case_id],
            "claims": claims_by_case[case_id],
        }
        recommendation = recommend_dynamic_analysis(case)
        if recommendation["recommended"] or recommendation["status"] in {"already_requested", "completed", "completed_unlinked"}:
            rows.append({
                "case_id": case_id,
                "title": str(row["title"] or case_id),
                "severity": str(row["severity"] or "medium"),
                "assessment": str(row["assessment"] or "unconfirmed"),
                "status": str(row["status"] or "draft"),
                "updated_at": row["updated_at"],
                "recommendation": recommendation,
            })
    rows.sort(key=lambda item: (
        0 if item["recommendation"].get("status") == "recommended"
        else 1 if item["recommendation"].get("status") == "blocked"
        else 2 if item["recommendation"].get("status") == "already_requested"
        else 3,
        -int(item["recommendation"].get("score") or 0),
        -_timestamp_for_sort(item.get("updated_at")),
    ))
    summary = {
        "scanned": len(case_rows),
        "recommended": sum(1 for item in rows if item["recommendation"].get("status") == "recommended"),
        "blocked": sum(1 for item in rows if item["recommendation"].get("status") == "blocked"),
        "already_requested": sum(1 for item in rows if item["recommendation"].get("status") == "already_requested"),
        "completed": sum(1 for item in rows if item["recommendation"].get("status") == "completed"),
        "completed_unlinked": sum(1 for item in rows if item["recommendation"].get("status") == "completed_unlinked"),
    }
    return {"policy_version": SANDBOX_RECOMMENDATION_POLICY_VERSION, "recommendations": rows[:bounded_limit], "summary": summary}


def _attached_approved_artifact(request: Dict[str, Any], *, db_path: Optional[str]) -> Dict[str, Any]:
    with soc_store.connect(db_path) as connection:
        rows = connection.execute(
            """SELECT DISTINCT a.artifact_id, a.sha256, a.filename, a.size_bytes,
                      a.quarantine_path, a.state
               FROM research_artifacts a
               JOIN research_case_artifacts ca ON ca.artifact_id = a.artifact_id
               WHERE ca.case_id = ? AND a.sha256 = ? AND a.state IN ('collected', 'externally_supplied')""",
            (request["case_id"], request["artifact_sha256"]),
        ).fetchall()
    if len(rows) != 1:
        raise SandboxProviderError("approved artifact is not uniquely attached to the research case")
    return dict(rows[0])


def prepare_manual_submission(
    request_id: str,
    *,
    output_dir: str,
    public_acknowledged: bool = False,
    actor: str = "analyst",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Copy one approved artifact into an owner-only, short-lived handoff file."""
    from secopsai.research_workflow import get_sandbox_request, record_manual_sandbox_export

    if not public_acknowledged:
        raise SandboxProviderError("explicit public-submission acknowledgment is required")
    request = get_sandbox_request(request_id, db_path=db_path)
    if request["status"] != "approved":
        raise SandboxProviderError("sandbox request must be approved before manual export")
    artifact = _attached_approved_artifact(request, db_path=db_path)
    source = Path(str(artifact["quarantine_path"]))
    if source.is_symlink() or not source.is_file():
        raise SandboxProviderError("approved artifact is unavailable from local quarantine")
    from secopsai.research_artifacts import quarantine_root

    resolved_source = source.resolve()
    resolved_quarantine = quarantine_root().resolve()
    if resolved_source != resolved_quarantine and resolved_quarantine not in resolved_source.parents:
        raise SandboxProviderError("approved artifact path is outside local quarantine")
    source = resolved_source
    if int(artifact.get("size_bytes") or 0) <= 0 or int(artifact.get("size_bytes") or 0) > MAX_SUBMISSION_BYTES:
        raise SandboxProviderError("sandbox artifact exceeds the configured submission limit")

    destination_root = Path(output_dir).expanduser().resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    os.chmod(destination_root, 0o700)
    original = Path(str(artifact.get("filename") or source.name)).name
    safe_original = re.sub(r"[^A-Za-z0-9._-]+", "_", original).strip("._")[:140] or "sample.bin"
    filename = f"secopsai-{request_id.lower()}-{request['artifact_sha256'][:12]}-{safe_original}"
    destination = destination_root / filename
    if destination.exists() or destination.is_symlink():
        raise SandboxProviderError("manual sandbox handoff destination already exists")
    temporary = destination_root / f".{filename}.{os.urandom(6).hex()}.tmp"
    digest = hashlib.sha256()
    size = 0
    try:
        with source.open("rb") as source_handle, temporary.open("xb") as output_handle:
            while True:
                chunk = source_handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_SUBMISSION_BYTES:
                    raise SandboxProviderError("sandbox artifact exceeds the configured submission limit")
                digest.update(chunk)
                output_handle.write(chunk)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        if digest.hexdigest().lower() != request["artifact_sha256"].lower():
            raise SandboxProviderError("artifact hash does not match the approved request")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    record_manual_sandbox_export(
        request_id,
        filename=filename,
        size_bytes=size,
        actor=actor,
        db_path=db_path,
    )
    return {
        "request_id": request_id,
        "case_id": request["case_id"],
        "artifact_id": artifact["artifact_id"],
        "artifact_sha256": request["artifact_sha256"],
        "filename": filename,
        "size_bytes": size,
        "output_path": str(destination),
        "public_submission": True,
        "warning": "Tria.ge public submissions are visible to the public and cannot be deleted by public-cloud users.",
    }


def normalize_result(payload: Dict[str, Any], *, submission_id: str = "", report_url: str = "") -> Dict[str, Any]:
    """Keep only sanitized, analyst-useful result fields."""
    if not isinstance(payload, dict):
        raise SandboxProviderError("sandbox result must be an object")
    normalized_submission_id = str(submission_id or payload.get("id") or "")[:240]
    if normalized_submission_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{3,239}", normalized_submission_id):
        raise SandboxProviderError("sandbox submission ID is invalid")
    normalized_report_url = str(report_url or payload.get("report_url") or "")[:2000]
    if normalized_report_url:
        parsed_report = urllib.parse.urlparse(normalized_report_url)
        report_hosts = {"tria.ge", "www.tria.ge", "api.tria.ge"}
        report_hosts.update(item.strip().lower() for item in os.environ.get("TRIAGE_API_ALLOWED_HOSTS", "").split(",") if item.strip())
        if parsed_report.scheme != "https" or parsed_report.hostname not in report_hosts:
            raise SandboxProviderError("sandbox report URL is not an approved Tria.ge HTTPS URL")
    network = payload.get("network") if isinstance(payload.get("network"), list) else []
    files = payload.get("files") if isinstance(payload.get("files"), list) else []
    try:
        score = max(0.0, min(float(payload.get("score")), 10.0)) if payload.get("score") is not None else None
    except (TypeError, ValueError):
        score = None
    signatures = payload.get("signatures") if isinstance(payload.get("signatures"), list) else []
    return {
        "schema_version": "secopsai.research.sandbox-submission.v1",
        "provider": "tria.ge",
        "submission_id": normalized_submission_id,
        "report_url": normalized_report_url,
        "status": str(payload.get("status") or "unknown")[:80],
        "score": score,
        "signatures": [
            {
                "name": str(item.get("name") or item.get("label") or "")[:240],
                "score": item.get("score"),
            }
            for item in signatures if isinstance(item, dict)
        ][:200],
        "network": [{"domain": str(item.get("domain") or "")[:240], "ip": str(item.get("ip") or "")[:80], "port": item.get("port")} for item in network if isinstance(item, dict)][:500],
        "files": [{"path": str(item.get("path") or "")[:500], "sha256": str(item.get("sha256") or "")[:128]} for item in files if isinstance(item, dict)][:500],
        "behavior": str(payload.get("behavior") or payload.get("summary") or "")[:12000],
        "raw_result_retained": False,
    }


def submit_approved_artifact(*, artifact_path: str, artifact_sha256: str, request_id: str, public_acknowledged: bool) -> Dict[str, Any]:
    if not public_acknowledged:
        raise SandboxProviderError("explicit public-submission acknowledgment is required")
    token = os.environ.get("TRIAGE_API_TOKEN", "")
    if not token:
        raise SandboxProviderError("TRIAGE_API_TOKEN is not configured; use manual-result-import")
    # The artifact is sent only after the caller has verified its hash and the
    # request has an approved state. Refuse symlinks, non-regular files, and
    # oversized artifacts before opening the file.
    path = Path(artifact_path)
    if path.is_symlink() or not path.is_file():
        raise SandboxProviderError("sandbox artifact must be a regular, non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_SUBMISSION_BYTES:
        raise SandboxProviderError("sandbox artifact exceeds the configured submission limit")
    digest_hasher = hashlib.sha256()
    chunks = []
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest_hasher.update(chunk)
            chunks.append(chunk)
    digest = digest_hasher.hexdigest()
    if digest.lower() != artifact_sha256.lower():
        raise SandboxProviderError("artifact hash does not match the approved request")
    boundary = "----SecOpsAIResearchBoundary"
    filename = path.name.replace('"', "_")[:240]
    data = b"".join(chunks)
    # Tria.ge requires a multipart ``kind=file`` field and names the uploaded
    # part ``file``.  A part named ``sample`` (the previous implementation)
    # is rejected before an analysis is created, leaving the request approved
    # with no submission ID to poll.
    body = b"".join(
        [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\nfile\r\n".encode(),
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode(),
            data,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    endpoint = os.environ.get("TRIAGE_API_SUBMIT_URL", "https://tria.ge/api/v0/samples")
    parsed = urllib.parse.urlparse(endpoint)
    allowed_hosts = {"tria.ge", "api.tria.ge"}
    allowed_hosts.update(item.strip().lower() for item in os.environ.get("TRIAGE_API_ALLOWED_HOSTS", "").split(",") if item.strip())
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise SandboxProviderError("sandbox submission endpoint is not an approved HTTPS host")
    request = urllib.request.Request(endpoint, data=body, method="POST", headers={"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": "SecOpsAI-Research/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Keep provider details bounded and avoid copying a potentially
        # sensitive response body into the case or browser.
        raise SandboxProviderError(f"sandbox submission rejected by Tria.ge (HTTP {exc.code})") from exc
    except urllib.error.URLError as exc:
        raise SandboxProviderError("sandbox submission could not reach Tria.ge") from exc
    except (TimeoutError, OSError) as exc:
        raise SandboxProviderError("sandbox submission timed out or failed locally") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxProviderError("sandbox returned an invalid JSON response") from exc
    except Exception as exc:
        raise SandboxProviderError("sandbox submission failed") from exc
    if not isinstance(payload, dict):
        raise SandboxProviderError("sandbox returned an invalid response")
    submission_id = str(payload.get("submission_id") or payload.get("id") or "")
    report_url = f"https://tria.ge/{submission_id}" if submission_id else ""
    return {
        "request_id": request_id,
        "provider": "tria.ge",
        "submission": normalize_result(payload, submission_id=submission_id, report_url=report_url),
    }


def submit_sandbox_request(request_id: str, *, db_path: Optional[str] = None, public_acknowledged: bool = False) -> Dict[str, Any]:
    from secopsai.research_workflow import get_sandbox_request, set_sandbox_status

    request = get_sandbox_request(request_id, db_path=db_path)
    if request["status"] != "approved":
        raise SandboxProviderError("sandbox request must be approved before submission")
    configured_root = os.environ.get("SECOPSAI_RESEARCH_QUARANTINE", "").strip()
    root = Path(configured_root) if configured_root else Path(__file__).resolve().parents[1] / "data" / "research" / "quarantine"
    matches = [path for path in root.glob(f"{request['artifact_sha256']}.*") if path.is_file() and not path.is_symlink()]
    if len(matches) != 1:
        raise SandboxProviderError("approved artifact is not uniquely available in quarantine")
    result = submit_approved_artifact(artifact_path=str(matches[0]), artifact_sha256=request["artifact_sha256"], request_id=request_id, public_acknowledged=public_acknowledged)
    return set_sandbox_status(request_id, "submitted", actor="sandbox-worker", result=result["submission"], db_path=db_path)


def poll_sandbox_request(request_id: str, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    from secopsai.research_workflow import get_sandbox_request, set_sandbox_status

    request = get_sandbox_request(request_id, db_path=db_path)
    if request["status"] not in {"submitted", "approved"}:
        return request
    result = request.get("result") or {}
    submission_id = str(result.get("submission_id") or "")
    token = os.environ.get("TRIAGE_API_TOKEN", "")
    if not token or not submission_id:
        return request
    endpoint = os.environ.get("TRIAGE_API_STATUS_URL", f"https://tria.ge/api/v0/samples/{urllib.parse.quote(submission_id)}")
    req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {token}", "User-Agent": "SecOpsAI-Research/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except Exception as exc:
        raise SandboxProviderError("sandbox status request failed") from exc
    normalized = normalize_result(payload, submission_id=submission_id, report_url=str(result.get("report_url") or ""))
    status = "completed" if normalized["status"].lower() in {"completed", "reported", "finished", "done", "success", "succeeded"} else "submitted"
    return set_sandbox_status(request_id, status, actor="sandbox-worker", result=normalized, db_path=db_path)
