"""Approval-gated external sandbox connector primitives."""

from __future__ import annotations

import json
import os
import hashlib
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

import soc_store


MAX_SUBMISSION_BYTES = 50 * 1024 * 1024


class SandboxProviderError(RuntimeError):
    pass


def provider_status() -> Dict[str, Any]:
    token = os.environ.get("TRIAGE_API_TOKEN", "")
    base_url = os.environ.get("TRIAGE_API_BASE_URL", "https://tria.ge/api/v0")
    return {"provider": "tria.ge", "configured": bool(token), "mode": "public" if token else "manual-result-import", "base_url": base_url, "public_submission": True, "warning": "Tria.ge public submissions are visible to the public and must not contain confidential data."}


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
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=sample; filename={filename}\r\nContent-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    endpoint = os.environ.get("TRIAGE_API_SUBMIT_URL", "https://tria.ge/api/v0/samples")
    parsed = urllib.parse.urlparse(endpoint)
    allowed_hosts = {"tria.ge", "api.tria.ge"}
    allowed_hosts.update(item.strip().lower() for item in os.environ.get("TRIAGE_API_ALLOWED_HOSTS", "").split(",") if item.strip())
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise SandboxProviderError("sandbox submission endpoint is not an approved HTTPS host")
    request = urllib.request.Request(endpoint, data=body, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": "SecOpsAI-Research/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except Exception as exc:
        raise SandboxProviderError("sandbox submission failed") from exc
    if not isinstance(payload, dict):
        raise SandboxProviderError("sandbox returned an invalid response")
    return {"request_id": request_id, "provider": "tria.ge", "submission": normalize_result(payload)}


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
    status = "completed" if normalized["status"].lower() in {"completed", "reported", "finished"} else "submitted"
    return set_sandbox_status(request_id, status, actor="sandbox-worker", result=normalized, db_path=db_path)
