"""Approval-gated external sandbox connector primitives."""

from __future__ import annotations

import json
import os
import hashlib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional


MAX_SUBMISSION_BYTES = 50 * 1024 * 1024


class SandboxProviderError(RuntimeError):
    pass


def provider_status() -> Dict[str, Any]:
    token = os.environ.get("TRIAGE_API_TOKEN", "")
    base_url = os.environ.get("TRIAGE_API_BASE_URL", "https://tria.ge/api/v0")
    return {"provider": "tria.ge", "configured": bool(token), "mode": "public" if token else "manual-result-import", "base_url": base_url, "public_submission": True, "warning": "Tria.ge public submissions are visible to the public and must not contain confidential data."}


def normalize_result(payload: Dict[str, Any], *, submission_id: str = "", report_url: str = "") -> Dict[str, Any]:
    """Keep only sanitized, analyst-useful result fields."""
    if not isinstance(payload, dict):
        raise SandboxProviderError("sandbox result must be an object")
    network = payload.get("network") if isinstance(payload.get("network"), list) else []
    files = payload.get("files") if isinstance(payload.get("files"), list) else []
    return {
        "schema_version": "secopsai.research.sandbox-submission.v1",
        "provider": "tria.ge",
        "submission_id": str(submission_id or payload.get("id") or "")[:240],
        "report_url": str(report_url or payload.get("report_url") or "")[:2000],
        "status": str(payload.get("status") or "unknown")[:80],
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
