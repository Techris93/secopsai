"""Private immutable artifact backup. No package extraction or execution.

Chunks and a content-addressed manifest are durable before the ledger receipt
is committed. Recovery checks every chunk and the complete original hash.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit

import soc_store
from secopsai.research_operation_store import append, canonical, records

CHUNK_BYTES = 32 * 1024 * 1024
MAX_BYTES = 250 * 1024 * 1024
HASH = re.compile(r"[a-f0-9]{64}\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class VaultClient:
    def __init__(self, *, url=None, token=None, seconds=60):
        self.url = (url or os.environ.get("LEDGER_STORE_URL", "")).rstrip("/")
        self.token = token or os.environ.get("LEDGER_STORE_TOKEN", "")
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path or not self.token:
            raise ValueError("a credential-free HTTPS vault origin and private token are required")
        self.deadline = time.monotonic() + seconds
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, digest, body=None):
        if not HASH.fullmatch(digest):
            raise ValueError("invalid object hash")
        for attempt in range(3):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("artifact vault deadline exceeded")
            request = urllib.request.Request(self.url + "/artifact-objects/" + digest, data=body, method=method,
                                            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/octet-stream"})
            try:
                with self.opener.open(request, timeout=min(15, remaining)) as response:
                    limit = CHUNK_BYTES if method == "GET" else 4096
                    value = response.read(limit + 1)
                    if len(value) > limit:
                        raise ValueError("oversized artifact object response")
                    return value
            except urllib.error.HTTPError as error:
                if error.code not in {429, 500, 502, 503, 504} or attempt == 2:
                    raise ValueError(f"artifact vault HTTP {error.code}") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt == 2:
                    raise ValueError("artifact vault connection failed") from None
            time.sleep(min(0.5 * (attempt + 1), max(0, self.deadline - time.monotonic())))

    def put(self, body):
        digest = hashlib.sha256(body).hexdigest()
        response = json.loads(self.request("PUT", digest, body))
        if response.get("sha256") != digest or response.get("size_bytes") != len(body):
            raise ValueError("artifact vault receipt mismatch")
        return digest

    def get(self, digest):
        body = self.request("GET", digest)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError("artifact object hash mismatch")
        return body


def artifact_row(artifact_id, db_path=None):
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as conn:
        row = conn.execute("SELECT * FROM research_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
    if row is None or row["state"] == "purged":
        raise ValueError("artifact unavailable or purged")
    return dict(row)


def receipt(artifact_id, db_path=None):
    return next((r["payload"] for r in records("artifact_backup", db_path=db_path, limit=10000)
                 if r["payload"].get("artifact_id") == artifact_id), None)


def backup_artifact(artifact_id, *, actor, db_path=None, client=None, cloud_storage_authorized=False):
    row = artifact_row(artifact_id, db_path)
    provenance = json.loads(row["provenance_json"])
    public_intake = provenance.get("source") == "secopsai_safe_registry_intake"
    if not public_intake and not cloud_storage_authorized:
        raise ValueError("restricted/local samples require explicit cloud-storage authorization")
    if not public_intake:
        from secopsai.research_assurance import person
        person(actor, role="operator", db_path=db_path)
    existing = receipt(artifact_id, db_path)
    if existing and existing["sha256"] == row["sha256"] and existing["size_bytes"] == row["size_bytes"]:
        return existing
    client = client or VaultClient()
    chunks, total, whole = [], 0, hashlib.sha256()
    # O_NOFOLLOW rejects a replaced quarantine symlink. Hash the open file,
    # rather than reopening it between validation and upload.
    fd = os.open(row["quarantine_path"], os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        import stat
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("artifact must be a regular file")
        while True:
            body = source.read(CHUNK_BYTES)
            if not body:
                break
            total += len(body)
            if total > MAX_BYTES:
                raise ValueError("artifact exceeds backup size limit")
            whole.update(body)
            chunks.append({"sha256": client.put(body), "size_bytes": len(body)})
    if not total or total != row["size_bytes"] or whole.hexdigest() != row["sha256"]:
        raise ValueError("artifact no longer matches catalog provenance")
    manifest = {"version": 1, "sha256": row["sha256"], "size_bytes": total, "chunks": chunks}
    manifest_hash = client.put(canonical(manifest).encode())
    result = {"artifact_id": artifact_id, "sha256": row["sha256"], "size_bytes": total,
              "manifest_sha256": manifest_hash, "objects": len(chunks) + 1,
              "cloud_storage_authorized": bool(cloud_storage_authorized), "status": "completed"}
    append("artifact_backup", result, actor=actor, db_path=db_path)
    return result


def restore_artifact(artifact_id, *, actor, db_path=None, client=None):
    row = artifact_row(artifact_id, db_path)
    saved = receipt(artifact_id, db_path)
    if not saved or saved["sha256"] != row["sha256"]:
        raise ValueError("no completed backup for this artifact")
    client = client or VaultClient()
    encoded = client.get(saved["manifest_sha256"])
    if len(encoded) > 16384 or hashlib.sha256(encoded).hexdigest() != saved["manifest_sha256"]:
        raise ValueError("oversized artifact manifest")
    manifest = json.loads(encoded)
    chunks = manifest.get("chunks")
    if manifest.get("version") != 1 or manifest.get("sha256") != row["sha256"] or manifest.get("size_bytes") != row["size_bytes"] or not 0 < row["size_bytes"] <= MAX_BYTES or not isinstance(chunks, list) or not 1 <= len(chunks) <= 8:
        raise ValueError("artifact manifest mismatch")
    if any(not isinstance(c, dict) or not HASH.fullmatch(str(c.get("sha256", ""))) or type(c.get("size_bytes")) is not int or not 0 < c["size_bytes"] <= CHUNK_BYTES for c in chunks) or sum(c["size_bytes"] for c in chunks) != row["size_bytes"]:
        raise ValueError("invalid artifact manifest chunks")
    from secopsai.research_artifacts import quarantine_root
    destination = quarantine_root() / row["sha256"]
    temporary = destination.with_name("." + destination.name + "." + secrets.token_hex(8))
    whole, total = hashlib.sha256(), 0
    try:
        with temporary.open("xb") as output:
            os.chmod(temporary, 0o600)
            for chunk in chunks:
                body = client.get(chunk["sha256"])
                if len(body) != chunk["size_bytes"] or hashlib.sha256(body).hexdigest() != chunk["sha256"]:
                    raise ValueError("artifact chunk integrity failure")
                total += len(body)
                whole.update(body)
                output.write(body)
            output.flush()
            os.fsync(output.fileno())
        if total != row["size_bytes"] or total > MAX_BYTES or whole.hexdigest() != row["sha256"]:
            raise ValueError("recovered artifact integrity failure")
        os.replace(temporary, destination)
        with closing(soc_store.connect(db_path)) as conn:
            conn.execute("UPDATE research_artifacts SET quarantine_path=?,state='collected',updated_at=? WHERE artifact_id=?", (str(destination), soc_store.utc_now(), artifact_id))
            conn.commit()
        result = {"artifact_id": artifact_id, "sha256": row["sha256"], "size_bytes": total, "hash_verified": True, "execution_performed": False}
        append("artifact_restore", result, actor=actor, db_path=db_path)
        return result
    finally:
        temporary.unlink(missing_ok=True)


def backup_public_artifacts(*, db_path=None, limit=5, client=None):
    if os.environ.get("SECOPSAI_ARTIFACT_VAULT", "0") != "1":
        return {"status": "skipped", "reason": "artifact_vault_disabled"}
    client = client or VaultClient(seconds=60)
    completed, failures = [], []
    with closing(soc_store.connect(db_path)) as conn:
        rows = conn.execute("SELECT artifact_id,provenance_json FROM research_artifacts WHERE state='collected' ORDER BY updated_at DESC LIMIT 1000").fetchall()
    backed_up = {r["payload"].get("artifact_id") for r in records("artifact_backup", db_path=db_path, limit=10000)}
    pending = [r["artifact_id"] for r in rows if json.loads(r["provenance_json"]).get("source") == "secopsai_safe_registry_intake" and r["artifact_id"] not in backed_up]
    for identity in pending[:limit]:
        try:
            completed.append(backup_artifact(identity, actor="research-worker", db_path=db_path, client=client))
        except (ValueError, OSError):
            failures.append({"artifact_id": identity, "reason": "backup_failed_or_local_bytes_missing"})
    return {"status": "degraded" if failures or len(pending) > limit else "succeeded", "completed": completed, "failures": failures,
            "pending_before_cycle": len(pending), "remaining": len(pending) - len(completed), "coverage": "public registered artifacts, bounded to latest 1000 catalog entries"}
