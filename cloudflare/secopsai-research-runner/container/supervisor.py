"""Container supervisor for the SecOpsAI research worker on Cloudflare.

Cloudflare Container disk is ephemeral, so the SQLite research ledger lives on
local disk while the container runs and is checkpointed to R2:

1. On start, restore the latest checkpoint (if any) from the ledger store.
2. Run ``secopsai.cli research worker run`` as a child process.
3. Every ``SECOPSAI_LEDGER_CHECKPOINT_SECONDS`` take a consistent online
   SQLite backup, gzip it, and upload it in parts.
4. On SIGTERM (deploy, host maintenance, inactivity) stop the worker and
   write a final checkpoint inside Cloudflare's 15-minute grace period.

The ledger store is a Worker entrypoint reached at ``LEDGER_STORE_URL``
through ``interceptOutboundHttp``; the container holds no R2 credentials.
Only the standard library is used so the production image is unchanged.
"""

from __future__ import annotations

from collections import deque
import gzip
import hashlib
import io
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import http.client
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import struct
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

PART_BYTES = 32 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 300
UPLOAD_TIMEOUT_SECONDS = 600
REQUEST_ATTEMPTS = 3
RETRY_HTTP_STATUSES = {408, 429, 500, 502, 503, 504}
# Cloudflare's browser integrity check rejects the default Python-urllib
# agent with 403 (error 1010) before the Worker runs.
USER_AGENT = "SecOpsAI-Research/1.0"
DELTA_MAGIC = b"SOCDLT1\0"
DELTA_BLOCK_BYTES = 4096
SPARSE_FRAME_RAW_LIMIT = 28 * 1024 * 1024
SPARSE_UPLOAD_WORKERS = 4
CHUNK_DOWNLOAD_WORKERS = 4
# A chunk that fails verification is downloaded again this many times in total.
CHUNK_VERIFY_ATTEMPTS = 3
CHECKPOINT_RESTORE_TIMEOUT_SECONDS = 3600


class RebaseRequired(Exception):
    """A bounded full snapshot is preferable to a large sparse delta."""


class LedgerRequestError(RuntimeError):
    """Sanitized transport failure with enough metadata to diagnose a write."""

    def __init__(self, method: str, operation: str, *, category: str, status: int | None = None,
                 error_code: str = "", request_id: str = "", attempts: int = 1) -> None:
        self.method = method
        self.operation = operation
        self.category = category
        self.status = status
        self.error_code = error_code
        self.request_id = request_id
        self.attempts = attempts
        details = [f"category={category}"]
        if status is not None:
            details.append(f"HTTP {status}")
        if error_code:
            details.append(f"code={error_code}")
        if request_id:
            details.append(f"request_id={request_id}")
        super().__init__(f"ledger {method} {operation} failed after {attempts} attempt(s) ({', '.join(details)})")


def _provider_error_metadata(body: bytes, headers) -> tuple[str, str]:
    """Extract only bounded, allowlisted identifiers from a provider error."""
    code = ""
    try:
        parsed = json.loads(body[:8192])
        if isinstance(parsed, dict):
            candidate = parsed.get("code")
            if not isinstance(candidate, str) and isinstance(parsed.get("error"), dict):
                candidate = parsed["error"].get("code")
            if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", candidate):
                code = candidate
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        pass
    request_id = ""
    for key in ("cf-ray", "x-request-id", "x-amz-request-id"):
        candidate = str(headers.get(key, "") or "")[:100]
        if candidate and re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", candidate):
            request_id = candidate
            break
    return code, request_id


def _log(event: str, **fields: object) -> None:
    print(json.dumps({"component": "research-runner", "event": event, **fields}, sort_keys=True), flush=True)


def _write_runtime_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
    temporary.replace(path)


def _error_fields(exc: BaseException) -> dict:
    fields = {"error_category": type(exc).__name__}
    if isinstance(exc, LedgerRequestError):
        fields.update(operation=exc.operation, http_status=exc.status, provider_code=exc.error_code or None,
                      request_id=exc.request_id or None, attempts=exc.attempts)
    return fields


class LedgerStore:
    """Minimal client for the Worker-side R2 ledger store."""

    def __init__(self, base_url: str, token: str, opener: Callable[..., object] = urllib.request.urlopen) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._open = opener

    def _request(self, method: str, path: str, body: Optional[bytes] = None, *, deadline: float, retry: bool = True) -> bytes:
        if getattr(self, "checkpoint_scope", "production") == "drill" and path in {"/checkpoints", "/checkpoint-manifest"}:
            path = "/recovery-drill" + path
        attempts = REQUEST_ATTEMPTS if retry else 1
        operation = path.split("/", 2)[1] if path.startswith("/") else "unknown"
        for attempt in range(attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("ledger upload deadline exceeded")
            request = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method)
            request.add_header("Authorization", f"Bearer {self.token}")
            request.add_header("User-Agent", USER_AGENT)
            if body is not None:
                request.add_header("Content-Type", "application/octet-stream")
            try:
                with self._open(request, timeout=min(REQUEST_TIMEOUT_SECONDS, remaining)) as response:
                    limit = 32 * 1024 * 1024 if path.startswith("/artifact-objects/") else 512 * 1024
                    data = response.read(limit + 1)
                    if len(data) > limit:
                        raise ValueError("ledger response exceeds its bounded contract")
                if time.monotonic() >= deadline:
                    raise TimeoutError("ledger upload deadline exceeded")
                return data
            except urllib.error.HTTPError as exc:
                retry_after = exc.headers.get("Retry-After", "") if exc.headers else ""
                error_code, request_id = _provider_error_metadata(exc.read(8192), exc.headers or {})
                failure_category, failure_status = "http", exc.code
                _log("ledger_request_failed", method=method, operation=operation,
                     category=failure_category, http_status=failure_status, error_code=error_code or None,
                     request_id=request_id or None, attempt=attempt + 1, request_bytes=len(body or b""))
                exc.close()
                if exc.code not in RETRY_HTTP_STATUSES:
                    raise LedgerRequestError(method, operation, category=failure_category, status=exc.code,
                                             error_code=error_code, request_id=request_id, attempts=attempt + 1) from exc
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                retry_after = ""
                failure_category, failure_status = type(exc).__name__, None
                error_code = request_id = ""
                _log("ledger_request_failed", method=method, operation=operation,
                     category=failure_category, http_status=None, attempt=attempt + 1,
                     request_bytes=len(body or b""))
            if attempt + 1 == attempts:
                raise LedgerRequestError(method, operation, category=failure_category, status=failure_status,
                                         error_code=error_code, request_id=request_id, attempts=attempts)
            delay = 2 ** attempt
            if retry_after.isdigit():
                delay = max(delay, int(retry_after))
            if delay >= deadline - time.monotonic():
                raise TimeoutError("ledger upload deadline exceeded during backoff")
            _log("ledger_request_retry", method=method, operation=path.split("?")[0], attempt=attempt + 2, delay=delay)
            time.sleep(delay)
        raise AssertionError("unreachable")

    def download(self, destination: Path) -> bool:
        if os.environ.get("SECOPSAI_INCREMENTAL_CHECKPOINTS", "0") == "1":
            try:
                manifest = json.loads(self._request("GET", "/checkpoint-manifest", deadline=time.monotonic() + 60))
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise
                error.close()
            except LedgerRequestError as error:
                # `_request` sanitizes provider failures. A missing manifest
                # is the supported first-run/legacy-ledger path; other errors
                # must not silently downgrade to an older snapshot endpoint.
                if error.status != 404:
                    raise
            else:
                return self.download_chunked(destination, manifest)
        request = urllib.request.Request(f"{self.base_url}/snapshot", method="GET")
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("User-Agent", USER_AGENT)
        try:
            with self._open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response, gzip.GzipFile(fileobj=response) as stream:
                partial = destination.with_suffix(".restore")
                with partial.open("wb") as handle:
                    shutil.copyfileobj(stream, handle, length=8 * 1024 * 1024)
                partial.replace(destination)
                return True
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            raise

    def _download_verified_chunk(self, chunk: dict, *, deadline: float, expected_prefix: bytes = b"") -> bytes:
        # Stored chunks are immutable and content-addressed, so a body that
        # fails verification was damaged or cut short in transit: download it
        # again.  Only a chunk that stays wrong after every attempt fails the
        # restore (and the existing database is left untouched).
        for attempt in range(CHUNK_VERIFY_ATTEMPTS):
            packed = self._request("GET", "/artifact-objects/" + chunk["sha256"], deadline=deadline)
            problem = ""
            raw = b""
            if len(packed) != chunk["size_bytes"] or hashlib.sha256(packed).hexdigest() != chunk["sha256"]:
                problem = "checkpoint chunk checksum mismatch"
            else:
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as reader:
                        raw = reader.read(chunk["raw_size_bytes"] + 1)
                except (OSError, EOFError):
                    problem = "checkpoint decompressed chunk mismatch"
                if not problem and (len(raw) != chunk["raw_size_bytes"] or hashlib.sha256(raw).hexdigest() != chunk["raw_sha256"]):
                    problem = "checkpoint decompressed chunk mismatch"
            if not problem:
                if expected_prefix and not raw.startswith(expected_prefix):
                    raise ValueError("checkpoint chunk has an invalid frame")
                return raw
            if attempt + 1 == CHUNK_VERIFY_ATTEMPTS:
                raise ValueError(problem)
            delay = 2 ** attempt
            if delay >= deadline - time.monotonic():
                raise ValueError(problem)
            _log("checkpoint_chunk_retry", reason=problem, attempt=attempt + 2, received_bytes=len(packed),
                 expected_bytes=chunk["size_bytes"])
            time.sleep(delay)
        raise AssertionError("unreachable")

    def _iter_verified_chunks(self, chunks: list[dict], *, deadline: float, expected_prefix: bytes = b""):
        """Fetch a bounded window concurrently, yielding verified chunks in manifest order."""
        if not chunks:
            return
        worker_count = min(CHUNK_DOWNLOAD_WORKERS, len(chunks))
        pending = deque()
        _log("checkpoint_restore_download_started", chunks=len(chunks), workers=worker_count)
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            next_index = 0
            while next_index < worker_count:
                pending.append(pool.submit(self._download_verified_chunk, chunks[next_index],
                                           deadline=deadline, expected_prefix=expected_prefix))
                next_index += 1
            while pending:
                # Results are consumed in manifest order so callers can preserve
                # the full-file digest and sparse patch offset validation.
                yield pending.popleft().result()
                if next_index < len(chunks):
                    pending.append(pool.submit(self._download_verified_chunk, chunks[next_index],
                                               deadline=deadline, expected_prefix=expected_prefix))
                    next_index += 1

    def download_chunked(self, destination: Path, manifest: dict, *, deadline: float | None = None) -> bool:
        if not valid_manifest(manifest):
            raise ValueError("invalid incremental checkpoint manifest")
        deadline = deadline or (time.monotonic() + CHECKPOINT_RESTORE_TIMEOUT_SECONDS)
        if manifest["version"] == 4 or os.environ.get("SECOPSAI_PAGE_DELTA_CHECKPOINTS", "0") == "1":
            footprint = max(manifest["size_bytes"], manifest.get("base", {}).get("size_bytes", 0))
            if shutil.disk_usage(destination.parent).free < footprint * 3 + 1024**3:
                raise ValueError("insufficient capacity for checkpoint, immutable baseline and consistent capture")
        if manifest["version"] == 4:
            return self.download_sparse(destination, manifest, deadline=deadline)
        partial = destination.with_suffix(".restore")
        digest, total = hashlib.sha256(), 0
        try:
            with partial.open("xb") as output:
                os.chmod(partial, 0o600)
                for raw in self._iter_verified_chunks(manifest["chunks"], deadline=deadline):
                    digest.update(raw)
                    total += len(raw)
                    output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if total != manifest["size_bytes"] or digest.hexdigest() != manifest["sha256"]:
                raise ValueError("checkpoint database checksum mismatch")
            with closing(sqlite3.connect(f"file:{partial}?mode=ro", uri=True)) as recovered:
                if recovered.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("checkpoint SQLite integrity check failed")
            partial.replace(destination)
            self.chunk_cache = {c["sha256"] for c in manifest["chunks"]}
            self.incremental_ready = True
            if os.environ.get("SECOPSAI_PAGE_DELTA_CHECKPOINTS", "0") == "1":
                self.freeze_baseline(destination, manifest)
            _log("incremental_restore_verified", bytes=total, sha256=digest.hexdigest())
            return True
        finally:
            partial.unlink(missing_ok=True)

    def freeze_baseline(self, source, manifest, *, move=False):
        baseline = source.parent / ".checkpoint-base.db"
        if move:
            # The caller supplies a consistent private snapshot, not the live DB.
            source.replace(baseline)
        else:
            staging = baseline.with_suffix(".copy")
            try:
                shutil.copyfile(source, staging)
                os.chmod(staging, 0o400)
                staging.replace(baseline)
            finally:
                staging.unlink(missing_ok=True)
        os.chmod(baseline, 0o400)
        self.baseline_path, self.baseline_manifest = baseline, manifest
        self.index_baseline()

    def index_baseline(self, *, deadline=None):
        """Bind compact page hashes to a verified immutable baseline once per restore.

        Recurring captures read only the current database. These hashes describe
        the canonical remote base; no page bytes or mutable live data are cached.
        """
        whole, pages, groups = hashlib.sha256(), bytearray(), bytearray()
        with self.baseline_path.open("rb") as source:
            while group := source.read(1024*1024):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("baseline indexing exceeds checkpoint budget")
                whole.update(group)
                groups.extend(hashlib.sha256(group).digest())
                for offset in range(0, len(group), DELTA_BLOCK_BYTES):
                    pages.extend(hashlib.sha256(group[offset:offset+DELTA_BLOCK_BYTES]).digest())
        if whole.hexdigest() != self.baseline_manifest["sha256"]:
            raise RebaseRequired("local baseline checksum changed")
        self.baseline_pages, self.baseline_groups = pages, groups
        stat = self.baseline_path.stat()
        self.baseline_identity = (stat.st_size, stat.st_mtime_ns, stat.st_ino, self.baseline_manifest["sha256"])

    def download_sparse(self, destination, manifest, *, deadline: float | None = None):
        deadline = deadline or (time.monotonic() + CHECKPOINT_RESTORE_TIMEOUT_SECONDS)
        base = manifest["base"]
        if getattr(self, "baseline_manifest", None) != base or not getattr(self, "baseline_path", None) or not self.baseline_path.exists():
            with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
                restored = Path(directory) / "base.db"
                self.download_chunked(restored, base, deadline=deadline)
                if not getattr(self, "baseline_path", None) or getattr(self, "baseline_manifest", None) != base:
                    self.freeze_baseline(restored, base)
                durable_base = destination.parent / ".checkpoint-base.db"
                self.baseline_path.replace(durable_base)
                self.baseline_path = durable_base
        partial = destination.with_suffix(".restore")
        last_offset = -1
        try:
            shutil.copyfile(self.baseline_path, partial)
            os.chmod(partial, 0o600)
            with partial.open("r+b") as output:
                for raw in self._iter_verified_chunks(manifest["patches"], deadline=deadline,
                                                      expected_prefix=DELTA_MAGIC):
                    cursor = len(DELTA_MAGIC)
                    while cursor < len(raw):
                        if len(raw) - cursor < 12:
                            raise ValueError("truncated sparse checkpoint record")
                        offset, length = struct.unpack_from(">QI", raw, cursor)
                        cursor += 12
                        expected = min(DELTA_BLOCK_BYTES, manifest["size_bytes"] - offset)
                        if offset <= last_offset or offset % DELTA_BLOCK_BYTES or length != expected or not 0 < length <= DELTA_BLOCK_BYTES or cursor + length > len(raw):
                            raise ValueError("invalid sparse checkpoint offset")
                        output.seek(offset)
                        output.write(raw[cursor:cursor+length])
                        cursor += length
                        last_offset = offset
                output.truncate(manifest["size_bytes"])
                output.flush()
                os.fsync(output.fileno())
            digest = hashlib.sha256()
            with partial.open("rb") as source:
                for raw in iter(lambda: source.read(8*1024*1024), b""):
                    digest.update(raw)
            if digest.hexdigest() != manifest["sha256"]:
                raise ValueError("sparse checkpoint database checksum mismatch")
            with closing(sqlite3.connect(f"file:{partial}?mode=ro", uri=True)) as recovered:
                if recovered.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("sparse checkpoint SQLite integrity check failed")
            partial.replace(destination)
            self.incremental_ready = True
            self.chunk_cache.update(entry["sha256"] for entry in manifest["patches"])
            _log("sparse_restore_verified", bytes=manifest["size_bytes"], patches=len(manifest["patches"]), sha256=manifest["sha256"])
            return True
        finally:
            partial.unlink(missing_ok=True)

    def upload_sparse(self, backup, *, captured_at, deadline):
        started = time.monotonic()
        base = self.baseline_manifest
        entries, pending, digest, offset, dirty = [], [], hashlib.sha256(), 0, 0
        frame = bytearray(DELTA_MAGIC)
        cache_lock = threading.Lock()
        cached = self.chunk_cache
        current_size = backup.stat().st_size
        stat = self.baseline_path.stat()
        identity = (stat.st_size, stat.st_mtime_ns, stat.st_ino, base["sha256"])
        if stat.st_size != base["size_bytes"]:
            raise RebaseRequired("local baseline size changed")
        if getattr(self, "baseline_identity", None) != identity:
            self.index_baseline(deadline=deadline)

        def upload_frame(raw):
            if time.monotonic() >= deadline:
                raise TimeoutError("sparse checkpoint upload exceeds its bounded budget")
            packed = gzip.compress(raw, compresslevel=1, mtime=0)
            key = hashlib.sha256(packed).hexdigest()
            with cache_lock:
                already_uploaded = key in cached
            if not already_uploaded:
                receipt = json.loads(self._request("PUT", "/artifact-objects/" + key, packed, deadline=deadline))
                if receipt.get("sha256") != key or receipt.get("size_bytes") != len(packed):
                    raise ValueError("sparse checkpoint upload receipt mismatch")
                with cache_lock:
                    cached.add(key)
            elif time.monotonic() >= deadline:
                raise TimeoutError("sparse checkpoint upload exceeds its bounded budget")
            return {"sha256": key, "size_bytes": len(packed), "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_size_bytes": len(raw)}

        def flush_frame(pool):
            raw = bytes(frame)
            pending.append(pool.submit(upload_frame, raw))
            frame[:] = DELTA_MAGIC
            # Keep at most four frames in flight so scanning can overlap the
            # network without retaining an unbounded portion of a large delta.
            if len(pending) >= SPARSE_UPLOAD_WORKERS:
                entries.append(pending.pop(0).result())

        with backup.open("rb") as current:
            with ThreadPoolExecutor(max_workers=SPARSE_UPLOAD_WORKERS) as pool:
                while group := current.read(1024*1024):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("sparse checkpoint scan exceeds its bounded budget")
                    digest.update(group)
                    group_index = (offset // (1024*1024)) * 32
                    if hashlib.sha256(group).digest() != self.baseline_groups[group_index:group_index+32]:
                        for index in range(0, len(group), DELTA_BLOCK_BYTES):
                            raw = group[index:index+DELTA_BLOCK_BYTES]
                            page_index = ((offset+index) // DELTA_BLOCK_BYTES) * 32
                            if hashlib.sha256(raw).digest() == self.baseline_pages[page_index:page_index+32]:
                                continue
                            dirty += len(raw)
                            if dirty > max(base["size_bytes"], current_size) // 4:
                                raise RebaseRequired("more than one quarter of baseline bytes changed")
                            if len(frame) + 12 + len(raw) > SPARSE_FRAME_RAW_LIMIT:
                                flush_frame(pool)
                            frame.extend(struct.pack(">QI", offset+index, len(raw)))
                            frame.extend(raw)
                    offset += len(group)
                if len(frame) > len(DELTA_MAGIC):
                    flush_frame(pool)
                while pending:
                    entries.append(pending.pop(0).result())
        if len(base["chunks"]) + len(entries) > 900:
            raise RebaseRequired("sparse checkpoint object budget exceeded")
        manifest = {"version": 4, "base": base, "block_bytes": DELTA_BLOCK_BYTES, "patches": entries,
                    "sha256": digest.hexdigest(), "size_bytes": offset, "captured_at": captured_at}
        result = json.loads(self._request("POST", "/checkpoints", json.dumps(manifest, separators=(",", ":")).encode(), deadline=deadline))
        if result.get("superseded") is True:
            raise ValueError("sparse checkpoint was superseded by a newer capture")
        _log("sparse_checkpoint_uploaded", bytes=offset, changed_bytes=dirty, patch_chunks=len(entries),
             elapsed_seconds=round(time.monotonic()-started, 1), captured_at=captured_at, key=result["key"])
        return str(result["key"])

    def upload_chunked(self, backup: Path, *, captured_at: str, deadline=None) -> str:
        deadline = deadline or (time.monotonic() + 240)
        cached = getattr(self, "chunk_cache", set())
        self.chunk_cache = cached
        cache_lock = threading.Lock()
        entries, whole, total, uploaded = [], hashlib.sha256(), 0, 0
        def upload_piece(raw):
            packed = gzip.compress(raw, compresslevel=1, mtime=0)
            key = hashlib.sha256(packed).hexdigest()
            with cache_lock:
                was_uploaded = key not in cached
            if was_uploaded:
                result = json.loads(self._request("PUT", "/artifact-objects/" + key, packed, deadline=deadline))
                if result.get("sha256") != key or result.get("size_bytes") != len(packed):
                    raise ValueError("incremental checkpoint upload receipt mismatch")
                # An immutable verified object remains durable even if another
                # chunk or the final manifest fails. Preserve that receipt for
                # the next bounded capture in this runner.
                with cache_lock:
                    cached.add(key)
            return ({"sha256": key, "size_bytes": len(packed), "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_size_bytes": len(raw)}, was_uploaded)
        with backup.open("rb") as source, ThreadPoolExecutor(max_workers=4) as pool:
            while True:
                batch = []
                for _ in range(4):
                    raw = source.read(28 * 1024 * 1024)
                    if not raw:
                        break
                    whole.update(raw)
                    total += len(raw)
                    batch.append(raw)
                if not batch:
                    break
                for entry, sent in pool.map(upload_piece, batch):
                    entries.append(entry)
                    uploaded += int(sent)
                if len(entries) > 900 or time.monotonic() >= deadline:
                    raise TimeoutError("incremental checkpoint exceeds its bounded budget")
        manifest = {"version": 3, "sha256": whole.hexdigest(), "size_bytes": total,
                    "captured_at": captured_at, "chunks": entries}
        body = json.dumps(manifest, separators=(",", ":")).encode()
        result = json.loads(self._request("POST", "/checkpoints", body, deadline=deadline))
        if result.get("superseded") is True:
            raise ValueError("incremental checkpoint was superseded by a newer capture")
        self.chunk_cache = {entry["sha256"] for entry in entries}
        self.incremental_ready = True
        self.baseline_manifest = manifest
        self.baseline_path = None
        _log("incremental_checkpoint_uploaded", bytes=total, uploaded_chunks=uploaded, reused_chunks=len(entries)-uploaded,
             captured_at=captured_at, key=result["key"])
        return str(result["key"])

    def upload(self, compressed: Path) -> str:
        deadline = time.monotonic() + UPLOAD_TIMEOUT_SECONDS
        upload = json.loads(self._request("POST", "/uploads", deadline=deadline))
        upload_id, key = upload["upload_id"], upload["key"]
        parts = []
        with compressed.open("rb") as handle:
            number = 1
            while chunk := handle.read(PART_BYTES):
                result = json.loads(self._request("PUT", f"/uploads/{upload_id}/parts/{number}?key={key}", chunk, deadline=deadline))
                parts.append({"partNumber": number, "etag": result["etag"]})
                number += 1
        body = json.dumps({"parts": parts}).encode("utf-8")
        # Older ledger stores cannot safely repeat completion after a lost
        # response. Only retry when the server advertises that contract.
        result = json.loads(self._request(
            "POST", f"/uploads/{upload_id}/complete?key={key}", body,
            deadline=deadline, retry=upload.get("completion_retry_safe") is True,
        ))
        return str(result["key"])


def valid_manifest(m):
    import re
    good_hash = lambda h: isinstance(h, str) and bool(re.fullmatch(r"[a-f0-9]{64}", h))
    if isinstance(m, dict) and m.get("version") == 4:
        base, patches = m.get("base"), m.get("patches")
        try:
            timestamps_valid = datetime.fromisoformat(base["captured_at"].replace("Z", "+00:00")) <= datetime.fromisoformat(m["captured_at"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError, AttributeError):
            return False
        return (isinstance(base, dict) and base.get("version") == 3 and valid_manifest(base) and timestamps_valid
                and m.get("block_bytes") == DELTA_BLOCK_BYTES and good_hash(m.get("sha256"))
                and type(m.get("size_bytes")) is int and 0 < m["size_bytes"] <= 900*28*1024*1024
                and isinstance(patches, list) and len(base["chunks"])+len(patches) <= 900
                and all(isinstance(c, dict) and good_hash(c.get("sha256")) and good_hash(c.get("raw_sha256"))
                        and type(c.get("size_bytes")) is int and 0 < c["size_bytes"] <= 32*1024*1024
                        and type(c.get("raw_size_bytes")) is int and 8 <= c["raw_size_bytes"] <= 28*1024*1024 for c in patches))
    if not isinstance(m, dict) or m.get("version") != 3 or not good_hash(m.get("sha256")) or type(m.get("size_bytes")) is not int or m["size_bytes"] <= 0:
        return False
    chunks = m.get("chunks")
    if not isinstance(chunks, list) or not 1 <= len(chunks) <= 900:
        return False
    try:
        datetime.fromisoformat(m["captured_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
    for c in chunks:
        if not isinstance(c, dict) or not good_hash(c.get("sha256")) or not good_hash(c.get("raw_sha256")) or type(c.get("size_bytes")) is not int or not 0 < c["size_bytes"] <= 32*1024*1024 or type(c.get("raw_size_bytes")) is not int or not 0 < c["raw_size_bytes"] <= 28*1024*1024:
            return False
    return sum(c["raw_size_bytes"] for c in chunks) == m["size_bytes"]


def checkpoint(db_path: Path, store: LedgerStore, workdir: Path) -> Optional[str]:
    """Upload a consistent snapshot of a live WAL database."""
    if not db_path.exists():
        return None
    started = time.monotonic()
    incremental = os.environ.get("SECOPSAI_INCREMENTAL_CHECKPOINTS", "0") == "1"
    bootstrap = incremental and not getattr(store, "incremental_ready", False)
    # A production-sized SQLite backup can consume roughly two minutes on its
    # own. Leave a bounded remainder for the sparse scan and object/manifest
    # uploads while keeping the checkpoint timestamp inside the watchdog's
    # five-minute freshness window.
    capture_budget = 600 if bootstrap else 300 if incremental else UPLOAD_TIMEOUT_SECONDS
    capture_deadline = started + capture_budget
    # Capture and upload have separate bounded phases. In the previous
    # implementation a slow online backup consumed the upload allowance too.
    upload_deadline = started + (capture_budget + UPLOAD_TIMEOUT_SECONDS if incremental else UPLOAD_TIMEOUT_SECONDS)
    _log("checkpoint_capture_started", phase="bootstrap" if bootstrap else "recurring", budget_seconds=round(capture_deadline-started))
    captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(dir=workdir) as temp_dir:
        backup_path = Path(temp_dir) / "ledger.db"
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=60)
        target = sqlite3.connect(backup_path)
        try:
            # Pin a WAL read snapshot so concurrent commits cannot repeatedly
            # restart a production-size backup. Bound busy waits as well.
            source.execute("BEGIN")
            source.execute("SELECT count(*) FROM sqlite_master").fetchone()
            def check_capture_deadline(_status, _remaining, _total):
                if time.monotonic() >= capture_deadline:
                    raise TimeoutError("checkpoint capture exceeds its bounded budget")
            source.backup(target, pages=4096, sleep=0.01, progress=check_capture_deadline)
        finally:
            target.close()
            source.close()
        _log("checkpoint_captured", bytes=backup_path.stat().st_size, seconds=round(time.monotonic()-started,1))
        if incremental:
            delta_enabled = os.environ.get("SECOPSAI_PAGE_DELTA_CHECKPOINTS", "0") == "1"
            if delta_enabled and getattr(store, "baseline_path", None):
                try:
                    return store.upload_sparse(backup_path, captured_at=captured_at, deadline=upload_deadline)
                except RebaseRequired as reason:
                    _log("checkpoint_rebase_required", reason=str(reason), remaining_seconds=round(upload_deadline-time.monotonic()))
            key = store.upload_chunked(backup_path, captured_at=captured_at, deadline=upload_deadline)
            if delta_enabled:
                # Keep the baseline outside the temporary capture directory.
                frozen = workdir / ".checkpoint-base.db"
                backup_path.replace(frozen)
                os.chmod(frozen, 0o400)
                store.baseline_path = frozen
                store.index_baseline(deadline=upload_deadline)
            return key
        compressed = Path(temp_dir) / "ledger.db.gz"
        with backup_path.open("rb") as raw, gzip.open(compressed, "wb", compresslevel=6) as packed:
            shutil.copyfileobj(raw, packed, length=8 * 1024 * 1024)
        backup_path.unlink()
        key = store.upload(compressed)
        _log("checkpoint_uploaded", key=key, bytes=compressed.stat().st_size, seconds=round(time.monotonic() - started, 1))
        return key


def periodic_checkpoints(stopping, interval, capture):
    """Wait a full interval after each bounded capture, including failed ones."""
    while not stopping.wait(interval):
        capture()


GRACE_SECONDS = 180


def delivery_verification_timeout_seconds(delivery_seconds: int, refresh_seconds: int = 0) -> int:
    if not 1 <= delivery_seconds <= 2700 or not 0 <= refresh_seconds <= 2700:
        raise ValueError("delivery and refresh budgets are outside their permitted ranges")
    return delivery_seconds + refresh_seconds + 30


def main(argv: Optional[list] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cycles", type=int, default=0, help="Run N worker cycles then checkpoint and exit (0 = run until SIGTERM)")
    parser.add_argument("--delivery-only", action="store_true", help="Verify durable delivery without collection, analysis, or model jobs")
    parser.add_argument("--drain-after-cycles", action="store_true", help="Run bounded delivery verification after worker cycles before the final checkpoint")
    parser.add_argument("--checkpoint-only", action="store_true", help="Upload the existing local ledger and exit (migration)")
    parser.add_argument("--max-seconds", type=int, default=0, help="Stop the worker after this many seconds, then checkpoint (0 = no budget)")
    args = parser.parse_args(argv)
    if args.delivery_only and args.drain_after_cycles:
        parser.error("--delivery-only and --drain-after-cycles cannot be combined")
    if args.drain_after_cycles and args.cycles <= 0 and args.max_seconds <= 0:
        parser.error("--drain-after-cycles requires a bounded worker run")

    data_dir = Path(os.environ.get("SECOPS_FINDINGS_DIR", "/home/secops/research"))
    data_dir.mkdir(parents=True, exist_ok=True)
    report_dir = Path(os.environ.get("SECOPSAI_WORKER_DIAGNOSTICS_DIR", str(data_dir / "reports" / "research")))
    report_path = report_dir / "worker-runtime.json"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "delivery-drain.json").unlink(missing_ok=True)
    report = {"schema_version": "secopsai.research.worker-runtime.v1", "status": "starting",
              "run_id": os.environ.get("GITHUB_RUN_ID") or None,
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT") or None,
              "revision": os.environ.get("GITHUB_SHA") or None,
              "mode": "prepare_only" if getattr(args, "prepare_intel_only", False) else "delivery_only" if args.delivery_only else "cycles",
              "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
              "checkpoints": [], "delivery": {"status": "not_started"}}
    _write_runtime_report(report_path, report)

    def save_checkpoint(reason: str) -> str | None:
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            key = checkpoint(db_path, store, data_dir)
            item = {"reason": reason, "status": "uploaded", "key": key, "started_at": started_at,
                    "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        except Exception as exc:
            item = {"reason": reason, "status": "failed", "started_at": started_at,
                    "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **_error_fields(exc)}
            report["checkpoints"].append(item)
            report["checkpoints"] = report["checkpoints"][-50:]
            report["updated_at"] = item["completed_at"]
            _write_runtime_report(report_path, report)
            raise
        report["checkpoints"].append(item)
        report["checkpoints"] = report["checkpoints"][-50:]
        report["last_checkpoint"] = item
        report["updated_at"] = item["completed_at"]
        _write_runtime_report(report_path, report)
        return key

    db_path = data_dir / "openclaw_soc.db"
    store = LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"])
    interval = max(60, int(os.environ.get("SECOPSAI_LEDGER_CHECKPOINT_SECONDS", "3600")))

    if args.checkpoint_only:
        key = save_checkpoint("migration")
        _log("migration_checkpoint", key=key)
        report.update(status="succeeded", completed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        _write_runtime_report(report_path, report)
        return 0 if key else 1

    restored = False
    if not db_path.exists():
        restored = store.download(db_path)
        if not restored and os.environ.get("SECOPSAI_LEDGER_ALLOW_EMPTY", "").lower() != "true":
            # Never silently start over: an empty ledger would later be
            # checkpointed as LATEST and hide the migrated research history.
            _log("ledger_missing", hint="migrate with --checkpoint-only or set SECOPSAI_LEDGER_ALLOW_EMPTY=true")
            report.update(status="failed", failure_category="ledger_missing", completed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
            _write_runtime_report(report_path, report)
            return 2
        _log("ledger_restored" if restored else "ledger_initialized", path=str(db_path))

    command = [sys.executable, "-u", "-m", "secopsai.cli", "research", "worker", "run", "--interval", os.environ.get("SECOPSAI_WORKER_INTERVAL", "60")]
    if args.delivery_only:
        command = [sys.executable, "-u", "-m", "secopsai.research_delivery_verification"]
    elif args.cycles > 0:
        command += ["--max-cycles", str(args.cycles)]
    worker = subprocess.Popen(command, env={**os.environ, "SECOPS_FINDINGS_DIR": str(data_dir),
                                               "SECOPSAI_RESTORED_LEDGER_RECOVERY": "1" if restored else "0"})
    active_child = [worker]
    stopping = threading.Event()
    forced = threading.Event()
    budget_stop = threading.Event()
    lock = threading.Lock()

    def safe_checkpoint(reason: str) -> None:
        with lock:
            try:
                save_checkpoint(reason)
            except Exception as exc:  # keep the worker running; retry next interval
                _log("checkpoint_failed", reason=reason, **_error_fields(exc))

    def periodic() -> None:
        periodic_checkpoints(stopping, interval, lambda: safe_checkpoint("interval"))

    checkpoint_thread = threading.Thread(target=periodic, daemon=True)
    checkpoint_thread.start()

    def handle_term(signum: int, _frame: object) -> None:
        _log("shutdown_requested", signal=signum)
        stopping.set()
        child = active_child[0]
        if child.poll() is None:
            child.terminate()

    signal.signal(signal.SIGTERM, handle_term)
    signal.signal(signal.SIGINT, handle_term)

    started_worker = time.monotonic()
    grace_deadline = None
    while True:
        try:
            exit_code = worker.wait(timeout=1)
            break
        except subprocess.TimeoutExpired:
            if args.max_seconds > 0 and not budget_stop.is_set() and time.monotonic() - started_worker >= args.max_seconds:
                _log("time_budget_reached", seconds=args.max_seconds)
                budget_stop.set()
                stopping.set()
                worker.terminate()
            if stopping.is_set():
                if grace_deadline is None:
                    grace_deadline = time.monotonic() + GRACE_SECONDS
                elif time.monotonic() >= grace_deadline:
                    _log("worker_killed", reason="did not stop within grace period")
                    forced.set()
                    worker.kill()
                    exit_code = worker.wait()
                    break
    if forced.is_set():
        exit_code = 1  # checkpoint preservation does not make forced shutdown healthy
    elif exit_code == -signal.SIGTERM and budget_stop.is_set():
        exit_code = 0
    stopping.set()
    # Do not race the pre-drain/final checkpoint against an interval save.
    # Each capture has a bounded upload deadline, so a completed worker waits
    # for the single writer to finish before continuing the durability order.
    checkpoint_thread.join(timeout=1200)
    if checkpoint_thread.is_alive():
        _log("checkpoint_coordinator_join_timeout", timeout_seconds=1200)
        exit_code = 1
    if args.drain_after_cycles and exit_code == 0:
        # Persist the worker's complete queue before any acknowledgement can
        # remove rows locally. The next snapshot makes retries safe even if
        # the runner is interrupted during the bounded drain.
        with lock:
            try:
                save_checkpoint("before_delivery_verification")
            except Exception as exc:
                _log("checkpoint_failed", reason="before_delivery_verification", **_error_fields(exc))
                exit_code = 1
    if args.drain_after_cycles and exit_code == 0:
        try:
            delivery_seconds = int(os.environ.get("SECOPSAI_VERIFY_DELIVERY_SECONDS", "840"))
        except ValueError:
            _log("delivery_verification_invalid_budget")
            delivery_seconds = 0
        if not 1 <= delivery_seconds <= 2700:
            _log("delivery_verification_invalid_budget", seconds=delivery_seconds)
            exit_code = 1
            report["delivery"] = {"status": "failed", "error_category": "invalid_budget"}
        else:
            refresh_seconds = 0
            if (os.environ.get("SECOPSAI_VERIFY_REFRESH_STALE_SOURCES", "0") == "1"
                    and os.environ.get("SECOPSAI_VERIFY_DELIVERY_ONLY", "0") != "1"):
                try:
                    refresh_seconds = int(os.environ.get("SECOPSAI_VERIFY_REFRESH_SECONDS", "840"))
                except ValueError:
                    refresh_seconds = 0
                if not 1 <= refresh_seconds <= 2700:
                    _log("delivery_verification_invalid_refresh_budget", seconds=refresh_seconds)
                    exit_code = 1
                    report["delivery"] = {"status": "failed", "error_category": "invalid_refresh_budget"}
                    refresh_seconds = 0
            if exit_code != 0:
                drain = None
            else:
                drain = subprocess.Popen(
                    [sys.executable, "-u", "-m", "secopsai.research_delivery_verification"],
                    env={**os.environ, "SECOPS_FINDINGS_DIR": str(data_dir),
                         "SECOPSAI_VERIFY_DELIVERY_SECONDS": str(delivery_seconds)},
                )
            if drain is None:
                drain_code = 1
            else:
                active_child[0] = drain
                drain_started = time.monotonic()
                drain_timeout_seconds = delivery_verification_timeout_seconds(delivery_seconds, refresh_seconds)
                while True:
                    try:
                        drain_code = drain.wait(timeout=1)
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() - drain_started > drain_timeout_seconds:
                            _log("delivery_verification_timeout", seconds=delivery_seconds,
                                 refresh_seconds=refresh_seconds)
                            drain.terminate()
                            try:
                                drain_code = drain.wait(timeout=GRACE_SECONDS)
                            except subprocess.TimeoutExpired:
                                drain.kill()
                                drain_code = drain.wait()
                            drain_code = drain_code or 1
                            break
                        if stopping.is_set():
                            continue
            if drain is not None:
                _log("delivery_verification_exited", exit_code=drain_code)
                drain_report = {}
                try:
                    drain_report = json.loads((report_dir / "delivery-drain.json").read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    pass
                report["delivery"] = {"status": drain_report.get("status", "succeeded" if drain_code == 0 else "failed"),
                                      "exit_code": drain_code,
                                      "pending": drain_report.get("pending"),
                                      "delivery_blockers": drain_report.get("delivery_blockers", [])}
                if drain_code != 0:
                    exit_code = 1
                active_child[0] = worker
    # Final checkpoint after the worker released its write transactions.
    # A failed final checkpoint fails the run so a lost update is visible.
    with lock:
        try:
            save_checkpoint("shutdown")
        except Exception as exc:
            _log("checkpoint_failed", reason="shutdown", **_error_fields(exc))
            report.update(status="failed", failure_category="checkpoint_failed", completed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
            _write_runtime_report(report_path, report)
            return 1
    _log("worker_exited", exit_code=exit_code)
    report.update(status="succeeded" if exit_code == 0 else "failed", exit_code=exit_code,
                  completed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    _write_runtime_report(report_path, report)
    return exit_code if exit_code is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
