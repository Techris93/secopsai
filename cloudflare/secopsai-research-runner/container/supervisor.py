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

import gzip
import hashlib
import io
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import http.client
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
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


def _log(event: str, **fields: object) -> None:
    print(json.dumps({"component": "research-runner", "event": event, **fields}, sort_keys=True), flush=True)


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
                if exc.code not in RETRY_HTTP_STATUSES:
                    raise
                retry_after = exc.headers.get("Retry-After", "") if exc.headers else ""
                exc.close()
            except (urllib.error.URLError, OSError, http.client.HTTPException):
                retry_after = ""
            if attempt + 1 == attempts:
                # Do not log URLs, tokens, or provider response bodies.
                raise ConnectionError(f"ledger {method} request failed after {attempts} attempt(s)")
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

    def download_chunked(self, destination: Path, manifest: dict) -> bool:
        if not valid_manifest(manifest):
            raise ValueError("invalid incremental checkpoint manifest")
        deadline = time.monotonic() + 3600
        partial = destination.with_suffix(".restore")
        digest, total = hashlib.sha256(), 0
        try:
            with partial.open("xb") as output:
                os.chmod(partial, 0o600)
                for chunk in manifest["chunks"]:
                    packed = self._request("GET", "/artifact-objects/" + chunk["sha256"], deadline=deadline)
                    if len(packed) != chunk["size_bytes"] or hashlib.sha256(packed).hexdigest() != chunk["sha256"]:
                        raise ValueError("checkpoint chunk checksum mismatch")
                    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as reader:
                        raw = reader.read(chunk["raw_size_bytes"] + 1)
                    if len(raw) != chunk["raw_size_bytes"] or hashlib.sha256(raw).hexdigest() != chunk["raw_sha256"]:
                        raise ValueError("checkpoint decompressed chunk mismatch")
                    digest.update(raw)
                    total += len(raw)
                    output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if total != manifest["size_bytes"] or digest.hexdigest() != manifest["sha256"]:
                raise ValueError("checkpoint database checksum mismatch")
            with sqlite3.connect(f"file:{partial}?mode=ro", uri=True) as recovered:
                if recovered.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("checkpoint SQLite integrity check failed")
            partial.replace(destination)
            self.chunk_cache = {c["sha256"] for c in manifest["chunks"]}
            _log("incremental_restore_verified", bytes=total, sha256=digest.hexdigest())
            return True
        finally:
            partial.unlink(missing_ok=True)

    def upload_chunked(self, backup: Path, *, captured_at: str, deadline=None) -> str:
        deadline = deadline or (time.monotonic() + 240)
        cached = getattr(self, "chunk_cache", set())
        entries, whole, total, uploaded = [], hashlib.sha256(), 0, 0
        def upload_piece(raw):
            packed = gzip.compress(raw, compresslevel=1, mtime=0)
            key = hashlib.sha256(packed).hexdigest()
            was_uploaded = key not in cached
            if was_uploaded:
                result = json.loads(self._request("PUT", "/artifact-objects/" + key, packed, deadline=deadline))
                if result.get("sha256") != key or result.get("size_bytes") != len(packed):
                    raise ValueError("incremental checkpoint upload receipt mismatch")
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
        self.chunk_cache = {entry["sha256"] for entry in entries}
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
    capture_deadline = started + (240 if incremental else UPLOAD_TIMEOUT_SECONDS)
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
        if incremental:
            return store.upload_chunked(backup_path, captured_at=captured_at, deadline=capture_deadline)
        compressed = Path(temp_dir) / "ledger.db.gz"
        with backup_path.open("rb") as raw, gzip.open(compressed, "wb", compresslevel=6) as packed:
            shutil.copyfileobj(raw, packed, length=8 * 1024 * 1024)
        backup_path.unlink()
        key = store.upload(compressed)
        _log("checkpoint_uploaded", key=key, bytes=compressed.stat().st_size, seconds=round(time.monotonic() - started, 1))
        return key


GRACE_SECONDS = 180


def main(argv: Optional[list] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cycles", type=int, default=0, help="Run N worker cycles then checkpoint and exit (0 = run until SIGTERM)")
    parser.add_argument("--checkpoint-only", action="store_true", help="Upload the existing local ledger and exit (migration)")
    parser.add_argument("--max-seconds", type=int, default=0, help="Stop the worker after this many seconds, then checkpoint (0 = no budget)")
    args = parser.parse_args(argv)

    data_dir = Path(os.environ.get("SECOPS_FINDINGS_DIR", "/home/secops/research"))
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "openclaw_soc.db"
    store = LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"])
    interval = max(60, int(os.environ.get("SECOPSAI_LEDGER_CHECKPOINT_SECONDS", "3600")))

    if args.checkpoint_only:
        key = checkpoint(db_path, store, data_dir)
        _log("migration_checkpoint", key=key)
        return 0 if key else 1

    if not db_path.exists():
        restored = store.download(db_path)
        if not restored and os.environ.get("SECOPSAI_LEDGER_ALLOW_EMPTY", "").lower() != "true":
            # Never silently start over: an empty ledger would later be
            # checkpointed as LATEST and hide the migrated research history.
            _log("ledger_missing", hint="migrate with --checkpoint-only or set SECOPSAI_LEDGER_ALLOW_EMPTY=true")
            return 2
        _log("ledger_restored" if restored else "ledger_initialized", path=str(db_path))

    command = [sys.executable, "-u", "-m", "secopsai.cli", "research", "worker", "run", "--interval", os.environ.get("SECOPSAI_WORKER_INTERVAL", "60")]
    if args.cycles > 0:
        command += ["--max-cycles", str(args.cycles)]
    worker = subprocess.Popen(command, env={**os.environ, "SECOPS_FINDINGS_DIR": str(data_dir)})
    stopping = threading.Event()
    forced = threading.Event()
    budget_stop = threading.Event()
    lock = threading.Lock()

    def safe_checkpoint(reason: str) -> None:
        with lock:
            try:
                checkpoint(db_path, store, data_dir)
            except Exception as exc:  # keep the worker running; retry next interval
                _log("checkpoint_failed", reason=reason, error=str(exc)[:500])

    def periodic() -> None:
        while not stopping.wait(interval):
            safe_checkpoint("interval")

    threading.Thread(target=periodic, daemon=True).start()

    def handle_term(signum: int, _frame: object) -> None:
        _log("shutdown_requested", signal=signum)
        stopping.set()
        if worker.poll() is None:
            worker.terminate()

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
    # Final checkpoint after the worker released its write transactions.
    # A failed final checkpoint fails the run so a lost update is visible.
    with lock:
        try:
            checkpoint(db_path, store, data_dir)
        except Exception as exc:
            _log("checkpoint_failed", reason="shutdown", error=str(exc)[:500])
            return 1
    _log("worker_exited", exit_code=exit_code)
    return exit_code if exit_code is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
