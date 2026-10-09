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


def _log(event: str, **fields: object) -> None:
    print(json.dumps({"component": "research-runner", "event": event, **fields}, sort_keys=True), flush=True)


class LedgerStore:
    """Minimal client for the Worker-side R2 ledger store."""

    def __init__(self, base_url: str, token: str, opener: Callable[..., object] = urllib.request.urlopen) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._open = opener

    def _request(self, method: str, path: str, body: Optional[bytes] = None) -> bytes:
        request = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        if body is not None:
            request.add_header("Content-Type", "application/octet-stream")
        with self._open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.read()

    def download(self, destination: Path) -> bool:
        request = urllib.request.Request(f"{self.base_url}/snapshot", method="GET")
        request.add_header("Authorization", f"Bearer {self.token}")
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

    def upload(self, compressed: Path) -> str:
        upload = json.loads(self._request("POST", "/uploads"))
        upload_id, key = upload["upload_id"], upload["key"]
        parts = []
        with compressed.open("rb") as handle:
            number = 1
            while chunk := handle.read(PART_BYTES):
                result = json.loads(self._request("PUT", f"/uploads/{upload_id}/parts/{number}?key={key}", chunk))
                parts.append({"partNumber": number, "etag": result["etag"]})
                number += 1
        body = json.dumps({"parts": parts}).encode("utf-8")
        result = json.loads(self._request("POST", f"/uploads/{upload_id}/complete?key={key}", body))
        return str(result["key"])


def checkpoint(db_path: Path, store: LedgerStore, workdir: Path) -> Optional[str]:
    """Upload a consistent snapshot of a live WAL database."""
    if not db_path.exists():
        return None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(dir=workdir) as temp_dir:
        backup_path = Path(temp_dir) / "ledger.db"
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=60)
        target = sqlite3.connect(backup_path)
        try:
            # The online backup API copies a transactionally consistent image
            # while the worker keeps writing.
            source.backup(target, pages=4096, sleep=0.01)
        finally:
            target.close()
            source.close()
        compressed = Path(temp_dir) / "ledger.db.gz"
        with backup_path.open("rb") as raw, gzip.open(compressed, "wb", compresslevel=6) as packed:
            shutil.copyfileobj(raw, packed, length=8 * 1024 * 1024)
        backup_path.unlink()
        key = store.upload(compressed)
        _log("checkpoint_uploaded", key=key, bytes=compressed.stat().st_size, seconds=round(time.monotonic() - started, 1))
        return key


def main() -> int:
    data_dir = Path(os.environ.get("SECOPS_FINDINGS_DIR", "/home/secops/research"))
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "openclaw_soc.db"
    store = LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"])
    interval = max(300, int(os.environ.get("SECOPSAI_LEDGER_CHECKPOINT_SECONDS", "3600")))

    if not db_path.exists():
        restored = store.download(db_path)
        _log("ledger_restored" if restored else "ledger_initialized", path=str(db_path))

    worker = subprocess.Popen(
        [sys.executable, "-u", "-m", "secopsai.cli", "research", "worker", "run", "--interval", os.environ.get("SECOPSAI_WORKER_INTERVAL", "60")],
        env={**os.environ, "SECOPS_FINDINGS_DIR": str(data_dir)},
    )
    stopping = threading.Event()
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

    exit_code = worker.wait()
    stopping.set()
    # Final checkpoint after the worker released its write transactions.
    safe_checkpoint("shutdown")
    _log("worker_exited", exit_code=exit_code)
    return exit_code if exit_code is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
