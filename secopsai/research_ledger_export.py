"""One-time export of the research ledger to the R2 ledger store.

Used to move the ledger off the Render worker.  Render's 5 GB disk cannot
hold a second copy of a ~4 GB database, so the export does not make a backup
file: it runs before any worker cycle (no concurrent writers), folds the WAL
into the main file, then gzip-streams the file directly into multipart
uploads.  It authenticates with the runner's existing Core bridge token,
which the ledger store verifies with Core Edge during the migration window.

Enable with ``SECOPSAI_LEDGER_EXPORT_URL`` (and optionally
``SECOPSAI_LEDGER_EXPORT_AND_STOP=true`` to idle afterwards instead of
running cycles, so a second worker can take over without two writers).
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.request
import zlib
from pathlib import Path
from typing import Callable, Optional

PART_BYTES = 32 * 1024 * 1024
READ_BYTES = 8 * 1024 * 1024
MARKER_NAME = ".ledger-exported"


def _log(event: str, **fields: object) -> None:
    print(json.dumps({"component": "ledger-export", "event": event, **fields}, sort_keys=True), flush=True)


class _Uploader:
    def __init__(self, base_url: str, token: str, opener: Callable[..., object] = urllib.request.urlopen) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.open = opener
        self.parts: list[dict] = []
        created = self._call("POST", "/uploads")
        self.upload_id, self.key = created["upload_id"], created["key"]

    def _call(self, method: str, path: str, body: Optional[bytes] = None) -> dict:
        request = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        # Cloudflare's browser integrity check rejects the default
        # Python-urllib agent with 403 (error 1010) before the Worker runs.
        request.add_header("User-Agent", "SecOpsAI-Research/1.0")
        if body is not None:
            request.add_header("Content-Type", "application/octet-stream")
        for attempt in range(5):
            try:
                with self.open(request, timeout=300) as response:
                    return json.loads(response.read())
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError("unreachable")

    def part(self, data: bytes) -> None:
        number = len(self.parts) + 1
        result = self._call("PUT", f"/uploads/{self.upload_id}/parts/{number}?key={self.key}", data)
        self.parts.append({"partNumber": number, "etag": result["etag"]})

    def complete(self) -> str:
        body = json.dumps({"parts": self.parts}).encode("utf-8")
        return str(self._call("POST", f"/uploads/{self.upload_id}/complete?key={self.key}", body)["key"])


def export_ledger(db_path: str, base_url: str, token: str, *, opener: Callable[..., object] = urllib.request.urlopen) -> dict:
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"ledger not found: {db_path}")
    started = time.monotonic()
    connection = sqlite3.connect(str(path), timeout=60)
    try:
        # Fold the WAL into the main file so the file alone is consistent.
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    uploader = _Uploader(base_url, token, opener)
    compressor = zlib.compressobj(6, zlib.DEFLATED, 31)  # gzip container
    buffer = bytearray()
    raw_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(READ_BYTES):
            raw_bytes += len(chunk)
            buffer += compressor.compress(chunk)
            while len(buffer) >= PART_BYTES:
                uploader.part(bytes(buffer[:PART_BYTES]))
                del buffer[:PART_BYTES]
    buffer += compressor.flush()
    if buffer:
        uploader.part(bytes(buffer))
    key = uploader.complete()
    result = {"key": key, "raw_bytes": raw_bytes, "parts": len(uploader.parts), "seconds": round(time.monotonic() - started, 1)}
    _log("exported", **result)
    return result


def maybe_export_before_worker(db_path: Optional[str]) -> bool:
    """Run the configured export once.  Returns True when the caller should
    idle instead of running worker cycles."""
    url = os.environ.get("SECOPSAI_LEDGER_EXPORT_URL", "").strip()
    if not url:
        return False
    import soc_store

    resolved = db_path or soc_store.default_db_path()
    marker = Path(resolved).with_name(MARKER_NAME)
    stop = os.environ.get("SECOPSAI_LEDGER_EXPORT_AND_STOP", "").strip().lower() == "true"
    if marker.exists():
        _log("already_exported", marker=str(marker))
        return stop
    token = os.environ.get("SECOPSAI_LEDGER_EXPORT_TOKEN", "").strip() or os.environ.get("SECOPSAI_CORE_BRIDGE_TOKEN", "").strip()
    if not token:
        _log("export_skipped", reason="no bridge token in the environment")
        return False
    result = export_ledger(resolved, url, token)
    marker.write_text(json.dumps(result), encoding="utf-8")
    return stop


def idle_forever() -> None:
    _log("idle", reason="ledger exported; another worker owns the ledger now")
    while True:
        time.sleep(3600)
        _log("idle")
