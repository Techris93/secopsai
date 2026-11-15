#!/usr/bin/env python3
"""Build the install-firewall blocklist shards and upload them to the ledger store.

    python scripts/build_blocklist.py --osv osv/malicious/npm --osv osv/malicious/pypi [--upload]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai import blocklist  # noqa: E402


def _body(entries: dict) -> bytes:
    return json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()


def _call(method: str, path: str, body: Optional[bytes] = None) -> Optional[bytes]:
    store = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")
    request = urllib.request.Request(f"{store}/firewall/{path}", data=body, method=method,
                                     headers={"Authorization": f"Bearer {os.environ['LEDGER_STORE_TOKEN']}",
                                              "Content-Type": "application/json", "User-Agent": "secopsai-blocklist"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and method == "GET":
                return None
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 4:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 4:
                raise
        time.sleep(2 ** attempt)
    return None


def changed_shards(shards: dict, manifest: dict) -> Dict[str, str]:
    """Shard key -> content hash, for shards whose content differs from the manifest."""
    hashes = {key: hashlib.sha256(_body(entries)).hexdigest() for key, entries in shards.items()}
    return {key: digest for key, digest in hashes.items() if manifest.get(key) != digest}


def upload_changed(shards: dict) -> Dict[str, int]:
    """Upload only shards whose content changed (storage writes are billed), then the manifest."""
    raw = _call("GET", "manifest")
    manifest = json.loads(raw) if raw else {}
    changed = changed_shards(shards, manifest)

    def put(key: str) -> Optional[int]:
        body = _body(shards[key])
        try:
            _call("PUT", key, body)
        except Exception as exc:  # noqa: BLE001 - recorded and retried next run
            print(f"upload failed for {key}: {exc}", file=sys.stderr)
            return None
        return len(body)

    with ThreadPoolExecutor(max_workers=8) as pool:
        sizes = dict(zip(changed, pool.map(put, changed)))
    done = {key: changed[key] for key, size in sizes.items() if size is not None}
    # Only what was stored enters the manifest; the rest is uploaded next run.
    manifest = {key: digest for key, digest in {**manifest, **done}.items() if key in shards}
    _call("PUT", "manifest", _body(manifest))
    return {"uploaded_shards": len(done), "failed_shards": len(changed) - len(done),
            "uploaded_bytes": sum(size for size in sizes.values() if size), "total_shards": len(shards)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--osv", type=Path, action="append", default=[])
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("reports/blocklist-summary.json"))
    args = parser.parse_args()
    blocks = blocklist.from_osv(args.osv)
    shards = blocklist.shards(blocks)
    summary = {ecosystem: {"packages": len(names), "all_versions": sum(1 for entry in names.values() if entry["all"]),
                           "versions": sum(len(entry["versions"]) for entry in names.values())} for ecosystem, names in blocks.items()}
    summary["largest_shard_bytes"] = max(len(json.dumps(entries)) for entries in shards.values())
    if args.upload:
        summary.update(upload_changed(shards))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(json.dumps(summary))
    return 1 if summary.get("failed_shards") else 0


if __name__ == "__main__":
    sys.exit(main())
