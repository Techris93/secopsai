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
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and method == "GET":
            return None
        raise


def changed_shards(shards: dict, manifest: dict) -> Dict[str, str]:
    """Shard key -> content hash, for shards whose content differs from the manifest."""
    hashes = {key: hashlib.sha256(_body(entries)).hexdigest() for key, entries in shards.items()}
    return {key: digest for key, digest in hashes.items() if manifest.get(key) != digest}


def upload_changed(shards: dict) -> Dict[str, int]:
    """Upload only shards whose content changed (storage writes are billed), then the manifest."""
    raw = _call("GET", "manifest")
    manifest = json.loads(raw) if raw else {}
    changed = changed_shards(shards, manifest)

    def put(key: str) -> int:
        body = _body(shards[key])
        _call("PUT", key, body)
        return len(body)

    with ThreadPoolExecutor(max_workers=16) as pool:
        uploaded = sum(pool.map(put, changed))
    # Manifest last: an interrupted run re-uploads what it did not record.
    manifest = {key: digest for key, digest in {**manifest, **changed}.items() if key in shards}
    _call("PUT", "manifest", _body(manifest))
    return {"uploaded_shards": len(changed), "uploaded_bytes": uploaded, "total_shards": len(shards)}


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
    return 0


if __name__ == "__main__":
    sys.exit(main())
