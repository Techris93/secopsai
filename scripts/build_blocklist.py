#!/usr/bin/env python3
"""Build the install-firewall blocklist shards and upload them to the ledger store.

    python scripts/build_blocklist.py --osv osv/malicious/npm --osv osv/malicious/pypi [--upload]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secopsai import blocklist  # noqa: E402


def upload(key: str, entries: dict) -> int:
    store = os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev").rstrip("/")
    body = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()
    request = urllib.request.Request(f"{store}/firewall/{key}", data=body, method="PUT",
                                     headers={"Authorization": f"Bearer {os.environ['LEDGER_STORE_TOKEN']}",
                                              "Content-Type": "application/json", "User-Agent": "secopsai-blocklist"})
    with urllib.request.urlopen(request, timeout=60) as response:
        response.read()
    return len(body)


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
        with ThreadPoolExecutor(max_workers=16) as pool:
            summary["uploaded_bytes"] = sum(pool.map(lambda item: upload(*item), shards.items()))
        summary["uploaded_shards"] = len(shards)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
