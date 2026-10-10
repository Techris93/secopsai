#!/usr/bin/env python3
"""Build the fast-lane watchlists of high-impact packages and store them.

- npm: ``npm-high-impact`` (MIT, by Titus Wormer), its download-ranked list,
  pinned to a version and verified against the registry's integrity hash.
- PyPI: hugovk/top-pypi-packages (30-day download ranking).

The lists are uploaded to the ledger store, where the per-minute Cloudflare
cron reads them.  Run by the "Fast Lane Watchlists" workflow.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.request

NPM_HIGH_IMPACT_VERSION = "1.13.0"
NPM_LIMIT = int(os.environ.get("FAST_LANE_NPM_LIMIT", "10000"))
PYPI_LIMIT = int(os.environ.get("FAST_LANE_PYPI_LIMIT", "5000"))
PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
UA = {"User-Agent": "SecOpsAI-Research/1.0"}


def _get(url: str, limit: int = 32 * 1024 * 1024) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{url} exceeds {limit} bytes")
    return data


def npm_watchlist() -> list:
    meta = json.loads(_get(f"https://registry.npmjs.org/npm-high-impact/{NPM_HIGH_IMPACT_VERSION}"))
    tarball = _get(meta["dist"]["tarball"])
    algorithm, expected = meta["dist"]["integrity"].split("-", 1)
    if algorithm != "sha512" or base64.b64encode(hashlib.sha512(tarball).digest()).decode() != expected:
        raise ValueError("npm-high-impact tarball failed its integrity check")
    with tarfile.open(fileobj=io.BytesIO(tarball)) as archive:
        source = archive.extractfile("package/lib/top-download.js").read().decode("utf-8")
    names = re.findall(r"^\s*'((?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*)',?\s*$", source, re.M)
    return names[:NPM_LIMIT]


def pypi_watchlist() -> list:
    rows = json.loads(_get(PYPI_URL)).get("rows") or []
    return [re.sub(r"[-_.]+", "-", str(row["project"]).lower()) for row in rows[:PYPI_LIMIT]]


def upload(ecosystem: str, names: list) -> None:
    base = os.environ["LEDGER_STORE_URL"].rstrip("/")
    body = json.dumps({"ecosystem": ecosystem, "names": names, "count": len(names)}).encode()
    request = urllib.request.Request(f"{base}/fastlane/watchlist/{ecosystem}", data=body, method="PUT", headers={
        **UA, "Authorization": f"Bearer {os.environ['LEDGER_STORE_TOKEN']}", "Content-Type": "application/json",
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        print(ecosystem, response.status, response.read().decode()[:200])


def main() -> int:
    lists = {"npm": npm_watchlist(), "pypi": pypi_watchlist()}
    for ecosystem, names in lists.items():
        if len(names) < 1000:
            raise SystemExit(f"{ecosystem} watchlist suspiciously small ({len(names)}); not uploading")
        print(f"{ecosystem}: {len(names)} packages, e.g. {names[:5]}")
        if os.environ.get("LEDGER_STORE_TOKEN"):
            upload(ecosystem, names)
    return 0


if __name__ == "__main__":
    sys.exit(main())
