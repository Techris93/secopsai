#!/usr/bin/env python3
"""Measure the deployed install firewall (frontier phase 5 targets).

- block_rate: share of the benchmark's known-malicious versions the firewall
  refuses, through its /check endpoint, with a sample confirmed end to end
  (npm tarball requests must get 403).
- p95_latency_ms: added time for package metadata through the firewall
  against the registry directly, 95th percentile over paired requests.

Reads the corpora's file listings only (git ls-tree); no sample is fetched.

    FIREWALL_TOKEN=... python scripts/firewall_check.py --firewall https://fw.example --dataset DIR [--registry DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

POPULAR = {"npm": ["react", "lodash", "express", "axios", "chalk", "commander", "debug", "typescript", "vue", "moment",
                   "uuid", "semver", "dotenv", "yargs", "glob", "webpack", "eslint", "jest", "prettier", "next"],
           "pypi": ["requests", "numpy", "pandas", "boto3", "urllib3", "setuptools", "certifi", "idna", "six", "pyyaml",
                    "click", "jinja2", "packaging", "cryptography", "pydantic", "attrs", "pytest", "wheel", "pip", "rich"]}
UPSTREAM = {"npm": "https://registry.npmjs.org/", "pypi": "https://pypi.org/simple/"}


def _listing(repo: Path, *paths: str) -> List[str]:
    return subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD", *paths],
                          check=True, capture_output=True, text=True).stdout.split("\n")


def benchmark_versions(dataset: Optional[Path], registry: Optional[Path]) -> List[Dict[str, str]]:
    found: Dict[Tuple[str, str, str], Dict[str, str]] = {}
    if dataset:
        for path in _listing(dataset, "samples/npm", "samples/pypi"):
            parts = path.split("/")
            if path.endswith(".zip") and len(parts) >= 5:
                item = {"ecosystem": parts[1], "name": "/".join(parts[3:-2]) or parts[3], "version": parts[-2],
                        "corpus": "datadog", "category": parts[2]}
                found.setdefault((item["ecosystem"], item["name"].lower(), item["version"]), item)
    if registry:
        for path in _listing(registry):
            parts = path.split("/")
            if len(parts) == 3 and re.search(r"\.(tar\.gz|tgz|zip|whl|tar\.bz2|egg)$", parts[2], re.I):
                item = {"ecosystem": "pypi", "name": parts[0], "version": parts[1], "corpus": "pypi_malregistry", "category": "malicious_intent"}
                found.setdefault(("pypi", re.sub(r"[-_.]+", "-", parts[0]).lower(), parts[1]), item)
    return list(found.values())


def _request(url: str, token: str = "", method: str = "GET", body: Optional[bytes] = None) -> Tuple[int, bytes, float]:
    headers = {"User-Agent": "secopsai-firewall-check", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            data, status = response.read(), response.status
    except urllib.error.HTTPError as exc:
        data, status = exc.read(), exc.code
    return status, data, (time.perf_counter() - started) * 1000


def percentile(values: List[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))], 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--firewall", required=True)
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--tarball-sample", type=int, default=100)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--out", type=Path, default=Path("reports/firewall-check.json"))
    args = parser.parse_args()
    token = os.environ["FIREWALL_TOKEN"]
    base = args.firewall.rstrip("/")

    versions = benchmark_versions(args.dataset, args.registry)
    blocked_keys = set()
    # Small batches: a cold lookup reads one blocklist shard from storage per package.
    for start in range(0, len(versions), 200):
        batch = [{key: item[key] for key in ("ecosystem", "name", "version")} for item in versions[start:start + 200]]
        status, data, _ = _request(f"{base}/check", token, "POST", json.dumps({"packages": batch}).encode())
        if status != 200:
            raise SystemExit(f"/check returned {status}: {data[:200]!r}")
        blocked_keys |= {(item["ecosystem"], item["name"], item["version"]) for item in json.loads(data)["blocked"]}
    totals, hits = Counter(), Counter()
    for item in versions:
        group = f"{item['corpus']}/{item['ecosystem']}/{item['category']}"
        totals[group] += 1
        hits[group] += int((item["ecosystem"], item["name"], item["version"]) in blocked_keys)

    # End to end: a blocked npm version's tarball must be refused before any upstream fetch.
    rng = random.Random(20261115)
    npm_blocked = [item for item in versions if item["ecosystem"] == "npm" and (item["ecosystem"], item["name"], item["version"]) in blocked_keys]
    sample = rng.sample(npm_blocked, min(args.tarball_sample, len(npm_blocked)))
    refused = sum(1 for item in sample
                  if _request(f"{base}/npm/{item['name']}/-/{item['name'].split('/')[-1]}-{item['version']}.tgz", token)[0] == 403)

    added: Dict[str, List[float]] = {"npm": [], "pypi": []}
    for _ in range(args.rounds):
        for ecosystem, names in POPULAR.items():
            for name in names:
                direct = _request(UPSTREAM[ecosystem] + name + ("/" if ecosystem == "pypi" else ""))
                through = _request(f"{base}/{ecosystem}/{'simple/' if ecosystem == 'pypi' else ''}{name}{'/' if ecosystem == 'pypi' else ''}", token)
                if direct[0] == 200 and through[0] == 200:
                    added[ecosystem].append(through[2] - direct[2])

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "firewall": base,
        "versions": len(versions), "blocked": len(blocked_keys),
        "block_rate": round(len(blocked_keys) / len(versions), 4) if versions else None,
        "by_group": {group: {"versions": totals[group], "blocked": hits[group], "rate": round(hits[group] / totals[group], 4)} for group in sorted(totals)},
        "tarball_sample": len(sample), "tarball_refused": refused,
        "p95_latency_ms": percentile(added["npm"] + added["pypi"], 0.95),
        "latency_ms": {ecosystem: {"p50": percentile(values, 0.5), "p95": percentile(values, 0.95), "n": len(values)} for ecosystem, values in added.items()},
    }
    if sample and refused < len(sample):
        result["block_rate"] = round(result["block_rate"] * refused / len(sample), 4)  # enforcement must hold end to end
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "by_group"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
