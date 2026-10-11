#!/usr/bin/env python3
"""Calibrate Cloudflare Clef as a triage model on known malware and clean packages.

Malicious set: the Recall Benchmark's seeded sample of the malware dataset
(decrypted and scanned in memory on a disposable runner, never executed).
Clean set: the latest release of top npm and PyPI packages.  Every package,
whatever its class, gets the same context shape (rule findings, install-time
files, evidence for its risky behaviour flags), so the format cannot reveal
the label.  Each context is sent to Clef on Workers AI and the report shows
how well its probability separates the classes: ROC AUC, malware caught and
clean packages flagged at each threshold, and the cost.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import requests  # noqa: E402

from recall_benchmark import checkout, clean_targets, sample_members, sample_paths  # noqa: E402
from secopsai import clef_triage, package_features, research_ai_triage, version_diff, yara_engine  # noqa: E402
from secopsai.research_intake import SafeFetcher  # noqa: E402

RISKY = sorted(version_diff.RISKY - {"new"})
PRICE_PER_MILLION = 0.24


def context_for(ecosystem: str, package: str, version: str, members: List[Tuple[str, bytes]]) -> Dict[str, Any]:
    flags = package_features.profile(members, version=version)
    scan = package_features.combine(yara_engine.scan_files(members), flags, ecosystem, members)
    evidence = [found for found in (package_features.flag_evidence(members, flag) for flag in flags if flag in RISKY) if found][:6]
    findings = list(scan.get("findings") or [])
    if evidence:
        findings.append({"rule_id": "BEHAVIOUR:profile", "file_path": evidence[0]["file_path"], "matched_indicator": "behaviour: " + " + ".join(e["flag"] for e in evidence),
                         "safe_context": "\n[...]\n".join(f"{e['flag']} in {e['file_path']} line {e.get('line', '?')}:\n{e['context']}" for e in evidence), "evidence": evidence})
    prescan = {**scan, "findings": findings, "install_files": package_features.install_time_files(members)}
    context = research_ai_triage.build_context(ecosystem=ecosystem, package=package, version=version, prescan=prescan,
                                               metadata_signals=[{"id": "behaviours", "flags": flags}])
    return {"context": research_ai_triage.fit_context(context), "level": scan.get("level") or "none", "score": scan.get("score") or 0}


def malicious_rows(dataset: Path, count_npm: int, count_pypi: int, seed: int) -> List[Dict[str, Any]]:
    paths = sample_paths(dataset, {"npm": count_npm, "pypi": count_pypi}, seed)
    checkout(dataset, paths)

    def one(path: str) -> Optional[Dict[str, Any]]:
        parts = path.split("/")
        ecosystem, package, version = parts[1], "/".join(parts[3:-2]) or parts[3], parts[-2]
        try:
            built = context_for(ecosystem, package, version, sample_members((dataset / path).read_bytes()))
        except Exception:
            return None
        return {"label": 1, "ecosystem": ecosystem, "category": parts[2], "package": package, **built}

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [row for row in pool.map(one, paths) if row]


def clean_rows(count_npm: int, count_pypi: int) -> List[Dict[str, Any]]:
    fetcher = SafeFetcher(timeout=60)

    def one(target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ecosystem, package = target["ecosystem"], target["package"]
        try:
            if ecosystem == "npm":
                version = json.loads(fetcher.get(f"https://registry.npmjs.org/{package.replace('/', '%2F')}/latest", allowed_hosts=("registry.npmjs.org",), max_bytes=4 << 20)[2])["version"]
            else:
                version = json.loads(fetcher.get(f"https://pypi.org/pypi/{package}/json", allowed_hosts=("pypi.org",), max_bytes=16 << 20)[2])["info"]["version"]
            built = context_for(ecosystem, package, version, version_diff.fetch_members(fetcher, ecosystem, package, version))
        except Exception:
            return None
        return {"label": 0, "ecosystem": ecosystem, "category": "popular", "package": package, **built}

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [row for row in pool.map(one, clean_targets(count_npm, count_pypi)) if row]


def score(rows: List[Dict[str, Any]], model: str, workers: int) -> None:
    session = requests.Session()

    def one(row: Dict[str, Any]) -> None:
        for attempt in range(4):
            try:
                row.update(clef_triage.classify(row["context"], model=model, session=session))
                return
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else 0
                if status not in {429, 500, 502, 503, 504} or attempt == 3:
                    row["error"] = f"HTTP {status}"
                    return
            except Exception as exc:
                if attempt == 3:
                    row["error"] = type(exc).__name__
                    return
            time.sleep(5 * (attempt + 1))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, rows))


def auc(rows: List[Dict[str, Any]]) -> float:
    positives = [row["probability"] for row in rows if row["label"] == 1]
    negatives = [row["probability"] for row in rows if row["label"] == 0]
    if not positives or not negatives:
        return float("nan")
    wins = sum((p > n) + 0.5 * (p == n) for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def report(rows: List[Dict[str, Any]], model: str) -> str:
    done = [row for row in rows if "probability" in row]
    tokens = sum(row.get("input_tokens", 0) for row in done)
    lines = [f"## Clef calibration ({model})", "",
             f"{len(done)} of {len(rows)} packages scored ({sum(r['label'] for r in done)} known malware, {sum(1 - r['label'] for r in done)} popular clean); "
             f"{tokens:,} input tokens, about ${tokens * PRICE_PER_MILLION / 1e6:.2f}.", ""]
    for title, subset in (("All packages", done), ("Flagged by our rules (production-like)", [r for r in done if r["level"] != "none"])):
        mal = [r for r in subset if r["label"] == 1]
        clean = [r for r in subset if r["label"] == 0]
        lines += [f"### {title}: ROC AUC {auc(subset):.3f} ({len(mal)} malware, {len(clean)} clean)", "",
                  "| Threshold (probability >=) | Malware caught | Clean flagged |", "| --- | --- | --- |"]
        for threshold in (10, 20, 30, 50, 70, 90):
            caught = sum(r["probability"] >= threshold for r in mal)
            flagged = sum(r["probability"] >= threshold for r in clean)
            lines.append(f"| {threshold}% | {caught}/{len(mal)} ({100 * caught / max(1, len(mal)):.0f}%) | {flagged}/{len(clean)} ({100 * flagged / max(1, len(clean)):.1f}%) |")
        lines.append("")
    mal = sorted([r for r in done if r["label"] == 1], key=lambda r: r["probability"])
    lines += ["Lowest-scored malware:", ""] + [f"- {r['probability']}% {r['ecosystem']}:{r['package']} ({r['category']}, rules: {r['level']})" for r in mal[:8]]
    clean = sorted([r for r in done if r["label"] == 0], key=lambda r: -r["probability"])
    lines += ["", "Highest-scored clean packages:", ""] + [f"- {r['probability']}% {r['ecosystem']}:{r['package']} (rules: {r['level']})" for r in clean[:8]]
    errors = [r.get("error") for r in rows if "error" in r]
    if errors:
        lines += ["", f"Errors: {len(errors)} ({', '.join(sorted(set(errors)))})"]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--npm-samples", type=int, default=2000)
    parser.add_argument("--pypi-samples", type=int, default=1000)
    parser.add_argument("--clean-npm", type=int, default=1000)
    parser.add_argument("--clean-pypi", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20261010)
    parser.add_argument("--model", default="clef", choices=["clef", "clef-flash"])
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", type=Path, default=Path("clef-calibration.json"))
    args = parser.parse_args()
    if not yara_engine.load().get("available"):
        raise SystemExit("YARA rules unavailable")
    rows = malicious_rows(args.dataset, args.npm_samples, args.pypi_samples, args.seed)
    print(f"{len(rows)} malware contexts built", flush=True)
    rows += clean_rows(args.clean_npm, args.clean_pypi)
    print(f"{len(rows)} contexts total; scoring with {args.model}", flush=True)
    score(rows, args.model, args.workers)
    for row in rows:
        row.pop("context", None)
    args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    text = report(rows, args.model)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
