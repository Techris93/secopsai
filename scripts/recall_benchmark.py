#!/usr/bin/env python3
"""Measure the rule funnel's recall on known malware and its false-positive rate.

Malicious set: Datadog Security Labs' malicious-software-packages-dataset
(Apache-2.0, every sample triaged by a human), sampled at a pinned commit.
Samples are password-protected zips; they are decrypted and scanned in memory
only, never extracted to disk or executed.  Run this on a disposable runner
only (the "Recall Benchmark" workflow), never on a workstation.

Clean set: the latest release of the most-downloaded npm and PyPI packages.

The funnel is what this measures: the same YARA rule set and hit threshold
the research worker uses to decide which releases get full analysis.
Results keep rule ids and file paths, never sample content.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from secopsai import package_features, yara_engine  # noqa: E402
from secopsai.artifact_fleet import MAX_FILE_BYTES, _safe_archive_files  # noqa: E402
from secopsai.research_funnel import MAX_ARCHIVE_BYTES, NPM_ARTIFACT_HOSTS  # noqa: E402
from secopsai.research_intake import SafeFetcher  # noqa: E402

PASSWORD = b"infected"
NESTED = (".tgz", ".tar.gz", ".whl", ".zip", ".tar", ".egg")
MAX_MEMBERS = 5000
MAX_SAMPLE_BYTES = 100 * 1024 * 1024
LEVEL_RANK = {"none": 0, "notice": 1, "warning": 2, "alert": 3}


# ---------------------------------------------------------------- malicious set
def sample_paths(dataset: Path, quotas: Dict[str, int], seed: int) -> List[str]:
    """Stratified random sample of sample zips, per ecosystem and category."""
    listing = subprocess.run(
        ["git", "-C", str(dataset), "ls-tree", "-r", "--name-only", "HEAD", *[f"samples/{eco}" for eco in quotas]],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    strata: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for path in listing:
        parts = path.split("/")
        if path.endswith(".zip") and len(parts) >= 4:
            strata[(parts[1], parts[2])].append(path)
    rng = random.Random(seed)
    chosen: List[str] = []
    for eco, quota in quotas.items():
        groups = {category: paths for (e, category), paths in strata.items() if e == eco}
        total = sum(len(paths) for paths in groups.values()) or 1
        for category, paths in sorted(groups.items()):
            # Proportional, but keep at least 150 of a small stratum
            # (compromised releases are rare and matter most).
            take = min(len(paths), max(round(quota * len(paths) / total), min(150, len(paths))))
            chosen.extend(rng.sample(sorted(paths), take))
    return chosen


def checkout(dataset: Path, paths: List[str]) -> None:
    """Fetch only the chosen blobs (the clone is blobless and sparse)."""
    subprocess.run(["git", "-C", str(dataset), "sparse-checkout", "set", "--no-cone", "--stdin"],
                   input="\n".join(paths), check=True, text=True)
    subprocess.run(["git", "-C", str(dataset), "checkout", "-q"], check=True)


def sample_members(raw: bytes) -> List[Tuple[str, bytes]]:
    """Decrypt a sample zip in memory; expand nested package archives one level."""
    members: List[Tuple[str, bytes]] = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()][:MAX_MEMBERS]
        for info in infos:
            total += info.file_size
            if total > MAX_SAMPLE_BYTES:
                break
            data = archive.read(info, pwd=PASSWORD)
            name = info.filename.replace("\\", "/")
            if name.lower().endswith(NESTED) and len(data) <= MAX_ARCHIVE_BYTES:
                nested: List[Tuple[str, bytes]] = []
                with tempfile.TemporaryDirectory(prefix="bench-") as tmp:
                    path = Path(tmp) / ("inner" + ("".join(Path(name).suffixes[-2:]) or ".bin"))
                    path.write_bytes(data)
                    try:
                        _safe_archive_files(path, nested)
                    except Exception:
                        nested = []
                if nested:
                    members.extend((f"{name}!/{inner}", body) for inner, body in nested)
                    continue
            members.append((name, data[:MAX_FILE_BYTES]))
    return members


def scan_sample(dataset: Path, path: str) -> Dict[str, Any]:
    parts = path.split("/")
    discovered = re.match(r"(\d{4}-\d{2}-\d{2})-", parts[-1])
    row: Dict[str, Any] = {"set": "malicious", "ecosystem": parts[1], "category": parts[2], "package": "/".join(parts[3:-2]) or parts[3],
                           "version": parts[-2], "discovered": discovered.group(1) if discovered else ""}
    try:
        members = sample_members((dataset / path).read_bytes())
    except Exception as exc:
        return {**row, "status": "error", "reason": str(exc)[:200]}
    return {**row, **_scan_members(members, row["version"])}


def _scan_members(members: List[Tuple[str, bytes]], version: str = "") -> Dict[str, Any]:
    """Funnel verdict plus behaviour flags (never content) for one package."""
    summary = _summarize(yara_engine.scan_files(members))
    return {**summary, "files": len(members), "features": package_features.profile(members, version=version)}


# ------------------------------------------------------------------- clean set
def clean_targets(npm_count: int, pypi_count: int) -> List[Dict[str, Any]]:
    from build_watchlists import npm_watchlist, pypi_watchlist

    targets = [{"ecosystem": "npm", "package": name} for name in npm_watchlist()[:npm_count]]
    return targets + [{"ecosystem": "pypi", "package": name} for name in pypi_watchlist()[:pypi_count]]


def scan_clean(target: Dict[str, Any], fetcher: SafeFetcher) -> Dict[str, Any]:
    row: Dict[str, Any] = {"set": "clean", "ecosystem": target["ecosystem"], "category": "popular", "package": target["package"]}
    try:
        if target["ecosystem"] == "npm":
            _u, _h, body = fetcher.get(f"https://registry.npmjs.org/{target['package'].replace('/', '%2F')}/latest", allowed_hosts=("registry.npmjs.org",), max_bytes=4 * 1024 * 1024)
            doc = json.loads(body)
            row["version"] = doc.get("version")
            tarball = str((doc.get("dist") or {}).get("tarball") or "")
            if not tarball.startswith("https://registry.npmjs.org/"):
                return {**row, "status": "error", "reason": "no registry tarball"}
            _u, _h, raw = fetcher.get(tarball, allowed_hosts=NPM_ARTIFACT_HOSTS, max_bytes=MAX_ARCHIVE_BYTES)
            members = []
            with tempfile.TemporaryDirectory(prefix="bench-") as tmp:
                path = Path(tmp) / "artifact.tgz"
                path.write_bytes(raw)
                _safe_archive_files(path, members)
            return {**row, **_scan_members(members, str(row["version"] or ""))}
        _u, _h, body = fetcher.get(f"https://pypi.org/pypi/{target['package']}/json", allowed_hosts=("pypi.org",), max_bytes=16 * 1024 * 1024)
        doc = json.loads(body)
        row["version"] = (doc.get("info") or {}).get("version")
        files = [item for item in doc.get("urls") or [] if int(item.get("size") or 0) <= MAX_ARCHIVE_BYTES]
        rank = {"sdist": 0, "bdist_wheel": 1}  # sdists carry setup.py, where most PyPI malware lives
        files.sort(key=lambda item: rank.get(item.get("packagetype"), 2))
        if not files:
            return {**row, "status": "error", "reason": "no artifact under the size cap"}
        _u, _h, raw = fetcher.get(files[0]["url"], allowed_hosts=("files.pythonhosted.org",), max_bytes=MAX_ARCHIVE_BYTES)
        members: List[Tuple[str, bytes]] = []
        with tempfile.TemporaryDirectory(prefix="bench-") as tmp:
            path = Path(tmp) / files[0]["filename"]
            path.write_bytes(raw)
            _safe_archive_files(path, members)
        return {**row, **_scan_members(members, str(row["version"] or ""))}
    except Exception as exc:
        return {**row, "status": "error", "reason": str(exc)[:200]}


# --------------------------------------------------------------------- report
def _rule_files(findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    by_rule: Dict[str, List[str]] = defaultdict(list)
    for item in findings:
        if item.get("rule_id") != "YARA-SCAN-ERROR" and len(by_rule[item["rule_id"]]) < 3:
            by_rule[item["rule_id"]].append(str(item.get("file_path"))[:200])
    return dict(by_rule)


def _summarize(result: Dict[str, Any]) -> Dict[str, Any]:
    findings = [item for item in result.get("findings") or [] if item.get("rule_id") != "YARA-SCAN-ERROR"]
    return {"status": "scanned", "level": result.get("level") or "none", "score": int(result.get("score") or 0),
            "rules": result.get("rules_matched") or [], "rule_files": _rule_files(findings)}


def _rate(rows: List[Dict[str, Any]], level: str) -> str:
    scanned = [row for row in rows if row.get("status") == "scanned"]
    if not scanned:
        return "-"
    hit = sum(1 for row in scanned if LEVEL_RANK.get(row.get("level"), 0) >= LEVEL_RANK[level])
    return f"{hit}/{len(scanned)} ({100 * hit / len(scanned):.1f}%)"


def _share(rows: List[Dict[str, Any]], flag: str) -> float:
    return 100 * sum(1 for row in rows if flag in (row.get("features") or [])) / len(rows) if rows else 0.0


def _miss_profile(malicious: List[Dict[str, Any]], clean: List[Dict[str, Any]]) -> List[str]:
    """Which behaviours missed malware shows, against clean packages of the same ecosystem."""
    lines: List[str] = []
    for eco in ("npm", "pypi"):
        misses = [row for row in malicious if row["ecosystem"] == eco and row.get("status") == "scanned" and LEVEL_RANK.get(row.get("level"), 0) == 0]
        baseline = [row for row in clean if row["ecosystem"] == eco and row.get("status") == "scanned"]
        if not misses:
            continue
        flags = sorted({flag for row in misses for flag in row.get("features") or []})
        ranked = sorted(flags, key=lambda flag: _share(misses, flag) - _share(baseline, flag), reverse=True)
        lines += ["", f"### Miss profile: {eco} ({len(misses)} missed samples vs {len(baseline)} clean)", "",
                  "Share of packages showing each behaviour. High in misses and low in clean packages is where a rule pays off.", "",
                  "| Behaviour | Missed malware | Clean | Lift |", "| --- | --- | --- | --- |"]
        for flag in ranked[:20]:
            miss_share, clean_share = _share(misses, flag), _share(baseline, flag)
            lift = f"{miss_share / clean_share:.1f}×" if clean_share else "only in malware"
            lines.append(f"| {flag} | {miss_share:.1f}% | {clean_share:.1f}% | {lift} |")
        pairs: Counter = Counter()
        for row in misses:
            features = [flag for flag in row.get("features") or [] if _share(baseline, flag) < 10]
            pairs.update(f"{a} + {b}" for i, a in enumerate(features) for b in features[i + 1:])
        if pairs:
            lines += ["", f"Most common combinations among {eco} misses (behaviours seen in under 10% of clean packages):", "",
                      "| Combination | Missed samples | Clean packages |", "| --- | --- | --- |"]
            for combo, count in pairs.most_common(12):
                a, b = combo.split(" + ")
                in_clean = sum(1 for row in baseline if a in (row.get("features") or []) and b in (row.get("features") or []))
                lines.append(f"| {combo} | {count} ({100 * count / len(misses):.0f}%) | {in_clean} |")
    return lines


def _recall_by_year(malicious: List[Dict[str, Any]]) -> List[str]:
    years: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in malicious:
        years[str(row.get("discovered") or "")[:4] or "unknown"].append(row)
    lines = ["", "### Recall by discovery year", "", "Rules written after a sample was found can flatter older years; the latest year is the honest one.", "",
             "| Year | Samples | Hit (≥40) |", "| --- | --- | --- |"]
    for year, group in sorted(years.items()):
        lines.append(f"| {year} | {len(group)} | {_rate(group, 'notice')} |")
    return lines


def report(rows: List[Dict[str, Any]], meta: Dict[str, Any]) -> str:
    malicious = [row for row in rows if row["set"] == "malicious"]
    clean = [row for row in rows if row["set"] == "clean"]
    lines = ["## Rule funnel benchmark", "",
             f"Dataset `DataDog/malicious-software-packages-dataset@{meta['dataset_commit'][:12]}`, seed {meta['seed']}, rule packs: {meta['rule_files']} files. "
             f"Funnel hit = level notice or higher (score ≥ 40), as in the research worker.", "",
             "### Recall on known malware", "", "| Ecosystem | Category | Errors | Hit (≥40) | Warning (≥60) | Alert (≥80) |", "| --- | --- | --- | --- | --- | --- |"]
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in malicious:
        groups[(row["ecosystem"], row["category"])].append(row)
    for (eco, category), group in sorted(groups.items()):
        errors = sum(1 for row in group if row.get("status") == "error")
        lines.append(f"| {eco} | {category} | {errors} | {_rate(group, 'notice')} | {_rate(group, 'warning')} | {_rate(group, 'alert')} |")
    lines.append(f"| **all** | | {sum(1 for r in malicious if r.get('status') == 'error')} | **{_rate(malicious, 'notice')}** | {_rate(malicious, 'warning')} | {_rate(malicious, 'alert')} |")
    lines += ["", "### False positives on popular packages", "", "| Ecosystem | Errors | Hit (≥40) | Warning (≥60) | Alert (≥80) |", "| --- | --- | --- | --- | --- |"]
    for eco in ("npm", "pypi"):
        group = [row for row in clean if row["ecosystem"] == eco]
        lines.append(f"| {eco} | {sum(1 for r in group if r.get('status') == 'error')} | {_rate(group, 'notice')} | {_rate(group, 'warning')} | {_rate(group, 'alert')} |")
    rule_mal: Counter = Counter(rule for row in malicious if LEVEL_RANK.get(row.get("level"), 0) >= 1 for rule in row.get("rules") or [])
    rule_fp: Counter = Counter(rule for row in clean if LEVEL_RANK.get(row.get("level"), 0) >= 1 for rule in row.get("rules") or [])
    lines += ["", "### Rules (hit-level samples they contributed to)", "", "| Rule | Malicious | Clean (FP) |", "| --- | --- | --- |"]
    for rule in sorted(set(rule_mal) | set(rule_fp), key=lambda name: (-rule_mal[name], rule_fp[name]))[:40]:
        lines.append(f"| {rule} | {rule_mal[rule]} | {rule_fp[rule]} |")
    fps = [row for row in clean if LEVEL_RANK.get(row.get("level"), 0) >= 1]
    if fps:
        lines += ["", "### False-positive packages", ""] + [f"- {row['ecosystem']}:{row['package']}@{row.get('version')} — {', '.join(row.get('rules') or [])} (score {row.get('score')})" for row in fps[:40]]
    lines += _miss_profile(malicious, clean) + _recall_by_year(malicious)
    lines += ["", f"Elapsed {meta['elapsed_seconds']} s. Full rows in the `recall-benchmark` artifact."]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--dataset", required=True, type=Path, help="blobless, sparse clone of the dataset at the pinned commit")
    parser.add_argument("--npm-samples", type=int, default=2000)
    parser.add_argument("--pypi-samples", type=int, default=1000)
    parser.add_argument("--clean-npm", type=int, default=1000)
    parser.add_argument("--clean-pypi", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20261010)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", type=Path, default=Path("recall-benchmark.json"))
    args = parser.parse_args()

    started = time.time()
    state = yara_engine.load()
    if not state.get("available"):
        raise SystemExit(f"YARA rules unavailable: {state.get('reason')}")
    commit = subprocess.run(["git", "-C", str(args.dataset), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    paths = sample_paths(args.dataset, {"npm": args.npm_samples, "pypi": args.pypi_samples}, args.seed)
    print(f"sampled {len(paths)} malicious samples; fetching blobs", flush=True)
    checkout(args.dataset, paths)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(lambda path: scan_sample(args.dataset, path), paths))
    print(f"malicious set scanned in {round(time.time() - started)} s", flush=True)
    fetcher = SafeFetcher(timeout=60)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows += list(pool.map(lambda target: scan_clean(target, fetcher), clean_targets(args.clean_npm, args.clean_pypi)))
    meta = {"dataset_commit": commit, "seed": args.seed, "rule_files": state.get("files"),
            "elapsed_seconds": round(time.time() - started), "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    args.out.write_text(json.dumps({"meta": meta, "rows": rows}, indent=1, sort_keys=True), encoding="utf-8")
    text = report(rows, meta)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
