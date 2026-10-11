#!/usr/bin/env python3
"""Calibrate the triage model's malicious_probability on known malware.

Draws a seeded sample from the malware dataset (as in the Recall Benchmark),
keeps the samples our rules flag (the model only ever sees flagged
packages), builds the same triage context production uses, and queues the
jobs to Core for the operator's model bridge.  It then waits for the
verdicts and reports how the probabilities fall: if known malware often
scores in the band that is auto-closed (<= 10) or deprioritised (<= 30),
those thresholds are unsafe.

Job ids carry an opaque suffix, not the word malware, so the model is not
told the answer.  Samples are decrypted and scanned in memory on a
disposable runner and never executed; only code excerpts reach the model,
as in production.  Run it from the "Model Calibration" workflow.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from recall_benchmark import checkout, sample_members, sample_paths  # noqa: E402
from secopsai import package_features, research_ai_triage, yara_engine  # noqa: E402
from secopsai.core_edge_client import CoreEdgeClient  # noqa: E402

LEVELS = {"notice", "warning", "alert"}


def flagged_contexts(dataset: Path, paths: List[str], run_tag: str) -> List[Dict[str, Any]]:
    def one(index_path):
        index, path = index_path
        parts = path.split("/")
        ecosystem, package, version = parts[1], "/".join(parts[3:-2]) or parts[3], parts[-2]
        try:
            members = sample_members((dataset / path).read_bytes())
        except Exception:
            return None
        flags = package_features.profile(members, version=version)
        scan = package_features.combine(yara_engine.scan_files(members), flags, ecosystem, members)
        if scan.get("level") not in LEVELS:
            return None
        prescan = {**scan, "install_files": package_features.install_time_files(members)}
        context = research_ai_triage.fit_context(research_ai_triage.build_context(ecosystem=ecosystem, package=package, version=version, prescan=prescan))
        artifact_id = f"{ecosystem}:{package}@{version}#c{run_tag}{index}"
        context["artifact_id"] = artifact_id
        return {"artifact_id": artifact_id, "category": parts[2], "score": scan.get("score"), "context": context}

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [item for item in pool.map(one, enumerate(paths)) if item]


def report(rows: List[Dict[str, Any]]) -> str:
    done = [row for row in rows if isinstance(row.get("probability"), int) and row["probability"] >= 0]
    bands = Counter("<=10 (auto-close)" if p <= 10 else "11-30 (deprioritised)" if p <= 30 else "31-69 (open)" if p < 70 else ">=70 (suspicious)"
                    for p in (row["probability"] for row in done))
    lines = ["## Model calibration on known malware", "",
             f"{len(done)} of {len(rows)} flagged malware samples triaged by the operator's model bridge.", "",
             "| Probability band | Malware samples | Share |", "| --- | --- | --- |"]
    for band in ("<=10 (auto-close)", "11-30 (deprioritised)", "31-69 (open)", ">=70 (suspicious)"):
        lines.append(f"| {band} | {bands.get(band, 0)} | {100 * bands.get(band, 0) / max(1, len(done)):.0f}% |")
    verdicts = Counter(str(row.get("verdict")) for row in done)
    lines += ["", "Verdicts: " + ", ".join(f"{name} {count}" for name, count in verdicts.most_common()), "",
              "Lowest-rated malware (what the thresholds would hide):", ""]
    for row in sorted(done, key=lambda item: item["probability"])[:10]:
        lines.append(f"- {row['probability']}% {row['artifact_id'].split('#')[0]} ({row['category']}, rule score {row['score']}): {row.get('summary', '')[:160]}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=40, help="flagged malware samples to send to the model")
    parser.add_argument("--seed", type=int, default=20261012)
    parser.add_argument("--wait-minutes", type=int, default=75)
    parser.add_argument("--out", type=Path, default=Path("model-calibration.json"))
    args = parser.parse_args()
    if not yara_engine.load().get("available"):
        raise SystemExit("YARA rules unavailable")
    run_tag = os.environ.get("GITHUB_RUN_ID", str(int(time.time())))[-6:]
    # Oversample: not every sample is flagged by the rules.
    paths = sample_paths(args.dataset, {"npm": args.samples * 2, "pypi": args.samples}, args.seed)
    checkout(args.dataset, paths)
    rows = flagged_contexts(args.dataset, paths, run_tag)[: args.samples]
    client = CoreEdgeClient.from_environment() if hasattr(CoreEdgeClient, "from_environment") else CoreEdgeClient()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
    for start in range(0, len(rows), 25):
        batch = rows[start:start + 25]
        client.queue_triage_jobs([{"artifact_id": row["artifact_id"], "idempotency_key": f"calibration:{row['artifact_id']}",
                                   "inputs": {"artifact_triage": row["context"]}} for row in batch])
    print(f"queued {len(rows)} flagged malware samples for model triage", flush=True)
    wanted = {row["artifact_id"]: row for row in rows}
    deadline = time.time() + args.wait_minutes * 60
    while time.time() < deadline and any("probability" not in row for row in rows):
        time.sleep(60)
        for item in (client.triage_results(since=started, limit=200).get("results") or []):
            row = wanted.get(item.get("artifact_id"))
            if row is not None and item.get("status") == "succeeded":
                result = item.get("result") or {}
                probability = result.get("malicious_probability")
                row.update(probability=int(probability) if isinstance(probability, (int, float)) else -1,
                           verdict=result.get("finding_verdict"), summary=str(result.get("summary") or ""))
        print(f"{sum('probability' in row for row in rows)}/{len(rows)} verdicts back", flush=True)
    for row in rows:
        row.pop("context", None)
    args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    text = report(rows)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
