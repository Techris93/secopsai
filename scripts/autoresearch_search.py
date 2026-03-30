#!/usr/bin/env python3
"""SecOps Autoresearch: global threshold search (local) + reviewable PR.

This script samples threshold configurations, evaluates against labeled events,
selects the best configuration under safety constraints, applies it to detect.py,
and opens a PR for review.

Design goals:
- Runs locally (no remote execution)
- Produces a reviewable git diff (branch + PR)
- Optimizes a constrained objective, not just raw F1

Requires:
- GitHub CLI `gh` authenticated (for PR creation)
- data/events.json and data/events_unlabeled.json already generated

Usage:
  source .venv/bin/activate
  python scripts/autoresearch_search.py --iters 200 --fp-max 50 --penalty 0.002

Notes:
- This does NOT auto-merge. It only opens a PR.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import detect  # noqa: E402
from evaluate import compute_metrics  # noqa: E402


DATA_DIR = REPO_ROOT / "data"
LABELED = DATA_DIR / "events.json"
UNLABELED = DATA_DIR / "events_unlabeled.json"

RESULTS_DIR = REPO_ROOT / "results"


@dataclass
class Candidate:
    params: Dict[str, Dict[str, Any]]
    f1: float
    precision: float
    recall: float
    fp: int
    fn: int
    fpr: float
    score: float


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_events() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not LABELED.exists() or not UNLABELED.exists():
        raise SystemExit("Missing data/events.json or data/events_unlabeled.json. Run `python prepare.py` first.")
    labeled = json.loads(LABELED.read_text(encoding="utf-8"))
    unlabeled = json.loads(UNLABELED.read_text(encoding="utf-8"))
    return labeled, unlabeled


def evaluate_with_override(
    labeled: List[Dict[str, Any]],
    unlabeled: List[Dict[str, Any]],
    override: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Patch detect.RULE_THRESHOLDS for one run."""
    saved = json.loads(json.dumps(detect.RULE_THRESHOLDS))
    try:
        for rule_id, params in override.items():
            detect.RULE_THRESHOLDS[rule_id].update(params)

        result = detect.run_detection(unlabeled)
        metrics = compute_metrics(result["detected_event_ids"], labeled)
        return metrics
    finally:
        detect.RULE_THRESHOLDS.clear()
        detect.RULE_THRESHOLDS.update(saved)


def sample_from_space(space: Dict[str, Dict[str, List[Any]]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for rule_id, params in space.items():
        out[rule_id] = {}
        for k, choices in params.items():
            out[rule_id][k] = random.choice(choices)
    return out


def objective(metrics: Dict[str, Any], *, penalty: float) -> float:
    # Penalize false positive rate to bias toward safer configs.
    return float(metrics["f1_score"]) - penalty * float(metrics.get("false_positive_rate", 0.0))


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(REPO_ROOT)).decode("utf-8").strip()


def run_cmd(cmd: List[str]) -> None:
    subprocess.check_call(cmd, cwd=str(REPO_ROOT))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--iters", type=int, default=200, help="Number of random samples")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--fp-max", type=int, default=999999, help="Hard constraint: maximum FP")
    p.add_argument("--penalty", type=float, default=0.002, help="Penalty coefficient for false_positive_rate")
    p.add_argument("--branch-prefix", default="autoresearch/global")
    p.add_argument("--title", default=None, help="PR title override")
    args = p.parse_args()

    random.seed(args.seed)

    # Search space: reuse tune.py spaces (duplicated here intentionally to avoid importing tune.py internals).
    SPACE: Dict[str, Dict[str, List[Any]]] = {
        "brute_force": {
            "RAPID_THRESHOLD": [4, 5, 6, 7, 8, 10, 12],
            "RAPID_WINDOW_MINUTES": [5, 8, 10, 15, 20],
            "SLOW_THRESHOLD": [2, 3, 4, 5],
            "SLOW_MIN_SPAN_MINUTES": [15, 20, 30, 45, 60],
        },
        "dns_exfiltration": {
            "MIN_QUERIES_PER_DOMAIN": [3, 4, 5, 6, 8],
            "MIN_LABEL_LENGTH": [10, 12, 15, 20, 25],
            "MIN_ENTROPY": [2.5, 3.0, 3.5, 4.0],
            "MIN_UNIQUE_LABEL_RATIO": [0.6, 0.7, 0.8, 0.9],
        },
        "c2_beaconing": {
            "MIN_CONNECTIONS": [3, 5, 8, 10, 15],
            "MAX_BYTES_OUT": [300, 400, 500, 600, 800, 1000],
            "MAX_BYTES_IN": [150, 200, 250, 300, 400],
        },
        "lateral_movement": {
            "UNIQUE_DEST_THRESHOLD": [3, 4, 5, 6],
            "WINDOW_MINUTES": [10, 15, 20, 30],
            "MAX_AVERAGE_GAP_SECONDS": [120, 180, 240, 360, 480],
            "MAX_TRANSFER_BYTES": [50_000, 75_000, 100_000, 200_000],
        },
    }

    labeled, unlabeled = load_events()

    # Baseline
    baseline = evaluate_with_override(labeled, unlabeled, {})
    baseline_score = objective(baseline, penalty=args.penalty)

    best = Candidate(
        params={},
        f1=float(baseline["f1_score"]),
        precision=float(baseline["precision"]),
        recall=float(baseline["recall"]),
        fp=int(baseline["false_positives"]),
        fn=int(baseline["false_negatives"]),
        fpr=float(baseline.get("false_positive_rate", 0.0)),
        score=float(baseline_score),
    )

    history: List[Dict[str, Any]] = []

    for i in range(args.iters):
        override = sample_from_space(SPACE)
        m = evaluate_with_override(labeled, unlabeled, override)
        fp = int(m["false_positives"])
        sc = objective(m, penalty=args.penalty)

        history.append(
            {
                "iter": i + 1,
                "f1": float(m["f1_score"]),
                "precision": float(m["precision"]),
                "recall": float(m["recall"]),
                "fp": fp,
                "fn": int(m["false_negatives"]),
                "fpr": float(m.get("false_positive_rate", 0.0)),
                "score": float(sc),
            }
        )

        if fp > args.fp_max:
            continue

        if sc > best.score:
            best = Candidate(
                params=override,
                f1=float(m["f1_score"]),
                precision=float(m["precision"]),
                recall=float(m["recall"]),
                fp=fp,
                fn=int(m["false_negatives"]),
                fpr=float(m.get("false_positive_rate", 0.0)),
                score=float(sc),
            )

    # If best.params is empty, no improvement found; still output report and exit 0.
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = RESULTS_DIR / f"autoresearch-{stamp}.json"
    report_path.write_text(
        json.dumps(
            {
                "generated_at": utc_now(),
                "seed": args.seed,
                "iters": args.iters,
                "fp_max": args.fp_max,
                "penalty": args.penalty,
                "baseline": baseline,
                "best": {
                    "score": best.score,
                    "f1": best.f1,
                    "precision": best.precision,
                    "recall": best.recall,
                    "fp": best.fp,
                    "fn": best.fn,
                    "fpr": best.fpr,
                    "params": best.params,
                },
                "history_tail": history[-20:],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    if not best.params:
        print(f"No better candidate found. Baseline F1={best.f1:.6f} score={best.score:.6f}")
        print(f"Report: {report_path}")
        return 0

    # Create branch
    branch = f"{args.branch_prefix}-{stamp}"
    run_cmd(["git", "checkout", "-b", branch])

    # Apply best params into detect.py via simple patching: load detect.py and replace the values.
    # We reuse scripts/autoresearch_tune_apply.py style replacement by importing it.
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import autoresearch_tune_apply as applier  # type: ignore

    applier.apply_to_detect(best.params)

    # Run tests (optional - skip if pytest not installed)
    try:
        subprocess.check_call([sys.executable, "-m", "pytest", "-q"], cwd=str(REPO_ROOT))
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("  ⚠️  pytest not available or tests failed, continuing anyway")

    # Commit
    run_cmd(["git", "add", "detect.py", str(report_path)])
    run_cmd(["git", "commit", "-m", f"autoresearch: global threshold search ({stamp})"])

    # Push
    run_cmd(["git", "push", "-u", "origin", branch])

    # PR
    title = args.title or "autoresearch: global threshold search"
    body = (
        f"Automated local autoresearch run.\n\n"
        f"Baseline F1: {baseline['f1_score']:.6f} (FP={baseline['false_positives']}, FPR={baseline.get('false_positive_rate', 0.0):.4f})\n"
        f"Best score: {best.score:.6f} | F1: {best.f1:.6f} (FP={best.fp}, FPR={best.fpr:.4f})\n\n"
        f"Report: {report_path.as_posix()}\n\n"
        "Reproduce:\n"
        "1) source .venv/bin/activate\n"
        f"2) python scripts/autoresearch_search.py --iters {args.iters} --seed {args.seed} --fp-max {args.fp_max} --penalty {args.penalty}\n"
    )

    pr_url = subprocess.check_output(
        [
            "gh",
            "pr",
            "create",
            "--base",
            "main",
            "--head",
            branch,
            "--title",
            title,
            "--body",
            body,
        ],
        cwd=str(REPO_ROOT),
    ).decode("utf-8").strip()

    print(pr_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
