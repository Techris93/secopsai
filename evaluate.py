"""
SecOps Autoresearch — Evaluation Harness
Runs detection against labeled data and computes accuracy metrics.

DO NOT MODIFY THIS FILE. The agent only modifies detect.py.

Usage:
    python evaluate.py             # Run evaluation, print metrics
    python evaluate.py --commit    # Auto-commit if score improved
    python evaluate.py --verbose   # Show per-rule breakdown
    python evaluate.py --baseline  # Show baseline score from best.json
"""

import json
import os
import sys
import subprocess
import argparse
from datetime import datetime
from typing import Dict, Any, List, Tuple

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detect import run_detection


# ═══ Constants ═══════════════════════════════════════════════════════════════

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
UNLABELED_FILE = os.path.join(DATA_DIR, "events_unlabeled.json")
BEST_SCORE_FILE = os.path.join(DATA_DIR, "best.json")
EXPERIMENT_LOG = os.path.join(DATA_DIR, "experiments.log")

# Experiment time budget (informational — the overhead is in the agent's loop)
EXPERIMENT_BUDGET_SECONDS = 300


# ═══ Metrics ═════════════════════════════════════════════════════════════════

def compute_metrics(
    detected_ids: List[str],
    events: List[Dict],
) -> Dict[str, Any]:
    """
    Compute precision, recall, F1-score, and false positive rate.

    - True Positive (TP): event is malicious AND was detected
    - False Positive (FP): event is benign BUT was detected
    - True Negative (TN): event is benign AND was NOT detected
    - False Negative (FN): event is malicious BUT was NOT detected
    """
    detected_set = set(detected_ids)

    tp = fp = tn = fn = 0

    for event in events:
        is_malicious = event.get("label") == "malicious"
        is_detected = event["event_id"] in detected_set

        if is_malicious and is_detected:
            tp += 1
        elif not is_malicious and is_detected:
            fp += 1
        elif not is_malicious and not is_detected:
            tn += 1
        elif is_malicious and not is_detected:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    return {
        "f1_score": round(f1, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_positive_rate": round(fpr, 6),
        "accuracy": round(accuracy, 6),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "total_events": len(events),
        "total_detected": len(detected_ids),
    }


def compute_per_rule_metrics(
    rule_results: Dict[str, List[str]],
    events: List[Dict],
) -> Dict[str, Dict[str, Any]]:
    """Compute metrics per detection rule."""
    per_rule = {}
    for rule_id, detected_ids in rule_results.items():
        per_rule[rule_id] = compute_metrics(detected_ids, events)
    return per_rule


# ═══ Reporting ═══════════════════════════════════════════════════════════════

def print_results(metrics: Dict[str, Any], rule_results: Dict = None,
                  events: List[Dict] = None, verbose: bool = False):
    """Print evaluation results in a clear format."""

    print(f"\n{'═' * 60}")
    print(f"  SecOps Autoresearch — Experiment Results")
    print(f"  {datetime.now(tz=None).isoformat()}Z")
    print(f"{'═' * 60}")
    print()
    print(f"  F1 Score:            {metrics['f1_score']:.6f}")
    print(f"  Precision:           {metrics['precision']:.6f}")
    print(f"  Recall:              {metrics['recall']:.6f}")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.6f}")
    print(f"  Accuracy:            {metrics['accuracy']:.6f}")
    print()
    print(f"  TP: {metrics['true_positives']:5d}  |  FP: {metrics['false_positives']:5d}")
    print(f"  FN: {metrics['false_negatives']:5d}  |  TN: {metrics['true_negatives']:5d}")
    print(f"  Total events: {metrics['total_events']}  |  Detected: {metrics['total_detected']}")
    print()

    if verbose and rule_results and events:
        print(f"  {'─' * 56}")
        print(f"  Per-Rule Breakdown:")
        print(f"  {'─' * 56}")

        per_rule = compute_per_rule_metrics(rule_results, events)
        for rule_id, rm in sorted(per_rule.items()):
            print(f"\n  {rule_id}:")
            print(f"    F1={rm['f1_score']:.4f}  P={rm['precision']:.4f}  "
                  f"R={rm['recall']:.4f}  FPR={rm['false_positive_rate']:.4f}")
            print(f"    TP={rm['true_positives']}  FP={rm['false_positives']}  "
                  f"FN={rm['false_negatives']}  TN={rm['true_negatives']}")

        # Show missed attack types
        detected_set = set()
        for ids in rule_results.values():
            detected_set.update(ids)

        missed = [e for e in events
                  if e.get("label") == "malicious" and e["event_id"] not in detected_set]
        if missed:
            missed_types = {}
            for e in missed:
                at = e.get("attack_type", "unknown")
                missed_types[at] = missed_types.get(at, 0) + 1
            print(f"\n  {'─' * 56}")
            print(f"  Missed attack events by type:")
            for at, count in sorted(missed_types.items(), key=lambda x: -x[1]):
                print(f"    {at:30s} {count:5d} missed")

    print(f"\n{'═' * 60}")

    # Print the primary metric in a parseable format for the agent
    print(f"\n>>> F1_SCORE={metrics['f1_score']:.6f} <<<\n")


# ═══ Git Integration ═════════════════════════════════════════════════════════

def get_best_score() -> float:
    """Get the best F1 score recorded so far."""
    if os.path.exists(BEST_SCORE_FILE):
        with open(BEST_SCORE_FILE, "r") as f:
            data = json.load(f)
            return data.get("f1_score", 0.0)
    return 0.0


def save_best_score(metrics: Dict[str, Any]):
    """Save new best score."""
    metrics["timestamp"] = datetime.now(tz=None).isoformat() + "Z"
    with open(BEST_SCORE_FILE, "w") as f:
        json.dump(metrics, f, indent=2)


def log_experiment(metrics: Dict[str, Any], committed: bool):
    """Append to experiment log."""
    entry = {
        "timestamp": datetime.now(tz=None).isoformat() + "Z",
        "f1_score": metrics["f1_score"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "fpr": metrics["false_positive_rate"],
        "committed": committed,
    }
    with open(EXPERIMENT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def git_commit_improvement(metrics: Dict[str, Any], previous_best: float):
    """Commit detect.py to git if F1 improved."""
    improvement = metrics["f1_score"] - previous_best

    try:
        # Ensure we're on a feature branch
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__))
        ).stdout.strip()

        if branch in ("main", "master"):
            # Create experiment branch
            branch_name = f"experiment/{datetime.now(tz=None).strftime('%Y%m%d-%H%M%S')}"
            subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            print(f"  Created branch: {branch_name}")

        # Stage and commit detect.py
        subprocess.run(
            ["git", "add", "detect.py"],
            cwd=os.path.dirname(os.path.abspath(__file__))
        )

        commit_msg = (
            f"feat(detect): F1={metrics['f1_score']:.4f} "
            f"(+{improvement:.4f}) "
            f"P={metrics['precision']:.4f} R={metrics['recall']:.4f} "
            f"FPR={metrics['false_positive_rate']:.4f}"
        )

        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=os.path.dirname(os.path.abspath(__file__))
        )

        print(f"\n  ✅ Committed: {commit_msg}")
        return True

    except Exception as e:
        print(f"\n  ⚠️  Git commit failed: {e}")
        return False


# ═══ Main ═════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="SecOps Autoresearch — Evaluation")
    parser.add_argument("--commit", action="store_true",
                        help="Auto-commit detect.py if F1 improved")
    parser.add_argument("--verbose", action="store_true",
                        help="Show per-rule breakdown")
    parser.add_argument("--baseline", action="store_true",
                        help="Show best recorded score")
    args = parser.parse_args()

    # Show baseline if requested
    if args.baseline:
        best = get_best_score()
        print(f"Best recorded F1 score: {best:.6f}")
        return

    # Load data
    if not os.path.exists(EVENTS_FILE):
        print("❌ No data found. Run `python prepare.py` first.")
        sys.exit(1)

    with open(EVENTS_FILE, "r") as f:
        labeled_events = json.load(f)

    if not os.path.exists(UNLABELED_FILE):
        print("❌ No unlabeled data. Run `python prepare.py` first.")
        sys.exit(1)

    with open(UNLABELED_FILE, "r") as f:
        unlabeled_events = json.load(f)

    # Run detection on unlabeled events
    print("Running detection...")
    results = run_detection(unlabeled_events)

    # Compute metrics against ground truth
    metrics = compute_metrics(results["detected_event_ids"], labeled_events)

    # Print results
    print_results(
        metrics,
        rule_results=results.get("rule_results"),
        events=labeled_events,
        verbose=args.verbose,
    )

    # Handle git integration
    previous_best = get_best_score()
    improved = metrics["f1_score"] > previous_best
    committed = False

    if args.commit:
        if improved:
            print(f"  📈 New best! {previous_best:.6f} → {metrics['f1_score']:.6f}")
            save_best_score(metrics)
            committed = git_commit_improvement(metrics, previous_best)
        else:
            print(f"  📉 No improvement. Current: {metrics['f1_score']:.6f}, "
                  f"Best: {previous_best:.6f}")
            print(f"  Discarding changes. Try a different approach.")

    elif improved or previous_best == 0.0:
        save_best_score(metrics)
        if previous_best > 0:
            print(f"  📈 New best! {previous_best:.6f} → {metrics['f1_score']:.6f}")
        else:
            print(f"  📊 Baseline recorded: {metrics['f1_score']:.6f}")

    # Log experiment
    log_experiment(metrics, committed)


if __name__ == "__main__":
    main()
