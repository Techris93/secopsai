"""
OpenClaw replay evaluation harness.

Runs detection against OpenClaw labeled replay data and optionally inspects an
unlabeled replay bundle. This keeps the OpenClaw lane separate from the default
synthetic benchmark in evaluate.py.

Usage:
    python evaluate_openclaw.py
    python evaluate_openclaw.py --verbose
    python evaluate_openclaw.py --mode live
    python evaluate_openclaw.py --labeled path/to/labeled.json --unlabeled path/to/unlabeled.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detect import run_detection


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT_DIR, "data", "openclaw", "replay")
DEFAULT_LABELED = os.path.join(DATA_DIR, "labeled", "sample_events.json")
DEFAULT_UNLABELED = os.path.join(DATA_DIR, "unlabeled", "sample_events.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate OpenClaw replay data")
    parser.add_argument("--labeled", default=DEFAULT_LABELED, help="Labeled replay JSON file")
    parser.add_argument("--unlabeled", default=DEFAULT_UNLABELED, help="Unlabeled replay JSON file")
    parser.add_argument(
        "--mode",
        default="auto",
        choices=["auto", "benchmark", "live"],
        help="Evaluation mode: benchmark uses labels/F1, live emphasizes detections without score gating",
    )
    parser.add_argument("--verbose", action="store_true", help="Show per-rule breakdown")
    return parser.parse_args()


def load_events(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)

    if not isinstance(loaded, list):
        raise ValueError(f"event file must contain a JSON array: {path}")
    return loaded


def compute_metrics(detected_ids: List[str], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    detected_set = set(detected_ids)

    tp = fp = tn = fn = 0
    for event in events:
        is_malicious = event.get("label") == "malicious"
        is_detected = event.get("event_id") in detected_set

        if is_malicious and is_detected:
            tp += 1
        elif not is_malicious and is_detected:
            fp += 1
        elif not is_malicious and not is_detected:
            tn += 1
        elif is_malicious and not is_detected:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

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


def compute_per_rule_metrics(rule_results: Dict[str, List[str]], events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {rule_id: compute_metrics(detected_ids, events) for rule_id, detected_ids in rule_results.items()}


def attack_type_counts(events: List[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter()
    for event in events:
        counter[str(event.get("attack_type", "none"))] += 1
    return dict(sorted(counter.items()))


def get_effective_mode(requested_mode: str, events: List[Dict[str, Any]]) -> str:
    if requested_mode != "auto":
        return requested_mode
    has_labeled_attacks = any(event.get("label") == "malicious" for event in events)
    return "benchmark" if has_labeled_attacks else "live"


def print_benchmark_results(
    metrics: Dict[str, Any],
    rule_results: Dict[str, List[str]],
    events: List[Dict[str, Any]],
    unlabeled_events: List[Dict[str, Any]],
    verbose: bool,
) -> None:
    print(f"\n{'═' * 60}")
    print("  OpenClaw Replay Evaluation")
    print(f"  {utc_now()}")
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
    print(f"  Labeled events: {metrics['total_events']}  |  Detected: {metrics['total_detected']}")
    print(f"  Unlabeled replay events: {len(unlabeled_events)}")

    print("\n  Attack Type Distribution:")
    for attack_type, count in attack_type_counts(events).items():
        print(f"    {attack_type:28s} {count:5d}")

    if verbose:
        print(f"\n  {'─' * 56}")
        print("  Per-Rule Breakdown:")
        print(f"  {'─' * 56}")
        per_rule = compute_per_rule_metrics(rule_results, events)
        for rule_id, rm in sorted(per_rule.items()):
            if rm["total_detected"] == 0:
                continue
            print(f"\n  {rule_id}:")
            print(
                f"    F1={rm['f1_score']:.4f}  P={rm['precision']:.4f}  "
                f"R={rm['recall']:.4f}  FPR={rm['false_positive_rate']:.4f}"
            )
            print(
                f"    TP={rm['true_positives']}  FP={rm['false_positives']}  "
                f"FN={rm['false_negatives']}  TN={rm['true_negatives']}"
            )

        detected_set = set()
        for ids in rule_results.values():
            detected_set.update(ids)

        missed = [event for event in events if event.get("label") == "malicious" and event.get("event_id") not in detected_set]
        if missed:
            print(f"\n  {'─' * 56}")
            print("  Missed Attack Events:")
            missed_counts = Counter(str(event.get("attack_type", "unknown")) for event in missed)
            for attack_type, count in sorted(missed_counts.items()):
                print(f"    {attack_type:28s} {count:5d}")

    print(f"\n{'═' * 60}")
    print(f"\n>>> OPENCLAW_F1={metrics['f1_score']:.6f} <<<\n")


def print_live_results(
    rule_results: Dict[str, List[str]],
    events: List[Dict[str, Any]],
    unlabeled_events: List[Dict[str, Any]],
    verbose: bool,
) -> None:
    detected_set = set()
    for ids in rule_results.values():
        detected_set.update(ids)

    detected_events = [event for event in events if event.get("event_id") in detected_set]
    attack_counter = Counter(str(event.get("attack_type", "none")) for event in detected_events)

    print(f"\n{'═' * 60}")
    print("  OpenClaw Live Evaluation")
    print(f"  {utc_now()}")
    print(f"{'═' * 60}")
    print()
    print("  Mode: live (ground-truth labels unavailable or not trusted)")
    print(f"  Input events: {len(events)}")
    print(f"  Detections:   {len(detected_set)}")
    print(f"  Detection rate: {(len(detected_set) / len(events) * 100.0) if events else 0.0:.2f}%")
    print(f"  Unlabeled replay events: {len(unlabeled_events)}")

    print("\n  Detected Attack Type Distribution:")
    if attack_counter:
        for attack_type, count in sorted(attack_counter.items()):
            print(f"    {attack_type:28s} {count:5d}")
    else:
        print("    none")

    print("\n  Rule Hits:")
    hit_rules = sorted(((rule_id, len(ids)) for rule_id, ids in rule_results.items() if ids), key=lambda item: (-item[1], item[0]))
    if hit_rules:
        for rule_id, count in hit_rules:
            print(f"    {rule_id:10s} {count:5d}")
    else:
        print("    none")

    if verbose and detected_events:
        print(f"\n  {'─' * 56}")
        print("  Recent Detected Event IDs:")
        for event in detected_events[-10:]:
            print(f"    {event.get('event_id', 'unknown')}")

    print(f"\n{'═' * 60}")
    print(f"\n>>> OPENCLAW_LIVE_DETECTIONS={len(detected_set)} <<<\n")


def main() -> int:
    args = parse_args()

    try:
        labeled_events = load_events(args.labeled)
        unlabeled_events = load_events(args.unlabeled)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}")
        return 1

    detection_result = run_detection(labeled_events)
    mode = get_effective_mode(args.mode, labeled_events)

    if mode == "benchmark":
        metrics = compute_metrics(detection_result["detected_event_ids"], labeled_events)
        print_benchmark_results(metrics, detection_result["rule_results"], labeled_events, unlabeled_events, args.verbose)
    else:
        print_live_results(detection_result["rule_results"], labeled_events, unlabeled_events, args.verbose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())