#!/usr/bin/env python3
"""Evaluate captured decisions offline; never contact a provider or change alerts."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secopsai.decision_evaluation import evaluate_records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('records', type=Path, help='JSON array of independently labelled captured decisions')
    parser.add_argument('--held-out', action='store_true')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    report = evaluate_records(json.loads(args.records.read_text()), held_out=args.held_out)
    output = json.dumps(report, indent=2, allow_nan=False) + '\n'
    if args.out: args.out.write_text(output)
    else: print(output, end='')
    return 0 if report['accepted'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
