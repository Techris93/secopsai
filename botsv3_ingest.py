"""
BOTSv3 metadata ingest helper.

This script normalizes BOTSv3 challenge metadata (questions, answers, hints)
into a single JSON file that can be used to drive labeling and mapping logic
once raw BOTSv3 event logs are exported.

Usage:
    python botsv3_ingest.py
    python botsv3_ingest.py --input-dir /path/to/botsv3content
    python botsv3_ingest.py --output data/botsv3_qa.json
"""

import argparse
import csv
import json
import os
from collections import defaultdict
from typing import Dict, List, Any


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT = os.path.join(PROJECT_ROOT, "data", "botsv3_qa.json")
DEFAULT_INPUT_CANDIDATES = [
    os.path.join(PROJECT_ROOT, "botsv3content"),
    os.path.join(os.path.expanduser("~"), "Downloads", "botsv3content"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize BOTSv3 metadata CSVs")
    parser.add_argument(
        "--input-dir",
        default=None,
        help="Directory containing ctf_questions.csv, ctf_answers.csv, ctf_hints.csv",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="Path to output normalized JSON",
    )
    return parser.parse_args()


def resolve_input_dir(cli_input_dir: str | None) -> str:
    if cli_input_dir:
        return cli_input_dir

    for candidate in DEFAULT_INPUT_CANDIDATES:
        if os.path.isdir(candidate):
            return candidate

    searched = "\n  - ".join(DEFAULT_INPUT_CANDIDATES)
    raise FileNotFoundError(
        "Could not find botsv3content directory. Searched:\n  - " + searched
    )


def load_csv_rows(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def as_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_questions(rows: List[Dict[str, str]]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        number = as_int(row.get("Number", ""), default=-1)
        if number < 0:
            continue

        out[number] = {
            "number": number,
            "question": (row.get("Question") or "").strip(),
            "base_points": as_int(row.get("BasePoints", "0")),
            "bonus_points": as_int(row.get("AdditionalBonusPoints", "0")),
            "bonus_instructions": (row.get("AdditionalBonusInstructions") or "").strip(),
            "hints": [],
            "answer": None,
        }
    return out


def merge_answers(records: Dict[int, Dict[str, Any]], rows: List[Dict[str, str]]) -> None:
    for row in rows:
        number = as_int(row.get("Number", ""), default=-1)
        if number < 0 or number not in records:
            continue
        records[number]["answer"] = (row.get("Answer") or "").strip()


def merge_hints(records: Dict[int, Dict[str, Any]], rows: List[Dict[str, str]]) -> None:
    hints_by_number: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

    for row in rows:
        number = as_int(row.get("Number", ""), default=-1)
        if number < 0:
            continue

        hints_by_number[number].append(
            {
                "hint_number": as_int(row.get("HintNumber", "0")),
                "hint": (row.get("Hint") or "").strip(),
                "hint_cost": as_int(row.get("HintCost", "0")),
            }
        )

    for number, hints in hints_by_number.items():
        if number in records:
            records[number]["hints"] = sorted(hints, key=lambda h: h["hint_number"])


def build_summary(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    answered = sum(1 for r in records if r.get("answer"))
    with_hints = sum(1 for r in records if r.get("hints"))
    return {
        "total_questions": len(records),
        "questions_with_answers": answered,
        "questions_with_hints": with_hints,
    }


def main() -> int:
    args = parse_args()
    input_dir = resolve_input_dir(args.input_dir)

    questions_path = os.path.join(input_dir, "ctf_questions.csv")
    answers_path = os.path.join(input_dir, "ctf_answers.csv")
    hints_path = os.path.join(input_dir, "ctf_hints.csv")

    for path in (questions_path, answers_path, hints_path):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Required file missing: {path}")

    questions = load_csv_rows(questions_path)
    answers = load_csv_rows(answers_path)
    hints = load_csv_rows(hints_path)

    records = normalize_questions(questions)
    merge_answers(records, answers)
    merge_hints(records, hints)

    sorted_records = [records[k] for k in sorted(records)]
    payload = {
        "source_dir": input_dir,
        "summary": build_summary(sorted_records),
        "records": sorted_records,
        "next_step": (
            "Export BOTSv3 raw events from Splunk and map them into data/events.json "
            "schema for evaluate.py"
        ),
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    summary = payload["summary"]
    print("BOTSv3 metadata normalized")
    print(f"- source_dir: {input_dir}")
    print(f"- output: {args.output}")
    print(f"- total_questions: {summary['total_questions']}")
    print(f"- questions_with_answers: {summary['questions_with_answers']}")
    print(f"- questions_with_hints: {summary['questions_with_hints']}")
    print("- next: export BOTSv3 event telemetry and build field-mapping ETL")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
