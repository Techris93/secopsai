"""
Safe BOTSv3 evaluation runner.

Temporarily swaps data/events.json with data/botsv3_events.json,
runs evaluate.py, and restores the original events file even on failure.

Usage:
    python evaluate_botsv3.py
    python evaluate_botsv3.py --verbose
"""

import argparse
import os
import json
import shutil
import subprocess
import sys


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
BOTS_FILE = os.path.join(DATA_DIR, "botsv3_events.json")
TEMP_BACKUP = os.path.join(DATA_DIR, "events_eval_temp_backup.json")
UNLABELED_FILE = os.path.join(DATA_DIR, "events_unlabeled.json")
UNLABELED_BACKUP = os.path.join(DATA_DIR, "events_unlabeled_eval_temp_backup.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run evaluate.py on BOTSv3 safely")
    parser.add_argument("--verbose", action="store_true", help="Pass --verbose to evaluate.py")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not os.path.isfile(BOTS_FILE):
        print(f"Missing BOTSv3 events file: {BOTS_FILE}")
        return 1
    if not os.path.isfile(EVENTS_FILE):
        print(f"Missing events file: {EVENTS_FILE}")
        return 1
    if not os.path.isfile(UNLABELED_FILE):
        print(f"Missing unlabeled events file: {UNLABELED_FILE}")
        return 1

    shutil.copy2(EVENTS_FILE, TEMP_BACKUP)
    shutil.copy2(UNLABELED_FILE, UNLABELED_BACKUP)
    try:
        with open(BOTS_FILE, "r", encoding="utf-8") as handle:
            bots_events = json.load(handle)

        unlabeled_events = []
        for event in bots_events:
            e = dict(event)
            e.pop("label", None)
            e.pop("attack_type", None)
            unlabeled_events.append(e)

        shutil.copy2(BOTS_FILE, EVENTS_FILE)
        with open(UNLABELED_FILE, "w", encoding="utf-8") as handle:
            json.dump(unlabeled_events, handle, separators=(",", ":"))

        cmd = [sys.executable, "evaluate.py"]
        if args.verbose:
            cmd.append("--verbose")
        return subprocess.call(cmd, cwd=PROJECT_ROOT)
    finally:
        if os.path.isfile(TEMP_BACKUP):
            shutil.copy2(TEMP_BACKUP, EVENTS_FILE)
            os.remove(TEMP_BACKUP)
        if os.path.isfile(UNLABELED_BACKUP):
            shutil.copy2(UNLABELED_BACKUP, UNLABELED_FILE)
            os.remove(UNLABELED_BACKUP)


if __name__ == "__main__":
    raise SystemExit(main())
