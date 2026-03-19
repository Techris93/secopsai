#!/usr/bin/env python3
"""Generate sample OpenClaw fixtures used by tests.

This script creates:
- data/openclaw/raw/sample_audit.jsonl
- data/openclaw/replay/labeled/sample_events.json

by reusing the attack-mix generator. It is safe to run multiple times
and will not overwrite files that already exist.
"""
from __future__ import annotations

import json
from pathlib import Path

import generate_openclaw_attack_mix
import openclaw_prepare


REPO_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = REPO_ROOT / "data" / "openclaw" / "raw"
LABELED_DIR = REPO_ROOT / "data" / "openclaw" / "replay" / "labeled"

SAMPLE_AUDIT = RAW_DIR / "sample_audit.jsonl"
SAMPLE_EVENTS = LABELED_DIR / "sample_events.json"


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    LABELED_DIR.mkdir(parents=True, exist_ok=True)

    # 1) sample_audit.jsonl
    if SAMPLE_AUDIT.exists():
        print(f"[samples] sample_audit.jsonl already exists at {SAMPLE_AUDIT}")
    else:
        # Prefer the attack-mix audit if it exists, since tests exercise that path.
        attack_mix_audit = RAW_DIR / "attack_mix_audit.jsonl"
        default_audit = RAW_DIR / "audit.jsonl"

        if attack_mix_audit.exists():
            print(f"[samples] Copying {attack_mix_audit} -> {SAMPLE_AUDIT}")
            SAMPLE_AUDIT.write_text(attack_mix_audit.read_text(encoding="utf-8"), encoding="utf-8")
        elif default_audit.exists():
            print(f"[samples] Copying {default_audit} -> {SAMPLE_AUDIT}")
            SAMPLE_AUDIT.write_text(default_audit.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            # Fall back to generating an attack-mix and using its audit as sample.
            print("[samples] No audit sources found; generating attack-mix audit for sample_audit.jsonl")
            generate_openclaw_attack_mix.main([])
            if attack_mix_audit.exists():
                SAMPLE_AUDIT.write_text(attack_mix_audit.read_text(encoding="utf-8"), encoding="utf-8")
            else:
                raise SystemExit("Failed to generate sample_audit.jsonl: no audit source available")

    # 2) sample_events.json
    if SAMPLE_EVENTS.exists():
        print(f"[samples] sample_events.json already exists at {SAMPLE_EVENTS}")
    else:
        print("[samples] Building sample_events.json from sample_audit.jsonl")
        records = openclaw_prepare.load_records(str(SAMPLE_AUDIT))
        flat = [openclaw_prepare.normalize_record(r)[1] for r in records]
        SAMPLE_EVENTS.write_text(json.dumps(flat, indent=2), encoding="utf-8")
        print(f"[samples] Wrote {len(flat)} events to {SAMPLE_EVENTS}")


if __name__ == "__main__":
    main()
