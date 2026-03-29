#!/usr/bin/env python3
"""Generate stable test fixtures for SecOpsAI.

This script snapshots a small, versioned fixture set under data/fixtures/
from the current local generated datasets. The fixture directory is intended
for tests and CI, while larger runtime artifacts remain ignored under data/.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "fixtures"
OPENCLAW_FIXTURES = FIXTURES / "openclaw"


def ensure_dirs() -> None:
    OPENCLAW_FIXTURES.mkdir(parents=True, exist_ok=True)


def copy_json(src: Path, dst: Path) -> None:
    payload = json.loads(src.read_text(encoding="utf-8"))
    dst.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def copy_text(src: Path, dst: Path) -> None:
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def main() -> int:
    ensure_dirs()

    sources = {
        ROOT / "data" / "events.json": FIXTURES / "events.json",
        ROOT / "data" / "events_unlabeled.json": FIXTURES / "events_unlabeled.json",
        ROOT / "data" / "openclaw" / "raw" / "audit.jsonl": OPENCLAW_FIXTURES / "sample_audit.jsonl",
        ROOT / "data" / "openclaw" / "replay" / "labeled" / "attack_mix.json": OPENCLAW_FIXTURES / "attack_mix.json",
        ROOT / "data" / "openclaw" / "replay" / "unlabeled" / "attack_mix.json": OPENCLAW_FIXTURES / "attack_mix_unlabeled.json",
    }

    for src, dst in sources.items():
        if not src.exists():
            raise SystemExit(f"Missing source fixture input: {src}")
        if src.suffix == ".json":
            copy_json(src, dst)
        else:
            copy_text(src, dst)
        print(f"wrote_fixture={dst}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
