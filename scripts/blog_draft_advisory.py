#!/usr/bin/env python3
"""Compatibility wrapper for creating a blog draft from a SecOpsAI advisory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secopsai.blog import draft_advisory  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True, help="Campaign id or advisory id")
    args = parser.parse_args()
    payload = draft_advisory(args.campaign)
    print(payload["draft_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
