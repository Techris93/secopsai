#!/usr/bin/env python3
"""Export approved, still-valid editorial releases for the publish job (read-only)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from secopsai.research_editorial import release_bundles


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    bundles = release_bundles()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps({"releases": bundles}, indent=2), encoding="utf-8")
    print(f"{len(bundles)} approved release(s): " + ", ".join(b["edition_id"] for b in bundles))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
