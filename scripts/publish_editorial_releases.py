#!/usr/bin/env python3
"""Write blog files for approved editorial releases exported by the Research Worker.

Each release is checked against its approved fingerprint before any file is
written.  The ledger is not available here; the next worker run marks the
edition published once the page is live.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from secopsai import blog
from secopsai.research_editorial import verify_release_bundle


def publish_all(releases: list[dict], paths: blog.BlogPaths | None = None) -> list[dict]:
    paths = paths or blog.BlogPaths()
    published = []
    with tempfile.TemporaryDirectory() as scratch:
        for bundle in releases:
            draft = verify_release_bundle(bundle)
            path = Path(scratch) / (draft["slug"] + ".json")
            path.write_text(json.dumps(draft, indent=2), encoding="utf-8")
            result = blog.publish(str(path), confirm=True, paths=paths, editorial_release=bundle)
            published.append({"edition_id": bundle["edition_id"], "url": result["url"]})
    return published


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("releases")
    args = parser.parse_args()
    releases = json.loads(Path(args.releases).read_text(encoding="utf-8")).get("releases") or []
    for item in publish_all(releases):
        print(f"{item['edition_id']} -> {item['url']}")
    if not releases:
        print("No approved releases.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
