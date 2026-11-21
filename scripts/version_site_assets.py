#!/usr/bin/env python3
"""Keep secopsai.dev's stylesheet and script URLs versioned by content.

Browsers may keep /assets files for hours (the zone sends max-age=14400), so a
deploy could pair new HTML with an old cached site.js. Every
``href``/``src`` to a local ``/assets/*.css`` or ``/assets/*.js`` carries
``?v=<sha256[:12]>`` of the file, so a changed file has a new URL.

    python scripts/version_site_assets.py          # rewrite www/ and website/
    python scripts/version_site_assets.py --check  # CI: fail if any version is stale
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITES = ("www", "website")
ASSET_REF = re.compile(r'(?P<attr>\b(?:href|src)=")(?P<path>/assets/[^"?#]+\.(?:css|js))(?P<query>\?[^"#]*)?"')


def versioned(site: Path, text: str) -> str:
    def rewrite(match: re.Match[str]) -> str:
        target = site / match.group("path").lstrip("/")
        if not target.is_file():
            return match.group(0)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()[:12]
        return f'{match.group("attr")}{match.group("path")}?v={digest}"'

    return ASSET_REF.sub(rewrite, text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report stale versions instead of rewriting")
    args = parser.parse_args()
    stale = []
    for name in SITES:
        site = ROOT / name
        for page in sorted(site.rglob("*.html")):
            text = page.read_text(encoding="utf-8")
            updated = versioned(site, text)
            if updated == text:
                continue
            stale.append(page.relative_to(ROOT))
            if not args.check:
                page.write_text(updated, encoding="utf-8")
    if args.check and stale:
        print("Stale or missing asset versions (run python scripts/version_site_assets.py):", file=sys.stderr)
        for path in stale:
            print(f"  {path}", file=sys.stderr)
        return 1
    print(f"{'checked' if args.check else 'updated'}: {len(stale)} page(s) {'stale' if args.check else 'rewritten'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
