#!/usr/bin/env python3
"""Verify the static security blog has required pages and valid feeds."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOG = ROOT / "blog"


def require(path: Path) -> str:
    if not path.exists():
        raise AssertionError(f"missing blog file: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise AssertionError(f"empty blog file: {path}")
    return text


def main() -> int:
    index = require(BLOG / "index.html")
    post = require(BLOG / "posts" / "mini-shai-hulud-emergency-advisory.html")
    feed_json = json.loads(require(BLOG / "feed.json"))
    ET.fromstring(require(BLOG / "feed.xml"))
    require(BLOG / "assets" / "blog.css")
    comments_js = require(BLOG / "assets" / "comments.js")
    comments_api = require(BLOG / "functions" / "api" / "comments.js")
    require(BLOG / "favicon.svg")

    if "mini-shai-hulud-emergency-advisory.html" not in index:
        raise AssertionError("index does not link the Mini Shai-Hulud post")
    if "data-comments" not in post:
        raise AssertionError("post does not include comments scaffold")
    if not feed_json.get("items"):
        raise AssertionError("JSON feed has no items")
    if "textContent" not in comments_js:
        raise AssertionError("comments client must render text safely")
    if "status=eq.approved" not in comments_api or "status: \"pending\"" not in comments_api:
        raise AssertionError("comments API must enforce pending writes and approved reads")
    if "SUPABASE_SERVICE_ROLE_KEY" not in comments_api:
        raise AssertionError("comments API must require the service-role secret")
    print("blog verification passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"blog verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
