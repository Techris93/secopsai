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
    feed_xml = require(BLOG / "feed.xml")
    ET.fromstring(feed_xml.split("?>", 2)[-1] if "<?xml-stylesheet" in feed_xml else feed_xml)
    json_landing = require(BLOG / "json-feed.html")
    require(BLOG / "assets" / "blog.css")
    blog_js = require(BLOG / "assets" / "blog.js")
    comments_js = require(BLOG / "assets" / "comments.js")
    comments_api = require(BLOG / "functions" / "api" / "comments.js")
    worker = require(BLOG / "_worker.js")
    require(BLOG / "favicon.svg")

    if "mini-shai-hulud-emergency-advisory.html" not in index:
        raise AssertionError("index does not link the Mini Shai-Hulud post")
    if "data-comments" not in post:
        raise AssertionError("post does not include comments scaffold")
    if "data-turnstile" not in post:
        raise AssertionError("post comments form must include the Turnstile mount point")
    if not feed_json.get("items"):
        raise AssertionError("JSON feed has no items")
    if "<?xml-stylesheet" not in feed_xml:
        raise AssertionError("RSS feed must include a browser-readable stylesheet")
    if not feed_json["items"][0].get("summary"):
        raise AssertionError("JSON feed items must include summaries")
    if "Raw JSON" not in json_landing:
        raise AssertionError("JSON feed landing page must link to the raw JSON endpoint")
    if "post-search" not in blog_js:
        raise AssertionError("blog search script must be served as a local asset")
    if "textContent" not in comments_js:
        raise AssertionError("comments client must render text safely")
    if "turnstile" not in comments_js:
        raise AssertionError("comments client must support Turnstile when configured")
    if "status=eq.approved" not in comments_api or "status: \"pending\"" not in comments_api:
        raise AssertionError("comments API must enforce pending writes and approved reads")
    if "SUPABASE_SERVICE_ROLE_KEY" not in comments_api:
        raise AssertionError("comments API must require the service-role secret")
    if "/api/comments" not in worker or "env.ASSETS.fetch" not in worker or "/json-feed" not in worker:
        raise AssertionError("Pages worker must route comments API and static assets")
    if "payload too large" not in worker or "content-type must be application/json" not in worker:
        raise AssertionError("comments worker must reject oversized and non-JSON submissions")
    if "TURNSTILE_SECRET_KEY" not in worker or "siteverify" not in worker:
        raise AssertionError("comments worker must verify Turnstile when configured")
    if "default-src 'none'" not in worker:
        raise AssertionError("comments worker JSON responses must include defensive security headers")
    print("blog verification passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"blog verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
