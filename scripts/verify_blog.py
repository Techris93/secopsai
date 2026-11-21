#!/usr/bin/env python3
"""Verify the static security blog has required pages and valid feeds."""

from __future__ import annotations

import json
import re
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
    latest = require(BLOG / "posts" / "index.html")
    post = require(BLOG / "posts" / "mini-shai-hulud-emergency-advisory.html")
    feed_json = json.loads(require(BLOG / "feed.json"))
    feed_xml = require(BLOG / "feed.xml")
    rss = ET.fromstring(feed_xml.encode("utf-8"))
    json_landing = require(BLOG / "json-feed.html")
    subscribe_page = require(BLOG / "subscribe.html")
    status_template = require(BLOG / "subscribe-status.html")
    subscribe_js = require(BLOG / "assets" / "subscribe.js")
    require(BLOG / "assets" / "blog.css")
    blog_js = require(BLOG / "assets" / "blog.js")
    comments_js = require(BLOG / "assets" / "comments.js")
    worker = require(BLOG / "_worker.js")
    require(BLOG / "favicon.svg")

    if 'href="/posts/mini-shai-hulud-emergency-advisory"' not in index:
        raise AssertionError("index does not link the Mini Shai-Hulud post")
    for marker in ["Security research and advisories", '<h2 class="topic-heading">Topics</h2>', 'class="section-label">Featured<', 'id="subscribe-heading">Subscribe<', "RSS 2.0 for feed readers", "JSON Feed 1.1 for scripts"]:
        if marker not in index:
            raise AssertionError(f"blog index missing advanced blog marker: {marker}")
    for marker in [
        '<section class="hero">\n        <div class="shell">',
        '<div class="content-section">\n        <div class="shell">',
        '<section class="subscribe-section" id="subscribe" aria-labelledby="subscribe-heading">\n        <div class="shell">',
    ]:
        if marker not in index:
            raise AssertionError("blog index section is missing the shared responsive content container")
    for marker in ["Latest posts", "data-topic-filter", "post-sort", "post-search", "latest-grid"]:
        if marker not in latest:
            raise AssertionError(f"latest posts page missing listing marker: {marker}")
    for marker in ["og:image", "twitter:card", "summary_large_image"]:
        if marker not in index:
            raise AssertionError(f"blog index missing social preview marker: {marker}")
    for marker in ["data-nav-toggle", "aria-controls=\"site-menu\"", "data-nav-menu", "#topics"]:
        if marker not in index:
            raise AssertionError(f"blog index missing mobile navigation marker: {marker}")
    if "data-comments" not in post:
        raise AssertionError("post does not include comments scaffold")
    if "Operator commands" in post or "Operator note" in post:
        raise AssertionError("public post must not render operator commands or notes")
    for marker in ["Affected Artifacts", "References", "What SecOpsAI Detected", "article:published_time", "twitter:image", "data-nav-toggle"]:
        if marker not in post:
            raise AssertionError(f"post page missing intelligence section: {marker}")
    if "Review Checklist" in post or "review_checklist" in post:
        raise AssertionError("public post must not render internal review checklist")
    if "data-turnstile" not in post:
        raise AssertionError("post comments form must include the Turnstile mount point")
    if not feed_json.get("items"):
        raise AssertionError("JSON feed has no items")
    # Browsers dropped XSLT: the worker serves /subscribe to browsers instead.
    if "<?xml-stylesheet" in feed_xml or (BLOG / "rss.xsl").exists():
        raise AssertionError("RSS feed must not depend on an XSLT stylesheet")
    if rss.find("./channel/{http://www.w3.org/2005/Atom}link[@rel='self']") is None:
        raise AssertionError("RSS feed must declare its own URL with atom:link rel=self")
    # Feed identities stay the original .html addresses (readers key on them);
    # links and canonicals use the served, extensionless address.
    first = feed_json["items"][0]
    if not first["id"].endswith(".html") or first["url"].endswith(".html") or first["id"] != first["url"] + ".html":
        raise AssertionError("JSON Feed items must keep their .html id and link to the extensionless URL")
    rss_item = rss.find("./channel/item")
    if not rss_item.findtext("guid").endswith(".html") or rss_item.findtext("link").endswith(".html"):
        raise AssertionError("RSS items must keep their .html guid and link to the extensionless URL")
    if 'rel="canonical" href="https://blog.secopsai.dev/posts/mini-shai-hulud-emergency-advisory"' not in post:
        raise AssertionError("post canonical must be the extensionless address Pages serves")
    missing_content = [item.get("url") for item in feed_json["items"] if not (item.get("content_html") or item.get("content_text"))]
    if missing_content:
        raise AssertionError(f"JSON Feed 1.1 items need content_html or content_text: {missing_content[:3]}")
    for page_name, page in (("index", index), ("JSON feed landing", json_landing), ("subscribe page", subscribe_page)):
        if "data-subscribe-form" not in page or "/assets/subscribe.js" not in page:
            raise AssertionError(f"{page_name} must include the email signup form and its script")
    for page_name, page in (("index", index), ("post", post), ("subscribe page", subscribe_page)):
        if re.search(r'(?:href|src)="/assets/[a-z]+\.(?:css|js)"', page):
            raise AssertionError(f"{page_name} links an unversioned stylesheet or script; use _asset_url so caches refresh")
    for slot in ("__STATUS_TITLE__", "__STATUS_MESSAGE__", "__STATUS_FORM__"):
        if slot not in status_template:
            raise AssertionError(f"subscription status template missing slot {slot}")
    if "/api/subscribe" not in subscribe_js or "turnstile" not in subscribe_js:
        raise AssertionError("signup client must post to /api/subscribe behind Turnstile")
    if not feed_json["items"][0].get("summary"):
        raise AssertionError("JSON feed items must include summaries")
    if not feed_json["items"][0].get("authors"):
        raise AssertionError("JSON feed items must include author metadata")
    if not feed_json["items"][0].get("reading_time_minutes"):
        raise AssertionError("JSON feed items must include reading-time metadata")
    if not feed_json["items"][0].get("image"):
        raise AssertionError("JSON feed items must include a social image")
    require(BLOG / "assets" / "social" / "secopsai-blog.svg")
    require(BLOG / "assets" / "social" / "mini-shai-hulud-emergency-advisory.svg")
    if not (BLOG / "data" / "news-sources.json").exists():
        raise AssertionError("news ingestion source registry is missing")
    news_sources = json.loads(require(BLOG / "data" / "news-sources.json")).get("sources", [])
    enabled_sources = [source for source in news_sources if source.get("enabled", True)]
    source_names = {str(source.get("name") or "") for source in enabled_sources}
    trust_levels = {str(source.get("trust_level") or "") for source in enabled_sources}
    for required in {
        "CISA Known Exploited Vulnerabilities",
        "CERT/CC Vulnerability Notes",
        "JFrog Security Research",
        "The Hacker News",
        "GitHub Security Advisories",
    }:
        if required not in source_names:
            raise AssertionError(f"news source registry missing required source: {required}")
    if not ({"government", "vendor", "project"} & trust_levels):
        raise AssertionError("news source registry must include direct government/vendor/project sources")
    if "Raw JSON" not in json_landing:
        raise AssertionError("JSON feed landing page must link to the raw JSON endpoint")
    if '<section class="hero">\n        <div class="shell">' not in json_landing:
        raise AssertionError("JSON feed hero is missing the shared responsive content container")
    for marker in ["post-search", "data-nav-toggle", "aria-expanded", "nav-open"]:
        if marker not in blog_js:
            raise AssertionError(f"blog script missing navigation/search marker: {marker}")
    blog_css = require(BLOG / "assets" / "blog.css")
    for marker in [".nav-toggle", ".nav.nav-open .nav-links", "@media (max-width: 840px)"]:
        if marker not in blog_css:
            raise AssertionError(f"blog stylesheet missing responsive navigation marker: {marker}")
    if ".shell { padding: 0 16px; }" in blog_css:
        raise AssertionError("blog mobile gutters must remain aligned with the 24px main-site and docs container")
    if "post-search" not in blog_js:
        raise AssertionError("blog search script must be served as a local asset")
    if "textContent" not in comments_js:
        raise AssertionError("comments client must render text safely")
    if "turnstile" not in comments_js:
        raise AssertionError("comments client must support Turnstile when configured")
    if "status = 'approved'" not in worker or "'pending'" not in worker:
        raise AssertionError("comments API must enforce pending writes and approved reads")
    if (BLOG / "functions").exists():
        raise AssertionError("blog/functions is ignored when _worker.js exists; keep comments in _worker.js only")
    not_found = require(BLOG / "404.html")
    if 'name="robots" content="noindex"' not in not_found:
        raise AssertionError("404 page must be noindex")
    if "Sitemap:" not in require(BLOG / "robots.txt"):
        raise AssertionError("robots.txt must advertise the sitemap")
    ET.fromstring(require(BLOG / "sitemap.xml"))
    security_txt = require(BLOG / ".well-known" / "security.txt")
    for field in ("Contact:", "Expires:", "Canonical:"):
        if field not in security_txt:
            raise AssertionError(f"security.txt missing RFC 9116 field {field}")
    if "/api/comments" not in worker or "env.ASSETS.fetch" not in worker or "/json-feed" not in worker:
        raise AssertionError("Pages worker must route comments API and static assets")
    for marker in ['"/api/subscribe"', '"/subscribe/confirm"', '"/unsubscribe"', "List-Unsubscribe-Post", '"/subscribe"', "BLOG_NEWSLETTER_SECRET"]:
        if marker not in worker:
            raise AssertionError(f"Pages worker missing email subscription marker: {marker}")
    if "payload too large" not in worker or "content-type must be application/json" not in worker:
        raise AssertionError("comments worker must reject oversized and non-JSON submissions")
    if "TURNSTILE_SECRET_KEY" not in worker or "siteverify" not in worker:
        raise AssertionError("comments worker must verify Turnstile")
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
