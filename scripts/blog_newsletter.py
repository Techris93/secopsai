#!/usr/bin/env python3
"""Ask the blog's Pages worker to email recent posts to confirmed subscribers.

Run by the Blog Ops deploy job after a deploy. It sends only the slugs of posts
published in the last two days; the worker checks each post against the live
feed, mails each post once, and resumes a send that stopped part-way. The
request is signed with BLOG_NEWSLETTER_SECRET, which the same job set on the
new deployment.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
FEED = ROOT / "blog" / "feed.json"
ENDPOINT = "https://blog.secopsai.dev/api/newsletter/send"
POST_PREFIX = "https://blog.secopsai.dev/posts/"
RECENT = _dt.timedelta(days=2)
# The new deployment, with this run's secret, can take a minute to replace the
# old one at the production hostname; until then the old one answers 401.
RETRY_DELAYS = (10, 20, 30, 45, 60)


def recent_slugs(feed: Dict[str, Any], now: _dt.datetime) -> List[str]:
    slugs = []
    for item in feed.get("items") or []:
        url = str(item.get("url") or "")
        try:
            published = _dt.datetime.fromisoformat(str(item.get("date_published") or "").replace("Z", "+00:00"))
        except ValueError:
            continue
        slug = url[len(POST_PREFIX):].removesuffix(".html") if url.startswith(POST_PREFIX) else ""
        if slug and "/" not in slug and now - published <= RECENT:
            slugs.append(slug)
    return slugs[:10]


def signed_request(body: bytes, secret: str, timestamp: int) -> urllib.request.Request:
    signature = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return urllib.request.Request(ENDPOINT, data=body, method="POST", headers={
        "content-type": "application/json",
        "user-agent": "SecOpsAI-Blog-Ops/1.0",
        "x-newsletter-timestamp": str(timestamp),
        "x-newsletter-signature": f"sha256={signature}",
    })


def send(slugs: List[str], secret: str, *, sleep=time.sleep) -> Dict[str, Any]:
    body = json.dumps({"slugs": slugs}).encode()
    for delay in (*RETRY_DELAYS, None):
        try:
            with urllib.request.urlopen(signed_request(body, secret, int(time.time())), timeout=120) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code not in (401, 503) or delay is None:
                raise
        sleep(delay)
    raise RuntimeError("unreachable")


def main() -> int:
    secret = os.environ.get("BLOG_NEWSLETTER_SECRET", "")
    if not secret:
        print("BLOG_NEWSLETTER_SECRET is not set; nothing sent.", file=sys.stderr)
        return 1
    slugs = recent_slugs(json.loads(FEED.read_text(encoding="utf-8")), _dt.datetime.now(_dt.timezone.utc))
    if not slugs:
        print("No posts from the last two days to email.")
        return 0
    result = send(slugs, secret)
    lines = [f"- {item.get('slug')}: {item.get('status')}" + (f" ({item.get('recipients')} recipients)" if "recipients" in item else "")
             for item in result.get("results") or []]
    text = "### Blog email\n\n" + "\n".join(lines) + "\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
