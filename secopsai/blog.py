from __future__ import annotations

import email.utils
import hashlib
import html
import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import soc_store

from secopsai.supply_chain import load_advisories

try:
    import feedparser
except ModuleNotFoundError:  # pragma: no cover - exercised when optional deps are absent locally
    feedparser = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
BLOG_DIR = ROOT / "blog"
POSTS_DIR = BLOG_DIR / "posts"
DRAFTS_DIR = BLOG_DIR / "drafts"
NEWS_CACHE_PATH = BLOG_DIR / "data" / "news-cache.json"
BASE_URL = "https://blog.secopsai.dev"
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|credential|authorization|bearer|refresh[_-]?token)\b"
    r"\s*[:=]\s*['\"]?[^'\"\s,;]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")


@dataclass
class BlogPaths:
    root: Path = BLOG_DIR

    @property
    def posts(self) -> Path:
        return self.root / "posts"

    @property
    def drafts(self) -> Path:
        return self.root / "drafts"

    @property
    def data(self) -> Path:
        return self.root / "data"

    @property
    def news_cache(self) -> Path:
        return self.data / "news-cache.json"


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return slug[:90].strip("-") or "secopsai-post"


def redact(text: Any) -> str:
    value = str(text or "")
    value = SENSITIVE_VALUE_RE.sub(lambda match: match.group(0).split("=", 1)[0].split(":", 1)[0] + "=[REDACTED]", value)
    return LONG_HEX_RE.sub("[HASH-REDACTED]", value)


def _safe_list(values: Iterable[Any], *, limit: int = 24) -> List[str]:
    seen: set[str] = set()
    output: List[str] = []
    for value in values:
        item = redact(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        output.append(item)
        if len(output) >= limit:
            break
    return output


def _markdown_inline(text: str) -> str:
    escaped = html.escape(redact(text))
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    return escaped


def markdown_to_html(markdown: str) -> str:
    lines = markdown.splitlines()
    html_lines: List[str] = []
    in_list = False
    in_code = False
    code_lines: List[str] = []

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            html_lines.append("</ul>")
            in_list = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                html_lines.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
                code_lines = []
                in_code = False
            else:
                close_list()
                in_code = True
            continue
        if in_code:
            code_lines.append(redact(line))
            continue
        if not stripped:
            close_list()
            continue
        if stripped.startswith("### "):
            close_list()
            html_lines.append(f"<h3>{_markdown_inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            close_list()
            html_lines.append(f"<h2>{_markdown_inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            close_list()
            html_lines.append(f"<h1>{_markdown_inline(stripped[2:])}</h1>")
        elif stripped.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_markdown_inline(stripped[2:])}</li>")
        else:
            close_list()
            html_lines.append(f"<p>{_markdown_inline(stripped)}</p>")
    close_list()
    return "\n".join(html_lines)


def _post_url(slug: str) -> str:
    return f"{BASE_URL}/posts/{slug}.html"


def _draft_path(slug: str, paths: BlogPaths) -> Path:
    return paths.drafts / f"{slug}.json"


def _post_json_path(slug: str, paths: BlogPaths) -> Path:
    return paths.posts / f"{slug}.json"


def _post_html_path(slug: str, paths: BlogPaths) -> Path:
    return paths.posts / f"{slug}.html"


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _base_post(
    *,
    title: str,
    summary: str,
    severity: str = "info",
    categories: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    slug: Optional[str] = None,
) -> Dict[str, Any]:
    now = _utc_now()
    slug_value = slug or slugify(title)
    return {
        "slug": slug_value,
        "title": redact(title),
        "summary": redact(summary),
        "severity": severity,
        "categories": categories or ["Detection Engineering"],
        "tags": categories or ["Detection Engineering"],
        "published_at": now,
        "updated_at": now,
        "status": "draft",
        "sources": _safe_list(sources or [], limit=12),
        "affected_ecosystems": [],
        "affected_packages": [],
        "iocs": [],
        "body_markdown": "",
    }


def _advisory_by_campaign(campaign: str) -> Dict[str, Any]:
    for advisory in load_advisories():
        if campaign in {advisory.get("campaign_id"), advisory.get("advisory_id")}:
            return advisory
    raise ValueError(f"No advisory found for campaign/advisory id: {campaign}")


def draft_advisory(campaign: str, *, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    advisory = _advisory_by_campaign(campaign)
    title = str(advisory.get("title") or f"SecOpsAI advisory: {campaign}")
    affected = advisory.get("affected", [])
    packages = _safe_list([item.get("package", "") for item in affected if isinstance(item, dict)])
    ecosystems = _safe_list([item.get("ecosystem", "") for item in affected if isinstance(item, dict)])
    iocs = advisory.get("iocs", {})
    ioc_values = []
    for values in iocs.values() if isinstance(iocs, dict) else []:
        if isinstance(values, list):
            ioc_values.extend(values)
    affected_lines = [
        f'- {item.get("ecosystem", "")}: `{item.get("package", "")}` versions '
        f'{", ".join(item.get("versions", [])) or "range-listed"}'
        for item in affected
        if isinstance(item, dict)
    ]
    remediation_lines = [
        f"- {item}"
        for item in _safe_list(advisory.get("remediation", []), limit=16)
    ]
    body = f"""# {title}

## Executive Summary

{advisory.get('summary', 'Emergency advisory generated from SecOpsAI advisory data.')}

## Affected Artifacts

{chr(10).join(affected_lines)}

## What SecOpsAI Detected

- Advisory id: `{advisory.get('advisory_id', '')}`
- Campaign id: `{advisory.get('campaign_id', '')}`
- Confidence: `{advisory.get('confidence', 'high')}`

## IOCs

{chr(10).join(f'- {ioc}' for ioc in _safe_list(ioc_values)) or '- No IOCs listed in the advisory.'}

## Mitigation Steps

{chr(10).join(remediation_lines) or '- Review advisory sources and block affected versions.'}

## Timeline

- Published: `{advisory.get('published_at', 'unknown')}`
- Updated: `{advisory.get('updated_at', 'unknown')}`

## References

{chr(10).join(f'- {source}' for source in _safe_list(advisory.get('source_urls', []), limit=12))}
"""
    post = _base_post(
        title=title,
        summary=str(advisory.get("summary") or title),
        severity=str(advisory.get("severity") or "critical"),
        categories=["Supply Chain", "Advisories", "Mitigation"],
        sources=list(advisory.get("source_urls", [])),
        slug=slugify(f"{campaign}-{title}"),
    )
    post.update(
        {
            "affected_ecosystems": ecosystems,
            "affected_packages": packages,
            "iocs": _safe_list(ioc_values),
            "body_markdown": redact(body),
        }
    )
    _write_json(_draft_path(post["slug"], paths), post)
    return {"draft_path": str(_draft_path(post["slug"], paths)), "post": post}


def draft_finding(finding_id: str, *, db_path: Optional[str] = None, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    finding = soc_store.get_finding(finding_id, db_path)
    if not finding:
        raise ValueError(f"finding not found: {finding_id}")
    title = str(finding.get("title") or finding_id)
    summary = str(finding.get("summary") or finding.get("analysis") or title)
    payload_iocs: List[str] = []
    for entry in finding.get("iocs", []) if isinstance(finding.get("iocs"), list) else []:
        if isinstance(entry, dict):
            for values in entry.values():
                if isinstance(values, list):
                    payload_iocs.extend(str(value) for value in values)
    remediation: List[str] = []
    for entry in finding.get("remediation", []) if isinstance(finding.get("remediation"), list) else []:
        if isinstance(entry, list):
            remediation.extend(str(item) for item in entry)
        else:
            remediation.append(str(entry))
    remediation_lines = [f"- {item}" for item in _safe_list(remediation, limit=16)]
    body = f"""# {title}

## Executive Summary

{summary}

## What SecOpsAI Detected

- Finding id: `{finding_id}`
- Severity: `{finding.get('severity', 'unknown')}`
- Status: `{finding.get('status', 'unknown')}`
- Disposition: `{finding.get('disposition', 'unknown')}`
- Source: `{finding.get('source', 'unknown')}`

## Evidence

{finding.get('analysis') or finding.get('summary') or 'Review the stored SOC finding for full evidence.'}

## IOCs

{chr(10).join(f'- {ioc}' for ioc in _safe_list(payload_iocs)) or '- No structured IOCs attached to this finding.'}

## Mitigation Steps

{chr(10).join(remediation_lines) or '- Review the finding and apply the recommended SecOpsAI triage workflow.'}

## Timeline

- First seen: `{finding.get('first_seen', 'unknown')}`
- Last seen: `{finding.get('last_seen', 'unknown')}`
"""
    post = _base_post(
        title=title,
        summary=summary,
        severity=str(finding.get("severity") or "info"),
        categories=["Detection Engineering", "Mitigation"],
        sources=[str(source) for match in finding.get("advisory_matches", []) for source in match.get("source_urls", [])]
        if isinstance(finding.get("advisory_matches"), list)
        else [],
        slug=slugify(f"{finding_id}-{title}"),
    )
    post.update(
        {
            "affected_ecosystems": _safe_list([finding.get("ecosystem", "")]),
            "affected_packages": _safe_list([finding.get("package", "")]),
            "iocs": _safe_list(payload_iocs),
            "body_markdown": redact(body),
        }
    )
    _write_json(_draft_path(post["slug"], paths), post)
    return {"draft_path": str(_draft_path(post["slug"], paths)), "post": post}


def _read_news_cache(paths: BlogPaths) -> Dict[str, Any]:
    if not paths.news_cache.exists():
        return {"items": []}
    return _load_json(paths.news_cache)


def _write_news_cache(paths: BlogPaths, cache: Dict[str, Any]) -> None:
    _write_json(paths.news_cache, cache)


def _source_key(url: str, title: str = "") -> str:
    return hashlib.sha256(f"{url}|{title}".encode("utf-8")).hexdigest()[:16]


def _fetch_text(url: str) -> str:
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        return Path(url).read_text(encoding="utf-8")
    request = urllib.request.Request(url, headers={"User-Agent": "secopsai-blog/0.1"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8", errors="replace")


def draft_news(source: str, *, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    parsed = feedparser.parse(source) if feedparser else None
    entries = getattr(parsed, "entries", []) if parsed else []
    if entries:
        entry = entries[0]
        title = str(entry.get("title") or "Security news item")
        link = str(entry.get("link") or source)
        summary = re.sub(r"<[^>]+>", " ", str(entry.get("summary") or title))
        source_name = str(parsed.feed.get("title") or urllib.parse.urlparse(link).netloc or "External source")
    else:
        text = _fetch_text(source)
        item_match = re.search(r"<item\b.*?</item>", text, re.IGNORECASE | re.DOTALL)
        if item_match:
            item_text = item_match.group(0)
            item_title = re.search(r"<title[^>]*>(.*?)</title>", item_text, re.IGNORECASE | re.DOTALL)
            item_link = re.search(r"<link[^>]*>(.*?)</link>", item_text, re.IGNORECASE | re.DOTALL)
            item_summary = re.search(r"<description[^>]*>(.*?)</description>", item_text, re.IGNORECASE | re.DOTALL)
            title = html.unescape(re.sub(r"\s+", " ", item_title.group(1)).strip()) if item_title else "Security news item"
            link = html.unescape(re.sub(r"\s+", " ", item_link.group(1)).strip()) if item_link else source
            summary = (
                html.unescape(re.sub(r"<[^>]+>", " ", item_summary.group(1))).strip()
                if item_summary
                else "External security-news source queued for analyst review."
            )
            source_name = urllib.parse.urlparse(link).netloc or "External source"
        else:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            title = html.unescape(re.sub(r"\s+", " ", title_match.group(1)).strip()) if title_match else source
            link = source
            summary = (
                "External security-news source queued for analyst review. "
                "Summarize only after reading and citing the source."
            )
            source_name = urllib.parse.urlparse(source).netloc or "External source"

    cache = _read_news_cache(paths)
    key = _source_key(link, title)
    if key in {item.get("key") for item in cache.get("items", [])}:
        raise ValueError(f"news source already drafted: {link}")
    cache.setdefault("items", []).append({"key": key, "url": link, "title": title, "fetched_at": _utc_now()})
    _write_news_cache(paths, cache)

    body = f"""# {title}

## Executive Summary

{summary}

## Why It Matters

- This external news item is a draft and requires human review before publishing.
- Confirm claims against the linked source and any primary references.
- Add SecOpsAI detection or mitigation context before publishing.

## SecOpsAI Relevance

- Add related detections, IOCs, affected products, or mitigation steps.

## References

- {link}
"""
    post = _base_post(
        title=title,
        summary=summary,
        severity="info",
        categories=["Security News"],
        sources=[link],
        slug=slugify(f"news-{title}"),
    )
    post.update({"source_name": source_name, "body_markdown": redact(body)})
    _write_json(_draft_path(post["slug"], paths), post)
    return {"draft_path": str(_draft_path(post["slug"], paths)), "post": post}


def _draft_advisory_batch(limit: int, paths: BlogPaths) -> List[str]:
    created: List[str] = []
    for advisory in load_advisories():
        if len(created) >= limit:
            break
        campaign = str(advisory.get("campaign_id") or advisory.get("advisory_id") or "")
        if not campaign:
            continue
        try:
            created.append(draft_advisory(campaign, paths=paths)["draft_path"])
        except Exception:
            continue
    return created


def _draft_finding_batch(limit: int, paths: BlogPaths) -> List[str]:
    created: List[str] = []
    for finding in soc_store.list_findings():
        if len(created) >= limit:
            break
        if str(finding.get("status", "")).lower() not in {"open", "in_review", "review"}:
            continue
        try:
            created.append(draft_finding(str(finding["finding_id"]), paths=paths)["draft_path"])
        except Exception:
            continue
    return created


def draft_daily(*, limit: int = 5, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    advisory_drafts = _draft_advisory_batch(limit, paths)
    finding_drafts = _draft_finding_batch(max(limit - len(advisory_drafts), 0), paths)
    created = advisory_drafts + finding_drafts
    sources = {"advisories": len(advisory_drafts), "findings": len(finding_drafts)}
    return {"created": created, "total": len(created), "sources": sources}


def _load_posts(paths: BlogPaths) -> List[Dict[str, Any]]:
    posts = []
    for path in sorted(paths.posts.glob("*.json")):
        post = _load_json(path)
        if post.get("status") == "published":
            posts.append(post)
        elif "published_at" in post and "body_markdown" not in post:
            post.setdefault("status", "published")
            posts.append(post)
    return sorted(posts, key=lambda item: str(item.get("updated_at") or item.get("published_at") or ""), reverse=True)


def _render_post_html(post: Dict[str, Any]) -> str:
    slug = str(post["slug"])
    title = html.escape(redact(post["title"]))
    summary = html.escape(redact(post.get("summary", "")))
    categories = post.get("categories") or post.get("tags") or []
    pills = "\n".join(f'<span class="pill">{html.escape(str(item))}</span>' for item in categories)
    body_html = markdown_to_html(str(post.get("body_markdown") or ""))
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title} | SecOpsAI Security Blog</title>
    <meta name="description" content="{summary}" />
    <link rel="canonical" href="{_post_url(slug)}" />
    <link rel="icon" type="image/png" href="/assets/favicon-512.png" />
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
    <link rel="stylesheet" href="/assets/blog.css" />
  </head>
  <body>
    <header class="topbar">
      <nav class="shell nav">
        <a class="brand" href="/">
          <img class="brand-mark" src="/assets/favicon-512.png" alt="SecOpsAI icon" />
          <span class="brand-title"><span>SecOpsAI</span><span>Security Blog</span></span>
        </a>
        <div class="nav-links">
          <a href="/">Blog Home</a>
          <a href="https://docs.secopsai.dev/">Docs</a>
          <a href="/feed.xml">RSS</a>
        </div>
      </nav>
    </header>
    <main class="shell post-layout">
      <article class="post-body">
        <p class="eyebrow">{html.escape(str(post.get("severity", "info")))} • SecOpsAI intelligence</p>
        <h1>{title}</h1>
        <div class="meta">
          <span class="pill critical">{html.escape(str(post.get("severity", "info")).title())}</span>
          <span>Published: {html.escape(str(post.get("published_at", "")))}</span>
          <span>Updated: {html.escape(str(post.get("updated_at", "")))}</span>
        </div>
        <div class="tags">{pills}</div>
        {body_html}
        <section class="comments" data-comments data-slug="{html.escape(slug)}">
          <h2>Comments</h2>
          <p>Comments are moderated before publication. Do not post secrets, tokens, customer data, or exploit payloads.</p>
          <div class="comment-list" data-comment-list></div>
          <form data-comment-form>
            <input name="name" maxlength="80" placeholder="Name or handle" required />
            <input name="email" type="email" maxlength="160" placeholder="Email for moderation only" required />
            <input name="website" tabindex="-1" autocomplete="off" style="display:none" />
            <textarea name="body" maxlength="2000"
              placeholder="Add source-backed context, a mitigation note, or a question..."
              required></textarea>
            <div class="turnstile-slot" data-turnstile></div>
            <button type="submit">Submit for moderation</button>
            <p data-comment-status></p>
          </form>
        </section>
      </article>
      <aside class="side">
        <section class="card">
          <p class="eyebrow">Operator note</p>
          <p>Source-backed posts are generated as drafts first and require explicit publishing.</p>
        </section>
      </aside>
    </main>
    <script src="/assets/comments.js" defer></script>
  </body>
</html>
"""


def publish(draft_or_slug: str, *, confirm: bool = False, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    candidate = Path(draft_or_slug)
    draft_path = candidate if candidate.exists() else _draft_path(draft_or_slug.removesuffix(".json"), paths)
    if not draft_path.exists():
        raise ValueError(f"draft not found: {draft_or_slug}")
    post = _load_json(draft_path)
    if not confirm:
        return {
            "published": False,
            "draft_path": str(draft_path),
            "message": "rerun with --publish to write public blog files",
        }
    post["status"] = "published"
    post["published_at"] = post.get("published_at") or _utc_now()
    post["updated_at"] = _utc_now()
    paths.posts.mkdir(parents=True, exist_ok=True)
    _write_json(_post_json_path(str(post["slug"]), paths), post)
    _post_html_path(str(post["slug"]), paths).write_text(
        _render_post_html(post),
        encoding="utf-8",
    )
    rebuild(paths=paths)
    return {
        "published": True,
        "post_path": str(_post_html_path(str(post["slug"]), paths)),
        "url": _post_url(str(post["slug"])),
    }


def _render_index(posts: List[Dict[str, Any]]) -> str:
    cards = []
    for post in posts:
        slug = html.escape(str(post["slug"]))
        title = html.escape(redact(post["title"]))
        summary = html.escape(redact(post.get("summary", "")))
        severity = html.escape(str(post.get("severity", "info")).title())
        tags = " ".join(
            f'<span class="pill">{html.escape(str(tag))}</span>'
            for tag in post.get("categories", [])[:5]
        )
        search = html.escape(
            " ".join(
                [
                    title,
                    summary,
                    " ".join(post.get("affected_packages", [])),
                    " ".join(post.get("iocs", [])),
                ]
            ).lower()
        )
        cards.append(
            f"""<a class="card post-card" href="/posts/{slug}.html" data-search="{search}">
          <div class="meta">
            <span class="pill critical">{severity}</span>
            <span>{html.escape(str(post.get("updated_at", "")))}</span>
          </div>
          <h2>{title}</h2>
          <p>{summary}</p>
          <div class="tags">{tags}</div>
        </a>"""
        )
    cards_html = "\n".join(cards)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SecOpsAI Security Blog</title>
    <meta name="description" content="Real-time SecOpsAI advisories, detections, mitigation steps, and incident updates." />
    <link rel="canonical" href="{BASE_URL}/" />
    <link rel="alternate" type="application/rss+xml" title="SecOpsAI Security Blog RSS" href="/feed.xml" />
    <link rel="alternate" type="application/feed+json" title="SecOpsAI Security Blog JSON Feed" href="/feed.json" />
    <link rel="icon" type="image/png" href="/assets/favicon-512.png" />
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
    <link rel="stylesheet" href="/assets/blog.css" />
  </head>
  <body>
    <header class="topbar">
      <nav class="shell nav">
        <a class="brand" href="/">
          <img class="brand-mark" src="/assets/favicon-512.png" alt="SecOpsAI icon" />
          <span class="brand-title"><span>SecOpsAI</span><span>Security Blog</span></span>
        </a>
        <div class="nav-links">
          <a href="https://secopsai.dev/">Platform</a>
          <a href="https://docs.secopsai.dev/">Docs</a>
          <a href="/feed.xml">RSS</a>
          <a href="/json-feed">JSON Feed</a>
        </div>
      </nav>
    </header>
    <main class="shell">
      <section class="hero">
        <p class="eyebrow">Live advisories • detections • mitigation</p>
        <h1>Security intelligence operators can act on quickly.</h1>
        <p class="lede">Fast incident posts from the SecOpsAI side of the console:
          affected packages, IOCs, detection logic, mitigations, timelines,
          and source-backed updates.</p>
        <div class="feed-actions">
          <a class="button" href="/feed.xml">Subscribe by RSS</a>
          <a class="button secondary" href="/json-feed">JSON Feed</a>
        </div>
      </section>
      <section class="filters card" aria-label="Search posts">
        <input id="post-search" type="search" placeholder="Search posts, tags, ecosystems, packages, or IOCs..." />
        <div class="tags">
          <span class="pill">Supply Chain</span><span class="pill">OpenClaw</span>
          <span class="pill">Detection Engineering</span><span class="pill">Malware Analysis</span>
          <span class="pill">Advisories</span><span class="pill">Mitigation</span>
        </div>
      </section>
      <section class="grid" id="posts">
        {cards_html}
        <aside class="card">
          <p class="eyebrow">Operator feed</p>
          <h2>What appears here</h2>
          <p>New SecOpsAI detections, package advisories, OpenClaw telemetry
            learnings, malware behavior cards, and practical response notes.</p>
        </aside>
      </section>
    </main>
    <footer class="footer">
      <div class="shell">SecOpsAI Security Blog • Local-first intelligence, source-backed actions.</div>
    </footer>
    <script src="/assets/blog.js" defer></script>
  </body>
</html>
"""


def _rss_date(value: str) -> str:
    try:
        parsed = time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
        return email.utils.formatdate(time.mktime(parsed), usegmt=True)
    except Exception:
        return email.utils.formatdate(time.time(), usegmt=True)


def _post_summary(post: Dict[str, Any]) -> str:
    summary = str(post.get("summary") or "").strip()
    if summary:
        return redact(summary)
    body = str(post.get("body_markdown") or "")
    body = re.sub(r"```.*?```", " ", body, flags=re.DOTALL)
    body = re.sub(r"^#+\s*", "", body, flags=re.MULTILINE)
    body = re.sub(r"\s+", " ", body).strip()
    return redact(body[:220])


def _render_json_feed_landing(posts: List[Dict[str, Any]]) -> str:
    items = "\n".join(
        f"""<article class="card">
          <p class="eyebrow">{html.escape(str(post.get("updated_at", "")))}</p>
          <h2><a href="/posts/{html.escape(str(post["slug"]))}.html">{html.escape(redact(post.get("title", "")))}</a></h2>
          <p>{html.escape(_post_summary(post))}</p>
        </article>"""
        for post in posts
    )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SecOpsAI JSON Feed</title>
    <meta name="description" content="Human-readable overview of the SecOpsAI JSON Feed." />
    <link rel="canonical" href="{BASE_URL}/json-feed" />
    <link rel="alternate" type="application/feed+json" title="SecOpsAI Security Blog JSON Feed" href="/feed.json" />
    <link rel="icon" type="image/png" href="/assets/favicon-512.png" />
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
    <link rel="stylesheet" href="/assets/blog.css" />
  </head>
  <body>
    <header class="topbar">
      <nav class="shell nav">
        <a class="brand" href="/">
          <img class="brand-mark" src="/assets/favicon-512.png" alt="SecOpsAI icon" />
          <span class="brand-title"><span>SecOpsAI</span><span>JSON Feed</span></span>
        </a>
        <div class="nav-links">
          <a href="/">Blog Home</a>
          <a href="/feed.json">Raw JSON</a>
          <a href="/feed.xml">RSS</a>
        </div>
      </nav>
    </header>
    <main class="shell">
      <section class="hero">
        <p class="eyebrow">Programmatic feed</p>
        <h1>SecOpsAI JSON Feed</h1>
        <p class="lede">This page makes the JSON feed readable in a browser.
          Feed readers and API clients can use the raw JSON endpoint.</p>
        <div class="feed-actions">
          <a class="button" href="/feed.json">Open raw JSON</a>
          <a class="button secondary" href="/feed.xml">Open RSS</a>
        </div>
      </section>
      <section class="grid">{items}</section>
    </main>
  </body>
</html>
"""


def rebuild(*, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    posts = _load_posts(paths)
    (paths.root / "index.html").write_text(_render_index(posts), encoding="utf-8")
    feed_items = []
    rss_items = []
    for post in posts:
        slug = str(post["slug"])
        url = _post_url(slug)
        if post.get("body_markdown"):
            _post_html_path(slug, paths).write_text(_render_post_html(post), encoding="utf-8")
        summary = _post_summary(post)
        feed_items.append(
            {
                "id": url,
                "url": url,
                "title": redact(post.get("title", "")),
                "summary": summary,
                "date_published": post.get("published_at"),
                "date_modified": post.get("updated_at"),
                "tags": post.get("tags") or post.get("categories") or [],
            }
        )
        rss_items.append(
            f"""    <item>
      <title>{html.escape(redact(post.get('title', '')))}</title>
      <link>{url}</link>
      <guid>{url}</guid>
      <pubDate>{_rss_date(str(post.get('published_at') or post.get('updated_at') or ''))}</pubDate>
      <description>{html.escape(summary)}</description>
    </item>"""
        )
    (paths.root / "json-feed.html").write_text(_render_json_feed_landing(posts), encoding="utf-8")
    _write_json(
        paths.root / "feed.json",
        {
            "version": "https://jsonfeed.org/version/1.1",
            "title": "SecOpsAI Security Blog",
            "home_page_url": f"{BASE_URL}/",
            "feed_url": f"{BASE_URL}/feed.json",
            "description": "Real-time SecOpsAI advisories, detections, mitigation steps, and incident updates.",
            "items": feed_items,
        },
    )
    rss_body = "\n".join(rss_items)
    rss_xml = (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<?xml-stylesheet type="text/xsl" href="/rss.xsl" ?>\n'
        '<rss version="2.0">\n'
        '  <channel>\n'
        '    <title>SecOpsAI Security Blog</title>\n'
        f'    <link>{BASE_URL}/</link>\n'
        '    <description>Real-time SecOpsAI advisories, detections, mitigation steps, '
        'and incident updates.</description>\n'
        '    <language>en-us</language>\n'
        f'    <lastBuildDate>{email.utils.formatdate(time.time(), usegmt=True)}</lastBuildDate>\n'
        f'{rss_body}\n'
        '  </channel>\n'
        '</rss>\n'
    )
    (paths.root / "feed.xml").write_text(rss_xml, encoding="utf-8")
    return {
        "posts": len(posts),
        "paths": [
            str(paths.root / "index.html"),
            str(paths.root / "json-feed.html"),
            str(paths.root / "feed.json"),
            str(paths.root / "feed.xml"),
        ],
    }


def comments_setup_status(env_names: Iterable[str]) -> Dict[str, Any]:
    required = {"SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"}
    optional = {"BLOG_COMMENTS_TABLE", "BLOG_COMMENT_IP_SALT"}
    present = set(env_names)
    return {
        "configured": required.issubset(present),
        "required_present": sorted(required & present),
        "required_missing": sorted(required - present),
        "optional_present": sorted(optional & present),
        "optional_missing": sorted(optional - present),
    }
