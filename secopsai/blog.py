from __future__ import annotations

import calendar
import copy
import email.utils
import hashlib
import html
import ipaddress
import json
import re
import shutil
import socket
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
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
NEWS_SOURCES_PATH = BLOG_DIR / "data" / "news-sources.json"
BASE_URL = "https://blog.secopsai.dev"
SOCIAL_CARD_WIDTH = 1200
SOCIAL_CARD_HEIGHT = 630
ALLOWED_MEDIA_SUFFIXES = {".avif", ".gif", ".jpg", ".jpeg", ".png", ".svg", ".webp"}
SOURCE_MEDIA_SUFFIXES = ALLOWED_MEDIA_SUFFIXES - {".svg"}
MEDIA_CONTENT_TYPE_SUFFIXES = {
    "image/avif": ".avif",
    "image/gif": ".gif",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/svg+xml": ".svg",
    "image/webp": ".webp",
}
SOURCE_MEDIA_CONTENT_TYPE_SUFFIXES = {
    media_type: suffix
    for media_type, suffix in MEDIA_CONTENT_TYPE_SUFFIXES.items()
    if suffix in SOURCE_MEDIA_SUFFIXES
}
TOPIC_SECTIONS = [
    "Security News",
    "Threat Intelligence",
    "Supply Chain",
    "Detection Engineering",
    "Mitigation",
    "OpenClaw",
    "Product Updates",
]
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|credential|authorization|bearer|refresh[_-]?token)\b"
    r"\s*[:=]\s*['\"]?[^'\"\s,;]{8,}"
)
LONG_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>)\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
NPM_SCOPED_PACKAGE_RE = re.compile(r"(?<![\w.-])@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*(?:@[\w.-]+)?", re.IGNORECASE)
VERSIONED_PACKAGE_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_.-]{1,80})@(\d+(?:\.\d+){1,3}(?:[a-zA-Z0-9_.-]+)?)\b")
KNOWN_PACKAGE_RE = re.compile(
    r"\b(?:mistralai|guardrails-ai|litellm|pydantic-ai(?:-slim)?|dnsmasq|composer|fsnotify|rubygems|npm|pypi)\b",
    re.IGNORECASE,
)
GENERIC_RECOMMENDATION_RE = re.compile(
    r"(?im)^-\s*(?:review the source|validate affected assets in your environment|add secopsai detection or mitigation commands before publishing)\.?\s*$"
)
REVIEW_CHECKLIST_SECTION_RE = re.compile(
    r"(?:^|\n)## Review Checklist\s*\n.*?(?=\n## |\Z)",
    re.DOTALL | re.IGNORECASE,
)
REVIEW_CHECKLIST_COMPLETE_STATUSES = {
    "approved",
    "checked",
    "complete",
    "completed",
    "done",
    "pass",
    "passed",
    "reviewed",
}
PUBLISHABLE_REVIEW_STATUSES = {"approved", "reviewed"}
DEPLOYED_REVIEW_STATUSES = {"deployed", "published"}
NEWS_REVIEW_STATUSES = {"needs_review", "approved", "reviewed", "rejected", *DEPLOYED_REVIEW_STATUSES}


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
    def assets(self) -> Path:
        return self.root / "assets"

    @property
    def social(self) -> Path:
        return self.assets / "social"

    def post_assets(self, slug: str) -> Path:
        return self.assets / "posts" / slug

    @property
    def news_cache(self) -> Path:
        return self.data / "news-cache.json"

    @property
    def news_sources(self) -> Path:
        return self.data / "news-sources.json"


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


def _safe_reference_list(values: Any, *, limit: int = 24) -> List[str]:
    """Normalize source/reference fields that feeds sometimes join into one string."""
    raw_values = values if isinstance(values, list) else [values]
    candidates: List[str] = []
    for value in raw_values:
        text = str(value or "").strip()
        if not text:
            continue
        urls = re.findall(r"https?://[^\s<>\"]+", text)
        if urls:
            candidates.extend(url.rstrip(".,);") for url in urls)
        else:
            candidates.extend(part.strip() for part in re.split(r"[\n,;]+", text) if part.strip())
    return [
        item
        for item in _safe_list(candidates, limit=limit)
        if urllib.parse.urlparse(item).scheme in {"http", "https"}
    ]


def _safe_text(value: Any, *, fallback: str = "") -> str:
    cleaned = re.sub(r"\s+", " ", redact(value)).strip()
    return cleaned or fallback


def _split_review_values(value: Any, *, limit: int = 24) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return _safe_list(value, limit=limit)
    parts = re.split(r"[\n,;]+", str(value or ""))
    return _safe_list(parts, limit=limit)


def _collapse_adjacent_duplicate_words(value: Any) -> str:
    text = str(value or "")
    return re.sub(r"\b([A-Z][\w.-]+)\s+\1\b", r"\1", text)


def _markdown_inline(text: str) -> str:
    escaped = html.escape(redact(text))
    escaped = re.sub(
        r"(https?://[^\s<]+)",
        lambda match: (
            f'<a class="inline-ref" href="{match.group(1).rstrip(".,);")}" '
            f'rel="noopener noreferrer" target="_blank">{match.group(1).rstrip(".,);")}</a>'
            + match.group(1)[len(match.group(1).rstrip(".,);")):]
        ),
        escaped,
    )
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


def _absolute_url(path_or_url: Any) -> str:
    value = str(path_or_url or "").strip()
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if value.startswith("/"):
        return f"{BASE_URL}{value}"
    return f"{BASE_URL}/{value.lstrip('/')}"


def _post_author(post: Dict[str, Any]) -> str:
    return str(post.get("author") or post.get("source_name") or "SecOpsAI Research")


def _post_categories(post: Dict[str, Any]) -> List[str]:
    categories = post.get("categories") or post.get("tags") or ["Detection Engineering"]
    return _safe_list(categories, limit=12) or ["Detection Engineering"]


def _post_reading_time(post: Dict[str, Any]) -> int:
    explicit = post.get("reading_time")
    try:
        if explicit:
            return max(1, int(explicit))
    except (TypeError, ValueError):
        pass
    body = str(post.get("body_markdown") or "")
    words = re.findall(r"\b[\w@./:-]+\b", f"{post.get('title', '')} {post.get('summary', '')} {body}")
    return max(1, round(len(words) / 220))


def _sanitize_public_asset_src(value: Any) -> Optional[str]:
    src = str(value or "").strip().replace("\\", "/")
    if not src or src.startswith(("/", "assets/")) is False:
        return None
    if src.startswith("assets/"):
        src = f"/{src}"
    parsed = urllib.parse.urlparse(src)
    if parsed.scheme or parsed.netloc or ".." in Path(parsed.path).parts:
        return None
    suffix = Path(parsed.path).suffix.lower()
    if suffix not in ALLOWED_MEDIA_SUFFIXES:
        return None
    if not parsed.path.startswith("/assets/"):
        return None
    return parsed.path


def _normalize_media_item(item: Any, *, fallback_alt: str, require_approved: bool = True) -> Optional[Dict[str, Any]]:
    raw = {"src": item} if isinstance(item, str) else dict(item) if isinstance(item, dict) else {}
    src = _sanitize_public_asset_src(raw.get("src") or raw.get("url"))
    if not src:
        return None
    if require_approved and raw.get("approved", True) is False:
        return None
    alt = _safe_text(raw.get("alt") or raw.get("title") or fallback_alt, fallback=fallback_alt)
    media = {
        "src": src,
        "alt": alt[:180],
        "caption": _safe_text(raw.get("caption"), fallback="")[:260],
        "source_name": _safe_text(raw.get("source_name"), fallback="")[:100],
        "source_url": str(raw.get("source_url") or "").strip(),
        "license": _safe_text(raw.get("license"), fallback="")[:80],
        "kind": _safe_text(raw.get("kind"), fallback="image")[:40],
        "width": int(raw.get("width") or SOCIAL_CARD_WIDTH),
        "height": int(raw.get("height") or SOCIAL_CARD_HEIGHT),
        "approved": True,
    }
    if urllib.parse.urlparse(media["source_url"]).scheme not in {"http", "https"}:
        media["source_url"] = ""
    return media


def _normalize_media(post: Dict[str, Any]) -> List[Dict[str, Any]]:
    fallback_alt = str(post.get("title") or "SecOpsAI blog image")
    media: List[Dict[str, Any]] = []
    for candidate in [post.get("hero_image"), *(post.get("images") if isinstance(post.get("images"), list) else [])]:
        item = _normalize_media_item(candidate, fallback_alt=fallback_alt)
        if not item:
            continue
        if item["src"] not in {existing["src"] for existing in media}:
            media.append(item)
    return media[:12]


def _primary_media(post: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    media = _normalize_media(post)
    return media[0] if media else None


def _social_card_path(slug: str, paths: BlogPaths) -> Path:
    return paths.social / f"{slug}.svg"


def _social_card_src(slug: str) -> str:
    return f"/assets/social/{slug}.svg"


def _wrap_card_text(value: Any, *, width: int = 34, lines: int = 4) -> List[str]:
    words = _safe_text(value, fallback="SecOpsAI Security Blog").split()
    output: List[str] = []
    current: List[str] = []
    for word in words:
        trial = " ".join([*current, word])
        if len(trial) > width and current:
            output.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
        if len(output) >= lines:
            break
    if current and len(output) < lines:
        output.append(" ".join(current))
    return output or ["SecOpsAI Security Blog"]


def _write_social_card(post: Dict[str, Any], paths: BlogPaths) -> str:
    slug = slugify(str(post.get("slug") or post.get("title") or "secopsai-post"))
    paths.social.mkdir(parents=True, exist_ok=True)
    title_lines = _wrap_card_text(post.get("title"), width=34, lines=4)
    severity = _safe_text(str(post.get("severity") or "info").upper(), fallback="INFO")
    category = _safe_text(", ".join(_post_categories(post)[:2]), fallback="Security Research")
    date = _post_date(post.get("published_at") or post.get("updated_at") or _utc_now())
    title_tspans = "\n".join(
        f'<tspan x="86" dy="{0 if index == 0 else 64}">{html.escape(line)}</tspan>'
        for index, line in enumerate(title_lines)
    )
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{SOCIAL_CARD_WIDTH}" height="{SOCIAL_CARD_HEIGHT}" viewBox="0 0 {SOCIAL_CARD_WIDTH} {SOCIAL_CARD_HEIGHT}" role="img" aria-label="{html.escape(_safe_text(post.get('title'), fallback='SecOpsAI Security Blog'))}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#061711"/>
      <stop offset="0.54" stop-color="#08251c"/>
      <stop offset="1" stop-color="#03100c"/>
    </linearGradient>
    <radialGradient id="glow" cx="18%" cy="18%" r="74%">
      <stop offset="0" stop-color="#2dd4a8" stop-opacity="0.55"/>
      <stop offset="1" stop-color="#2dd4a8" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1200" height="630" rx="0" fill="url(#bg)"/>
  <rect width="1200" height="630" fill="url(#glow)"/>
  <circle cx="1010" cy="112" r="190" fill="#67e8f9" opacity="0.12"/>
  <rect x="58" y="50" width="1084" height="530" rx="42" fill="#ffffff" fill-opacity="0.045" stroke="#2dd4a8" stroke-opacity="0.34"/>
  <rect x="86" y="82" width="78" height="78" rx="22" fill="#123d2f" stroke="#2dd4a8" stroke-opacity="0.5"/>
  <text x="125" y="134" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="44" font-weight="900" fill="#e5f0f7">S</text>
  <text x="184" y="116" font-family="Arial, Helvetica, sans-serif" font-size="30" font-weight="900" fill="#e5f0f7">SecOpsAI</text>
  <text x="184" y="148" font-family="Arial, Helvetica, sans-serif" font-size="18" font-weight="700" fill="#93a6b8" letter-spacing="3">SECURITY BLOG</text>
  <text x="86" y="256" font-family="Arial, Helvetica, sans-serif" font-size="58" font-weight="900" fill="#f4fbf8">{title_tspans}</text>
  <rect x="86" y="488" width="168" height="44" rx="22" fill="#2dd4a8"/>
  <text x="170" y="517" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="21" font-weight="900" fill="#03100c">{html.escape(severity)}</text>
  <text x="278" y="517" font-family="Arial, Helvetica, sans-serif" font-size="22" font-weight="700" fill="#c9d8e3">{html.escape(category)}</text>
  <text x="86" y="558" font-family="Arial, Helvetica, sans-serif" font-size="18" font-weight="700" fill="#93a6b8">blog.secopsai.dev • {html.escape(date)}</text>
</svg>
"""
    _social_card_path(slug, paths).write_text(svg, encoding="utf-8")
    return _social_card_src(slug)


def _ensure_social_image(post: Dict[str, Any], paths: BlogPaths) -> Dict[str, Any]:
    post = dict(post)
    primary = _primary_media(post)
    if primary:
        post["social_image"] = primary["src"]
        post["social_image_alt"] = primary["alt"]
        post["social_image_width"] = primary.get("width", SOCIAL_CARD_WIDTH)
        post["social_image_height"] = primary.get("height", SOCIAL_CARD_HEIGHT)
    else:
        post["social_image"] = _write_social_card(post, paths)
        post["social_image_alt"] = f"SecOpsAI social preview card for {post.get('title', 'blog post')}"
        post["social_image_width"] = SOCIAL_CARD_WIDTH
        post["social_image_height"] = SOCIAL_CARD_HEIGHT
    return post


def strip_review_checklist_section(markdown: Any) -> str:
    """Keep review workflow notes out of public post bodies."""
    cleaned = REVIEW_CHECKLIST_SECTION_RE.sub("\n", str(markdown or ""))
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _strip_redundant_public_intro(markdown: Any, *, title: Any = "") -> str:
    """Avoid repeating the rendered page title and summary inside generated posts."""
    lines = str(markdown or "").splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    title_key = slugify(_collapse_adjacent_duplicate_words(title))
    if (
        lines
        and lines[0].lstrip().startswith("# ")
        and slugify(_collapse_adjacent_duplicate_words(lines[0].lstrip()[2:])) == title_key
    ):
        lines.pop(0)
        while lines and not lines[0].strip():
            lines.pop(0)
    if lines and lines[0].strip().lower() == "## executive summary":
        next_section = len(lines)
        for index, line in enumerate(lines[1:], start=1):
            stripped = line.strip()
            if stripped.startswith("# ") or stripped.startswith("## "):
                next_section = index
                break
        lines = lines[next_section:]
        while lines and not lines[0].strip():
            lines.pop(0)
    cleaned_lines: List[str] = []
    in_references = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            in_references = stripped.lower() == "## references"
        if stripped.startswith("- Canonical URL:"):
            urls = _safe_reference_list(stripped, limit=12)
            if len(urls) > 1:
                cleaned_lines.append(f"- Canonical URL: {urls[0]}")
                cleaned_lines.append(f"- Additional references: {', '.join(urls[1:])}")
                continue
        if in_references and stripped.startswith("- "):
            urls = _safe_reference_list(stripped, limit=12)
            if len(urls) > 1:
                cleaned_lines.extend(f"- {url}" for url in urls)
                continue
        cleaned_lines.append(_collapse_adjacent_duplicate_words(line))
    return "\n".join(cleaned_lines).strip()


def _public_post(post: Dict[str, Any]) -> Dict[str, Any]:
    public = _normalize_post(post)
    public["body_markdown"] = _strip_redundant_public_intro(
        strip_review_checklist_section(public.get("body_markdown") or ""),
        title=public.get("title"),
    )
    public.pop("review_checklist", None)
    return public


def _post_severity_rank(post: Dict[str, Any]) -> int:
    return SEVERITY_RANK.get(str(post.get("severity") or "info").lower(), 0)


def _post_date(value: Any) -> str:
    text = str(value or "")
    return text[:10] if len(text) >= 10 else text


def _normalize_post(post: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(post)
    if normalized.get("title"):
        normalized["title"] = _collapse_adjacent_duplicate_words(normalized["title"])
    categories = _post_categories(normalized)
    normalized["categories"] = categories
    normalized.setdefault("tags", categories)
    normalized.setdefault("author", _post_author(normalized))
    normalized["reading_time"] = _post_reading_time(normalized)
    normalized.setdefault("featured", False)
    normalized.setdefault("related_posts", [])
    references = _safe_reference_list(normalized.get("references") or normalized.get("sources") or [], limit=16)
    normalized["references"] = references
    normalized["sources"] = references or _safe_reference_list(normalized.get("sources", []), limit=16)
    if normalized["references"]:
        normalized["canonical_url"] = normalized["references"][0]
        normalized["source_links"] = normalized["references"]
        normalized["primary_references"] = normalized["references"][:5]
    normalized.setdefault("affected_ecosystems", [])
    normalized.setdefault("affected_packages", [])
    normalized["affected_products"] = _safe_list(
        [_collapse_adjacent_duplicate_words(item) for item in normalized.get("affected_products", [])],
        limit=24,
    )
    normalized.setdefault("affected_artifacts", [])
    normalized.setdefault("iocs", [])
    normalized.setdefault("extracted", {})
    if isinstance(normalized["extracted"], dict) and isinstance(normalized["extracted"].get("products"), list):
        normalized["extracted"]["products"] = _safe_list(
            [_collapse_adjacent_duplicate_words(item) for item in normalized["extracted"]["products"]],
            limit=24,
        )
    normalized["images"] = _normalize_media(normalized)
    if normalized["images"]:
        normalized["hero_image"] = normalized["images"][0]
    else:
        normalized.pop("hero_image", None)
    normalized.pop("media_candidates", None)
    normalized.setdefault("review_checklist", [])
    normalized.setdefault("readiness_score", 0)
    normalized.setdefault("readiness_status", "needs_edits")
    normalized.setdefault("readiness_blockers", [])
    normalized.setdefault("readiness_warnings", [])
    return normalized


def _badge_class(severity: Any) -> str:
    value = str(severity or "info").lower()
    if value in {"critical", "high", "medium", "low", "info"}:
        return value
    return "info"


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
        "author": "SecOpsAI Research",
        "source_name": "SecOpsAI",
        "reading_time": 1,
        "featured": False,
        "related_posts": [],
        "status": "draft",
        "sources": _safe_list(sources or [], limit=12),
        "references": _safe_list(sources or [], limit=12),
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
            "affected_artifacts": [
                {
                    "ecosystem": item.get("ecosystem", ""),
                    "package": item.get("package", ""),
                    "versions": item.get("versions", []),
                }
                for item in affected
                if isinstance(item, dict)
            ],
            "iocs": _safe_list(ioc_values),
            "featured": True,
            "author": "SecOpsAI Threat Research",
            "source_name": "SecOpsAI Advisory Engine",
            "references": _safe_list(advisory.get("source_urls", []), limit=12),
            "body_markdown": redact(body),
        }
    )
    post["reading_time"] = _post_reading_time(post)
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
            "author": "SecOpsAI SOC",
            "source_name": str(finding.get("source") or "SecOpsAI SOC"),
            "references": post.get("sources", []),
            "body_markdown": redact(body),
        }
    )
    post["reading_time"] = _post_reading_time(post)
    _write_json(_draft_path(post["slug"], paths), post)
    return {"draft_path": str(_draft_path(post["slug"], paths)), "post": post}


def _campaign_from_source(campaign: str) -> Dict[str, Any]:
    candidate = Path(campaign)
    if candidate.exists():
        payload = _load_json(candidate)
        if not isinstance(payload, dict):
            raise ValueError("campaign input must be a JSON object")
        return payload
    for advisory in load_advisories():
        if campaign in {advisory.get("campaign_id"), advisory.get("advisory_id")}:
            return {
                "campaign_id": advisory.get("campaign_id") or advisory.get("advisory_id"),
                "title": advisory.get("title"),
                "summary": advisory.get("summary"),
                "severity": advisory.get("severity", "critical"),
                "confidence": advisory.get("confidence", "high"),
                "source_urls": advisory.get("source_urls", []),
                "source_names": advisory.get("source_names", []),
                "iocs": advisory.get("iocs", {}),
                "behavioral_indicators": advisory.get("detection_rationale", []),
                "packages": [
                    {
                        "ecosystem": item.get("ecosystem", ""),
                        "package": item.get("package", ""),
                        "version": ", ".join(str(v) for v in item.get("versions", [])) or "range-listed",
                        "advisory_matches": [{"campaign_id": advisory.get("campaign_id"), "advisory_id": advisory.get("advisory_id")}],
                        "package_verdict": "likely_true_positive",
                        "confidence": advisory.get("confidence", "high"),
                        "environment_impact": {"status": "unknown"},
                        "behavioral_indicators": advisory.get("detection_rationale", []),
                        "recommended_mitigation": advisory.get("remediation", []),
                    }
                    for item in advisory.get("affected", [])
                    if isinstance(item, dict)
                ],
                "recommended_mitigation": advisory.get("remediation", []),
                "references": advisory.get("source_urls", []),
            }
    raise ValueError(f"No campaign found: {campaign}")


def draft_campaign(
    campaign: Optional[str] = None,
    *,
    campaign_data: Optional[Dict[str, Any]] = None,
    paths: Optional[BlogPaths] = None,
) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    payload = campaign_data or _campaign_from_source(campaign or "")
    campaign_id = str(payload.get("campaign_id") or "supply-chain-campaign")
    title = str(payload.get("title") or campaign_id.replace("-", " ").title())
    summary = str(payload.get("blog_ready_summary") or payload.get("summary") or title)
    packages = [item for item in payload.get("packages", []) if isinstance(item, dict)]
    iocs = payload.get("iocs", {})
    ioc_values: List[str] = []
    if isinstance(iocs, dict):
        for values in iocs.values():
            if isinstance(values, list):
                ioc_values.extend(str(value) for value in values)
    package_lines = [
        "| Ecosystem | Package | Version | Verdict | Local impact |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in packages:
        impact = item.get("environment_impact", {})
        impact_status = str(impact.get("status") or "unknown") if isinstance(impact, dict) else "unknown"
        package_lines.append(
            "| {eco} | `{pkg}` | `{ver}` | {verdict} | {impact} |".format(
                eco=redact(str(item.get("ecosystem") or "")),
                pkg=redact(str(item.get("package") or "")),
                ver=redact(str(item.get("version") or "")),
                verdict=redact(str(item.get("package_verdict") or "needs_review")),
                impact=redact(impact_status),
            )
        )
    detected = sorted(set(
        str(indicator)
        for item in packages
        for indicator in item.get("behavioral_indicators", [])
        if indicator
    ))
    if not detected:
        detected = [str(item) for item in payload.get("behavioral_indicators", []) if item]
    mitigation = _safe_list(payload.get("recommended_mitigation", []), limit=20)
    refs = _safe_list(payload.get("references") or payload.get("source_urls") or [], limit=12)
    env_impact = payload.get("environment_impact", {})
    env_status = str(env_impact.get("status") or "unknown") if isinstance(env_impact, dict) else "unknown"
    body = f"""# {title}

## Executive Summary

{summary}

## Campaign Overview

- Campaign id: `{campaign_id}`
- Severity: `{payload.get('severity', 'critical')}`
- Confidence: `{payload.get('confidence', 'medium')}`
- Campaign verdict: `{payload.get('campaign_verdict') or payload.get('package_verdict') or 'needs_review'}`
- Environment impact: `{env_status}`

## Affected Packages

{chr(10).join(package_lines)}

## What SecOpsAI Detected

{chr(10).join(f'- {redact(item)}' for item in _safe_list(detected, limit=16)) or '- Review campaign package evidence before publishing.'}

## IOCs

{chr(10).join(f'- `{redact(item)}`' for item in _safe_list(ioc_values, limit=24)) or '- No structured IOCs attached.'}

## Environment Impact Guidance

Absence of local usage lowers local exposure, but it does not downgrade package-level maliciousness when advisory or behavioral evidence is strong.

## Recommended Actions

{chr(10).join(f'- {redact(item)}' for item in mitigation) or '- Block affected package versions, inspect lockfiles and caches, and rotate credentials if installation or execution is confirmed.'}

## Operator Commands

```bash
secopsai supply-chain research-campaign --campaign-id {campaign_id} --dry-run --json
secopsai triage summary
secopsai blog draft-campaign --campaign {campaign_id}
```

## References

{chr(10).join(f'- {source}' for source in refs)}
"""
    post = _base_post(
        title=title,
        summary=summary,
        severity=str(payload.get("severity") or "critical"),
        categories=["Supply Chain", "Threat Intelligence", "Mitigation"],
        sources=refs,
        slug=slugify(f"{campaign_id}-{title}"),
    )
    post.update(
        {
            "affected_ecosystems": _safe_list(payload.get("ecosystems") or [item.get("ecosystem", "") for item in packages]),
            "affected_packages": _safe_list([item.get("package", "") for item in packages]),
            "affected_artifacts": [
                {
                    "ecosystem": item.get("ecosystem", ""),
                    "package": item.get("package", ""),
                    "version": item.get("version", ""),
                    "verdict": item.get("package_verdict", "needs_review"),
                }
                for item in packages
            ],
            "iocs": _safe_list(ioc_values, limit=50),
            "featured": False,
            "external_news": bool(payload.get("source_urls")),
            "review_status": "needs_review",
            "author": "SecOpsAI Threat Research",
            "source_name": "SecOpsAI Campaign Research",
            "references": refs,
            "campaign_id": campaign_id,
            "campaign_verdict": payload.get("campaign_verdict") or payload.get("package_verdict"),
            "body_markdown": redact(body),
        }
    )
    post["reading_time"] = _post_reading_time(post)
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


def _source_media_host_is_blocked(hostname: str) -> bool:
    host = hostname.strip().strip("[]").rstrip(".").lower()
    if not host:
        return True
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(
        (
            address.is_loopback,
            address.is_private,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def _source_media_resolves_to_blocked_address(hostname: str, port: int) -> bool:
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError:
        # Keep URL parsing deterministic in offline tests; urllib will still fail if the
        # host cannot be resolved when an operator actually attaches the image.
        return False
    for result in results:
        address = result[4][0]
        if _source_media_host_is_blocked(address):
            return True
    return False


def _safe_source_media_url(value: Any, *, base_url: str = "", for_fetch: bool = False) -> str:
    raw = html.unescape(str(value or "")).strip()
    if not raw:
        return ""
    if base_url:
        raw = urllib.parse.urljoin(base_url, raw)
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    if _source_media_host_is_blocked(parsed.hostname or ""):
        return ""
    suffix = Path(parsed.path).suffix.lower()
    if suffix and suffix not in SOURCE_MEDIA_SUFFIXES:
        return ""
    if for_fetch:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if _source_media_resolves_to_blocked_address(parsed.hostname or "", port):
            return ""
    return raw


def _dedupe_media_candidates(candidates: Iterable[Dict[str, Any]], *, limit: int = 8) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    deduped: List[Dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        src = _safe_source_media_url(candidate.get("src") or candidate.get("url"), base_url=str(candidate.get("source_url") or ""))
        if not src or src in seen:
            continue
        seen.add(src)
        deduped.append({
            "src": src,
            "alt": _safe_text(candidate.get("alt") or candidate.get("title"), fallback="Source image")[:180],
            "caption": _safe_text(candidate.get("caption"), fallback="")[:260],
            "source_name": _safe_text(candidate.get("source_name"), fallback="External source")[:120],
            "source_url": _safe_text(candidate.get("source_url"), fallback="")[:600],
            "approved": False,
            "kind": _safe_text(candidate.get("kind"), fallback="source-candidate")[:40],
        })
        if len(deduped) >= limit:
            break
    return deduped


def _extract_meta_content(text: str, names: Iterable[str]) -> List[str]:
    wanted = {name.lower() for name in names}
    values: List[str] = []
    for match in re.finditer(r"<meta\b[^>]*>", text, flags=re.IGNORECASE):
        tag = match.group(0)
        attrs = {
            attr.lower(): html.unescape(value)
            for attr, value in re.findall(r"""([\w:-]+)\s*=\s*["']([^"']+)["']""", tag)
        }
        key = str(attrs.get("property") or attrs.get("name") or attrs.get("itemprop") or "").lower()
        content = str(attrs.get("content") or "").strip()
        if key in wanted and content:
            values.append(content)
    return values


def _json_ld_image_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {"image", "thumbnail", "thumbnailurl"}:
                if isinstance(child, str):
                    yield child
                elif isinstance(child, dict):
                    url = child.get("url") or child.get("@id")
                    if url:
                        yield str(url)
                elif isinstance(child, list):
                    for item in child:
                        yield from _json_ld_image_values({"image": item})
            else:
                yield from _json_ld_image_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _json_ld_image_values(child)


def _extract_source_page_media_candidates(item: Dict[str, Any], *, limit: int = 6) -> List[Dict[str, Any]]:
    url = str(item.get("canonical_url") or item.get("url") or "").strip()
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        return []
    try:
        text = _fetch_text(url)
    except Exception:
        return []
    title = str(item.get("title") or "Source image")
    source_name = str(item.get("source_name") or urllib.parse.urlparse(url).netloc or "External source")
    raw_urls = _extract_meta_content(text, ("og:image", "og:image:url", "twitter:image", "twitter:image:src", "image"))
    for match in re.finditer(r"""<script\b[^>]*type=["']application/ld\+json["'][^>]*>(.*?)</script>""", text, flags=re.IGNORECASE | re.DOTALL):
        try:
            payload = json.loads(html.unescape(match.group(1)).strip())
        except Exception:
            continue
        raw_urls.extend(_json_ld_image_values(payload))
    candidates = [
        {
            "src": media_url,
            "alt": title,
            "caption": f"Source image candidate from {source_name}",
            "source_name": source_name,
            "source_url": url,
            "approved": False,
            "kind": "source-image",
        }
        for media_url in raw_urls
    ]
    return _dedupe_media_candidates(candidates, limit=limit)


def _strip_markup(value: Any) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _news_text_blob(item: Dict[str, Any]) -> str:
    tags = item.get("tags", [])
    tag_text = " ".join(str(tag) for tag in tags) if isinstance(tags, list) else str(tags or "")
    return " ".join(
        str(value or "")
        for value in (
            item.get("title"),
            item.get("summary"),
            item.get("category"),
            tag_text,
            item.get("source_name"),
        )
    )


def _domain_from_url(value: str) -> str:
    try:
        return urllib.parse.urlparse(value).netloc.lower().removeprefix("www.")
    except Exception:
        return ""


def _extract_products(text: str) -> List[str]:
    products: List[str] = []
    kev_match = re.search(r"\bCISA KEV:\s*(.+?)(?:\s+CVE-\d{4}-\d{4,7}|$)", text, re.IGNORECASE)
    if kev_match:
        products.extend(part.strip(" ,:-") for part in re.split(r"\s{2,}|/", kev_match.group(1)) if part.strip(" ,:-"))
    known_products = (
        "GitHub Actions",
        "Cloudflare",
        "Composer",
        "Packagist",
        "RubyGems",
        "Docker",
        "OAuth",
        "OpenSearch",
        "LiteLLM",
        "dnsmasq",
        "TanStack",
    )
    lower = text.lower()
    products.extend(product for product in known_products if product.lower() in lower)
    return _safe_list(products, limit=16)


def _infer_ecosystems(text: str, packages: List[str], domains: List[str]) -> List[str]:
    lower = text.lower()
    ecosystems: List[str] = []
    checks = [
        ("npm", ("npm", "node package", "javascript package")),
        ("pypi", ("pypi", "python package", "pip ")),
        ("github", ("github", "github actions", "github advisory")),
        ("docker", ("docker", "container image", "oci image")),
        ("rubygems", ("rubygems", "ruby gems", "gemstuffer", ".gem")),
        ("composer", ("composer", "packagist", "php package")),
        ("go", ("golang", "go module", "fsnotify")),
    ]
    for ecosystem, needles in checks:
        if any(needle in lower for needle in needles):
            ecosystems.append(ecosystem)
    if any(package.startswith("@") for package in packages):
        ecosystems.append("npm")
    if any(domain in {"npmjs.com", "npmjs.org"} for domain in domains):
        ecosystems.append("npm")
    if any(domain in {"pypi.org", "python.org"} for domain in domains):
        ecosystems.append("pypi")
    return _safe_list(ecosystems, limit=12)


def extract_news_security_fields(item: Dict[str, Any]) -> Dict[str, List[str]]:
    text = _news_text_blob(item)
    urls = _safe_list(URL_RE.findall(text), limit=16)
    domains = _safe_list([_domain_from_url(url) for url in urls], limit=16)
    domains = _safe_list([*domains, *DOMAIN_RE.findall(text)], limit=16)
    ips = _safe_list(IP_RE.findall(text), limit=16)
    hashes = _safe_list(HASH_RE.findall(text), limit=16)
    scoped_packages = NPM_SCOPED_PACKAGE_RE.findall(text)
    versioned_packages = [match.group(0) for match in VERSIONED_PACKAGE_RE.finditer(text)]
    known_packages = KNOWN_PACKAGE_RE.findall(text)
    packages = _safe_list([*scoped_packages, *versioned_packages, *known_packages], limit=24)
    cves = _safe_list([match.upper() for match in CVE_RE.findall(text)], limit=16)
    signals = _safe_list(_severity_signals(text), limit=16)
    products = _extract_products(text)
    ecosystems = _infer_ecosystems(text, packages, domains)
    return {
        "cves": cves,
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "hashes": hashes,
        "packages": packages,
        "ecosystems": ecosystems,
        "products": products,
        "severity_signals": signals,
    }


def _severity_signals(text: str) -> List[str]:
    lower = text.lower()
    checks = [
        ("CISA KEV", ("cisa kev", "known exploited vulnerabilities", "known exploited vulnerability")),
        ("active exploitation", ("active exploitation", "exploited in the wild", "actively exploited")),
        ("compromised package", ("compromised package", "package compromise", "compromised npm", "compromised pypi")),
        ("credential theft", ("credential theft", "stealing credentials", "token leak", "credential leak", "secret leakage")),
        ("RCE", ("remote code execution", " rce", "code execution")),
        ("SQL injection", ("sql injection",)),
        ("supply-chain attack", ("supply-chain attack", "supply chain attack", "supply chain concerns")),
        ("malware", ("malware", "trojan", "backdoor")),
        ("zero-day", ("zero-day", "0-day")),
    ]
    return [label for label, needles in checks if any(needle in lower for needle in needles)]


def infer_news_severity(item: Dict[str, Any], extracted: Dict[str, List[str]]) -> tuple[str, str]:
    current = str(item.get("severity") or "info").lower()
    severity = current if current in SEVERITY_RANK else "info"
    reason = "Default source severity."
    signals = set(extracted.get("severity_signals", []))
    text = _news_text_blob(item).lower()
    source_name = str(item.get("source_name") or "").lower()
    category = str(item.get("category") or "").lower()
    if "CISA KEV" in signals or "active exploitation" in signals or "known exploited" in text:
        severity, reason = "high", "CISA KEV or active exploitation signal."
    elif {"compromised package", "credential theft", "malware", "supply-chain attack"} & signals:
        severity, reason = "high", "Compromise, credential-theft, malware, or supply-chain signal."
    elif "RCE" in signals:
        severity, reason = "high", "Remote code execution signal."
    elif "SQL injection" in signals and any(word in text for word in ("credential", "proxy", "admin", "database")):
        severity, reason = "high", "SQL injection signal affects sensitive service or data."
    elif "company news" in category or any(word in text for word in ("named to", "award", "funding", "startup")):
        severity, reason = "info", "Company/news update without direct operator exposure."
    elif extracted.get("cves") or "vulnerability" in text or "security" in source_name:
        severity, reason = max(severity, "medium", key=lambda value: SEVERITY_RANK.get(value, 0)), "Security-relevant vulnerability/news signal."
    return severity, reason


def _news_context_kind(extracted: Dict[str, List[str]], item: Dict[str, Any]) -> str:
    text = _news_text_blob(item).lower()
    signals = set(extracted.get("severity_signals", []))
    if any(needle in text for needle in ("oauth", "token", "credential", "non-human identit", "oidc")):
        return "identity"
    if extracted.get("packages") or extracted.get("ecosystems") or "supply-chain attack" in signals or "compromised package" in signals:
        return "supply_chain"
    if extracted.get("ips") or extracted.get("hashes") or extracted.get("urls") or "malware" in signals:
        return "malware"
    if extracted.get("cves") or "CISA KEV" in signals or "vulnerability" in text:
        return "vulnerability"
    return "general"


def _secopsai_detection_context(kind: str) -> str:
    contexts = {
        "vulnerability": (
            "SecOpsAI can track affected product names, related CVEs, local SOC findings, "
            "advisory matches, and OpenClaw telemetry that mention this vulnerability or impacted component."
        ),
        "supply_chain": (
            "SecOpsAI can compare affected package names and versions against emergency advisories, "
            "lockfiles, package manifests, package registry changes, and supply-chain SOC findings."
        ),
        "malware": (
            "SecOpsAI can track listed IOCs, suspicious URLs/domains/IPs, file paths, hashes, process "
            "behavior, and matching OpenClaw replay telemetry."
        ),
        "identity": (
            "SecOpsAI can help operators review token exposure, credential-rotation tasks, CI/CD workflow "
            "risk, and SOC findings related to secret leakage or suspicious authentication activity."
        ),
        "general": (
            "SecOpsAI can turn this source-backed item into a triage task, link it to local SOC findings, "
            "and track any source-backed detections or mitigations added during review."
        ),
    }
    return contexts.get(kind, contexts["general"])


def _recommended_actions(kind: str, extracted: Dict[str, List[str]]) -> List[str]:
    if kind == "vulnerability":
        actions = [
            "Inventory affected product or component names from the source.",
            "Check whether exposed systems, dependencies, or services use the affected component.",
            "Prioritize vendor mitigation or patch guidance and record the remediation deadline.",
            "Add monitoring terms for extracted CVEs and product names.",
        ]
    elif kind == "supply_chain":
        actions = [
            "Block affected package names or versions when source-backed version details are available.",
            "Inspect lockfiles, manifests, and CI dependency caches for affected package references.",
            "Rotate package-manager, CI, and registry credentials if compromise or token theft is reported.",
            "Run SecOpsAI supply-chain advisory checks for extracted package names.",
        ]
    elif kind == "malware":
        actions = [
            "Search telemetry for extracted domains, IPs, URLs, hashes, and file names.",
            "Block source-backed indicators where appropriate for your environment.",
            "Investigate matching endpoints and preserve relevant artifacts before cleanup.",
            "Create a SecOpsAI/OpenClaw triage task for any local indicator match.",
        ]
    elif kind == "identity":
        actions = [
            "Rotate affected tokens or credentials if exposure is plausible.",
            "Review GitHub Actions, OIDC trust relationships, OAuth grants, and cloud roles.",
            "Check audit logs for suspicious use of impacted credentials or identities.",
            "Tighten token scopes and remove stale non-human identities where possible.",
        ]
    else:
        actions = [
            "Compare the source-backed claim against local assets and current SOC findings.",
            "Create a follow-up triage task if the affected technology is present.",
            "Document whether this item requires a new advisory, detection, or mitigation note.",
        ]
    if extracted.get("cves"):
        actions.append(f"Track extracted CVEs: {', '.join(extracted['cves'][:4])}.")
    if extracted.get("packages"):
        actions.append(f"Review extracted package references: {', '.join(extracted['packages'][:4])}.")
    return _safe_list(actions, limit=8)


def _review_checklist() -> List[Dict[str, str]]:
    labels = [
        "Main claim is supported by source",
        "Affected product/package/CVE is named or explicitly marked not found",
        "IOCs are present or explicitly marked none found",
        "Recommended actions are specific",
        "SecOpsAI detection/mitigation angle is added",
        "No copied external article text",
    ]
    return [{"label": label, "status": "needs_review"} for label in labels]


def _normalise_review_checklist(checklist: Any) -> List[Dict[str, str]]:
    if not isinstance(checklist, list) or not checklist:
        return _review_checklist()
    normalised: List[Dict[str, str]] = []
    for item in checklist:
        if isinstance(item, dict):
            label = str(item.get("label") or "").strip()
            status = str(item.get("status") or "needs_review").strip().lower()
        else:
            label = str(item or "").strip()
            status = "needs_review"
        if label:
            normalised.append({"label": label, "status": status or "needs_review"})
    return normalised or _review_checklist()


def _set_review_checklist_status(post: Dict[str, Any], status: str) -> None:
    if not post.get("external_news"):
        return
    if status in PUBLISHABLE_REVIEW_STATUSES | DEPLOYED_REVIEW_STATUSES:
        checklist_status = "completed"
    elif status == "rejected":
        checklist_status = "rejected"
    else:
        checklist_status = "needs_review"
    post["review_checklist"] = [
        {"label": item["label"], "status": checklist_status}
        for item in _normalise_review_checklist(post.get("review_checklist"))
    ]


def review_checklist_publish_blockers(post: Dict[str, Any]) -> List[str]:
    if not post.get("external_news"):
        return []
    checklist = _normalise_review_checklist(post.get("review_checklist"))
    incomplete = [
        item["label"]
        for item in checklist
        if item.get("status", "").lower() not in REVIEW_CHECKLIST_COMPLETE_STATUSES
    ]
    if not incomplete:
        return []
    shown = ", ".join(incomplete[:3])
    if len(incomplete) > 3:
        shown += f", and {len(incomplete) - 3} more"
    return [f"review checklist incomplete: {shown}"]


def _markdown_list(values: Iterable[Any], *, empty: str) -> str:
    items = _safe_list(values, limit=24)
    if not items:
        return f"- {empty}"
    return "\n".join(f"- {item}" for item in items)


def _source_summary(item: Dict[str, Any], summary: str, title: str) -> str:
    clean_summary = re.sub(r"\s+", " ", redact(summary)).strip()
    clean_title = re.sub(r"\s+", " ", redact(title)).strip()
    if clean_summary and clean_summary.lower() != clean_title.lower():
        return clean_summary
    source_name = str(item.get("source_name") or "external source")
    return (
        f"{source_name} reports a security-relevant update titled \"{clean_title}\". "
        "Operators should validate the source details, map any affected assets, and add SecOpsAI-specific detections or mitigations before publication."
    )


def load_news_sources(*, paths: Optional[BlogPaths] = None) -> List[Dict[str, Any]]:
    paths = paths or BlogPaths()
    if not paths.news_sources.exists():
        return []
    payload = _load_json(paths.news_sources)
    sources = payload.get("sources", payload if isinstance(payload, list) else [])
    if not isinstance(sources, list):
        return []
    return [source for source in sources if isinstance(source, dict)]


def _normalise_news_item(raw: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    title = _collapse_adjacent_duplicate_words(redact(_strip_markup(raw.get("title") or "Security news item")))
    raw_url = str(raw.get("url") or raw.get("link") or source.get("url") or source.get("feed_url") or "").strip()
    source_links = _safe_reference_list(raw.get("source_links") or [raw_url], limit=12)
    url = source_links[0] if source_links else raw_url
    if url.startswith("/"):
        parsed_source = urllib.parse.urlparse(str(source.get("url") or source.get("feed_url") or ""))
        url = f"{parsed_source.scheme}://{parsed_source.netloc}{url}" if parsed_source.netloc else url
    summary = redact(_strip_markup(raw.get("summary") or raw.get("description") or title))
    source_name = str(source.get("name") or raw.get("source_name") or urllib.parse.urlparse(url).netloc or "External source")
    category = str(raw.get("category") or source.get("category") or "Security News")
    source_tags = source.get("default_tags", []) if isinstance(source.get("default_tags", []), list) else []
    raw_tags = raw.get("tags", []) if isinstance(raw.get("tags", []), list) else []
    tags = _safe_list([category, *source_tags, *raw_tags], limit=12)
    key = _source_key(url, title)
    media_candidates = _dedupe_media_candidates(raw.get("media_candidates", []) if isinstance(raw.get("media_candidates", []), list) else [])
    return {
        "key": key,
        "title": title,
        "url": url,
        "canonical_url": url,
        "source_name": source_name,
        "source_url": str(source.get("url") or source.get("feed_url") or url),
        "source_links": source_links or ([url] if url else []),
        "source_type": str(source.get("type") or "rss"),
        "category": category,
        "tags": tags,
        "summary": summary[:500],
        "published_at": str(raw.get("published_at") or raw.get("published") or raw.get("date") or ""),
        "fetched_at": _utc_now(),
        "severity": str(raw.get("severity") or source.get("default_severity") or "info"),
        "trust_level": str(source.get("trust_level") or "external"),
        "review_status": "new",
        "media_candidates": media_candidates[:8],
    }


def _parse_rss_items(text: str, source: Dict[str, Any], *, limit: int) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError:
        return items
    channel_items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    for item in channel_items[:limit]:
        def first_text(*names: str) -> str:
            for name in names:
                found = item.find(name)
                if found is not None and found.text:
                    return found.text
            return ""
        atom_link = item.find("{http://www.w3.org/2005/Atom}link")
        link = first_text("link", "{http://www.w3.org/2005/Atom}id")
        if atom_link is not None and atom_link.get("href"):
            link = atom_link.get("href", "")
        media_candidates: List[Dict[str, Any]] = []
        for enclosure in item.findall("enclosure"):
            url = enclosure.get("url", "")
            media_type = enclosure.get("type", "")
            if url and media_type.startswith("image/"):
                media_candidates.append({
                    "src": url,
                    "alt": first_text("title", "{http://www.w3.org/2005/Atom}title"),
                    "source_name": source.get("name", ""),
                    "source_url": link,
                    "approved": False,
                    "kind": "source-candidate",
                })
        for media in [
            *item.findall("{http://search.yahoo.com/mrss/}content"),
            *item.findall("{http://search.yahoo.com/mrss/}thumbnail"),
        ]:
            url = media.get("url", "")
            if url:
                media_candidates.append({
                    "src": url,
                    "alt": media.get("title") or first_text("title", "{http://www.w3.org/2005/Atom}title"),
                    "source_name": source.get("name", ""),
                    "source_url": link,
                    "approved": False,
                    "kind": "source-candidate",
                })
        items.append(_normalise_news_item({
            "title": first_text("title", "{http://www.w3.org/2005/Atom}title"),
            "url": link,
            "summary": first_text("description", "summary", "{http://www.w3.org/2005/Atom}summary"),
            "published_at": first_text("pubDate", "published", "{http://www.w3.org/2005/Atom}published", "{http://www.w3.org/2005/Atom}updated"),
            "media_candidates": media_candidates,
        }, source))
    return items


def _walk_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _parse_html_items(text: str, source: Dict[str, Any], *, limit: int) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    next_data = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', text, re.DOTALL)
    if next_data:
        try:
            payload = json.loads(html.unescape(next_data.group(1)))
            seen: set[str] = set()
            for node in _walk_dicts(payload):
                if not {"slug", "title"} <= set(node):
                    continue
                if not node.get("publishedAt"):
                    continue
                slug = str(node.get("slug") or "")
                title = str(node.get("title") or "")
                if not slug or not title or slug in seen:
                    continue
                seen.add(slug)
                categories = [
                    category.get("title", "")
                    for category in node.get("categories", [])
                    if isinstance(category, dict)
                ]
                authors = [
                    author.get("name", "")
                    for author in node.get("authors", [])
                    if isinstance(author, dict)
                ]
                items.append(_normalise_news_item({
                    "title": title,
                    "url": f"https://socket.dev/blog/{slug}" if "socket.dev" in str(source.get("url")) else slug,
                    "summary": node.get("description") or title,
                    "published_at": node.get("publishedAt", ""),
                    "tags": categories,
                    "source_name": ", ".join(_safe_list(authors, limit=3)),
                    "category": categories[0] if categories else source.get("category", "Security News"),
                }, source))
                if len(items) >= limit:
                    return items
        except Exception:
            pass
    for match in re.finditer(r'href="([^"]*/blog/[^"]+)".{0,900}?>([^<>]{12,180})<', text, re.DOTALL):
        if len(items) >= limit:
            break
        items.append(_normalise_news_item({
            "title": match.group(2),
            "url": match.group(1),
            "summary": "External security-news item queued for analyst review.",
        }, source))
    return items


def _parse_json_items(text: str, source: Dict[str, Any], *, limit: int) -> List[Dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        items = []
        for item in payload["vulnerabilities"][:limit]:
            if not isinstance(item, dict):
                continue
            vendor = str(item.get("vendorProject") or "").strip()
            product = str(item.get("product") or "").strip()
            product_label = vendor if vendor.lower() == product.lower() else " ".join(part for part in [vendor, product] if part)
            notes = item.get("notes") or "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            items.append(_normalise_news_item({
                "title": f"CISA KEV: {product_label} {item.get('cveID', '')}".strip(),
                "url": (_safe_reference_list(notes, limit=1) or [str(notes)])[0],
                "source_links": _safe_reference_list(notes, limit=8),
                "summary": item.get("shortDescription") or item.get("vulnerabilityName") or "",
                "published_at": item.get("dateAdded") or "",
                "tags": ["CISA KEV", item.get("cveID", "")],
                "severity": "high",
            }, source))
        return items
    return []


def _parse_news_items(text: str, source: Dict[str, Any], *, limit: int) -> List[Dict[str, Any]]:
    source_type = str(source.get("type") or "rss").lower()
    stripped = text.lstrip()
    if source_type == "json" or stripped.startswith("{"):
        return _parse_json_items(text, source, limit=limit)
    if source_type == "html" or "<html" in stripped[:500].lower():
        return _parse_html_items(text, source, limit=limit)
    return _parse_rss_items(text, source, limit=limit)


def news_sources_list(*, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    sources = load_news_sources(paths=paths)
    return {
        "sources": sources,
        "total": len(sources),
        "enabled": sum(1 for source in sources if source.get("enabled", True)),
    }


def _news_source_rank(source: Dict[str, Any]) -> int:
    trust = str(source.get("trust_level") or source.get("source_kind") or "").lower()
    name = str(source.get("name") or "").lower()
    if "secopsai" in name or trust in {"first_party", "internal"}:
        return 0
    if trust in {"government", "standards"}:
        return 1
    if trust in {"vendor", "primary", "project"}:
        return 2
    if trust in {"external_research", "research"}:
        return 3
    if trust in {"aggregator", "news"}:
        return 4
    return 5


def news_fetch(*, limit: int = 20, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    cache = _read_news_cache(paths)
    cached_by_key = {item.get("key"): item for item in cache.get("items", []) if isinstance(item, dict)}
    enabled_sources = [source for source in load_news_sources(paths=paths) if source.get("enabled", True)]
    per_source_limit = max(3, min(max(limit, 1), 8))
    candidates_by_key: Dict[str, Dict[str, Any]] = {}
    errors: List[Dict[str, str]] = []
    for source in enabled_sources:
        source_url = str(source.get("feed_url") or source.get("url") or "")
        if not source_url:
            continue
        try:
            text = _fetch_text(source_url)
            parsed_items = _parse_news_items(text, source, limit=per_source_limit)
            for item in parsed_items:
                if item["key"] in cached_by_key or item["key"] in candidates_by_key:
                    continue
                item["_source_rank"] = _news_source_rank(source)
                item["_source_group"] = str(source.get("name") or item.get("source_name") or source_url)
                candidates_by_key[item["key"]] = item
        except Exception as exc:
            errors.append({"source": str(source.get("name") or source_url), "error": str(exc)})
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for item in candidates_by_key.values():
        groups.setdefault(str(item.get("_source_group") or item.get("source_name") or item.get("source_url") or "unknown"), []).append(item)
    for values in groups.values():
        values.sort(key=lambda item: str(item.get("published_at") or item.get("fetched_at") or ""), reverse=True)
    ordered_sources = sorted(
        groups,
        key=lambda name: (
            min(int(item.get("_source_rank", 5)) for item in groups[name]),
            name.lower(),
        ),
    )
    created = []
    while len(created) < limit and ordered_sources:
        progressed = False
        for source_name in ordered_sources:
            if len(created) >= limit:
                break
            if groups[source_name]:
                created.append(groups[source_name].pop(0))
                progressed = True
        ordered_sources = [name for name in ordered_sources if groups[name]]
        if not progressed:
            break
    for item in created:
        item.pop("_source_rank", None)
        item.pop("_source_group", None)
        cached_by_key[item["key"]] = item
    cache["items"] = sorted(cached_by_key.values(), key=lambda item: str(item.get("published_at") or item.get("fetched_at") or ""), reverse=True)
    cache["updated_at"] = _utc_now()
    _write_news_cache(paths, cache)
    return {"created": len(created), "cached": len(cache["items"]), "errors": errors, "items": created}


def _draft_from_news_item(item: Dict[str, Any], *, paths: BlogPaths) -> Dict[str, Any]:
    title = str(item.get("title") or "Security news item")
    link = str(item.get("canonical_url") or item.get("url") or "")
    summary = _source_summary(item, str(item.get("summary") or title), title)
    category = str(item.get("category") or "Security News")
    extracted = extract_news_security_fields(item)
    severity, severity_reason = infer_news_severity(item, extracted)
    context_kind = _news_context_kind(extracted, item)
    detection_context = _secopsai_detection_context(context_kind)
    actions = _recommended_actions(context_kind, extracted)
    references = _safe_reference_list([link, *item.get("source_links", [])] if isinstance(item.get("source_links"), list) else [link], limit=12)
    primary_references = _safe_reference_list([link], limit=5)
    canonical_for_body = references[0] if references else link
    source_trust_level = str(item.get("trust_level") or item.get("source_trust_level") or "external")
    source_category = str(item.get("category") or "Security News")
    slug_value = slugify(f"news-{item.get('key', '')}-{title}")
    extracted_iocs = _safe_list(
        [
            *extracted.get("urls", []),
            *extracted.get("domains", []),
            *extracted.get("ips", []),
            *extracted.get("hashes", []),
        ],
        limit=24,
    )
    affected_packages = _safe_list(extracted.get("packages", []), limit=24)
    affected_ecosystems = _safe_list(extracted.get("ecosystems", []), limit=12)
    affected_products = _safe_list(extracted.get("products", []), limit=16)
    media_candidates = _dedupe_media_candidates(
        item.get("media_candidates", []) if isinstance(item.get("media_candidates"), list) else []
    )
    if not media_candidates:
        media_candidates = _extract_source_page_media_candidates(item)
    body = f"""# {title}

## Executive Summary

{summary}

## Source Metadata

- Source: {item.get('source_name', 'External source')}
- Canonical URL: {canonical_for_body or 'not provided'}
- Additional references: {', '.join(references[1:]) if len(references) > 1 else 'none'}
- Published at: {item.get('published_at') or 'not provided'}
- Fetched at: {item.get('fetched_at') or _utc_now()}
- Trust level: {source_trust_level}

## Review Checklist

{chr(10).join(f"- [ ] {entry['label']}" for entry in _review_checklist())}

## Why It Matters

- Source type: {source_category}
- Severity hint: {severity} ({severity_reason})
- Extracted signals: {', '.join(extracted.get('severity_signals', [])) or 'none detected deterministically'}

## What SecOpsAI Can Detect

{detection_context}

## Extracted Intelligence

### CVEs

{_markdown_list(extracted.get('cves', []), empty='None found deterministically; reviewer should confirm source details.')}

### Affected Packages Or Products

{_markdown_list([*affected_packages, *affected_products], empty='None found deterministically; reviewer should add source-backed affected assets if present.')}

## IOCs

{_markdown_list(extracted_iocs, empty='None found deterministically; reviewer should add source-backed indicators if present.')}

## Recommended Actions

{chr(10).join(f'- {action}' for action in actions)}

## Operator Commands

```bash
secopsai triage summary
secopsai research preflight
secopsai supply-chain advisory list
secopsai blog news-review show {slug_value}
```

## References

{chr(10).join(f'- {reference}' for reference in references) or '- No source URL available; do not publish until a source is added.'}
"""
    post = _base_post(
        title=title,
        summary=summary,
        severity=severity,
        categories=_safe_list(["Security News", category, *item.get("tags", []), *affected_ecosystems, *extracted.get("severity_signals", [])], limit=12),
        sources=references,
        slug=slug_value,
    )
    post.update({
        "source_name": item.get("source_name") or "External source",
        "author": item.get("source_name") or "External source",
        "canonical_url": canonical_for_body,
        "source_url": item.get("source_url") or link,
        "source_trust_level": source_trust_level,
        "source_category": source_category,
        "primary_references": primary_references,
        "source_links": references,
        "published_at": item.get("published_at") or post.get("published_at"),
        "body_markdown": redact(body),
        "external_news": True,
        "review_status": "needs_review",
        "review_checklist": _review_checklist(),
        "news_key": item.get("key"),
        "fetched_at": item.get("fetched_at"),
        "media_candidates": media_candidates,
        "extracted": extracted,
        "iocs": extracted_iocs,
        "affected_packages": affected_packages,
        "affected_ecosystems": affected_ecosystems,
        "affected_products": affected_products,
        "severity_reason": severity_reason,
        "operator_commands": [
            "secopsai triage summary",
            "secopsai research preflight",
            "secopsai supply-chain advisory list",
            f"secopsai blog news-review show {slug_value}",
        ],
    })
    post["references"] = references
    post["reading_time"] = _post_reading_time(post)
    post.update(score_external_news_readiness(post))
    _write_json(_draft_path(post["slug"], paths), post)
    return {"draft_path": str(_draft_path(post["slug"], paths)), "post": post}


def news_draft(*, limit: int = 5, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    cache = _read_news_cache(paths)
    created: List[str] = []
    for item in cache.get("items", []):
        if len(created) >= limit:
            break
        if not isinstance(item, dict) or item.get("draft_path") or item.get("review_status") in DEPLOYED_REVIEW_STATUSES:
            continue
        title = str(item.get("title") or "Security news item")
        existing_slug = slugify(f"news-{item.get('key', '')}-{title}")
        existing_draft = _draft_path(existing_slug, paths)
        if existing_draft.exists():
            item["draft_path"] = str(existing_draft)
            item["review_status"] = "existing"
            continue
        payload = _draft_from_news_item(item, paths=paths)
        item["draft_path"] = payload["draft_path"]
        item["drafted_at"] = _utc_now()
        item["review_status"] = "drafted"
        created.append(payload["draft_path"])
    _write_news_cache(paths, cache)
    return {"created": created, "total": len(created)}


def news_run(*, limit: int = 5, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    fetched = news_fetch(limit=limit, paths=paths)
    drafted = news_draft(limit=limit, paths=paths)
    return {"fetched": fetched, "drafted": drafted}


_EXTERNAL_NEWS_PLACEHOLDERS = (
    "requires human review before publishing",
    "confirm claims against the linked source",
    "add matching secopsai advisories",
    "add source-backed iocs manually",
    "review the source and add affected products",
    "add secopsai detection or mitigation commands",
    "this external security-news item was imported automatically",
)


def score_external_news_readiness(post: Dict[str, Any]) -> Dict[str, Any]:
    if not post.get("external_news"):
        return {"readiness_score": 100, "readiness_status": "ready_to_review", "readiness_blockers": [], "readiness_warnings": []}

    score = 0
    blockers: List[str] = []
    warnings: List[str] = []
    body = str(post.get("body_markdown") or "")
    body_lower = body.lower()
    summary = " ".join(str(post.get("summary") or "").lower().split())
    title = " ".join(str(post.get("title") or "").lower().split())
    sources = _safe_reference_list(post.get("sources") or post.get("references") or [], limit=12)
    references = _safe_reference_list(post.get("references") or post.get("sources") or [], limit=12)
    extracted = post.get("extracted") if isinstance(post.get("extracted"), dict) else {}
    extracted_values = []
    for key in ("cves", "packages", "products", "urls", "domains", "ips", "hashes", "ecosystems"):
        values = extracted.get(key, [])
        if isinstance(values, list):
            extracted_values.extend(values)
    body_words = [word for word in body.split() if word.strip()]

    if sources:
        score += 20
    else:
        blockers.append("no source URL")
    if summary and title and summary != title:
        score += 15
    else:
        blockers.append("summary equals title")
    if extracted_values:
        score += 15
    elif "none found deterministically" in body_lower:
        score += 10
        warnings.append("no CVEs, IOCs, packages, or products were extracted deterministically")
    else:
        blockers.append("affected product/package/CVE/IOC is missing and not explicitly marked none found")
    if "## recommended actions" in body_lower and not GENERIC_RECOMMENDATION_RE.search(body):
        score += 15
    else:
        blockers.append("recommended actions are generic or missing")
    if "## what secopsai can detect" in body_lower:
        score += 15
    else:
        blockers.append("no SecOpsAI detection/mitigation angle")
    if references:
        score += 10
    else:
        blockers.append("references are missing")
    if len(body_words) >= 180:
        score += 10
    else:
        blockers.append("body too thin")

    for phrase in _EXTERNAL_NEWS_PLACEHOLDERS:
        if phrase in body_lower:
            blockers.append(f"placeholder text remains: {phrase}")

    raw_summary = str(post.get("summary") or "").strip()
    if raw_summary and len(raw_summary) > 80 and body_lower.count(raw_summary.lower()) > 1:
        warnings.append("source summary appears multiple times; check copied-text risk")
    if title and body_lower.count(title) > 2:
        warnings.append("title appears repeatedly; add more original analyst context")

    unique_blockers = _safe_list(blockers, limit=20)
    status = "ready_to_review" if not unique_blockers and score >= 80 else "needs_edits"
    if unique_blockers:
        status = "blocked"
    return {
        "readiness_score": min(score, 100),
        "readiness_status": status,
        "readiness_blockers": unique_blockers,
        "readiness_warnings": _safe_list(warnings, limit=12),
    }


def external_news_publish_blockers(post: Dict[str, Any]) -> List[str]:
    if not post.get("external_news"):
        return []
    readiness = score_external_news_readiness(post)
    blockers = list(readiness.get("readiness_blockers", []))
    if post.get("review_status") not in PUBLISHABLE_REVIEW_STATUSES:
        blockers.append("external-news draft has not been approved or reviewed")
    blockers.extend(review_checklist_publish_blockers(post))
    return _safe_list(blockers, limit=24)


def _draft_paths_for_post(path: Path) -> BlogPaths:
    return BlogPaths(path.parent.parent)


def _published_post_exists(post: Dict[str, Any], path: Path, paths: BlogPaths) -> bool:
    slug = str(post.get("slug") or path.stem)
    return _post_json_path(slug, paths).exists() or _post_html_path(slug, paths).exists()


def _published_post_is_current(post: Dict[str, Any], path: Path, paths: BlogPaths) -> bool:
    slug = str(post.get("slug") or path.stem)
    public_json = _post_json_path(slug, paths)
    if not public_json.exists():
        return _post_html_path(slug, paths).exists()
    try:
        public_post = _load_json(public_json)
    except Exception:
        return False
    candidate = _public_post(copy.deepcopy({**post, "slug": slug}))
    for key in ("title", "summary", "body_markdown"):
        if str(public_post.get(key) or "") != str(candidate.get(key) or ""):
            return False
    return True


def _effective_review_status(post: Dict[str, Any], path: Path, paths: BlogPaths) -> str:
    return str(post.get("review_status") or "needs_review")


def _published_post_metadata_path(slug: str, paths: BlogPaths) -> str:
    public_path = _post_json_path(slug, paths)
    try:
        return str(public_path.relative_to(paths.root.parent))
    except ValueError:
        return str(public_path)


def _mark_draft_deployed(path: Path, post: Dict[str, Any], paths: BlogPaths, *, url: Optional[str] = None) -> Dict[str, Any]:
    now = _utc_now()
    slug = str(post.get("slug") or path.stem)
    post["slug"] = slug
    post["review_status"] = "deployed"
    post["status"] = "published"
    post["published_at"] = post.get("published_at") or now
    post["updated_at"] = now
    post["deployed_at"] = now
    post["published_url"] = url or _post_url(slug)
    post["published_post_path"] = _published_post_metadata_path(slug, paths)
    _set_review_checklist_status(post, "deployed")
    _write_json(path, post)
    return post


def _mark_draft_published(path: Path, post: Dict[str, Any], paths: BlogPaths, *, url: Optional[str] = None) -> Dict[str, Any]:
    now = _utc_now()
    slug = str(post.get("slug") or path.stem)
    post["slug"] = slug
    was_published = post.get("status") == "published"
    post["status"] = "published"
    post["published_at"] = post.get("published_at") or now
    if not was_published:
        post["updated_at"] = now
    else:
        post.setdefault("updated_at", now)
    post["published_url"] = url or _post_url(slug)
    post["published_post_path"] = _published_post_metadata_path(slug, paths)
    _set_review_checklist_status(post, str(post.get("review_status") or "approved"))
    _write_json(path, post)
    return post


def news_publish_approved(*, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    published: List[str] = []
    ready_for_deploy: List[str] = []
    blocked: List[Dict[str, Any]] = []
    for path in sorted(paths.drafts.glob("*.json")):
        post = _load_json(path)
        if post.get("external_news") and post.get("review_status") not in PUBLISHABLE_REVIEW_STATUSES:
            continue
        if post.get("external_news"):
            if _published_post_is_current(post, path, paths):
                published_post = _mark_draft_published(path, post, paths)
                ready_for_deploy.append(str(published_post["published_url"]))
                continue
            blockers = external_news_publish_blockers(post)
            if blockers:
                blocked.append({
                    "path": str(path),
                    "slug": post.get("slug") or path.stem,
                    "title": post.get("title"),
                    "reasons": blockers,
                })
                continue
            payload = publish(str(path), confirm=True, paths=paths)
            if payload.get("url"):
                published.append(str(payload["url"]))
    return {
        "published": published,
        "ready_for_deploy": ready_for_deploy,
        "deployed": [],
        "blocked": blocked,
        "total": len(published),
    }


def news_mark_deployed(*, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    deployed: List[str] = []
    blocked: List[Dict[str, Any]] = []
    for path in sorted(paths.drafts.glob("*.json")):
        post = _load_json(path)
        if not post.get("external_news") or post.get("review_status") not in PUBLISHABLE_REVIEW_STATUSES:
            continue
        if not _published_post_is_current(post, path, paths):
            blocked.append({
                "path": str(path),
                "slug": post.get("slug") or path.stem,
                "title": post.get("title"),
                "reasons": ["approved draft is not published to the local blog output; run Publish approved before Deploy blog"],
            })
            continue
        deployed_post = _mark_draft_deployed(path, post, paths)
        deployed.append(str(deployed_post["published_url"]))
    return {"deployed": deployed, "blocked": blocked, "total": len(deployed)}


def _resolve_draft(identifier: str, paths: BlogPaths) -> Path:
    drafts_root = paths.drafts.resolve()
    candidate = Path(identifier).expanduser()
    if candidate.exists():
        resolved = candidate.resolve()
        if drafts_root not in resolved.parents or resolved.suffix.lower() != ".json":
            raise ValueError("draft path must be a JSON file under blog/drafts")
        return resolved
    slug = identifier.removesuffix(".json").strip()
    if (
        not slug
        or slug in {".", ".."}
        or "/" in slug
        or "\\" in slug
        or ".." in Path(slug).parts
    ):
        raise ValueError(f"invalid draft identifier: {identifier}")
    path = _draft_path(slug, paths)
    if path.exists():
        return path
    matches = sorted(paths.drafts.glob(f"*{slug}*.json"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(f"multiple drafts match {identifier}: {', '.join(path.name for path in matches[:5])}")
    raise ValueError(f"draft not found: {identifier}")


def _draft_review_summary(path: Path, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or _draft_paths_for_post(path)
    post = _load_json(path)
    readiness = score_external_news_readiness(post) if post.get("external_news") else {}
    extracted = post.get("extracted") if isinstance(post.get("extracted"), dict) else {}
    review_status = _effective_review_status(post, path, paths)
    return {
        "path": str(path),
        "slug": str(post.get("slug") or path.stem),
        "title": str(post.get("title") or path.stem),
        "summary": str(post.get("summary") or "")[:240],
        "review_status": review_status,
        "severity": str(post.get("severity") or "info"),
        "source_name": str(post.get("source_name") or post.get("author") or "SecOpsAI"),
        "sources": _safe_list(post.get("sources") or post.get("references") or [], limit=5),
        "categories": _safe_list(post.get("categories") or [], limit=8),
        "external_news": bool(post.get("external_news")),
        "updated_at": str(post.get("updated_at") or post.get("fetched_at") or ""),
        "readiness_score": readiness.get("readiness_score", post.get("readiness_score", 0)),
        "readiness_status": readiness.get("readiness_status", post.get("readiness_status", "")),
        "readiness_blockers": readiness.get("readiness_blockers", post.get("readiness_blockers", [])),
        "readiness_warnings": readiness.get("readiness_warnings", post.get("readiness_warnings", [])),
        "extracted": extracted,
        "source_metadata": {
            "canonical_url": post.get("canonical_url"),
            "source_url": post.get("source_url"),
            "source_trust_level": post.get("source_trust_level"),
            "source_category": post.get("source_category"),
            "fetched_at": post.get("fetched_at"),
            "published_at": post.get("published_at"),
        },
        "review_checklist": post.get("review_checklist") if isinstance(post.get("review_checklist"), list) else [],
    }


def news_review_list(*, status: Optional[str] = None, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    drafts = []
    for path in sorted(paths.drafts.glob("*.json")):
        summary = _draft_review_summary(path, paths)
        if status and summary["review_status"] != status:
            continue
        drafts.append(summary)
    return {"drafts": drafts, "total": len(drafts)}


def news_review_show(identifier: str, *, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    path = _resolve_draft(identifier, paths)
    post = _load_json(path)
    if post.get("external_news") and not post.get("media_candidates"):
        references = _safe_reference_list(post.get("primary_references") or post.get("references") or post.get("sources") or [], limit=3)
        source_url = references[0] if references else str(post.get("canonical_url") or post.get("source_url") or "")
        media_candidates = _extract_source_page_media_candidates({
            "title": post.get("title"),
            "canonical_url": source_url,
            "url": source_url,
            "source_name": post.get("source_name") or post.get("author") or "External source",
        })
        if media_candidates:
            post["media_candidates"] = media_candidates
            try:
                _write_json(path, post)
            except OSError:
                pass
    summary = _draft_review_summary(path, paths)
    summary["body_markdown"] = str(post.get("body_markdown") or "")
    summary["references"] = _safe_list(post.get("references") or post.get("sources") or [], limit=12)
    summary["primary_references"] = _safe_list(post.get("primary_references") or [], limit=8)
    summary["source_links"] = _safe_list(post.get("source_links") or [], limit=12)
    summary["media_candidates"] = post.get("media_candidates") if isinstance(post.get("media_candidates"), list) else []
    summary["images"] = post.get("images") if isinstance(post.get("images"), list) else []
    return summary


def news_review_update(
    identifier: str,
    *,
    status: str,
    note: Optional[str] = None,
    paths: Optional[BlogPaths] = None,
) -> Dict[str, Any]:
    if status not in NEWS_REVIEW_STATUSES:
        raise ValueError("status must be one of: needs_review, approved, reviewed, rejected, deployed, published")
    paths = paths or BlogPaths()
    path = _resolve_draft(identifier, paths)
    post = _load_json(path)
    post["review_status"] = status
    post["reviewed_at"] = _utc_now()
    _set_review_checklist_status(post, status)
    if note:
        post["review_note"] = redact(note)
    if post.get("external_news"):
        post.update(score_external_news_readiness(post))
    _write_json(path, post)
    return _draft_review_summary(path, paths)


def news_review_edit(
    identifier: str,
    *,
    title: Optional[str] = None,
    summary: Optional[str] = None,
    severity: Optional[str] = None,
    categories: Optional[Any] = None,
    references: Optional[Any] = None,
    body_markdown: Optional[str] = None,
    note: Optional[str] = None,
    paths: Optional[BlogPaths] = None,
) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    path = _resolve_draft(identifier, paths)
    post = _load_json(path)

    if title is not None:
        cleaned_title = redact(title).strip()
        if not cleaned_title:
            raise ValueError("title cannot be empty")
        post["title"] = cleaned_title
    if summary is not None:
        cleaned_summary = redact(summary).strip()
        if not cleaned_summary:
            raise ValueError("summary cannot be empty")
        post["summary"] = cleaned_summary
    if severity is not None:
        cleaned_severity = str(severity or "").strip().lower()
        if cleaned_severity not in SEVERITY_RANK:
            raise ValueError("severity must be one of: critical, high, medium, low, info")
        post["severity"] = cleaned_severity
    if categories is not None:
        parsed_categories = _split_review_values(categories, limit=16)
        if parsed_categories:
            post["categories"] = parsed_categories
            post["tags"] = parsed_categories
    if references is not None:
        parsed_references = _split_review_values(references, limit=16)
        safe_references = [
            value for value in parsed_references
            if urllib.parse.urlparse(value).scheme in {"http", "https"}
        ]
        if parsed_references and not safe_references:
            raise ValueError("references must include at least one http(s) URL")
        if safe_references:
            post["references"] = safe_references
            post["sources"] = safe_references
            post["source_links"] = safe_references
            post["primary_references"] = safe_references[:5]
    if body_markdown is not None:
        cleaned_body = redact(body_markdown).strip()
        if len(cleaned_body.split()) < 25:
            raise ValueError("body_markdown is too short to save as a reviewed article draft")
        post["body_markdown"] = cleaned_body

    post["updated_at"] = _utc_now()
    post["edited_at"] = post["updated_at"]
    post["review_status"] = "needs_review"
    _set_review_checklist_status(post, "needs_review")
    if note:
        post["edit_note"] = redact(note)

    if post.get("external_news"):
        extraction_item = {
            "title": post.get("title"),
            "summary": f"{post.get('summary', '')} {str(post.get('body_markdown') or '')[:5000]}",
            "category": ", ".join(_safe_list(post.get("categories") or [], limit=12)),
            "tags": post.get("categories") or post.get("tags") or [],
            "source_name": post.get("source_name") or post.get("author"),
            "canonical_url": post.get("canonical_url") or (post.get("references") or [""])[0],
            "severity": post.get("severity"),
        }
        extracted = extract_news_security_fields(extraction_item)
        post["extracted"] = extracted
        post["iocs"] = _safe_list(
            [
                *extracted.get("urls", []),
                *extracted.get("domains", []),
                *extracted.get("ips", []),
                *extracted.get("hashes", []),
            ],
            limit=24,
        )
        post["affected_packages"] = _safe_list(extracted.get("packages", []), limit=24)
        post["affected_ecosystems"] = _safe_list(extracted.get("ecosystems", []), limit=12)
        post["affected_products"] = _safe_list(extracted.get("products", []), limit=16)
        post.update(score_external_news_readiness(post))

    post["reading_time"] = _post_reading_time(post)
    _write_json(path, post)
    return news_review_show(str(path), paths=paths)


def attach_media(
    identifier: str,
    *,
    file_path: str,
    alt: str,
    caption: Optional[str] = None,
    kind: str = "screenshot",
    source_name: str = "SecOpsAI",
    source_url: Optional[str] = None,
    paths: Optional[BlogPaths] = None,
) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    draft_path = _resolve_draft(identifier, paths)
    post = _load_json(draft_path)
    slug = str(post.get("slug") or draft_path.stem)
    source = Path(file_path).expanduser().resolve()
    if not source.exists() or not source.is_file():
        raise ValueError(f"media file not found: {file_path}")
    if source.suffix.lower() not in ALLOWED_MEDIA_SUFFIXES:
        raise ValueError(f"unsupported media type: {source.suffix}")
    if source.stat().st_size > 5 * 1024 * 1024:
        raise ValueError("media file is too large; keep public blog images under 5 MB")
    cleaned_alt = _safe_text(alt, fallback="")
    if not cleaned_alt:
        raise ValueError("alt text is required for blog media")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()[:12]
    safe_name = slugify(source.stem)[:48] or "media"
    destination = paths.post_assets(slug) / f"{digest}-{safe_name}{source.suffix.lower()}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    src = "/" + destination.relative_to(paths.root).as_posix()
    media = {
        "src": src,
        "alt": cleaned_alt[:180],
        "caption": _safe_text(caption, fallback="")[:260],
        "source_name": _safe_text(source_name, fallback="SecOpsAI")[:100],
        "source_url": source_url or "",
        "license": "operator-approved",
        "kind": _safe_text(kind, fallback="screenshot")[:40],
        "hash": digest,
        "approved": True,
    }
    normalised = _normalize_media_item(media, fallback_alt=cleaned_alt)
    if not normalised:
        raise ValueError("media destination did not pass public asset validation")
    existing = [item for item in post.get("images", []) if isinstance(item, dict)]
    existing = [item for item in existing if item.get("src") != normalised["src"]]
    post["images"] = [normalised, *existing]
    post["hero_image"] = normalised
    post["updated_at"] = _utc_now()
    if post.get("external_news"):
        post["review_status"] = "needs_review"
        _set_review_checklist_status(post, "needs_review")
        post.update(score_external_news_readiness(post))
    post["reading_time"] = _post_reading_time(post)
    _write_json(draft_path, post)
    return {"draft_path": str(draft_path), "media": normalised, "hero_image": normalised}


def _source_media_suffix(url: str, content_type: str = "") -> str:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "image/svg+xml":
        raise ValueError("remote SVG source images are not supported")
    suffix = Path(urllib.parse.urlparse(url).path).suffix.lower()
    if suffix in SOURCE_MEDIA_SUFFIXES:
        return suffix
    if media_type in SOURCE_MEDIA_CONTENT_TYPE_SUFFIXES:
        return SOURCE_MEDIA_CONTENT_TYPE_SUFFIXES[media_type]
    raise ValueError("source media URL must point to a supported image type")


def _download_source_media(url: str, destination: Path, *, max_bytes: int = 5 * 1024 * 1024) -> None:
    if not _safe_source_media_url(url, for_fetch=True):
        raise ValueError("source media URL is not allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "secopsai-blog/0.1"})
    with urllib.request.urlopen(request, timeout=20) as response:
        content_type = response.headers.get("Content-Type", "")
        if content_type and not content_type.lower().startswith("image/"):
            raise ValueError(f"source media is not an image: {content_type}")
        if content_type.split(";", 1)[0].strip().lower() == "image/svg+xml":
            raise ValueError("remote SVG source images are not supported")
        remaining = max_bytes + 1
        with destination.open("wb") as handle:
            while remaining > 0:
                chunk = response.read(min(1024 * 256, remaining))
                if not chunk:
                    break
                handle.write(chunk)
                remaining -= len(chunk)
        if remaining <= 0:
            raise ValueError("source media is too large; keep public blog images under 5 MB")


def attach_source_media(
    identifier: str,
    *,
    url: Optional[str] = None,
    media_index: Optional[int] = None,
    alt: Optional[str] = None,
    caption: Optional[str] = None,
    kind: str = "source-image",
    source_name: Optional[str] = None,
    source_url: Optional[str] = None,
    paths: Optional[BlogPaths] = None,
) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    draft_path = _resolve_draft(identifier, paths)
    post = _load_json(draft_path)
    candidates = post.get("media_candidates", []) if isinstance(post.get("media_candidates"), list) else []
    candidate: Dict[str, Any] = {}
    if media_index is not None:
        try:
            candidate = candidates[int(media_index)]
        except (IndexError, TypeError, ValueError):
            raise ValueError("media candidate not found") from None
    media_url = _safe_source_media_url(url or candidate.get("src") or candidate.get("url"), for_fetch=True)
    if not media_url:
        raise ValueError("source media URL is required")
    media_source_url = source_url or str(candidate.get("source_url") or media_url)
    cleaned_alt = _safe_text(alt or candidate.get("alt") or post.get("title"), fallback="")
    if not cleaned_alt:
        raise ValueError("alt text is required for blog media")
    cleaned_source_name = _safe_text(
        source_name or candidate.get("source_name") or post.get("source_name"),
        fallback="External source",
    )
    cleaned_caption = caption if caption is not None else candidate.get("caption")
    content_type = ""
    try:
        request = urllib.request.Request(media_url, method="HEAD", headers={"User-Agent": "secopsai-blog/0.1"})
        with urllib.request.urlopen(request, timeout=10) as response:
            content_type = response.headers.get("Content-Type", "")
    except Exception:
        content_type = ""
    suffix = _source_media_suffix(media_url, content_type)
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / f"source-media{suffix}"
        _download_source_media(media_url, temp_path)
        payload = attach_media(
            identifier,
            file_path=str(temp_path),
            alt=cleaned_alt,
            caption=cleaned_caption,
            kind=kind or str(candidate.get("kind") or "source-image"),
            source_name=cleaned_source_name,
            source_url=media_source_url,
            paths=paths,
        )
    payload["source_media_url"] = media_url
    payload["media_index"] = media_index
    return payload


def draft_news(source: str, *, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    source_config = {
        "name": urllib.parse.urlparse(source).netloc or "External source",
        "url": source,
        "feed_url": source,
        "type": "rss",
        "category": "Security News",
        "trust_level": "external",
        "default_tags": ["Security News"],
    }
    text = _fetch_text(source)
    items = _parse_news_items(text, source_config, limit=1)
    if not items:
        items = [_normalise_news_item({
            "title": source,
            "url": source,
            "summary": "External security-news source queued for analyst review.",
        }, source_config)]
    return _draft_from_news_item(items[0], paths=paths)


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
        post = _normalize_post(_load_json(path))
        if post.get("status") == "published":
            posts.append(post)
        elif "published_at" in post and "body_markdown" not in post:
            post.setdefault("status", "published")
            posts.append(post)
    return sorted(posts, key=lambda item: str(item.get("updated_at") or item.get("published_at") or ""), reverse=True)


def _render_pills(values: Iterable[Any], *, limit: int = 8) -> str:
    return " ".join(
        f'<span class="pill">{html.escape(str(value))}</span>'
        for value in _safe_list(values, limit=limit)
    )


def _render_command_blocks(post: Dict[str, Any]) -> str:
    commands = post.get("operator_commands")
    if not isinstance(commands, list) or not commands:
        packages = _safe_list(post.get("affected_packages", []), limit=2)
        commands = [
            "secopsai blog rebuild-feeds",
            "secopsai supply-chain reconcile-history --include-advisories",
        ]
        if packages:
            commands.insert(0, f"secopsai supply-chain explain-verdict --package {packages[0]}")
    safe_commands = _safe_list(commands, limit=6)
    return "\n".join(
        f'<button class="command-chip" type="button" data-copy="{html.escape(command)}"><code>{html.escape(command)}</code></button>'
        for command in safe_commands
    )


def _render_reference_links(post: Dict[str, Any]) -> str:
    references = _safe_reference_list(post.get("references") or post.get("sources") or [], limit=8)
    if not references:
        return "<p>No external references attached yet. Add source URLs before publishing major incident updates.</p>"
    links = []
    for reference in references:
        if urllib.parse.urlparse(reference).scheme not in {"http", "https"}:
            continue
        parsed = urllib.parse.urlparse(reference)
        label = parsed.netloc or reference
        links.append(f'<li><a href="{html.escape(reference)}" rel="noopener noreferrer" target="_blank">{html.escape(label)}</a></li>')
    if not links:
        return "<p>No safe external references attached yet.</p>"
    return "<ul>" + "".join(links) + "</ul>"


def _render_related_links(post: Dict[str, Any], posts: Optional[List[Dict[str, Any]]] = None) -> str:
    related = _safe_list(post.get("related_posts", []), limit=5)
    if not related and posts:
        own_categories = set(_post_categories(post))
        for candidate in posts:
            if candidate.get("slug") == post.get("slug"):
                continue
            if own_categories & set(_post_categories(candidate)):
                related.append(str(candidate.get("slug")))
            if len(related) >= 3:
                break
    if not related:
        return "<p>No related posts yet.</p>"
    items = []
    by_slug = {str(item.get("slug")): item for item in posts or []}
    for slug in related:
        candidate = by_slug.get(slug)
        title = candidate.get("title") if candidate else slug.replace("-", " ").title()
        items.append(f'<li><a href="/posts/{html.escape(slug)}.html">{html.escape(redact(title))}</a></li>')
    return "<ul>" + "".join(items) + "</ul>"


def _render_artifact_table(post: Dict[str, Any]) -> str:
    artifacts = post.get("affected_artifacts")
    if isinstance(artifacts, list) and artifacts:
        rows = []
        for item in artifacts[:24]:
            if not isinstance(item, dict):
                continue
            versions = ", ".join(_safe_list(item.get("versions", []), limit=8)) or "listed"
            rows.append(
                "<tr>"
                f"<td>{html.escape(str(item.get('ecosystem') or 'unknown'))}</td>"
                f"<td><code>{html.escape(str(item.get('package') or 'unknown'))}</code></td>"
                f"<td>{html.escape(versions)}</td>"
                "</tr>"
            )
        if rows:
            return (
                "<table><thead><tr><th>Ecosystem</th><th>Artifact</th><th>Versions</th></tr></thead><tbody>"
                + "".join(rows)
                + "</tbody></table>"
            )
    ecosystems = _safe_list(post.get("affected_ecosystems", []), limit=12)
    packages = _safe_list(post.get("affected_packages", []), limit=24)
    if not packages and not ecosystems:
        return "<p>No structured affected artifacts attached yet.</p>"
    rows = []
    if packages:
        for index, package in enumerate(packages):
            ecosystem = ecosystems[index] if index < len(ecosystems) else (ecosystems[0] if ecosystems else "unknown")
            rows.append(f"<tr><td>{html.escape(ecosystem)}</td><td><code>{html.escape(package)}</code></td></tr>")
    else:
        rows = [f"<tr><td>{html.escape(ecosystem)}</td><td>See post details</td></tr>" for ecosystem in ecosystems]
    return "<table><thead><tr><th>Ecosystem</th><th>Artifact</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _render_meta_tags(
    *,
    title: str,
    description: str,
    url: str,
    image: str,
    image_alt: str,
    image_width: Any = SOCIAL_CARD_WIDTH,
    image_height: Any = SOCIAL_CARD_HEIGHT,
    post: Optional[Dict[str, Any]] = None,
) -> str:
    tags = [
        f'<meta property="og:site_name" content="SecOpsAI Security Blog" />',
        f'<meta property="og:title" content="{html.escape(title)}" />',
        f'<meta property="og:description" content="{html.escape(description)}" />',
        f'<meta property="og:url" content="{html.escape(url)}" />',
        f'<meta property="og:image" content="{html.escape(_absolute_url(image))}" />',
        f'<meta property="og:image:alt" content="{html.escape(image_alt)}" />',
        f'<meta property="og:image:width" content="{html.escape(str(image_width or SOCIAL_CARD_WIDTH))}" />',
        f'<meta property="og:image:height" content="{html.escape(str(image_height or SOCIAL_CARD_HEIGHT))}" />',
        '<meta name="twitter:card" content="summary_large_image" />',
        f'<meta name="twitter:title" content="{html.escape(title)}" />',
        f'<meta name="twitter:description" content="{html.escape(description)}" />',
        f'<meta name="twitter:image" content="{html.escape(_absolute_url(image))}" />',
        f'<meta name="twitter:image:alt" content="{html.escape(image_alt)}" />',
    ]
    if post:
        tags.insert(0, '<meta property="og:type" content="article" />')
        if post.get("published_at"):
            tags.append(f'<meta property="article:published_time" content="{html.escape(str(post.get("published_at")))}" />')
        if post.get("updated_at"):
            tags.append(f'<meta property="article:modified_time" content="{html.escape(str(post.get("updated_at")))}" />')
        for category in _post_categories(post)[:8]:
            tags.append(f'<meta property="article:tag" content="{html.escape(category)}" />')
    else:
        tags.insert(0, '<meta property="og:type" content="website" />')
    return "\n    ".join(tags)


def _render_site_header(*, subtitle: str = "Security Blog", links: Optional[List[tuple[str, str]]] = None) -> str:
    nav_links = links or [
        ("/", "Blog Home"),
        ("https://docs.secopsai.dev/", "Docs"),
        ("/feed.xml", "RSS"),
        ("/json-feed", "JSON Feed"),
    ]
    link_html = "\n".join(
        f'          <a href="{html.escape(href)}">{html.escape(label)}</a>'
        for href, label in nav_links
    )
    return f"""<header class="topbar">
      <nav class="shell nav" data-site-nav>
        <a class="brand" href="/">
          <img class="brand-mark" src="/assets/favicon-512.png" alt="SecOpsAI icon" />
          <span class="brand-title"><span>SECOPSAI</span><span>{html.escape(subtitle).upper()}</span></span>
        </a>
        <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-menu" data-nav-toggle>
          <span class="nav-toggle-lines" aria-hidden="true"><span></span><span></span><span></span></span>
          <span class="nav-toggle-label">Menu</span>
        </button>
        <div class="nav-links" id="site-menu" data-nav-menu>
{link_html}
        </div>
      </nav>
    </header>"""


def _render_site_footer() -> str:
    return f"""<footer class="footer">
      <div class="shell footer-inner">
        <div class="footer-top">
          <div><span>SecOpsAI</span><span>Security Blog</span></div>
          <span>Operator feed</span>
        </div>
        <p>New SecOpsAI detections, package advisories, OpenClaw telemetry learnings, malware behavior cards, and practical response notes.</p>
        <div class="footer-bottom">
          <div><span>SecOpsAI Security Blog</span><span>Local-first intelligence, source-backed actions.</span></div>
          <nav aria-label="Footer links">
            <a href="https://secopsai.dev/">Platform</a>
            <a href="/#topics">Topics</a>
            <a href="/posts/">Latest</a>
            <a href="https://docs.secopsai.dev/">Docs</a>
            <a href="/feed.xml">RSS</a>
            <a href="/json-feed">JSON Feed</a>
          </nav>
        </div>
        <div class="copyright">© {time.strftime('%Y')} SecOpsAI. All rights reserved.</div>
      </div>
    </footer>"""


def _feed_icon(kind: str) -> str:
    if kind == "rss":
        return """<svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M4 11a9 9 0 0 1 9 9" />
              <path d="M4 4a16 16 0 0 1 16 16" />
              <circle cx="5" cy="19" r="1.5" />
            </svg>"""
    return """<svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <polyline points="8 3 4 7 8 11" />
              <polyline points="16 3 20 7 16 11" />
              <line x1="10" y1="21" x2="14" y2="3" />
            </svg>"""


def _render_feed_card(*, kind: str, title: str, subtitle: str, heading: str, body: str, url: str, href: str) -> str:
    return f"""<article class="feed-card">
          <div class="feed-card-bar" aria-hidden="true"></div>
          <div class="feed-card-body">
            <div class="feed-card-head">
              <div class="feed-icon">{_feed_icon(kind)}</div>
              <div>
                <span class="feed-choice-kicker">{html.escape(title)}</span>
                <p>{html.escape(subtitle)}</p>
              </div>
            </div>
            <h3>{html.escape(heading)}</h3>
            <p>{html.escape(body)}</p>
            <div class="feed-url-row">
              <a class="feed-url" href="{html.escape(href)}">
                <span aria-hidden="true">⌁</span>
                <code>{html.escape(url)}</code>
              </a>
              <button class="copy-url" type="button" data-copy="{html.escape(url)}" title="Copy URL" aria-label="Copy {html.escape(title)} URL">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <rect x="3" y="3" width="7" height="7" rx="1" />
                  <rect x="6" y="6" width="7" height="7" rx="1" />
                </svg>
              </button>
            </div>
          </div>
        </article>"""


def _category_counts(posts: List[Dict[str, Any]]) -> Dict[str, int]:
    return {topic: sum(1 for post in posts if topic in _post_categories(post)) for topic in TOPIC_SECTIONS}


def _render_category_cards(posts: Optional[List[Dict[str, Any]]] = None) -> str:
    counts = _category_counts(posts or [])
    cards = []
    for topic in TOPIC_SECTIONS:
        count = counts.get(topic, 0)
        body = (
            f"{count} posts with SecOpsAI context, detections, or operator guidance."
            if count
            else "No posts yet. Coming soon."
        )
        cards.append(
            f"""<article class="topic-card">
              <div class="topic-card-top">
                <span>{html.escape(topic.upper())}</span>
                <span>{count} post{'s' if count != 1 else ''}</span>
              </div>
              <p>{html.escape(body)}</p>
            </article>"""
        )
    return f"""<section class="topic-catalog" id="topics" aria-label="Intelligence categories">
        <div class="section-kicker"><span></span>Intelligence Categories</div>
        <div class="topic-grid">{''.join(cards)}</div>
      </section>"""


def _render_subscribe_panel(posts: Optional[List[Dict[str, Any]]] = None) -> str:
    return f"""<section class="subscribe-section" id="subscribe" aria-labelledby="subscribe-heading">
        <div class="subscribe-top">
          <div>
            <p class="section-label">Subscribe</p>
            <h2 id="subscribe-heading">Follow SecOpsAI advisories and research.</h2>
          </div>
          <p>Subscribe through your preferred feed reader, security workflow, or automation platform. Both feeds update simultaneously.</p>
        </div>
        <div class="section-divider" aria-hidden="true"></div>
        <div class="feed-choice-grid">
          {_render_feed_card(
              kind="rss",
              title="RSS Feed",
              subtitle="XML-based syndication",
              heading="Traditional syndication",
              body="For feed readers, email digests, Slack RSS integrations, and news aggregators. Standard RSS 2.0 format.",
              url=f"{BASE_URL}/feed.xml",
              href="/feed.xml",
          )}
          {_render_feed_card(
              kind="json",
              title="JSON Feed",
              subtitle="JSON-based automation",
              heading="Structured automation",
              body="For applications, scripts, SOAR platforms, and security automation that prefer structured JSON data.",
              url=f"{BASE_URL}/feed.json",
              href="/json-feed",
          )}
        </div>
        {_render_category_cards(posts)}
      </section>"""


def _render_hero_media(post: Dict[str, Any]) -> str:
    media = _primary_media(post)
    if not media:
        return ""
    caption_parts = [media.get("caption") or ""]
    if media.get("source_name"):
        source_label = html.escape(str(media["source_name"]))
        if media.get("source_url"):
            caption_parts.append(
                f'Source: <a href="{html.escape(str(media["source_url"]))}" rel="noopener noreferrer" target="_blank">{source_label}</a>'
            )
        else:
            caption_parts.append(f"Source: {source_label}")
    caption = " · ".join(part for part in caption_parts if part)
    return f"""<figure class="hero-image">
          <img src="{html.escape(media['src'])}" alt="{html.escape(media['alt'])}" loading="eager" decoding="async" />
          {f'<figcaption>{caption}</figcaption>' if caption else ''}
        </figure>"""


def _render_media_gallery(post: Dict[str, Any]) -> str:
    media = _normalize_media(post)
    if len(media) <= 1:
        return ""
    figures = []
    for item in media[1:]:
        caption = html.escape(str(item.get("caption") or item.get("source_name") or "SecOpsAI media artifact"))
        figures.append(
            f"""<figure class="media-card">
              <img src="{html.escape(item['src'])}" alt="{html.escape(item['alt'])}" loading="lazy" decoding="async" />
              <figcaption>{caption}</figcaption>
            </figure>"""
        )
    return f"""<section class="media-gallery" aria-label="Related screenshots and media">
          <h2>Media Artifacts</h2>
          <div class="media-grid">{''.join(figures)}</div>
        </section>"""


def _render_card_thumbnail(post: Dict[str, Any]) -> str:
    media = _primary_media(post)
    if not media:
        src = str(post.get("social_image") or _social_card_src(str(post.get("slug") or "secopsai-post")))
        alt = str(post.get("social_image_alt") or f"SecOpsAI social card for {post.get('title', 'blog post')}")
    else:
        src = media["src"]
        alt = media["alt"]
    return f'<div class="post-thumb"><img src="{html.escape(src)}" alt="{html.escape(alt)}" loading="lazy" decoding="async" /></div>'


def _render_post_html(post: Dict[str, Any]) -> str:
    post = _public_post(post)
    slug = str(post["slug"])
    title = html.escape(redact(post["title"]))
    raw_title = redact(post["title"])
    raw_summary = redact(post.get("summary", ""))
    summary = html.escape(raw_summary)
    categories = _post_categories(post)
    pills = _render_pills(categories)
    severity = html.escape(str(post.get("severity", "info")).title())
    severity_class = _badge_class(post.get("severity"))
    author = html.escape(_post_author(post))
    reading_time = _post_reading_time(post)
    body_html = markdown_to_html(str(post.get("body_markdown") or ""))
    social_image = str(post.get("social_image") or _social_card_src(slug))
    social_alt = str(post.get("social_image_alt") or f"SecOpsAI social preview card for {raw_title}")
    hero_media = _render_hero_media(post)
    media_gallery = _render_media_gallery(post)
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title} | SecOpsAI Security Blog</title>
    <meta name="description" content="{summary}" />
    {_render_meta_tags(
        title=f"{raw_title} | SecOpsAI Security Blog",
        description=raw_summary,
        url=_post_url(slug),
        image=social_image,
        image_alt=social_alt,
        image_width=post.get("social_image_width", SOCIAL_CARD_WIDTH),
        image_height=post.get("social_image_height", SOCIAL_CARD_HEIGHT),
        post=post,
    )}
    <link rel="canonical" href="{_post_url(slug)}" />
    <link rel="icon" type="image/png" href="/assets/favicon-512.png" />
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&family=Playfair+Display:wght@400;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/assets/blog.css" />
  </head>
  <body>
    {_render_site_header(links=[
        ("/", "Blog Home"),
        ("https://docs.secopsai.dev/", "Docs"),
        ("/feed.xml", "RSS"),
        ("/json-feed", "JSON Feed"),
    ])}
    <main>
      <header class="shell article-hero">
        <div class="breadcrumb">
          <a href="/">Blog Home</a><span>&gt;</span><span>{title}</span>
        </div>
        <p class="eyebrow">{severity.upper()} • SecOpsAI Intelligence</p>
        <h1>{title}</h1>
        <p class="dek">{summary}</p>
        <div class="meta">
          <span class="pill {severity_class}">{severity}</span>
          <span>By {author}</span>
          <span>{reading_time} min read</span>
          <span>Published: {html.escape(_post_date(post.get("published_at")))}</span>
            <span>Updated: {html.escape(_post_date(post.get("updated_at")))}</span>
        </div>
        <div class="tags">{pills}</div>
{hero_media}
      </header>
      <div class="shell post-layout">
        <article class="post-body">
        {body_html}
{media_gallery}
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
        <section class="card command-panel">
          <p class="eyebrow">Operator commands</p>
          {_render_command_blocks(post)}
        </section>
        <section class="card">
          <p class="eyebrow">References</p>
          {_render_reference_links(post)}
        </section>
        <section class="card">
          <p class="eyebrow">Related posts</p>
          {_render_related_links(post)}
        </section>
      </aside>
      </div>
    </main>
    <script src="/assets/blog.js" defer></script>
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
    blockers = external_news_publish_blockers(post)
    if blockers:
        raise ValueError("external-news draft is not publication-ready: " + "; ".join(blockers))
    if post.get("external_news"):
        post.update(score_external_news_readiness(post))
    post["status"] = "published"
    post["published_at"] = post.get("published_at") or _utc_now()
    post["updated_at"] = _utc_now()
    draft_record = dict(post)
    post = _ensure_social_image(_public_post(post), paths)
    paths.posts.mkdir(parents=True, exist_ok=True)
    _write_json(_post_json_path(str(post["slug"]), paths), post)
    _post_html_path(str(post["slug"]), paths).write_text(
        _render_post_html(post),
        encoding="utf-8",
    )
    rebuild(paths=paths)
    if draft_record.get("external_news"):
        draft_record["published_at"] = post.get("published_at")
        draft_record["updated_at"] = post.get("updated_at")
        _mark_draft_published(draft_path, draft_record, paths, url=_post_url(str(post["slug"])))
    return {
        "published": True,
        "post_path": str(_post_html_path(str(post["slug"]), paths)),
        "url": _post_url(str(post["slug"])),
    }


def _render_index(posts: List[Dict[str, Any]]) -> str:
    posts = [_normalize_post(post) for post in posts]
    featured = next((post for post in posts if post.get("featured")), posts[0] if posts else None)
    cards = []
    for post in posts:
        slug = html.escape(str(post["slug"]))
        title = html.escape(redact(post["title"]))
        summary = html.escape(redact(post.get("summary", "")))
        severity = html.escape(str(post.get("severity", "info")).title())
        severity_class = _badge_class(post.get("severity"))
        categories = _post_categories(post)
        tags = _render_pills(categories[:5])
        topics = " ".join(categories).lower()
        packages = " ".join(post.get("affected_packages", []))
        iocs = " ".join(post.get("iocs", []))
        sources = " ".join(post.get("sources", []))
        reading_time = _post_reading_time(post)
        updated = str(post.get("updated_at") or post.get("published_at") or "")
        search = html.escape(
            " ".join([title, summary, packages, iocs, sources, topics]).lower()
        )
        cards.append(
            f"""<a class="post-card" href="/posts/{slug}.html"
          data-search="{search}"
          data-topic="{html.escape(topics)}"
          data-severity="{_post_severity_rank(post)}"
          data-date="{html.escape(updated)}"
          data-reading="{reading_time}">
          <span class="pill {severity_class}">{severity}</span>
          <h2>{title}</h2>
          <p>{summary}</p>
          <div class="meta">
            <span>{html.escape(_post_author(post))}</span>
            <span>{reading_time} min read</span>
            <span>{html.escape(_post_date(updated))}</span>
          </div>
          <div class="tags">{tags}</div>
        </a>"""
        )
    cards_html = "\n".join(cards)
    topic_buttons = "\n".join(
        f'<button class="topic-filter" type="button" data-topic-filter="{html.escape(topic.lower())}">{html.escape(topic)}</button>'
        for topic in TOPIC_SECTIONS
    )
    section_cards = "\n".join(
        f"""<article class="topic-card">
          <p class="eyebrow">{html.escape(topic)}</p>
          <p>{sum(1 for post in posts if topic in _post_categories(post))} posts with SecOpsAI context, detections, or operator guidance.</p>
        </article>"""
        for topic in TOPIC_SECTIONS
    )
    if featured:
        featured_slug = html.escape(str(featured["slug"]))
        featured_html = f"""<section class="featured-grid" aria-label="Featured security research">
        <a class="featured-card" href="/posts/{featured_slug}.html">
          <p class="section-label">Featured Research</p>
          <h2>{html.escape(redact(featured.get("title", "")))}</h2>
          <p>{html.escape(_post_summary(featured))}</p>
          <div class="meta">
            <span class="pill {_badge_class(featured.get("severity"))}">{html.escape(str(featured.get("severity", "info")).title())}</span>
            <span>{html.escape(_post_author(featured))}</span>
            <span>{_post_reading_time(featured)} min read</span>
          </div>
        </a>
        <aside class="card intelligence-card">
          <p class="section-label">Operator Intelligence Model</p>
          <h2>Source-backed. Detection-aware. Mitigation-first.</h2>
          <p>Every published post is designed to connect external reporting, SecOpsAI detections, IOCs, and concrete response commands.</p>
        </aside>
      </section>"""
    else:
        featured_html = ""
    homepage_social = _absolute_url(_social_card_src("secopsai-blog"))
    homepage_description = "Real-time SecOpsAI advisories, detections, mitigation steps, and incident updates."
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SecOpsAI Security Blog</title>
    <meta name="description" content="{homepage_description}" />
    {_render_meta_tags(
        title="SecOpsAI Security Blog",
        description=homepage_description,
        url=f"{BASE_URL}/",
        image=homepage_social,
        image_alt="SecOpsAI Security Blog social preview card",
    )}
    <link rel="canonical" href="{BASE_URL}/" />
    <link rel="alternate" type="application/rss+xml" title="SecOpsAI Security Blog RSS" href="/feed.xml" />
    <link rel="alternate" type="application/feed+json" title="SecOpsAI Security Blog JSON Feed" href="/feed.json" />
    <link rel="icon" type="image/png" href="/assets/favicon-512.png" />
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&family=Playfair+Display:wght@400;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/assets/blog.css" />
  </head>
  <body>
    {_render_site_header(links=[
        ("https://secopsai.dev/", "Platform"),
        ("#topics", "Topics"),
        ("/posts/", "Latest"),
        ("https://docs.secopsai.dev/", "Docs"),
        ("/feed.xml", "RSS"),
        ("/json-feed", "JSON Feed"),
    ])}
    <main>
      <section class="hero">
        <p class="eyebrow">Security Research & Advisories</p>
        <h1>Security intelligence operators can act on quickly.</h1>
        <p class="lede">Fast incident posts from the SecOpsAI side of the console:
          affected packages, IOCs, detection logic, mitigations, timelines,
          and source-backed updates.</p>
        <div class="feed-actions">
          <a class="button" href="#subscribe">Subscribe</a>
          <a class="button secondary" href="/json-feed">JSON Feed</a>
        </div>
        <div class="scroll-indicator" aria-hidden="true"></div>
      </section>
      <div class="content-section">
        {featured_html}
      </div>
      {_render_subscribe_panel(posts)}
    </main>
    {_render_site_footer()}
    <script src="/assets/blog.js" defer></script>
  </body>
</html>
"""


def _render_latest_page(posts: List[Dict[str, Any]]) -> str:
    posts = [_normalize_post(post) for post in posts]
    cards = []
    for post in posts:
        slug = html.escape(str(post["slug"]))
        title = html.escape(redact(post["title"]))
        summary = html.escape(redact(post.get("summary", "")))
        severity = html.escape(str(post.get("severity", "info")).title())
        severity_class = _badge_class(post.get("severity"))
        categories = _post_categories(post)
        tags = _render_pills(categories[:5])
        topics = " ".join(categories).lower()
        packages = " ".join(post.get("affected_packages", []))
        iocs = " ".join(post.get("iocs", []))
        sources = " ".join(post.get("sources", []))
        reading_time = _post_reading_time(post)
        updated = str(post.get("updated_at") or post.get("published_at") or "")
        search = html.escape(" ".join([title, summary, packages, iocs, sources, topics]).lower())
        cards.append(
            f"""<a class="post-card" href="/posts/{slug}.html"
          data-search="{search}"
          data-topic="{html.escape(topics)}"
          data-severity="{_post_severity_rank(post)}"
          data-date="{html.escape(updated)}"
          data-reading="{reading_time}">
          <span class="pill {severity_class}">{severity}</span>
          <h2>{title}</h2>
          <p>{summary}</p>
          <div class="meta">
            <span>{html.escape(_post_author(post))}</span>
            <span>{reading_time} min read</span>
            <span>{html.escape(_post_date(updated))}</span>
          </div>
          <div class="tags">{tags}</div>
        </a>"""
        )
    topic_buttons = "\n".join(
        f'<button class="topic-filter" type="button" data-topic-filter="{html.escape(topic.lower())}">{html.escape(topic)}</button>'
        for topic in TOPIC_SECTIONS
    )
    latest_description = "Research, advisories, detections, and mitigation notes"
    homepage_social = _absolute_url(_social_card_src("secopsai-blog"))
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Latest posts | SecOpsAI Security Blog</title>
    <meta name="description" content="{latest_description}" />
    {_render_meta_tags(
        title="Latest posts | SecOpsAI Security Blog",
        description=latest_description,
        url=f"{BASE_URL}/posts/",
        image=homepage_social,
        image_alt="SecOpsAI Security Blog social preview card",
    )}
    <link rel="canonical" href="{BASE_URL}/posts/" />
    <link rel="alternate" type="application/rss+xml" title="SecOpsAI Security Blog RSS" href="/feed.xml" />
    <link rel="alternate" type="application/feed+json" title="SecOpsAI Security Blog JSON Feed" href="/feed.json" />
    <link rel="icon" type="image/png" href="/assets/favicon-512.png" />
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&family=Playfair+Display:wght@400;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/assets/blog.css" />
  </head>
  <body>
    {_render_site_header(links=[
        ("https://secopsai.dev/", "Platform"),
        ("/#topics", "Topics"),
        ("/posts/", "Latest"),
        ("https://docs.secopsai.dev/", "Docs"),
        ("/feed.xml", "RSS"),
        ("/json-feed", "JSON Feed"),
    ])}
    <main class="listing-page">
      <section class="shell listing-hero">
        <h1>Latest posts</h1>
        <p>{latest_description}</p>
        <div class="filter-row" aria-label="Post topic filters">
          <button class="topic-filter active" type="button" data-topic-filter="all">All</button>
          {topic_buttons}
        </div>
        <div class="filters compact" aria-label="Search and sort posts">
          <input id="post-search" type="search" placeholder="Search posts, tags, ecosystems, packages, or IOCs..." />
          <label for="post-sort">Sort</label>
          <select id="post-sort">
            <option value="latest">Latest</option>
            <option value="oldest">Oldest</option>
            <option value="severity">Severity</option>
            <option value="reading">Reading Time</option>
          </select>
        </div>
      </section>
      <section class="shell latest-grid" id="posts" aria-live="polite">
        {''.join(cards)}
      </section>
    </main>
    {_render_site_footer()}
    <script src="/assets/blog.js" defer></script>
  </body>
</html>
"""


def _rss_date(value: str) -> str:
    try:
        raw = str(value or "").strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
            raw = f"{raw}T00:00:00"
        parsed = time.strptime(raw[:19], "%Y-%m-%dT%H:%M:%S")
        return email.utils.formatdate(calendar.timegm(parsed), usegmt=True)
    except Exception:
        return email.utils.formatdate(time.time(), usegmt=True)


def _post_summary(post: Dict[str, Any]) -> str:
    summary = str(post.get("summary") or "").strip()
    if summary:
        return redact(summary)
    body = strip_review_checklist_section(post.get("body_markdown") or "")
    body = re.sub(r"```.*?```", " ", body, flags=re.DOTALL)
    body = re.sub(r"^#+\s*", "", body, flags=re.MULTILINE)
    body = re.sub(r"\s+", " ", body).strip()
    return redact(body[:220])


def _render_json_feed_landing(posts: List[Dict[str, Any]]) -> str:
    items = "\n".join(
        f"""<article class="post-card">
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
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700;800&family=Playfair+Display:wght@400;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/assets/blog.css" />
  </head>
  <body>
    {_render_site_header(subtitle="JSON Feed", links=[
        ("/", "Blog Home"),
        ("/feed.json", "Raw JSON"),
        ("/feed.xml", "RSS"),
        ("https://docs.secopsai.dev/", "Docs"),
    ])}
    <main>
      <section class="hero">
        <p class="eyebrow">Programmatic feed</p>
        <h1>SecOpsAI JSON Feed</h1>
        <p class="lede">A structured JSON feed for applications, scripts, and
          automation workflows that consume SecOpsAI advisories and research.</p>
        <div class="feed-actions">
          <a class="button" href="/feed.json?raw=1">Open raw JSON</a>
          <a class="button secondary" href="/feed.xml">Open RSS</a>
        </div>
      </section>
      {_render_subscribe_panel(posts)}
      <section class="shell latest-grid">{items}</section>
    </main>
    {_render_site_footer()}
  </body>
</html>
"""


def rebuild(*, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    posts = _load_posts(paths)
    latest_feed_date = (
        str(posts[0].get("updated_at") or posts[0].get("published_at") or "")
        if posts
        else "2026-05-12T00:00:00Z"
    )
    _write_social_card({
        "slug": "secopsai-blog",
        "title": "SecOpsAI Security Blog",
        "summary": "Real-time SecOpsAI advisories, detections, mitigation steps, and incident updates.",
        "severity": "info",
        "categories": ["Security Research", "Advisories"],
        "published_at": latest_feed_date,
    }, paths)
    (paths.root / "index.html").write_text(_render_index(posts), encoding="utf-8")
    (paths.posts / "index.html").write_text(_render_latest_page(posts), encoding="utf-8")
    feed_items = []
    rss_items = []
    for post in posts:
        post = _ensure_social_image(_public_post(post), paths)
        slug = str(post["slug"])
        url = _post_url(slug)
        if post.get("body_markdown"):
            _post_html_path(slug, paths).write_text(_render_post_html(post), encoding="utf-8")
            _write_json(_post_json_path(slug, paths), post)
        summary = _post_summary(post)
        feed_items.append(
            {
                "id": url,
                "url": url,
                "title": redact(post.get("title", "")),
                "summary": summary,
                "image": _absolute_url(post.get("social_image") or _social_card_src(slug)),
                "banner_image": _absolute_url(post.get("social_image") or _social_card_src(slug)),
                "date_published": post.get("published_at"),
                "date_modified": post.get("updated_at"),
                "tags": post.get("tags") or post.get("categories") or [],
                "authors": [{"name": _post_author(post)}],
                "reading_time_minutes": _post_reading_time(post),
                "severity": post.get("severity"),
                "affected_packages": post.get("affected_packages", []),
                "images": post.get("images", []),
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
        f'    <lastBuildDate>{_rss_date(latest_feed_date)}</lastBuildDate>\n'
        f'{rss_body}\n'
        '  </channel>\n'
        '</rss>\n'
    )
    (paths.root / "feed.xml").write_text(rss_xml, encoding="utf-8")
    return {
        "posts": len(posts),
        "paths": [
            str(paths.root / "index.html"),
            str(paths.posts / "index.html"),
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
