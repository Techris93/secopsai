from __future__ import annotations

import email.utils
import hashlib
import html
import json
import re
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


def _post_severity_rank(post: Dict[str, Any]) -> int:
    return SEVERITY_RANK.get(str(post.get("severity") or "info").lower(), 0)


def _post_date(value: Any) -> str:
    text = str(value or "")
    return text[:10] if len(text) >= 10 else text


def _normalize_post(post: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(post)
    categories = _post_categories(normalized)
    normalized["categories"] = categories
    normalized.setdefault("tags", categories)
    normalized.setdefault("author", _post_author(normalized))
    normalized["reading_time"] = _post_reading_time(normalized)
    normalized.setdefault("featured", False)
    normalized.setdefault("related_posts", [])
    normalized.setdefault("references", normalized.get("sources", []))
    normalized.setdefault("affected_ecosystems", [])
    normalized.setdefault("affected_packages", [])
    normalized.setdefault("affected_products", [])
    normalized.setdefault("affected_artifacts", [])
    normalized.setdefault("iocs", [])
    normalized.setdefault("extracted", {})
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
    title = redact(_strip_markup(raw.get("title") or "Security news item"))
    url = str(raw.get("url") or raw.get("link") or source.get("url") or source.get("feed_url") or "").strip()
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
    return {
        "key": key,
        "title": title,
        "url": url,
        "canonical_url": url,
        "source_name": source_name,
        "source_url": str(source.get("url") or source.get("feed_url") or url),
        "source_type": str(source.get("type") or "rss"),
        "category": category,
        "tags": tags,
        "summary": summary[:500],
        "published_at": str(raw.get("published_at") or raw.get("published") or raw.get("date") or ""),
        "fetched_at": _utc_now(),
        "severity": str(raw.get("severity") or source.get("default_severity") or "info"),
        "trust_level": str(source.get("trust_level") or "external"),
        "review_status": "new",
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
        items.append(_normalise_news_item({
            "title": first_text("title", "{http://www.w3.org/2005/Atom}title"),
            "url": link,
            "summary": first_text("description", "summary", "{http://www.w3.org/2005/Atom}summary"),
            "published_at": first_text("pubDate", "published", "{http://www.w3.org/2005/Atom}published", "{http://www.w3.org/2005/Atom}updated"),
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
        return [
            _normalise_news_item({
                "title": f"CISA KEV: {item.get('vendorProject', '')} {item.get('product', '')} {item.get('cveID', '')}".strip(),
                "url": item.get("notes") or "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "summary": item.get("shortDescription") or item.get("vulnerabilityName") or "",
                "published_at": item.get("dateAdded") or "",
                "tags": ["CISA KEV", item.get("cveID", "")],
                "severity": "high",
            }, source)
            for item in payload["vulnerabilities"][:limit]
            if isinstance(item, dict)
        ]
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
    references = _safe_list([link, *item.get("source_links", [])] if isinstance(item.get("source_links"), list) else [link], limit=12)
    primary_references = _safe_list([link], limit=5)
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
    body = f"""# {title}

## Executive Summary

{summary}

## Source Metadata

- Source: {item.get('source_name', 'External source')}
- Canonical URL: {link or 'not provided'}
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
        "canonical_url": link,
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
        if not isinstance(item, dict) or item.get("draft_path") or item.get("review_status") == "published":
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
    sources = _safe_list(post.get("sources") or post.get("references") or [], limit=12)
    references = _safe_list(post.get("references") or post.get("sources") or [], limit=12)
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
    return list(readiness.get("readiness_blockers", []))


def news_publish_approved(*, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    published: List[str] = []
    blocked: List[Dict[str, Any]] = []
    for path in sorted(paths.drafts.glob("*.json")):
        post = _load_json(path)
        if post.get("external_news") and post.get("review_status") not in {"approved", "reviewed"}:
            continue
        if post.get("external_news"):
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
    return {"published": published, "blocked": blocked, "total": len(published)}


def _resolve_draft(identifier: str, paths: BlogPaths) -> Path:
    candidate = Path(identifier)
    if candidate.exists():
        return candidate
    slug = identifier.removesuffix(".json")
    path = _draft_path(slug, paths)
    if path.exists():
        return path
    matches = sorted(paths.drafts.glob(f"*{slug}*.json"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(f"multiple drafts match {identifier}: {', '.join(path.name for path in matches[:5])}")
    raise ValueError(f"draft not found: {identifier}")


def _draft_review_summary(path: Path) -> Dict[str, Any]:
    post = _load_json(path)
    readiness = score_external_news_readiness(post) if post.get("external_news") else {}
    extracted = post.get("extracted") if isinstance(post.get("extracted"), dict) else {}
    return {
        "path": str(path),
        "slug": str(post.get("slug") or path.stem),
        "title": str(post.get("title") or path.stem),
        "summary": str(post.get("summary") or "")[:240],
        "review_status": str(post.get("review_status") or "needs_review"),
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
        summary = _draft_review_summary(path)
        if status and summary["review_status"] != status:
            continue
        drafts.append(summary)
    return {"drafts": drafts, "total": len(drafts)}


def news_review_show(identifier: str, *, paths: Optional[BlogPaths] = None) -> Dict[str, Any]:
    paths = paths or BlogPaths()
    path = _resolve_draft(identifier, paths)
    post = _load_json(path)
    summary = _draft_review_summary(path)
    summary["body_markdown"] = str(post.get("body_markdown") or "")
    summary["references"] = _safe_list(post.get("references") or post.get("sources") or [], limit=12)
    summary["primary_references"] = _safe_list(post.get("primary_references") or [], limit=8)
    summary["source_links"] = _safe_list(post.get("source_links") or [], limit=12)
    return summary


def news_review_update(
    identifier: str,
    *,
    status: str,
    note: Optional[str] = None,
    paths: Optional[BlogPaths] = None,
) -> Dict[str, Any]:
    if status not in {"needs_review", "approved", "reviewed", "rejected"}:
        raise ValueError("status must be one of: needs_review, approved, reviewed, rejected")
    paths = paths or BlogPaths()
    path = _resolve_draft(identifier, paths)
    post = _load_json(path)
    post["review_status"] = status
    post["reviewed_at"] = _utc_now()
    if note:
        post["review_note"] = redact(note)
    if post.get("external_news"):
        post.update(score_external_news_readiness(post))
    _write_json(path, post)
    return _draft_review_summary(path)


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
    references = _safe_list(post.get("references") or post.get("sources") or [], limit=8)
    if not references:
        return "<p>No external references attached yet. Add source URLs before publishing major incident updates.</p>"
    links = []
    for reference in references:
        if urllib.parse.urlparse(reference).scheme not in {"http", "https"}:
            continue
        label = urllib.parse.urlparse(reference).netloc or reference
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


def _render_post_html(post: Dict[str, Any]) -> str:
    post = _normalize_post(post)
    slug = str(post["slug"])
    title = html.escape(redact(post["title"]))
    summary = html.escape(redact(post.get("summary", "")))
    categories = _post_categories(post)
    pills = _render_pills(categories)
    severity = html.escape(str(post.get("severity", "info")).title())
    severity_class = _badge_class(post.get("severity"))
    author = html.escape(_post_author(post))
    reading_time = _post_reading_time(post)
    body_html = markdown_to_html(str(post.get("body_markdown") or ""))
    iocs = _safe_list(post.get("iocs", []), limit=12)
    ioc_items = "".join(f"<li><code>{html.escape(ioc)}</code></li>" for ioc in iocs) or "<li>No structured IOCs attached.</li>"
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
        <p class="eyebrow">{severity} • SecOpsAI intelligence</p>
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
        <section class="intelligence-brief" aria-label="Post intelligence brief">
          <div>
            <p class="eyebrow">Executive summary</p>
            <p>{summary}</p>
          </div>
          <div>
            <p class="eyebrow">Affected artifacts</p>
            {_render_artifact_table(post)}
          </div>
          <div>
            <p class="eyebrow">IOCs</p>
            <ul>{ioc_items}</ul>
          </div>
        </section>
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
    post = _normalize_post(post)
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
            f"""<a class="card post-card" href="/posts/{slug}.html"
          data-search="{search}"
          data-topic="{html.escape(topics)}"
          data-severity="{_post_severity_rank(post)}"
          data-date="{html.escape(updated)}"
          data-reading="{reading_time}">
          <div class="meta">
            <span class="pill {severity_class}">{severity}</span>
            <span>{html.escape(_post_author(post))}</span>
            <span>{reading_time} min read</span>
            <span>{html.escape(_post_date(updated))}</span>
          </div>
          <h2>{title}</h2>
          <p>{summary}</p>
          <p class="artifact-line">{html.escape(packages[:140])}</p>
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
          <p class="eyebrow">Featured research</p>
          <h2>{html.escape(redact(featured.get("title", "")))}</h2>
          <p>{html.escape(_post_summary(featured))}</p>
          <div class="meta">
            <span class="pill {_badge_class(featured.get("severity"))}">{html.escape(str(featured.get("severity", "info")).title())}</span>
            <span>{html.escape(_post_author(featured))}</span>
            <span>{_post_reading_time(featured)} min read</span>
          </div>
        </a>
        <aside class="card intelligence-card">
          <p class="eyebrow">Operator intelligence model</p>
          <h2>Source-backed. Detection-aware. Mitigation-first.</h2>
          <p>Every published post is designed to connect external reporting, SecOpsAI detections, IOCs, and concrete response commands.</p>
        </aside>
      </section>"""
    else:
        featured_html = ""
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
        <p class="eyebrow">Security Research & Advisories</p>
        <h1>Security intelligence operators can act on quickly.</h1>
        <p class="lede">Fast incident posts from the SecOpsAI side of the console:
          affected packages, IOCs, detection logic, mitigations, timelines,
          and source-backed updates.</p>
        <div class="feed-actions">
          <a class="button" href="/feed.xml">Subscribe by RSS</a>
          <a class="button secondary" href="/json-feed">JSON Feed</a>
        </div>
      </section>
      {featured_html}
      <section class="topic-strip" aria-label="Security topics">
        {section_cards}
      </section>
      <section class="filters card" aria-label="Search and filter posts">
        <input id="post-search" type="search" placeholder="Search posts, tags, ecosystems, packages, or IOCs..." />
        <div class="filter-row">
          <button class="topic-filter active" type="button" data-topic-filter="all">All</button>
          {topic_buttons}
        </div>
        <div class="filter-row">
          <label for="post-sort">Sort</label>
          <select id="post-sort">
            <option value="latest">Latest</option>
            <option value="oldest">Oldest</option>
            <option value="severity">Severity</option>
            <option value="reading">Reading Time</option>
          </select>
        </div>
      </section>
      <section class="section-heading">
        <p class="eyebrow">Latest posts</p>
        <h2>Research, advisories, detections, and mitigation notes</h2>
      </section>
      <section class="post-list" id="posts" aria-live="polite">
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
        post = _normalize_post(post)
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
                "date_published": post.get("published_at"),
                "date_modified": post.get("updated_at"),
                "tags": post.get("tags") or post.get("categories") or [],
                "authors": [{"name": _post_author(post)}],
                "reading_time_minutes": _post_reading_time(post),
                "severity": post.get("severity"),
                "affected_packages": post.get("affected_packages", []),
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
