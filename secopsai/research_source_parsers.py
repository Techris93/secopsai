"""Reviewed, bounded source indexes; entries are leads, never incident proof."""
from html.parser import HTMLParser
import json
from urllib.parse import urljoin, urlparse

PRIMARY_SOURCE_OVERRIDES = {
    # The official RSS endpoint returns a rolling historical catalogue with
    # more entries than one transactional intake pass should process. The
    # source-specific parser applies a durable, overlapping update window.
    "Microsoft Security Response Center Advisories": ("https://api.msrc.microsoft.com/update-guide/rss", "msrc_rss"),
    "GitHub Security Advisories": ("https://api.github.com/advisories?per_page=100&sort=updated&direction=desc", "github_advisories"),
    "JFrog Security Research": ("https://research.jfrog.com/", "jfrog_index"),
    "Grafana Security": ("https://grafana.com/security/security-advisories/index.xml", "rss"),
    "Open VSX Registry": ("https://open-vsx.org/api/-/search?size=100&sortBy=timestamp&sortOrder=desc", "openvsx_index"),
    "Socket Blog": ("https://socket.dev/blog", "socket_index"),
}


def source_spec(source):
    if source["name"] in PRIMARY_SOURCE_OVERRIDES:
        return PRIMARY_SOURCE_OVERRIDES[source["name"]]
    if source.get("type") == "html":
        raise ValueError("source has no reviewed parser")
    return source["feed_url"], "cisa_kev" if source["name"] == "CISA Known Exploited Vulnerabilities" else "rss"


class IndexLinks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.href, self.bits, self.rows, self.hidden = "", [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        if tag == "a" and not self.hidden:
            self.href, self.bits = dict(attrs).get("href", ""), []

    def handle_data(self, data):
        if self.href and not self.hidden:
            self.bits.append(data)

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)
        if tag == "a" and self.href:
            self.rows.append((self.href, " ".join(" ".join(self.bits).split())))
            self.href, self.bits = "", []


def parse_index(config, content):
    parser, items = config["parser"], []
    if parser == "github_advisories":
        body = json.loads(content)
        if not isinstance(body, list) or not body:
            raise ValueError("GitHub advisory index is empty or malformed")
        for row in body:
            if not isinstance(row, dict) or not str(row.get("ghsa_id", "")).startswith("GHSA-"):
                raise ValueError("invalid GitHub advisory identity")
            items.append({"external_id": row["ghsa_id"], "url": row["html_url"], "title": row["summary"],
                          "excerpt": row.get("description") or row["summary"], "published_at": row.get("published_at"),
                          "source_updated_at": row.get("updated_at"), "affected_versions": row.get("vulnerabilities", []),
                          "withdrawn_at": row.get("withdrawn_at"), "collection_scope": "bounded_recent_advisory_index",
                          **({"cve_id": row["cve_id"]} if row.get("cve_id") else {})})
    elif parser == "openvsx_index":
        body = json.loads(content)
        if not isinstance(body, dict) or not isinstance(body.get("extensions"), list) or not body["extensions"]:
            raise ValueError("Open VSX index is empty or malformed")
        for row in body["extensions"]:
            name, version = row["namespace"] + "/" + row["name"], row["version"]
            items.append({"external_id": name + "@" + version, "url": row["url"], "title": name + " " + version,
                          "excerpt": row.get("description") or name, "published_at": row.get("timestamp"),
                          "collection_scope": "bounded_recent_release_metadata", "artifact_analysis_performed": False})
    else:
        reader = IndexLinks()
        reader.feed(content.decode("utf-8", errors="strict"))
        host = urlparse(config["url"]).hostname
        seen = set()
        for href, label in reader.rows:
            url = urljoin(config["url"], href)
            parsed = urlparse(url)
            parts = [p for p in parsed.path.split("/") if p]
            eligible = (len(parts) == 2 and parts[0] == "vulnerabilities" if parser == "jfrog_index"
                        else len(parts) == 2 and parts[0] == "blog" and parts[1] not in {"category", "tag", "author", "rss", "feed"})
            if not eligible or parsed.scheme != "https" or parsed.hostname != host or parsed.username or parsed.password or not label or url in seen:
                continue
            seen.add(url)
            items.append({"external_id": url, "url": url, "title": label[:1000], "excerpt": label,
                          "published_at": None, "collection_scope": "bounded_publisher_index", "article_body_acquired": False})
        if not items:
            raise ValueError("publisher index contains no recognized entries; coverage cannot advance")
    if len(items) > 1000:
        raise ValueError("source index exceeds its reviewed budget")
    for item in items:
        excerpt = item["excerpt"]
        if not isinstance(excerpt, str):
            raise ValueError("invalid source excerpt")
        if len(excerpt) > 20000:
            import hashlib
            item.update(excerpt=excerpt[:20000], excerpt_truncated=True, excerpt_original_characters=len(excerpt),
                        excerpt_sha256=hashlib.sha256(excerpt.encode()).hexdigest(), excerpt_selection={"start": 0, "end": 20000})
    return items
