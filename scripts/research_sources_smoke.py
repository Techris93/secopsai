"""Read-only feed verification; no ledger, models, samples or publication."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlparse

from secopsai.research_intake import SafeFetcher
from secopsai.research_primary_intel import MAX_SOURCE_BYTES, parse_source, source_headers, source_url


def check_source(source, *, fetcher=None):
    result = {"name": source["name"], "status": "failed", "stage": "fetch"}
    if source.get("comparison"):
        result["comparison"] = True
    parser = "cisa_kev" if source["name"] == "CISA Known Exploited Vulnerabilities" else "rss"
    try:
        url = source_url(source["feed_url"])
        _, headers, body = (fetcher or SafeFetcher(timeout=15)).get(
            url, allowed_hosts=[urlparse(url).hostname], max_bytes=MAX_SOURCE_BYTES, headers=source_headers(parser))
    except Exception as error:
        result["error_category"] = type(error).__name__
        status = re.fullmatch(r"registry returned HTTP ([0-9]{3})", str(error))
        if status:
            result["http_status"] = int(status.group(1))
        return result
    result.update(stage="parse", bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                  content_type=str(headers.get("content-type", ""))[:160])
    try:
        events = parse_source({"parser": parser, "url": url}, body)
    except Exception as error:
        result["error_category"] = type(error).__name__
        return result
    result.update(status="passed", events=len(events), truncated_excerpts=sum(bool(e.get("excerpt_truncated")) for e in events))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cisa-advisories", action="store_true", help="Also verify CISA's official advisory feed as a separately labeled comparison")
    args = parser.parse_args()
    catalog = Path(__file__).resolve().parents[1] / "blog/data/news-sources.json"
    sources = [s for s in json.loads(catalog.read_text())["sources"] if s.get("enabled") and s.get("type") in {"rss", "json"}]
    if len(sources) > 10:
        raise ValueError("source probe budget exceeded")
    if args.cisa_advisories:
        sources.append({"name": "CISA Cybersecurity Advisories (comparison)", "feed_url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "comparison": True})
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check_source, sources))
    report = {"status": "passed" if all(r["status"] == "passed" for r in results if not r.get("comparison")) else "failed", "results": results,
              "scope": "Read-only bounded source acquisition and parsing; no production ledger writes"}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
