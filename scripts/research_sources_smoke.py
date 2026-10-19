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
from secopsai.research_primary_intel import MAX_SOURCE_BYTES, msrc_window_start, parse_source_report, source_headers, source_url


def check_source(source, *, fetcher=None, now=None):
    result = {"name": source["name"], "status": "failed", "stage": "fetch", "eligible_events": 0,
              "ingested_events": 0, "historical_excluded": 0, "failed_events": 0}
    if source.get("comparison"):
        result["comparison"] = True
    from secopsai.research_source_parsers import source_spec
    url, parser = source_spec(source)
    try:
        url = source_url(url)
        from secopsai.research_source_transport import fetch_source
        _, headers, body = fetch_source(url, fetcher=fetcher or SafeFetcher(timeout=15),
                                        max_bytes=MAX_SOURCE_BYTES, headers=source_headers(parser, url=url))
    except Exception as error:
        result["error_category"] = type(error).__name__
        status = re.fullmatch(r"registry returned HTTP ([0-9]{3})", str(error))
        if status:
            result["http_status"] = int(status.group(1))
        return result
    result.update(stage="parse", transport=headers.get("secopsai-transport", "direct"), bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                  content_type=str(headers.get("content-type", ""))[:160])
    try:
        config = {"parser": parser, "url": url}
        if parser == "msrc_rss":
            config["msrc_lookback_start"] = msrc_window_start(now=now)
        parsed = parse_source_report(config, body, now=now)
    except Exception as error:
        result["error_category"] = type(error).__name__
        return result
    omitted = parsed["events_total"] - parsed["events_in_scope"] - parsed["historical_excluded"]
    if omitted:
        result.update(error_category="event_accounting_mismatch", failed_events=omitted)
        return result
    result.update(status="passed", events=parsed["events_in_scope"],
                  events_total=parsed["events_total"], eligible_events=parsed["events_in_scope"],
                  ingested_events=parsed["events_in_scope"], historical_excluded=parsed["historical_excluded"],
                  failed_events=0, ingestion_mode="read_only_would_ingest", window_start=parsed["window_start"],
                  truncated_excerpts=sum(bool(e.get("excerpt_truncated")) for e in parsed["items"]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cisa-advisories", action="store_true", help="Also verify CISA's official advisory feed as a separately labeled comparison")
    args = parser.parse_args()
    catalog = Path(__file__).resolve().parents[1] / "blog/data/news-sources.json"
    sources = [s for s in json.loads(catalog.read_text())["sources"] if s.get("enabled")]
    if not 1 <= len(sources) <= 20:
        raise ValueError("source probe requires 1-20 enabled reviewed sources")
    if args.cisa_advisories:
        sources.append({"name": "CISA Cybersecurity Advisories (comparison)", "feed_url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "comparison": True})
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check_source, sources))
    required = [r for r in results if not r.get("comparison")]
    report = {"status": "passed" if all(r["status"] == "passed" for r in required) else "failed", "results": results,
              "counts": {"eligible_events": sum(r.get("eligible_events", 0) for r in required),
                         "ingested_events": sum(r.get("ingested_events", 0) for r in required),
                         "historical_excluded": sum(r.get("historical_excluded", 0) for r in required),
                         "failed_sources": sum(r.get("status") != "passed" for r in required),
                         "failed_events": sum(r.get("failed_events", 0) for r in required)},
              "scope": "Read-only bounded source acquisition and parsing; ingested_events means eligible for intake, with no production ledger writes"}
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
