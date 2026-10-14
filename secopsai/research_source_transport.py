"""Bounded primary-source collection with an authenticated fixed-source relay.

The relay fetches the same original bytes from another approved collection
location. It never substitutes a different publisher or claims completeness.
"""
from __future__ import annotations

import hashlib
import os
import urllib.request
from urllib.parse import urlparse

from secopsai.research_intake import IntakeError, SafeFetcher
from secopsai.research_artifact_vault import NoRedirect

RELAY_SOURCES = {
    "https://www.cisa.gov/news.xml": "cisa-news",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml": "cisa-advisories",
}


def fetch_source(url, *, headers, max_bytes, fetcher=None):
    fetcher = fetcher or SafeFetcher(timeout=15)
    try:
        final, response_headers, body = fetcher.get(url, allowed_hosts=[urlparse(url).hostname],
                                                   max_bytes=max_bytes, headers=headers)
        return final, response_headers, body
    except IntakeError as exc:
        if str(exc) != "registry returned HTTP 403" or url not in RELAY_SOURCES:
            raise
        token = os.environ.get("LEDGER_STORE_TOKEN", "")
        origin = os.environ.get("LEDGER_STORE_URL", "")
        # Credentials are never attached to a source URL or an operator redirect.
        if not token or origin.rstrip("/") != "https://ledger.secopsai.dev":
            raise
    from secopsai.worker_control import check_shutdown
    check_shutdown()
    request = urllib.request.Request(origin.rstrip("/") + "/public-sources/" + RELAY_SOURCES[url],
        headers={"Authorization": "Bearer " + token, "User-Agent": "SecOpsAI-Research/1.0"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            body = response.read(max_bytes + 1)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
    except OSError:
        raise IntakeError("source relay unavailable") from None
    if not body or len(body) > max_bytes or response_headers.get("x-secopsai-source-url") != url or response_headers.get("x-secopsai-source-sha256") != hashlib.sha256(body).hexdigest():
        raise IntakeError("source relay provenance validation failed")
    response_headers["secopsai-transport"] = "cloudflare-fixed-source-relay"
    return url, response_headers, body
