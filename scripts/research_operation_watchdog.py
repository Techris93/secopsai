"""Independent read-only liveness checks. Never starts work or writes the ledger."""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("watchdog endpoint redirects are not allowed")


def fetch(url, token="", *, opener=None):
    endpoint = urlparse(url)
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError("watchdog endpoints require HTTPS")
    opener = opener or urllib.request.build_opener(NoRedirect()).open
    request = urllib.request.Request(url, headers={"User-Agent": "SecOpsAI-Research-Watchdog/1", **({"Authorization": f"Bearer {token}"} if token else {})})
    for attempt in range(3):
        try:
            with opener(request, timeout=15) as response:
                if response.status != 200:
                    raise ValueError("non-successful endpoint")
                raw = response.read(131073)
                if len(raw) > 131072:
                    raise ValueError("watchdog response exceeds budget")
                return raw
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def inspect(*, reader=fetch, now=None) -> dict:
    now = now or datetime.now(timezone.utc)
    checks, blockers = {}, []
    for name, url, token in (
        ("checkpoint", os.environ.get("LEDGER_STORE_URL", "https://ledger.secopsai.dev") + "/status", os.environ.get("LEDGER_STORE_TOKEN", "")),
        ("research_operation", os.environ.get("SECOPSAI_CORE_COORDINATOR_URL", "https://core.secopsai.dev") + "/api/v1/research/operation", os.environ.get("SECOPSAI_CORE_BRIDGE_TOKEN", "")),
        ("public_blog", os.environ.get("SECOPSAI_PUBLIC_BLOG_URL", "https://blog.secopsai.dev/"), ""),
    ):
        try:
            raw = reader(url, token)
            if name == "public_blog":
                if b"<html" not in raw.lower() and b"<!doctype html" not in raw.lower():
                    raise ValueError("public blog did not return HTML")
                checks[name] = {"available": True}
                continue
            value = json.loads(raw)
            key = "uploaded_at" if name == "checkpoint" else "synced_at"
            observed = value.get(key)
            if not observed:
                raise ValueError("missing durable freshness timestamp")
            age = (now - datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
            if name == "checkpoint" and (not value.get("checkpoint_available") or value.get("completion_retry_safe") is not True):
                raise ValueError("checkpoint protocol is not ready")
            if age < -300 or age > 5400:
                blockers.append(f"{name} freshness is outside the operational limit")
            checks[name] = {"available": True, "age_seconds": round(age), "rpo_target_met": age <= 300 if name == "checkpoint" else None}
            if name == "research_operation":
                health = value.get("coverage", {}).get("health", {})
                checks[name]["freshness_gaps"] = health.get("freshness_gaps", [])
                checks[name]["dead_letters"] = health.get("dead_letters", 0)
                if health.get("freshness_gaps") or health.get("dead_letters"):
                    blockers.append("source freshness or dead-letter review requires attention")
        except Exception as exc:
            # Never print endpoint bodies, credential-bearing errors or tokens.
            checks[name] = {"available": False, "error_category": type(exc).__name__}
            blockers.append(f"{name} availability/freshness check failed")
    return {"as_of": now.isoformat(), "status": "failed" if blockers else "passed", "checks": checks, "blockers": blockers}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = inspect()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    print(json.dumps({"status": report["status"], "blockers": report["blockers"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
