"""Ledger store calls from the digest and stream-scan scripts ride out a slow or dropped connection."""
import importlib.util
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_stream_scan_store_retries_timeouts_but_not_http_errors(monkeypatch):
    module = _script("stream_scan")
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    calls = []

    def flaky(method, name, value=None):
        calls.append(name)
        if len(calls) < 3:
            raise urllib.error.URLError(TimeoutError("The write operation timed out"))
        return {"ok": True}

    monkeypatch.setattr(module, "_store_once", flaky)
    assert module._store("PUT", "state", {}) == {"ok": True}
    assert len(calls) == 3

    def denied(method, name, value=None):
        raise urllib.error.HTTPError("https://ledger.example/stream/state", 401, "unauthorized", {}, None)

    monkeypatch.setattr(module, "_store_once", denied)
    with pytest.raises(urllib.error.HTTPError):
        module._store("PUT", "state", {})


def test_alert_digest_reads_a_day_with_a_long_timeout_and_one_retry(monkeypatch):
    module = _script("alert_digest")
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    seen = []

    def slow_then_ok(url, *, token="", accept="application/json", timeout=30):
        seen.append(timeout)
        if len(seen) == 1:
            raise TimeoutError("The read operation timed out")
        return {"entries": [{"alert_id": "a"}]}

    monkeypatch.setattr(module, "_get", slow_then_ok)
    assert module._digest_day("2026-11-19", "token") == {"entries": [{"alert_id": "a"}]}
    assert seen == [120, 120]


def test_alert_digest_follows_the_cursor_through_every_page_of_a_day(monkeypatch):
    module = _script("alert_digest")
    pages = {"": {"entries": [{"alert_id": "a"}], "cursor": "c/1+"},
             "c%2F1%2B": {"entries": [{"alert_id": "b"}], "cursor": "c2"},
             "c2": {"entries": [{"alert_id": "c"}], "cursor": None}}
    urls = []

    def page(url, *, token="", accept="application/json", timeout=30):
        urls.append(url)
        return pages[url.partition("?cursor=")[2]]

    monkeypatch.setattr(module, "_get", page)
    assert [e["alert_id"] for e in module._digest_day("2026-11-19", "token")["entries"]] == ["a", "b", "c"]
    assert urls[0].endswith("/digest/2026-11-19") and len(urls) == 3


def test_alert_digest_starts_from_the_last_successful_run(monkeypatch):
    from datetime import datetime, timezone
    module = _script("alert_digest")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert module._last_digest() is None, "without a token the digest falls back to 24 hours"
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    seen = []

    def runs(url, *, token="", accept="application/json", timeout=30):
        seen.append(url)
        return {"workflow_runs": [{"run_started_at": "2026-11-15T20:25:17Z"}]}

    monkeypatch.setattr(module, "_get", runs)
    assert module._last_digest() == datetime(2026, 11, 15, 20, 25, 17, tzinfo=timezone.utc)
    assert "status=success" in seen[0] and "branch=main" in seen[0]

    def down(url, **kwargs):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(module, "_get", down)
    assert module._last_digest() is None
    monkeypatch.setattr(module, "_get", lambda url, **kwargs: {"workflow_runs": []})
    assert module._last_digest() is None
