"""The Blog Ops step that asks the Pages worker to email new posts."""
import datetime as dt
import hashlib
import hmac
import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("blog_newsletter", ROOT / "scripts" / "blog_newsletter.py")
newsletter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(newsletter)

NOW = dt.datetime(2026, 11, 21, 12, tzinfo=dt.timezone.utc)


def item(slug, hours_ago, host="https://blog.secopsai.dev/posts/"):
    return {"url": f"{host}{slug}.html", "date_published": (NOW - dt.timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")}


def test_only_posts_from_the_last_two_days_are_sent():
    feed = {"items": [item("today", 3), item("yesterday", 30), item("old", 60), item("elsewhere", 1, "https://evil.example/posts/"),
                      {"url": "https://blog.secopsai.dev/posts/undated.html", "date_published": "soon"}]}
    assert newsletter.recent_slugs(feed, NOW) == ["today", "yesterday"]


def test_the_signature_is_an_hmac_over_timestamp_dot_body():
    request = newsletter.signed_request(b'{"slugs":["a"]}', "secret", 1795000000)
    expected = hmac.new(b"secret", b'1795000000.{"slugs":["a"]}', hashlib.sha256).hexdigest()
    assert request.get_header("X-newsletter-signature") == f"sha256={expected}"
    assert request.get_header("X-newsletter-timestamp") == "1795000000"
    assert request.full_url == "https://blog.secopsai.dev/api/newsletter/send"


def test_send_waits_for_the_new_deployment_then_stops_on_other_errors(monkeypatch):
    answers = [401, 503, {"ok": True, "results": []}]
    waits = []

    def fake_urlopen(request, timeout):
        answer = answers.pop(0)
        if isinstance(answer, int):
            raise urllib.error.HTTPError(request.full_url, answer, "no", {}, io.BytesIO(b"{}"))
        return io.BytesIO(json.dumps(answer).encode())

    monkeypatch.setattr(newsletter.urllib.request, "urlopen", fake_urlopen)
    assert newsletter.send(["a"], "secret", sleep=waits.append) == {"ok": True, "results": []}
    assert waits == list(newsletter.RETRY_DELAYS[:2])

    answers[:] = [400]
    with pytest.raises(urllib.error.HTTPError):
        newsletter.send(["a"], "secret", sleep=waits.append)
