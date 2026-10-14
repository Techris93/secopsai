import pytest

from scripts.research_sources_smoke import check_source


SOURCE = {"name": "Synthetic vendor", "feed_url": "https://vendor.example/feed"}


def test_transport_denial_is_identifiable_without_printing_error_secrets():
    class Denied:
        def get(self, *args, **kwargs):
            raise ValueError("registry returned HTTP 403")

    assert check_source(SOURCE, fetcher=Denied()) == {"name": "Synthetic vendor", "status": "failed", "stage": "fetch", "error_category": "ValueError", "http_status": 403}

    class SecretError:
        def get(self, *args, **kwargs):
            raise RuntimeError("sensitive synthetic error value")

    assert "sensitive" not in str(check_source(SOURCE, fetcher=SecretError()))


@pytest.mark.parametrize("body, status", [(b"<html>not a feed</html>", "failed"),
    (b'<rss version="2.0"><channel><title>Fixture</title><link>https://vendor.example/</link><description>Fixture</description><item><guid>notice</guid><title>Notice</title><link>https://vendor.example/notice</link><description>Fixture</description></item></channel></rss>', "passed")])
def test_probe_separates_invalid_body_from_successful_feed(body, status):
    class Feed:
        def get(self, *args, **kwargs):
            assert kwargs["headers"]["Accept"].startswith("application/rss+xml")
            return SOURCE["feed_url"], {"content-type": "application/xml"}, body

    result = check_source(SOURCE, fetcher=Feed())
    assert result["stage"] == "parse" and result["status"] == status
    assert "Fixture" not in str(result)
    if status == "passed":
        assert result["events"] == 1


def test_watchdog_blocks_incomplete_durable_artifact_backups():
    from datetime import datetime, timezone
    import json
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
    def reader(url, token):
        if url.endswith("/status"):
            return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True, "completion_retry_safe": True}).encode()
        if "/research/operation" in url:
            return json.dumps({"synced_at": now.isoformat(), "coverage": {"health": {"artifact_backup_pending": 7}}}).encode()
        return b"<html>synthetic</html>"
    result = inspect(reader=reader, now=now)
    assert result["status"] == "failed"
    assert result["blockers"] == ["registered public artifacts lack completed durable backups"]
    assert result["checks"]["research_operation"]["artifact_backup_pending"] == 7
