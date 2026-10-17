import pytest

from scripts.research_sources_smoke import check_source


SOURCE = {"name": "Synthetic vendor", "feed_url": "https://vendor.example/feed"}


def test_transport_denial_is_identifiable_without_printing_error_secrets():
    class Denied:
        def get(self, *args, **kwargs):
            raise ValueError("registry returned HTTP 403")

    denied = check_source(SOURCE, fetcher=Denied())
    assert {key: denied[key] for key in ("name", "status", "stage", "error_category", "http_status")} == {
        "name": "Synthetic vendor", "status": "failed", "stage": "fetch", "error_category": "ValueError", "http_status": 403
    }
    assert denied["eligible_events"] == denied["ingested_events"] == denied["historical_excluded"] == 0

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


def test_msrc_smoke_accounts_for_large_feed_and_recent_revisions():
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    entries = []
    for index in range(5280):
        published = now - timedelta(days=30 + index % 100)
        updated = published
        if index == 0:
            published = updated = now - timedelta(hours=1)
        elif index == 1:
            # An old advisory revised today must remain in scope.
            updated = now - timedelta(minutes=30)
        entries.append(
            f"<entry><id>ADV-{index:04d}</id><title>Advisory {index}</title>"
            f"<updated>{updated.isoformat()}</updated><published>{published.isoformat()}</published>"
            f"<link href=\"https://msrc.example/advisory/{index}\"/></entry>"
        )
    body = ("<feed xmlns=\"http://www.w3.org/2005/Atom\"><id>fixture</id><title>MSRC fixture</title>"
            f"<updated>{now.isoformat()}</updated>{''.join(entries)}</feed>").encode()

    class Feed:
        def get(self, url, **kwargs):
            assert url == "https://api.msrc.microsoft.com/update-guide/rss"
            return url, {"content-type": "application/atom+xml"}, body

    result = check_source({"name": "Microsoft Security Response Center Advisories", "feed_url": "https://example.invalid/feed"}, fetcher=Feed(), now=now)
    assert result["status"] == "passed"
    assert result["events_total"] == 5280
    assert result["eligible_events"] == result["ingested_events"] == 2
    assert result["historical_excluded"] == 5278
    assert result["failed_events"] == 0
    assert result["events_total"] == result["eligible_events"] + result["historical_excluded"]


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


def test_watchdog_reports_active_worker_and_recent_delivery_as_in_progress():
    from datetime import datetime, timedelta, timezone
    import json
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)

    def reader(url, _token):
        if url.endswith("/status"):
            return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                               "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
        if "/research/operation" in url:
            health = {"freshness_gaps": [], "dead_letters": 0, "artifact_backup_pending": 0,
                      "ontology_pending": 8, "ontology_due_pending": 8,
                      "ontology_oldest_age_seconds": 300,
                      "ontology_last_acknowledged_at": (now - timedelta(seconds=30)).isoformat(),
                      "ontology_validation_failures": 0, "ontology_authorization_failures": 0,
                      "ontology_new_unique_chunks_24h": 100, "ontology_acknowledged_chunks_24h": 92}
            return json.dumps({"synced_at": (now - timedelta(hours=2)).isoformat(), "coverage": {"health": health}}).encode()
        return b"<html>synthetic</html>"

    active = inspect(reader=reader, now=now, worker_active=True)
    assert active["status"] == "in_progress" and active["decision_final"] is False
    assert active["blockers"] == []
    assert "provisional" in active["warnings"][0]
    assert active["checks"]["research_operation"]["source_freshness_status"] == "provisional"

    current = inspect(reader=reader, now=now, worker_active=False)
    assert current["status"] == "in_progress" and current["decision_final"] is False
    assert current["blockers"] == []
    assert any("delivery is in progress" in warning for warning in current["warnings"])

    # A quiet period followed by a newly queued item is not evidence of a
    # stalled acknowledgement path; measure the age of the actual oldest item.
    def newly_queued_reader(url, token):
        raw = reader(url, token)
        if "/research/operation" not in url:
            return raw
        value = json.loads(raw)
        health = value["coverage"]["health"]
        health["ontology_pending"] = 1
        health["ontology_oldest_age_seconds"] = 10
        health["ontology_last_acknowledged_at"] = (now - timedelta(hours=3)).isoformat()
        health["ontology_new_unique_chunks_24h"] = 101
        health["ontology_acknowledged_chunks_24h"] = 100
        return json.dumps(value).encode()

    newly_queued = inspect(reader=newly_queued_reader, now=now, worker_active=False)
    assert newly_queued["status"] == "in_progress"
    assert not any("stopped acknowledging" in blocker for blocker in newly_queued["blockers"])

    strict = inspect(reader=reader, now=now, scope="delivery", worker_active=False)
    assert strict["status"] == "failed"
    assert "semantic delivery has unacknowledged durable chunks" in strict["blockers"]


def test_watchdog_defers_source_freshness_gate_until_worker_snapshot_is_final():
    from datetime import datetime, timezone
    import json
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)

    def reader(url, _token):
        if url.endswith("/status"):
            return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                               "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
        if "/research/operation" in url:
            health = {"freshness_gaps": ["crates.io recently updated crates"],
                      "dead_letters": 0, "artifact_backup_pending": 0, "ontology_pending": 0}
            return json.dumps({"synced_at": now.isoformat(), "coverage": {"health": health}}).encode()
        return b"<html>synthetic</html>"

    provisional = inspect(reader=reader, now=now, scope="all", worker_active=True)
    assert provisional["status"] == "in_progress"
    assert provisional["decision_final"] is False
    assert provisional["blockers"] == []
    assert provisional["checks"]["research_operation"]["source_freshness_status"] == "provisional"
    assert provisional["checks"]["research_operation"]["freshness_gaps"] == [
        "crates.io recently updated crates"
    ]

    final = inspect(reader=reader, now=now, scope="all", worker_active=False,
                    upstream_worker_conclusion="success",
                    upstream_worker_completed_at=now.isoformat(),
                    upstream_worker_run_id="synthetic-worker-run")
    assert final["status"] == "failed"
    assert final["checks"]["research_operation"]["source_freshness_status"] == "degraded"
    assert final["blockers"] == ["enabled research sources are outside their freshness targets"]


def test_watchdog_fails_stalled_or_permanently_rejected_delivery_and_stale_post_run_snapshot():
    from datetime import datetime, timedelta, timezone
    import json
    from scripts.research_operation_watchdog import inspect

    now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    health = {"freshness_gaps": [], "dead_letters": 0, "artifact_backup_pending": 0,
              "ontology_pending": 3, "ontology_due_pending": 3,
              "ontology_oldest_age_seconds": 8000, "ontology_last_acknowledged_at": None,
              "ontology_validation_failures": 1, "ontology_authorization_failures": 0,
              "ontology_new_unique_chunks_24h": 4, "ontology_acknowledged_chunks_24h": 0}

    def reader(url, _token):
        if url.endswith("/status"):
            return json.dumps({"uploaded_at": now.isoformat(), "checkpoint_available": True,
                               "completion_retry_safe": True, "captured_at": now.isoformat()}).encode()
        if "/research/operation" in url:
            return json.dumps({"synced_at": (now - timedelta(minutes=3)).isoformat(), "coverage": {"health": health}}).encode()
        return b"<html>synthetic</html>"

    stalled = inspect(reader=reader, now=now)
    assert stalled["status"] == "failed"
    assert any("validation" in blocker for blocker in stalled["blockers"])
    assert any("two-hour service window" in blocker for blocker in stalled["blockers"])

    stale = inspect(reader=reader, now=now, upstream_worker_conclusion="success",
                     upstream_worker_completed_at=now.isoformat(), upstream_worker_run_id="fixture-run")
    assert "research operation snapshot predates the completed Research Worker run" in stale["blockers"]
