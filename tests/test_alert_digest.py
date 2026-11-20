from datetime import datetime, timezone

from secopsai import alert_digest, notification_policy

NOW = datetime(2026, 11, 16, 7, 0, tzinfo=timezone.utc)


def _entry(alert_id, severity="high", package="pkg", version="1.0.0", eco="npm", when="2026-11-15T12:00:00Z", **extra):
    return notification_policy.digest_entry(source="fast_lane", alert_id=alert_id, severity=severity, title=f"{package}@{version}",
                                            reason="new install script", occurred_at=when, ecosystem=eco, package=package,
                                            version=version, **extra)


def test_window_keeps_the_last_day_once_per_alert_most_severe_first():
    entries = [_entry("a", "high"), _entry("a", "critical"), _entry("b", "low"), _entry("old", when="2026-11-14T06:00:00Z"),
               _entry("future", when="2026-11-16T08:00:00Z")]
    kept = alert_digest.window(entries, NOW)
    assert [(e["alert_id"], e["severity"]) for e in kept] == [("a", "critical"), ("b", "low")]


def test_triage_groups_known_removed_review_and_operational():
    entries = [_entry("known", package="evil"), _entry("gone", package="pulled"), _entry("live", package="fresh"),
               notification_policy.digest_entry(source="research_worker", alert_id="op", severity="medium", title="collector_degraded"),
               _entry("unknown", package="flaky")]
    blocked = {"evil": ["MAL-1"]}
    published = {"pulled": False, "fresh": True, "flaky": None}
    out = {e["alert_id"]: e for e in alert_digest.triage(entries, blocked=lambda eco, n, v: blocked.get(n, []),
                                                           published=lambda eco, n, v: published.get(n))}
    assert out["known"]["group"] == "known_malicious" and out["known"]["advisories"] == ["MAL-1"]
    assert out["gone"]["group"] == "removed"
    assert out["live"]["group"] == "needs_review"
    assert out["op"]["group"] == "operational"
    assert out["unknown"]["group"] == "unchecked", "an unanswered registry is never treated as removed"


def test_render_leads_with_what_needs_review_and_links_the_dashboard():
    entries = alert_digest.triage([_entry("live", package="fresh", emailed=True)], blocked=lambda *a: [], published=lambda *a: True)
    message = alert_digest.render(entries, NOW)
    assert message["subject"].startswith("SecOpsAI daily digest: 1 to review")
    assert notification_policy.DASHBOARD_INBOX in message["body"]
    assert "fresh@1.0.0 (npm) [sent]" in message["body"]
    assert "not sent" in alert_digest.render(entries, NOW, paused=True)["body"]


def test_core_alert_id_matches_the_dashboard():
    import hashlib
    assert notification_policy.core_alert_id("FASTLANE-npm:x@1") == "RAL-WEB-" + hashlib.sha256(b"FASTLANE-npm:x@1").hexdigest()[:24].upper()


def test_only_ossf_listed_fast_lane_alerts_are_closed():
    entries = alert_digest.triage(
        [_entry("listed", package="evil"), _entry("listed-no-mal", package="odd"), _entry("live", package="fresh"),
         notification_policy.digest_entry(source="research_worker", alert_id="op", severity="high", title="x", ecosystem="npm",
                                          package="evil", version="1.0.0")],
        blocked=lambda eco, n, v: {"evil": ["MAL-2026-808"], "odd": ["listed"]}.get(n, []), published=lambda *a: True)
    payloads = alert_digest.resolutions(entries)
    assert [p["source_alert_id"] for p in payloads] == ["listed"], "fast lane only, MAL- ids only, never needs-review"
    assert payloads[0]["resolution"] == "listed_by_ossf" and payloads[0]["advisories"] == ["MAL-2026-808"]
    body = alert_digest.render([{**entries[0], "auto_resolved": True}], NOW)["body"]
    assert "[closed automatically]" in body


def test_window_starts_at_the_last_completed_digest_so_failed_days_are_caught_up():
    from datetime import timedelta
    four_days_ago = NOW - timedelta(days=4)
    assert alert_digest.window_start(NOW, None) == NOW - timedelta(hours=24)
    assert alert_digest.window_start(NOW, four_days_ago) == four_days_ago
    assert alert_digest.window_start(NOW, NOW - timedelta(days=30)) == NOW - timedelta(days=alert_digest.CATCH_UP_DAYS)
    assert alert_digest.window_start(NOW, NOW + timedelta(hours=1)) == NOW - timedelta(hours=24)
    assert alert_digest.days(four_days_ago, NOW) == ["2026-11-12", "2026-11-13", "2026-11-14", "2026-11-15", "2026-11-16"]
    entries = [_entry("missed", when="2026-11-13T09:00:00Z"), _entry("sent-before", when="2026-11-12T06:00:00Z")]
    kept = alert_digest.window(entries, NOW, start=four_days_ago)
    assert [e["alert_id"] for e in kept] == ["missed"]
    message = alert_digest.render(alert_digest.triage(kept, blocked=lambda *a: [], published=lambda *a: True), NOW,
                                  start=four_days_ago)
    assert message["subject"].endswith("(12 Nov to 16 Nov)")
    assert message["body"].startswith("Alerts from 2026-11-12 07:00 to 2026-11-16 07:00 UTC: 1.")
    assert alert_digest.render([], NOW)["subject"].endswith("(16 Nov)")
