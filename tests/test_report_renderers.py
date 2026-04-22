from __future__ import annotations

from secopsai.report_renderers import render_daily_brief, render_daily_intel, render_status_summary


def _sample_snapshot() -> dict:
    return {
        "generated_at": "2026-04-20T09:00:46.014629Z",
        "repo": {
            "branch": "main",
            "commit_counts": {"last_24h": 0, "since_local_midnight": 0},
            "last_commit": {
                "sha": "c02c2232f78c9acdfad380deadc98084adfe4ab4",
                "committed_at": "2026-04-16T21:16:40+03:00",
                "subject": "Fix adaptive intel validation and snapshot reporting",
            },
            "worktree": {
                "dirty": True,
                "total_changes": 73,
                "tracked_changes": 73,
                "untracked_changes": 0,
            },
        },
        "findings": {
            "soc_store": {
                "db_path": "/Users/chrixchange/secopsai/data/openclaw/findings/openclaw_soc.db",
                "exists": True,
                "total_findings": 59,
                "open_or_in_review": 0,
                "latest_last_seen": "2026-04-16T07:44:25Z",
                "severity_counts": {"critical": 59},
                "open_severity_counts": {},
                "source_counts": {"secopsai-supply-chain": 59},
                "status_counts": {"closed": 59},
                "top_open_findings": [],
            }
        },
        "telemetry": {
            "labeled_replay": {
                "exists": True,
                "path": "/Users/chrixchange/secopsai/data/openclaw/replay/labeled/current.json",
                "total_events": 2533,
                "latest_event_ts": "2026-04-16T18:01:29.539000Z",
                "age_hours_since_latest_event": 86.99,
                "event_type_counts": {"config": 553, "exec": 771, "session": 24, "tool": 1185},
                "status_counts": {
                    "accepted": 11,
                    "approval-pending": 24,
                    "approval-unavailable": 2,
                    "completed": 718,
                    "error": 50,
                    "failed": 110,
                    "ok": 589,
                    "running": 1029,
                },
            },
            "openclaw_latest_bundle": {
                "findings_dir": "/Users/chrixchange/secopsai/data/openclaw/findings",
                "latest_bundle_path": "/Users/chrixchange/secopsai/data/openclaw/findings/openclaw-findings-20260416-181650.json",
                "generated_at": "2026-04-16T18:16:50.212447Z",
                "age_hours": 86.73,
                "total_events": 2533,
                "total_detections": 0,
                "total_findings": 0,
                "total_candidate_findings": 0,
            },
        },
        "intel": {
            "exists": True,
            "path": "/Users/chrixchange/secopsai/data/intel/iocs.json",
            "generated_at": "2026-04-19T03:00:50.038672Z",
            "age_hours": 30.0,
            "total_iocs": 11991,
            "ioc_type_counts": {"artifact": 14, "domain": 1, "hash": 5, "ip": 1, "url": 11970},
            "source_counts": {"elastic-curated": 22, "urlhaus": 11969},
            "top_tags": {"CoinMiner": 4094, "malware_download": 11969},
        },
        "adaptive_intel": {
            "latest_pipeline_log": {
                "path": "/Users/chrixchange/.openclaw/workspace/logs/adaptive_intel_20260419_200003.log",
                "modified_at": "2026-04-19T20:00:33.135539Z",
                "age_hours": 13.0,
            },
            "latest_results": {
                "path": "/Users/chrixchange/.openclaw/workspace/logs/adaptive_results.json",
                "started_at": "2026-04-19T20:00:03.000456Z",
                "ended_at": "2026-04-19T20:00:33.135650Z",
                "age_hours_since_end": 13.0,
                "deployed": False,
                "indicators_fetched": 176,
                "rules_generated": 72,
                "f1_baseline": 0.974813,
                "f1_new": 0.974813,
                "f1_improvement": 0.0,
                "errors": [],
            },
        },
        "correlation": {
            "total_correlations": 0,
            "cross_platform_ip": 0,
            "cross_platform_user": 0,
            "time_cluster": 0,
            "cross_platform_file": 0,
        },
        "staleness_flags": ["intel_older_than_24h", "telemetry_older_than_24h"],
    }


def test_render_status_summary_formats_empty_mappings_without_recipient_noise() -> None:
    rendered = render_status_summary(_sample_snapshot())

    assert "Open severity counts: none" in rendered
    assert "Top open findings: none" in rendered
    assert "Send to Telegram chat" not in rendered
    assert "Target:" not in rendered


def test_render_daily_brief_uses_canonical_snapshot_fields() -> None:
    rendered = render_daily_brief(_sample_snapshot())

    assert rendered.startswith("SecOpsAI Daily Brief - 2026-04-20")
    assert "Staleness flags: intel_older_than_24h, telemetry_older_than_24h." in rendered
    assert "SOC findings: 59 total findings in the SOC store, 0 open or in review." in rendered
    assert "Replay findings: latest OpenClaw bundle generated at 2026-04-16T18:16:50.212447Z" in rendered


def test_render_daily_intel_keeps_soc_and_replay_findings_separate() -> None:
    rendered = render_daily_intel(
        _sample_snapshot(),
        command_status={
            "refresh": "succeeded",
            "match": "succeeded",
            "refresh_metrics": {"refresh": {"total": 11991}},
            "match_metrics": {"events_total": 2533, "iocs_considered": 500, "matched_findings": 0},
        },
    )

    assert "SOC findings, kept separate from replay findings" in rendered
    assert "Replay findings, kept separate from SOC findings" in rendered
    assert "• intel refresh: succeeded" in rendered
    assert "• Replay events scanned: 2533" in rendered


def test_render_daily_intel_highlights_export_bridge_staleness() -> None:
    snapshot = _sample_snapshot()
    snapshot["telemetry"]["openclaw_source"] = {
        "home": "/Users/chrixchange/.openclaw",
        "latest_activity_at": "2026-04-20T08:55:00Z",
        "age_hours_since_latest_activity": 0.1,
        "latest_activity_path": "/Users/chrixchange/.openclaw/agents/main/sessions/latest.jsonl",
    }
    snapshot["staleness_flags"] = ["telemetry_older_than_24h", "telemetry_export_bridge_stale"]

    rendered = render_daily_intel(
        snapshot,
        command_status={
            "refresh": "succeeded",
            "match": "succeeded",
            "refresh_metrics": {"refresh": {"total": 11991}},
            "match_metrics": {"events_total": 2533, "iocs_considered": 500, "matched_findings": 0},
        },
    )

    assert "• Latest OpenClaw source activity: 2026-04-20T08:55:00Z" in rendered
    assert "• OpenClaw source logs are fresher than the replay bundle, so the export bridge likely needs attention" in rendered
    assert "• OpenClaw source logs are fresh, but the replay export pipeline is stale; rerun secopsai refresh or repair the scheduled refresh bridge" in rendered
