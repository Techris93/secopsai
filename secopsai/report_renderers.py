from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from zoneinfo import ZoneInfo


DEFAULT_TIMEZONE = "Europe/Istanbul"


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _tz(name: str) -> ZoneInfo:
    return ZoneInfo(name)


def _local_dt(value: Any, tz_name: str) -> datetime | None:
    parsed = _parse_dt(value)
    if parsed is None:
        return None
    return parsed.astimezone(_tz(tz_name))


def _local_date(value: Any, tz_name: str) -> str:
    parsed = _local_dt(value, tz_name)
    if parsed is None:
        return "unknown-date"
    return parsed.strftime("%Y-%m-%d")


def _local_stamp(value: Any, tz_name: str) -> str:
    parsed = _local_dt(value, tz_name)
    if parsed is None:
        return "unknown-time"
    return parsed.strftime("%Y-%m-%d %H:%M")


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _mapping_items(value: Mapping[str, Any] | None) -> list[tuple[str, Any]]:
    if not _is_mapping(value):
        return []
    return [(str(key), value[key]) for key in value]


def format_mapping(
    value: Mapping[str, Any] | None,
    *,
    empty: str = "none",
    unavailable: str = "unavailable",
) -> str:
    if value is None:
        return unavailable
    if not _is_mapping(value):
        return unavailable
    items = _mapping_items(value)
    if not items:
        return empty
    return ", ".join(f"{key}={item}" for key, item in items)


def format_value(value: Any, *, unavailable: str = "unavailable") -> str:
    if value is None:
        return unavailable
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return str(value)
    if isinstance(value, (int, str)):
        return str(value)
    return unavailable


def format_flag_list(flags: Sequence[Any] | None) -> str:
    if flags is None:
        return "unavailable"
    if not flags:
        return "none"
    return ", ".join(str(flag) for flag in flags)


def _bool_label(value: Any) -> str:
    if value is True:
        return "dirty"
    if value is False:
        return "clean"
    return "unknown"


def _hours_phrase(value: Any) -> str:
    if value is None:
        return "unavailable"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{number:.2f}"


def _nested(mapping: Mapping[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def _top_open_lines(findings: Sequence[Mapping[str, Any]] | None) -> list[str]:
    if findings is None:
        return ["- Top open findings: unavailable"]
    if not findings:
        return ["- Top open findings: none"]

    lines = ["- Top open findings:"]
    for finding in findings[:10]:
        lines.append(
            "  - {fid}, {sev}, {status}, {title}, first_seen {first_seen}, last_seen {last_seen}".format(
                fid=format_value(finding.get("finding_id")),
                sev=format_value(finding.get("severity")),
                status=format_value(finding.get("status")),
                title=format_value(finding.get("title")),
                first_seen=format_value(finding.get("first_seen")),
                last_seen=format_value(finding.get("last_seen")),
            )
        )
    return lines


def _command_status(status: Mapping[str, Any] | None, key: str) -> str:
    if not _is_mapping(status):
        return "unavailable"
    return str(status.get(key) or "unavailable")


def _recommended_actions(
    snapshot: Mapping[str, Any],
    command_status: Mapping[str, Any] | None,
) -> list[str]:
    actions: list[str] = []
    staleness_flags = _nested(snapshot, "staleness_flags") or []
    replay_age = _nested(snapshot, "telemetry", "labeled_replay", "age_hours_since_latest_event")
    latest_event_ts = _nested(snapshot, "telemetry", "labeled_replay", "latest_event_ts")
    intel_age = _nested(snapshot, "intel", "age_hours")
    matched_findings = _nested(command_status or {}, "match_metrics", "matched_findings")
    soc_open = _nested(snapshot, "findings", "soc_store", "open_or_in_review")

    if "telemetry_older_than_24h" in staleness_flags:
        actions.append("Refresh or ingest newer OpenClaw replay telemetry first, current visibility is limited by stale data")
        if latest_event_ts:
            actions.append(f"Investigate why telemetry stopped updating after {latest_event_ts}")
    elif replay_age is not None:
        try:
            if float(replay_age) >= 12:
                actions.append("Keep watching replay freshness so IOC matching stays current")
        except (TypeError, ValueError):
            pass

    if "intel_older_than_24h" in staleness_flags:
        actions.append("Refresh threat intel so IOC matching uses a fresh IOC corpus")
    elif _command_status(command_status, "refresh") == "failed":
        actions.append("Review the intel refresh failure and confirm the IOC corpus was updated")

    if matched_findings not in (None, 0, "0"):
        actions.append("Review matched IOC findings immediately and compare them against replay telemetry context")

    if soc_open not in (None, 0, "0"):
        actions.append("Review active SOC-store findings separately from replay telemetry results")
    elif not actions:
        actions.append("Continue monitoring URLhaus-driven intel growth, but there is no current evidence of IOC overlap in replay data")

    deduped: list[str] = []
    seen: set[str] = set()
    for action in actions:
        if action not in seen:
            deduped.append(action)
            seen.add(action)
    return deduped[:3]


def render_status_summary(snapshot: Mapping[str, Any], *, tz_name: str = DEFAULT_TIMEZONE) -> str:
    repo = _nested(snapshot, "repo") or {}
    repo_commit_counts = _nested(repo, "commit_counts") or {}
    repo_last_commit = _nested(repo, "last_commit") or {}
    repo_worktree = _nested(repo, "worktree") or {}
    soc_store = _nested(snapshot, "findings", "soc_store") or {}
    replay = _nested(snapshot, "telemetry", "labeled_replay") or {}
    replay_bundle = _nested(snapshot, "telemetry", "openclaw_latest_bundle") or {}
    intel = _nested(snapshot, "intel") or {}
    adaptive = _nested(snapshot, "adaptive_intel", "latest_results") or {}
    pipeline_log = _nested(snapshot, "adaptive_intel", "latest_pipeline_log") or {}
    lines = [
        "SecOpsAI status summary",
        f"Snapshot generated_at: {format_value(snapshot.get('generated_at'))}",
        "",
        "Repo activity and worktree",
        f"- Branch: {format_value(repo.get('branch'))}",
        f"- Commits in last 24h: {format_value(repo_commit_counts.get('last_24h'))}",
        f"- Commits since local midnight: {format_value(repo_commit_counts.get('since_local_midnight'))}",
        f"- Last commit: {format_value(repo_last_commit.get('sha'))}",
        f"- Last commit time: {format_value(repo_last_commit.get('committed_at'))}",
        f"- Last commit subject: {format_value(repo_last_commit.get('subject'))}",
        f"- Worktree dirty: {format_value(repo_worktree.get('dirty'))}",
        f"- Total changes: {format_value(repo_worktree.get('total_changes'))}",
        f"- Tracked changes: {format_value(repo_worktree.get('tracked_changes'))}",
        f"- Untracked changes: {format_value(repo_worktree.get('untracked_changes'))}",
        "",
        "SOC store findings",
        f"- DB path: {format_value(soc_store.get('db_path'))}",
        f"- Exists: {format_value(soc_store.get('exists'))}",
        f"- Total findings: {format_value(soc_store.get('total_findings'))}",
        f"- Open or in review: {format_value(soc_store.get('open_or_in_review'))}",
        f"- Latest last_seen: {format_value(soc_store.get('latest_last_seen'))}",
        f"- Severity counts: {format_mapping(soc_store.get('severity_counts'))}",
        f"- Open severity counts: {format_mapping(soc_store.get('open_severity_counts'))}",
        f"- Source counts: {format_mapping(soc_store.get('source_counts'))}",
        f"- Status counts: {format_mapping(soc_store.get('status_counts'))}",
    ]
    lines.extend(_top_open_lines(soc_store.get("top_open_findings")))
    lines.extend(
        [
            "",
            "OpenClaw replay bundle findings",
            f"- Findings dir: {format_value(replay_bundle.get('findings_dir'))}",
            f"- Latest bundle path: {format_value(replay_bundle.get('latest_bundle_path'))}",
            f"- Generated at: {format_value(replay_bundle.get('generated_at'))}",
            f"- Total events: {format_value(replay_bundle.get('total_events'))}",
            f"- Total detections: {format_value(replay_bundle.get('total_detections'))}",
            f"- Total findings: {format_value(replay_bundle.get('total_findings'))}",
            f"- Total candidate findings: {format_value(replay_bundle.get('total_candidate_findings'))}",
            f"- Age hours: {format_value(replay_bundle.get('age_hours'))}",
            "",
            "Telemetry replay status",
            f"- Labeled replay exists: {format_value(replay.get('exists'))}",
            f"- Path: {format_value(replay.get('path'))}",
            f"- Total events: {format_value(replay.get('total_events'))}",
            f"- Latest event ts: {format_value(replay.get('latest_event_ts'))}",
            f"- Age hours since latest event: {format_value(replay.get('age_hours_since_latest_event'))}",
            f"- Event type counts: {format_mapping(replay.get('event_type_counts'))}",
            f"- Status counts: {format_mapping(replay.get('status_counts'))}",
            "",
            "Threat intel status",
            f"- Exists: {format_value(intel.get('exists'))}",
            f"- Path: {format_value(intel.get('path'))}",
            f"- Generated at: {format_value(intel.get('generated_at'))}",
            f"- Age hours: {format_value(intel.get('age_hours'))}",
            f"- Total IOCs: {format_value(intel.get('total_iocs'))}",
            f"- IOC type counts: {format_mapping(intel.get('ioc_type_counts'))}",
            f"- Source counts: {format_mapping(intel.get('source_counts'))}",
            f"- Top tags: {format_mapping(intel.get('top_tags'))}",
            "",
            "Adaptive intel status",
            f"- Latest pipeline log: {format_value(pipeline_log.get('path'))}",
            f"- Latest pipeline log modified_at: {format_value(pipeline_log.get('modified_at'))}",
            f"- Latest pipeline log age_hours: {format_value(pipeline_log.get('age_hours'))}",
            f"- Latest results path: {format_value(adaptive.get('path'))}",
            f"- Started at: {format_value(adaptive.get('started_at'))}",
            f"- Ended at: {format_value(adaptive.get('ended_at'))}",
            f"- Age hours since end: {format_value(adaptive.get('age_hours_since_end'))}",
            f"- Deployed: {format_value(adaptive.get('deployed'))}",
            f"- Indicators fetched: {format_value(adaptive.get('indicators_fetched'))}",
            f"- Rules generated: {format_value(adaptive.get('rules_generated'))}",
            f"- F1 baseline: {format_value(adaptive.get('f1_baseline'))}",
            f"- F1 new: {format_value(adaptive.get('f1_new'))}",
            f"- F1 improvement: {format_value(adaptive.get('f1_improvement'))}",
            f"- Errors: {format_value(adaptive.get('errors'), unavailable='[]') if adaptive.get('errors') is not None else '[]'}",
            "",
            "Staleness flags",
            f"- {format_flag_list(snapshot.get('staleness_flags'))}",
        ]
    )
    return "\n".join(lines)


def render_daily_brief(snapshot: Mapping[str, Any], *, tz_name: str = DEFAULT_TIMEZONE) -> str:
    repo = _nested(snapshot, "repo") or {}
    repo_commit_counts = _nested(repo, "commit_counts") or {}
    repo_last_commit = _nested(repo, "last_commit") or {}
    repo_worktree = _nested(repo, "worktree") or {}
    soc_store = _nested(snapshot, "findings", "soc_store") or {}
    replay = _nested(snapshot, "telemetry", "labeled_replay") or {}
    replay_bundle = _nested(snapshot, "telemetry", "openclaw_latest_bundle") or {}
    intel = _nested(snapshot, "intel") or {}
    staleness_flags = snapshot.get("staleness_flags") or []

    return "\n".join(
        [
            f"SecOpsAI Daily Brief - {_local_date(snapshot.get('generated_at'), tz_name)}",
            "",
            f"generated_at: {format_value(snapshot.get('generated_at'))}",
            "",
            (
                "- Repo activity: {midnight} commits since local midnight, {last24} commits in the last 24h.".format(
                    midnight=format_value(repo_commit_counts.get("since_local_midnight")),
                    last24=format_value(repo_commit_counts.get("last_24h")),
                )
            ),
            (
                '- Last commit: {sha} at {when}, "{subject}".'.format(
                    sha=format_value(repo_last_commit.get("sha")),
                    when=format_value(repo_last_commit.get("committed_at")),
                    subject=format_value(repo_last_commit.get("subject")),
                )
            ),
            (
                "- Worktree hygiene: {state}, {tracked} tracked changes, {untracked} untracked changes.".format(
                    state=_bool_label(repo_worktree.get("dirty")),
                    tracked=format_value(repo_worktree.get("tracked_changes")),
                    untracked=format_value(repo_worktree.get("untracked_changes")),
                )
            ),
            (
                "- SOC findings: {total} total findings in the SOC store, {open_count} open or in review. "
                "Status counts: {status_counts}. Severity counts: {severity_counts}.".format(
                    total=format_value(soc_store.get("total_findings")),
                    open_count=format_value(soc_store.get("open_or_in_review")),
                    status_counts=format_mapping(soc_store.get("status_counts")),
                    severity_counts=format_mapping(soc_store.get("severity_counts")),
                )
            ),
            (
                "- Replay findings: latest OpenClaw bundle generated at {generated_at}, {findings} total findings, "
                "{candidate} candidate findings, {detections} detections across {events} events.".format(
                    generated_at=format_value(replay_bundle.get("generated_at")),
                    findings=format_value(replay_bundle.get("total_findings")),
                    candidate=format_value(replay_bundle.get("total_candidate_findings")),
                    detections=format_value(replay_bundle.get("total_detections")),
                    events=format_value(replay_bundle.get("total_events")),
                )
            ),
            (
                "- Intel status: {total} total IOCs, generated at {generated_at}, age {age}h.".format(
                    total=format_value(intel.get("total_iocs")),
                    generated_at=format_value(intel.get("generated_at")),
                    age=format_value(intel.get("age_hours")),
                )
            ),
            (
                "- Telemetry freshness: {freshness}. Staleness flags: {flags}.".format(
                    freshness="stale" if staleness_flags else "current",
                    flags=format_flag_list(staleness_flags),
                )
            ),
            (
                "- Latest replay event: {latest_event}, age {age}h.".format(
                    latest_event=format_value(replay.get("latest_event_ts")),
                    age=format_value(replay.get("age_hours_since_latest_event")),
                )
            ),
            f"- Telemetry status counts: {format_mapping(replay.get('status_counts'))}.",
        ]
    )


def render_daily_intel(
    snapshot: Mapping[str, Any],
    *,
    command_status: Mapping[str, Any] | None = None,
    tz_name: str = DEFAULT_TIMEZONE,
) -> str:
    intel = _nested(snapshot, "intel") or {}
    replay = _nested(snapshot, "telemetry", "labeled_replay") or {}
    replay_bundle = _nested(snapshot, "telemetry", "openclaw_latest_bundle") or {}
    soc_store = _nested(snapshot, "findings", "soc_store") or {}
    correlation = _nested(snapshot, "correlation") or {}
    failed_count = _nested(replay, "status_counts", "failed")
    error_count = _nested(replay, "status_counts", "error")
    match_metrics = _nested(command_status or {}, "match_metrics") or {}
    refresh_metrics = _nested(command_status or {}, "refresh_metrics") or {}
    refresh_total = _nested(refresh_metrics, "refresh", "total")
    title_time = _local_stamp(snapshot.get("generated_at"), tz_name)
    actions = _recommended_actions(snapshot, command_status)

    lines = [
        f"SecOpsAI daily intel summary for {title_time} {tz_name}",
        "",
        "Freshness",
        f"• Snapshot generated_at: {format_value(snapshot.get('generated_at'))}",
        f"• Intel generated_at: {format_value(intel.get('generated_at'))}",
        f"• Latest labeled replay event: {format_value(replay.get('latest_event_ts'))}",
        f"• Latest findings bundle generated_at: {format_value(replay_bundle.get('generated_at'))}",
        "",
        "Command status",
        f"• intel refresh: {_command_status(command_status, 'refresh')}",
        f"• intel match: {_command_status(command_status, 'match')}",
        "",
        "Threat intel",
        f"• Total IOCs in canonical snapshot: {format_value(intel.get('total_iocs'))}",
        f"• IOC types: {format_mapping(intel.get('ioc_type_counts'))}",
        f"• Main sources: {format_mapping(intel.get('source_counts'))}",
        f"• Top tags: {format_mapping(intel.get('top_tags'))}",
    ]
    if refresh_total is not None and refresh_total != intel.get("total_iocs"):
        lines.append(f"• Refresh output total: {format_value(refresh_total)} (mismatch vs snapshot)")

    lines.extend(
        [
            "",
            "IOC matching",
            f"• Replay events scanned: {format_value(match_metrics.get('events_total', replay.get('total_events')))}",
            f"• IOCs considered: {format_value(match_metrics.get('iocs_considered'))}",
            f"• Matched findings: {format_value(match_metrics.get('matched_findings'))}",
            "",
            "SOC findings, kept separate from replay findings",
            f"• SOC store total findings: {format_value(soc_store.get('total_findings'))}",
            f"• SOC findings open or in review: {format_value(soc_store.get('open_or_in_review'))}",
            f"• SOC severity counts: {format_mapping(soc_store.get('severity_counts'))}",
            f"• SOC latest last_seen: {format_value(soc_store.get('latest_last_seen'))}",
            "",
            "Replay findings, kept separate from SOC findings",
            f"• Latest OpenClaw replay bundle detections: {format_value(replay_bundle.get('total_detections'))}",
            f"• Latest OpenClaw replay bundle findings: {format_value(replay_bundle.get('total_findings'))}",
            f"• Latest replay bundle candidate findings: {format_value(replay_bundle.get('total_candidate_findings'))}",
            "",
            "Telemetry / anomalies",
        ]
    )
    if "telemetry_older_than_24h" in (snapshot.get("staleness_flags") or []):
        lines.append("• Telemetry is stale, flagged older than 24h")
    else:
        lines.append("• Telemetry freshness is within the last 24h")
    lines.append(f"• Latest replay event is about {_hours_phrase(replay.get('age_hours_since_latest_event'))} hours old")
    lines.append(
        "• Status mix in replay includes {failed} failed and {error} error events, but there are no new replay detections or IOC hits in the current bundle".format(
            failed=format_value(failed_count),
            error=format_value(error_count),
        )
    )
    lines.append(f"• Correlation summary is {format_value(correlation.get('total_correlations'), unavailable='0')} total correlations")
    lines.extend(["", "Recommended actions"])
    for action in actions:
        lines.append(f"• {action}")
    return "\n".join(lines)
