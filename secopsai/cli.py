from __future__ import annotations

import argparse
import contextlib
import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - unavailable on Windows
    fcntl = None  # type: ignore[assignment]

import openclaw_plugin
import soc_store
from adapters import AdapterRegistry
from correlation import run_correlation
from detect import run_detection
from scripts.sync_findings_to_supabase import execute_sync as execute_findings_sync

from secopsai.agent_core import (
    ToolRouter,
    compact_session_context,
    list_jobs as list_agent_jobs,
    run_isolated_job,
)
from secopsai.adaptive_response import evaluate_adaptive_response
from secopsai.blog import (
    comments_setup_status,
    draft_advisory as draft_blog_advisory,
    draft_daily as draft_blog_daily,
    draft_finding as draft_blog_finding,
    draft_news as draft_blog_news,
    news_draft as draft_blog_news_batch,
    news_fetch as fetch_blog_news,
    news_publish_approved as publish_approved_blog_news,
    news_review_list as list_blog_news_reviews,
    news_review_show as show_blog_news_review,
    news_review_update as update_blog_news_review,
    news_run as run_blog_news,
    news_sources_list as list_blog_news_sources,
    publish as publish_blog_post,
    rebuild as rebuild_blog,
)
from secopsai.formatters import fmt_finding, fmt_list, to_json
from secopsai.intel import enrich_iocs, load_iocs, match_iocs_against_replay, refresh_iocs
from secopsai.pipeline import refresh as refresh_pipeline
from secopsai.research import (
    build_preflight_report,
    research_finding as research_finding_report,
    research_package as research_package_report,
)
from secopsai.sessions import (
    add_artifact as add_session_artifact,
    add_event as add_session_event,
    add_note as add_session_note,
    create_session,
    list_sessions,
    load_session,
    request_approval as request_session_approval,
    resolve_approval as resolve_session_approval,
    session_path,
    set_session_status,
    update_step as update_session_step,
)

from secopsai.supply_chain import (
    allowlist_add,
    allowlist_remove,
    check_advisory,
    explain_policy,
    explain_verdict,
    ingest_advisory,
    load_advisories,
    load_recent_results,
    reconcile_history,
    run_recent_top_scan,
    run_scan,
    tune_rule,
    tune_threshold,
)
from secopsai.triage import (
    VALID_DISPOSITIONS,
    apply_action,
    close_finding,
    generate_summary,
    get_action,
    infer_category,
    investigate_finding,
    list_actions,
    list_triage_findings,
    orchestrate_findings,
    start_finding,
)

ROOT = Path(__file__).resolve().parents[1]
CACHE_FILE = ROOT / "data" / ".last_refresh"
REFRESH_LOCK_FILE = ROOT / "data" / ".refresh.lock"
DEFAULT_TTL_SECONDS = 60


def _severity_at_least(sev: str, threshold: str) -> bool:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(sev.lower(), 0) >= order.get(threshold.lower(), 0)


def _read_last_refresh() -> Optional[int]:
    if not CACHE_FILE.exists():
        return None
    try:
        return int(CACHE_FILE.read_text().strip())
    except Exception:
        return None


def _write_last_refresh(ts: Optional[int] = None) -> None:
    ts = ts or int(time.time())
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        CACHE_FILE.write_text(str(ts))
    except Exception:
        pass


def _maybe_skip_refresh(ttl: int, json_mode: bool) -> Optional[Dict[str, Any]]:
    now = int(time.time())
    last = _read_last_refresh()
    if last is None or now - last >= ttl:
        return None

    meta: Dict[str, Any] = {
        "skipped": True,
        "last_refresh": last,
        "ttl": ttl,
        "age_seconds": now - last,
    }

    if json_mode:
        print(to_json(meta))
    else:
        print(
            f"Skipped auto-refresh: last run {now - last}s ago (< {ttl}s); "
            "using existing findings from soc_store."
        )

    return meta


@contextlib.contextmanager
def _refresh_lock(json_mode: bool):
    if fcntl is None:
        yield True
        return

    REFRESH_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    handle = REFRESH_LOCK_FILE.open("w", encoding="utf-8")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            payload = {
                "skipped": True,
                "reason": "refresh_already_running",
            }
            if json_mode:
                print(to_json(payload))
            else:
                print("Skipped refresh: another SecOpsAI refresh is already running.")
            yield False
            return

        handle.write(str(int(time.time())))
        handle.flush()
        yield True
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def _normalize_global_flags(argv: Optional[List[str]] = None) -> List[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--json" in args and (not args or args[0] != "--json"):
        args = [a for a in args if a != "--json"]
        args.insert(0, "--json")
    return args


def _parse_platforms(platforms: Optional[str]) -> List[str]:
    if platforms is None:
        return AdapterRegistry.list_adapters()
    return [p.strip() for p in platforms.split(",") if p.strip()]


def _run_adapter_refresh(platforms: Optional[str], **kwargs: Any) -> Dict[str, Any]:
    from soc_store import init_db, persist_findings

    init_db()
    selected = _parse_platforms(platforms)
    all_findings: List[Dict[str, Any]] = []
    platform_results: List[Dict[str, Any]] = []
    findings_db: Optional[str] = None
    total_findings = 0

    if "openclaw" in selected:
        print(f"\n[SecOpsAI] Refreshing OPENCLAW replay pipeline")
        try:
            pipeline_result = refresh_pipeline(
                skip_export=bool(kwargs.get("skip_export", False)),
                openclaw_home=kwargs.get("openclaw_home"),
                verbose=bool(kwargs.get("verbose", False)),
            )
            findings_db = pipeline_result.findings_db
            total_findings += int(pipeline_result.total_findings)
            print(f"  ✓ Exported native logs: {'yes' if pipeline_result.exported else 'no'}")
            print(f"  ✓ Wrote replay bundle: {pipeline_result.wrote_labeled}")
            print(f"  ✓ Found {pipeline_result.total_findings} threats")
            platform_results.append(
                {
                    "platform": "openclaw",
                    "mode": "pipeline_refresh",
                    "exported": pipeline_result.exported,
                    "findings": pipeline_result.total_findings,
                    "detections": pipeline_result.total_detections,
                    "findings_file": pipeline_result.findings_file,
                    "findings_db": pipeline_result.findings_db,
                    "wrote_labeled": pipeline_result.wrote_labeled,
                    "wrote_unlabeled": pipeline_result.wrote_unlabeled,
                    "sync_attempted": pipeline_result.sync_attempted,
                    "sync_succeeded": pipeline_result.sync_succeeded,
                }
            )
        except Exception as exc:
            print(f"  ✗ Error: {exc}")
            platform_results.append(
                {
                    "platform": "openclaw",
                    "mode": "pipeline_refresh",
                    "error": str(exc),
                }
            )

    for platform_name in selected:
        if platform_name == "openclaw":
            continue
        print(f"\n[SecOpsAI] Collecting from {platform_name.upper()}")
        try:
            adapter = AdapterRegistry.create(platform_name)
            events = list(adapter.collect(**kwargs))
            normalized = []
            for event in events:
                norm = adapter.normalize(event)
                if norm:
                    normalized.append(norm)
            detection_result = run_detection(normalized)
            findings = detection_result.get("findings", [])
            print(f"  ✓ Collected {len(events)} raw events")
            print(f"  ✓ Normalized {len(normalized)} events")
            print(f"  ✓ Found {len(findings)} threats")
            all_findings.extend(findings)
            platform_results.append(
                {
                    "platform": platform_name,
                    "raw_events": len(events),
                    "normalized_events": len(normalized),
                    "findings": len(findings),
                }
            )
        except Exception as exc:
            print(f"  ✗ Error: {exc}")
            platform_results.append({"platform": platform_name, "error": str(exc)})

    db_path = None
    if all_findings:
        db_path = persist_findings(all_findings, source="secopsai_cli", db_path=findings_db)
        print(f"  ✓ Saved to {db_path}")
        total_findings += len(all_findings)
    else:
        db_path = findings_db

    _write_last_refresh()
    summary = {
        "mode": "adapter_refresh",
        "platforms": selected,
        "platform_results": platform_results,
        "total_findings": total_findings,
        "findings_db": db_path,
    }
    print(f"\n{'=' * 60}")
    print(f"TOTAL: {total_findings} findings from {len(selected)} platform(s)")
    print(f"{'=' * 60}")
    return summary


def _run_live(platforms: Optional[str], duration: int = 60) -> int:
    selected = _parse_platforms(platforms)
    print(f"\n[SecOpsAI] LIVE MODE - Streaming from {', '.join(selected)}")
    print(f"Duration: {duration} seconds (Ctrl+C to stop)\n")

    stop_requested = False
    deadline = None if duration <= 0 else time.time() + duration

    def signal_handler(sig: int, frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True
        print("\n[SecOpsAI] Stopping live stream...")

    signal.signal(signal.SIGINT, signal_handler)

    for platform_name in selected:
        if stop_requested:
            break

        print(f"\n[Streaming from {platform_name.upper()}]")
        try:
            adapter = AdapterRegistry.create(platform_name)
            try:
                event_count = 0
                for event in adapter.stream():
                    if stop_requested or (deadline is not None and time.time() >= deadline):
                        stop_requested = True
                        break
                    norm = adapter.normalize(event)
                    if norm:
                        event_count += 1
                        print(
                            f"  [{event_count}] {norm.get('event_type', 'unknown')} - "
                            f"{norm.get('source', 'unknown')}"
                        )
                        result = run_detection([norm])
                        if result.get("findings"):
                            print(f"    ⚠️  THREAT DETECTED: {result['findings'][0]}")
            except NotImplementedError:
                print(f"  Streaming not implemented for {platform_name}, using poll mode")
                last_count = 0
                while not stop_requested:
                    if deadline is not None and time.time() >= deadline:
                        stop_requested = True
                        break
                    events = list(adapter.collect())
                    new_events = events[last_count:]
                    last_count = len(events)
                    for event in new_events:
                        norm = adapter.normalize(event)
                        if norm:
                            print(f"  [NEW] {norm.get('event_type', 'unknown')}")
                    time.sleep(5)
        except Exception as exc:
            print(f"  Error: {exc}")

    print("\n[SecOpsAI] Live stream ended")
    return 0


def _run_correlate(time_window: int = 60, json_output: bool = False) -> int:
    findings = soc_store.list_findings()
    if not findings:
        if json_output:
            print(to_json({"total_correlations": 0, "message": "No findings to correlate"}))
        else:
            print("No findings to correlate")
        return 0

    print("\n[SecOpsAI] Running cross-platform correlation...")
    print(f"Time window: {time_window} minutes")
    print(f"Total findings: {len(findings)}")

    results = run_correlation(findings, time_window_minutes=time_window)

    if results["total_correlations"] > 0:
        message = f"""🚨 SecOpsAI Cross-Platform Alert

{results['total_correlations']} correlations detected:

"""
        for corr_type, correlations in results.items():
            if isinstance(correlations, list) and correlations:
                for corr in correlations:
                    message += f"• {corr.get('description', 'Unknown')}\n"
                    message += f"  Platforms: {', '.join(corr.get('platforms', []))}\n"
                    message += f"  Severity: {corr.get('severity', 'unknown')}\n\n"
        try:
            subprocess.run(
                ["wacli", "send", "+905528493671", message],
                capture_output=True,
                timeout=30,
                check=False,
            )
            print("  ✓ WhatsApp alert sent")
        except Exception as exc:
            print(f"  ✗ WhatsApp failed: {exc}")

    if json_output:
        print(to_json(results))
    else:
        print(f"\n{'=' * 80}")
        print(f"CROSS-PLATFORM CORRELATIONS: {results['total_correlations']}")
        print(f"{'=' * 80}")
        for corr_type, correlations in results.items():
            if isinstance(correlations, list) and correlations:
                print(f"\n{corr_type.upper()}:")
                for corr in correlations:
                    print(f"  ⚠️  {corr.get('description')}")
                    print(f"      Severity: {corr.get('severity')}")
                    print(f"      Platforms: {', '.join(corr.get('platforms', []))}")
                    print(f"      Findings: {len(corr.get('findings', []))}")
        print(f"\n{'=' * 80}")
    return 0


def _run_supply_chain_monitor(
    *,
    enable_pypi: bool,
    enable_npm: bool,
    top: int,
    npm_top: Optional[int],
    interval: int,
    lookback_seconds: int,
    model: Optional[str],
    slack: bool,
    json_output: bool,
) -> int:
    stop_requested = False

    def signal_handler(sig: int, frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True
        print("\n[SecOpsAI] Stopping supply-chain monitor...")

    signal.signal(signal.SIGINT, signal_handler)

    while not stop_requested:
        payload = run_recent_top_scan(
            enable_pypi=enable_pypi,
            enable_npm=enable_npm,
            top=top,
            npm_top=npm_top,
            lookback_seconds=lookback_seconds,
            model=model,
            slack=slack,
            use_state=True,
        )
        if json_output:
            print(to_json(payload))
        else:
            print(
                "supply-chain monitor cycle: scanned={scanned} malicious={mal} benign={benign} errors={errors} skipped={skipped} slack_alerts={alerts}".format(
                    scanned=payload["total_scanned"],
                    mal=payload["malicious"],
                    benign=payload["benign"],
                    errors=payload["errors"],
                    skipped=payload["skipped"],
                    alerts=payload.get("slack_alerts_sent", 0),
                )
            )
        if stop_requested:
            break
        time.sleep(interval)

    return 0


def _resolve_supply_chain_report(
    *,
    report_path: Optional[str],
    ecosystem: str,
    package: str,
    version: Optional[str],
) -> Path:
    if report_path:
        return Path(report_path)

    for row in load_recent_results(limit=500):
        if row.get("ecosystem") != ecosystem or row.get("package") != package:
            continue
        if version and row.get("new_version") != version:
            continue
        candidate = row.get("report_path")
        if candidate:
            return Path(candidate)
    version_hint = f" version={version}" if version else ""
    raise FileNotFoundError(f"No stored report found for {ecosystem}:{package}{version_hint}")


def _triage_session_plan() -> List[Dict[str, str]]:
    return [
        {"title": "Review finding context", "status": "pending"},
        {"title": "Investigate locally", "status": "pending"},
        {"title": "Decide disposition", "status": "pending"},
        {"title": "Apply or queue next action", "status": "pending"},
    ]


def _json_object(raw: Optional[str], *, label: str) -> Dict[str, Any]:
    if raw is None:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _session_subject_for_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    subject = {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "status": finding.get("status"),
        "category": infer_category(finding),
    }
    for key in ("source", "platform", "package", "ecosystem"):
        value = finding.get(key)
        if value:
            subject[key] = value
    return subject


def _default_session_title(
    *,
    kind: str,
    title: Optional[str] = None,
    finding: Optional[Dict[str, Any]] = None,
    finding_id: Optional[str] = None,
) -> str:
    if title:
        return title.strip()
    if finding:
        return f"{str(kind).title()} {finding.get('finding_id')}: {finding.get('title')}"
    if finding_id:
        return f"{str(kind).title()} {finding_id}"
    return ""


def _fmt_session_list(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "No sessions found."
    lines: List[str] = []
    for row in rows:
        subject = row.get("subject") or {}
        finding_id = str(subject.get("finding_id") or "")
        suffix = f" | finding={finding_id}" if finding_id else ""
        lines.append(
            "{session_id} | {kind} | {status} | {title}{suffix}".format(
                session_id=row.get("session_id"),
                kind=row.get("kind"),
                status=row.get("status"),
                title=row.get("title"),
                suffix=suffix,
            )
        )
    return "\n".join(lines)


def _fmt_session_detail(session: Dict[str, Any]) -> str:
    subject = session.get("subject") or {}
    metadata = session.get("metadata") or {}
    plan = session.get("plan") or []
    approvals = session.get("approvals") or []
    artifacts = session.get("artifacts") or []
    events = session.get("events") or []

    lines = [
        f"SESSION: {session.get('session_id')}",
        f"KIND: {session.get('kind')}",
        f"STATUS: {session.get('status')}",
        f"TITLE: {session.get('title')}",
        f"CREATED_AT: {session.get('created_at')}",
        f"UPDATED_AT: {session.get('updated_at')}",
    ]
    if subject:
        lines.append(f"SUBJECT: {to_json(subject)}")
    if metadata:
        lines.append(f"METADATA: {to_json(metadata)}")
    if plan:
        lines.append("PLAN:")
        for item in plan:
            note = f" | {item.get('note')}" if item.get("note") else ""
            lines.append(f"- {item.get('title')} [{item.get('status')}] {item.get('step_id')}{note}")
    if approvals:
        lines.append("APPROVALS:")
        for item in approvals:
            lines.append(
                f"- {item.get('approval_id')} | {item.get('state')} | {item.get('type')} | {item.get('summary')}"
            )
    if artifacts:
        lines.append("ARTIFACTS:")
        for item in artifacts:
            label = f" ({item.get('label')})" if item.get("label") else ""
            lines.append(f"- {item.get('kind')}{label}: {item.get('path')}")
    if events:
        lines.append("RECENT_EVENTS:")
        for item in events[-10:]:
            lines.append(
                f"- {item.get('ts')} | {item.get('type')} | {item.get('message')}"
            )
    return "\n".join(lines)


def _find_approval(session: Dict[str, Any], approval_id: str) -> Dict[str, Any]:
    for item in session.get("approvals", []):
        if str(item.get("approval_id") or "") == approval_id:
            return item
    raise ValueError(f"approval not found: {approval_id}")


def _preflight_is_blocking(preflight: Dict[str, Any]) -> bool:
    return str(preflight.get("status") or "").lower() == "block"


def _preflight_text(preflight: Dict[str, Any]) -> str:
    status = str(preflight.get("status") or "unknown").upper()
    issues = preflight.get("issues") or []
    if issues:
        lead = str(issues[0].get("message") or preflight.get("summary") or "preflight issue")
    else:
        lead = str(preflight.get("summary") or "Preflight checks passed.")
    return f"PRE-FLIGHT: {status} | {lead}"


def _apply_session_approval(
    session_id: str,
    approval_id: str,
    *,
    session_dir: Optional[str] = None,
    queue_file: Optional[str] = None,
    db_path: Optional[str] = None,
    author: Optional[str] = None,
) -> Dict[str, Any]:
    session = load_session(session_id, session_dir)
    approval = _find_approval(session, approval_id)
    if str(approval.get("state") or "") != "approved":
        raise ValueError(f"approval is not approved: {approval_id}")

    payload = approval.get("payload") or {}
    payload_kind = str(payload.get("kind") or "")
    if payload_kind == "triage_action":
        action_id = str(payload.get("action_id") or "")
        if not action_id:
            raise ValueError("approval payload missing action_id")
        resolved_queue_file = str(payload.get("queue_file") or queue_file or "") or None
        result = apply_action(
            action_id,
            queue_file=resolved_queue_file,
            db_path=db_path,
            author=author,
            yes=True,
        )
        add_session_event(
            session_id,
            event_type="approval_applied",
            message=f"Applied approved triage action {action_id}.",
            data={"approval_id": approval_id, "action_id": action_id},
            author=author,
            path=session_dir,
        )
        update_session_step(
            session_id,
            step="Apply or queue next action",
            status="completed",
            note=f"Applied queued action {action_id}.",
            path=session_dir,
        )
        nested = result.get("result")
        if isinstance(nested, dict) and str(nested.get("status") or "").lower() == "closed":
            set_session_status(
                session_id,
                status="closed",
                message=f"Session closed after applying approved action {action_id}.",
                path=session_dir,
            )
        return {"kind": payload_kind, "result": result}

    if payload_kind == "triage_close":
        finding_id = str(payload.get("finding_id") or "")
        if not finding_id:
            raise ValueError("approval payload missing finding_id")
        result = close_finding(
            finding_id,
            disposition=str(payload.get("disposition") or "needs_review"),
            note=str(payload.get("note") or approval.get("summary") or "Applied approved triage closure."),
            status=str(payload.get("status") or "triaged"),
            author=author,
            db_path=db_path,
        )
        add_session_event(
            session_id,
            event_type="approval_applied",
            message=f"Applied approved disposition for {finding_id}.",
            data={
                "approval_id": approval_id,
                "finding_id": finding_id,
                "disposition": result.get("disposition"),
                "status": result.get("status"),
            },
            author=author,
            path=session_dir,
        )
        update_session_step(
            session_id,
            step="Decide disposition",
            status="completed",
            note=f"{result.get('disposition')} / {result.get('status')}",
            path=session_dir,
        )
        update_session_step(
            session_id,
            step="Apply or queue next action",
            status="completed",
            note=f"Applied approved disposition for {finding_id}.",
            path=session_dir,
        )
        if str(result.get("status") or "").lower() == "closed":
            set_session_status(
                session_id,
                status="closed",
                message=f"Session closed after approved disposition for {finding_id}.",
                path=session_dir,
            )
        return {"kind": payload_kind, "result": result}

    raise ValueError(f"unsupported approval payload kind: {payload_kind}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    argv = _normalize_global_flags(argv)
    p = argparse.ArgumentParser(
        prog="secopsai",
        description="SecOpsAI unified CLI (OpenClaw pipeline + cross-platform adapters)",
    )
    p.add_argument("--json", action="store_true", help="Output JSON instead of pretty text")

    sub = p.add_subparsers(dest="cmd", required=True)

    status = sub.add_parser("status", help="Build the canonical SecOpsAI status/freshness snapshot")
    status.add_argument(
        "--workspace-logs",
        default=None,
        help="Override adaptive-intel logs directory (default: ~/.openclaw/workspace/logs)",
    )
    status.add_argument(
        "--openclaw-home",
        default=None,
        help="Override OpenClaw home directory (default: ~/.openclaw)",
    )

    refresh = sub.add_parser(
        "refresh",
        help="Run the OpenClaw pipeline or adapter refresh when --platform is supplied",
    )
    refresh.add_argument("--platform", "-p", help="Adapters: openclaw,macos,linux,windows")
    refresh.add_argument("--skip-export", action="store_true", help="Skip export from ~/.openclaw")
    refresh.add_argument("--cache-ttl", type=int, default=DEFAULT_TTL_SECONDS)
    refresh.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")
    refresh.add_argument("--verbose", action="store_true", help="Verbose refresh output (future use)")

    live = sub.add_parser("live", help="Stream events in real time from platform adapters")
    live.add_argument("--platform", "-p", help="Adapters to stream: openclaw,macos,linux,windows")
    live.add_argument("--duration", "-d", type=int, default=60, help="Stream duration in seconds (0=infinite)")

    listing = sub.add_parser("list", help="List findings")
    listing.add_argument("--severity", default=None, choices=["info", "low", "medium", "high", "critical"])
    listing.add_argument("--platform", default=None, help="Filter findings by platform")
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--no-refresh", action="store_true", help="Do not auto-refresh before listing")
    listing.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    listing.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    show = sub.add_parser("show", help="Show a finding")
    show.add_argument("finding_id")
    show.add_argument("--no-refresh", action="store_true")
    show.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    show.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    mitigate = sub.add_parser("mitigate", help="Show mitigation recommendations for a finding")
    mitigate.add_argument("finding_id")
    mitigate.add_argument("--no-refresh", action="store_true")
    mitigate.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    mitigate.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    check = sub.add_parser("check", help="Presence checks (malware/exfil/both)")
    check.add_argument("--type", required=True, choices=["malware", "exfil", "both"])
    check.add_argument("--severity", default="low", choices=["info", "low", "medium", "high", "critical"])
    check.add_argument("--no-refresh", action="store_true")
    check.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    check.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    correlate = sub.add_parser("correlate", help="Run cross-platform correlation on stored findings")
    correlate.add_argument("--window", "-w", type=int, default=60, help="Time window in minutes (default: 60)")
    correlate.add_argument(
        "--enforce-preflight",
        action="store_true",
        help="Block correlation when telemetry or intel freshness checks fail",
    )

    research = sub.add_parser("research", help="Generate source-backed research reports and preflight checks")
    research_sub = research.add_subparsers(dest="research_cmd", required=True)

    research_preflight = research_sub.add_parser("preflight", help="Run telemetry and intel preflight checks")
    research_preflight.add_argument("--workspace-logs", default=None, help="Override adaptive-intel logs directory")
    research_preflight.add_argument("--openclaw-home", default=None, help="Override OpenClaw home directory")

    research_finding_cmd = research_sub.add_parser("finding", help="Generate a source-backed research report for one finding")
    research_finding_cmd.add_argument("finding_id")
    research_finding_cmd.add_argument("--db-path", default=None, help="Override SQLite database path")
    research_finding_cmd.add_argument("--search-root", default=None, help="Root path to scan for local references")
    research_finding_cmd.add_argument("--report-dir", default=None, help="Directory to write research reports")
    research_finding_cmd.add_argument("--session-id", default=None, help="Attach the report to an existing session")
    research_finding_cmd.add_argument("--session-dir", default=None, help="Override session storage directory")

    research_package_cmd = research_sub.add_parser("package", help="Generate a source-backed research report for one package")
    research_package_cmd.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    research_package_cmd.add_argument("--package", required=True, help="Package name")
    research_package_cmd.add_argument("--version", default=None, help="Optional version hint")
    research_package_cmd.add_argument("--search-root", default=None, help="Root path to scan for local references")
    research_package_cmd.add_argument("--report-dir", default=None, help="Directory to write research reports")
    research_package_cmd.add_argument("--session-id", default=None, help="Attach the report to an existing session")
    research_package_cmd.add_argument("--session-dir", default=None, help="Override session storage directory")

    blog = sub.add_parser("blog", help="Draft, publish, and verify SecOpsAI security blog posts")
    blog_sub = blog.add_subparsers(dest="blog_cmd", required=True)

    blog_finding = blog_sub.add_parser("draft-finding", help="Create a moderated blog draft from one SOC finding")
    blog_finding.add_argument("finding_id")
    blog_finding.add_argument("--db-path", default=None, help="Override SQLite findings DB path")

    blog_advisory = blog_sub.add_parser("draft-advisory", help="Create a moderated blog draft from an advisory")
    blog_advisory.add_argument("--campaign", required=True, help="Campaign id or advisory id")

    blog_news = blog_sub.add_parser("draft-news", help="Create a review-only blog draft from a URL or RSS feed")
    blog_news.add_argument("--source", required=True, help="Source URL or feed URL")

    blog_news_sources = blog_sub.add_parser("news-sources", help="Manage curated security-news sources")
    news_sources_sub = blog_news_sources.add_subparsers(dest="news_sources_cmd", required=True)
    news_sources_sub.add_parser("list", help="List configured news sources")

    blog_news_fetch = blog_sub.add_parser("news-fetch", help="Fetch and cache security-news items from configured sources")
    blog_news_fetch.add_argument("--limit", type=int, default=20, help="Maximum new items to cache")

    blog_news_draft = blog_sub.add_parser("news-draft", help="Create review-only drafts from cached news items")
    blog_news_draft.add_argument("--limit", type=int, default=5, help="Maximum news drafts to create")

    blog_news_run = blog_sub.add_parser("news-run", help="Fetch news and create review-only drafts")
    blog_news_run.add_argument("--limit", type=int, default=5, help="Maximum items to fetch/draft")

    blog_news_review = blog_sub.add_parser("news-review", help="Review, approve, or reject generated news drafts")
    news_review_sub = blog_news_review.add_subparsers(dest="news_review_cmd", required=True)
    news_review_list = news_review_sub.add_parser("list", help="List generated drafts waiting for review")
    news_review_list.add_argument("--status", default=None, choices=["needs_review", "approved", "reviewed", "rejected"], help="Filter by review status")
    news_review_show = news_review_sub.add_parser("show", help="Show one draft summary and body")
    news_review_show.add_argument("draft", help="Draft path, slug, or unique slug fragment")
    news_review_approve = news_review_sub.add_parser("approve", help="Approve one reviewed draft for publishing")
    news_review_approve.add_argument("draft", help="Draft path, slug, or unique slug fragment")
    news_review_approve.add_argument("--note", default=None, help="Optional reviewer note")
    news_review_reject = news_review_sub.add_parser("reject", help="Reject one draft so it will not publish")
    news_review_reject.add_argument("draft", help="Draft path, slug, or unique slug fragment")
    news_review_reject.add_argument("--note", default=None, help="Optional reviewer note")
    news_review_reset = news_review_sub.add_parser("needs-review", help="Move one draft back to needs_review")
    news_review_reset.add_argument("draft", help="Draft path, slug, or unique slug fragment")
    news_review_reset.add_argument("--note", default=None, help="Optional reviewer note")

    blog_news_publish = blog_sub.add_parser("news-publish-approved", help="Publish only external-news drafts marked approved/reviewed")
    blog_news_publish.add_argument("--rebuild", action="store_true", help="Rebuild index, RSS, and JSON feeds after publishing")

    blog_daily = blog_sub.add_parser("draft-daily", help="Automation-ready draft generation without autopublishing")
    blog_daily.add_argument("--limit", type=int, default=5, help="Maximum advisory drafts to create")

    blog_publish = blog_sub.add_parser("publish", help="Publish a reviewed draft and rebuild feeds")
    blog_publish.add_argument("draft_or_slug", help="Path to draft JSON or draft slug")
    blog_publish.add_argument("--publish", action="store_true", help="Required confirmation to write public files")

    blog_sub.add_parser("rebuild-feeds", help="Rebuild blog index, RSS feed, and JSON feed from published metadata")
    blog_sub.add_parser("comments-status", help="Report required comment env/secret names without printing values")

    intel = sub.add_parser("intel", help="Threat intelligence (IOC) pipeline")
    intel_sub = intel.add_subparsers(dest="intel_cmd", required=True)

    intel_refresh = intel_sub.add_parser("refresh", help="Download + normalize open-source IOC feeds")
    intel_refresh.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds")
    intel_refresh.add_argument("--enrich", action="store_true", help="Perform lightweight local enrichment (DNS)")

    intel_list = intel_sub.add_parser("list", help="List locally stored IOCs")
    intel_list.add_argument("--limit", type=int, default=50)

    intel_match = intel_sub.add_parser("match", help="Match IOCs against latest OpenClaw replay and persist matches")
    intel_match.add_argument("--limit-iocs", type=int, default=2000)
    intel_match.add_argument("--replay", help="Override replay path (default: data/openclaw/replay/labeled/current.json)")

    supply_chain = sub.add_parser("supply-chain", help="Monitor PyPI/npm package releases for supply-chain compromise")
    supply_chain_sub = supply_chain.add_subparsers(dest="supply_chain_cmd", required=True)

    supply_chain_scan = supply_chain_sub.add_parser("scan", help="Scan a specific package release")
    supply_chain_scan.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_scan.add_argument("--package", required=True, help="Package name")
    supply_chain_scan.add_argument("--version", required=True, help="New version to review")
    supply_chain_scan.add_argument("--previous-version", help="Override previous version instead of auto-discovery")
    supply_chain_scan.add_argument("--model", help="Override analysis model passed to Cursor Agent CLI")
    supply_chain_scan.add_argument("--no-report", action="store_true", help="Do not persist the diff report to disk")
    supply_chain_scan.add_argument("--slack", action="store_true", help="Send Slack alert when verdict is malicious")

    supply_chain_once = supply_chain_sub.add_parser("once", help="Scan recent releases from the top watchlists")
    supply_chain_once.add_argument("--top", type=int, default=1000, help="Top N packages per ecosystem (default: 1000)")
    supply_chain_once.add_argument("--npm-top", type=int, help="Top N npm packages (defaults to --top)")
    supply_chain_once.add_argument("--lookback", type=int, default=600, help="Look back this many seconds (default: 600)")
    supply_chain_once.add_argument("--no-pypi", action="store_true", help="Disable PyPI scanning")
    supply_chain_once.add_argument("--no-npm", action="store_true", help="Disable npm scanning")
    supply_chain_once.add_argument("--model", help="Override analysis model passed to Cursor Agent CLI")
    supply_chain_once.add_argument("--slack", action="store_true", help="Send Slack alert for malicious results")

    supply_chain_monitor = supply_chain_sub.add_parser("monitor", help="Continuously scan recent top-package releases")
    supply_chain_monitor.add_argument("--top", type=int, default=1000, help="Top N packages per ecosystem (default: 1000)")
    supply_chain_monitor.add_argument("--npm-top", type=int, help="Top N npm packages (defaults to --top)")
    supply_chain_monitor.add_argument("--lookback", type=int, default=600, help="Look back this many seconds per cycle (default: 600)")
    supply_chain_monitor.add_argument("--interval", type=int, default=300, help="Sleep seconds between cycles (default: 300)")
    supply_chain_monitor.add_argument("--no-pypi", action="store_true", help="Disable PyPI scanning")
    supply_chain_monitor.add_argument("--no-npm", action="store_true", help="Disable npm scanning")
    supply_chain_monitor.add_argument("--model", help="Override analysis model passed to Cursor Agent CLI")
    supply_chain_monitor.add_argument("--slack", action="store_true", help="Send Slack alert for malicious results")

    supply_chain_list = supply_chain_sub.add_parser("list", help="List recent supply-chain scan results")
    supply_chain_list.add_argument("--limit", type=int, default=20)

    supply_chain_reconcile = supply_chain_sub.add_parser(
        "reconcile-history",
        help="Re-evaluate stored supply-chain results and clean stale false positives",
    )
    supply_chain_reconcile.add_argument(
        "--drop-benign",
        action="store_true",
        help="Remove reclassified benign rows from local history instead of keeping them with updated verdicts",
    )
    supply_chain_reconcile.add_argument(
        "--include-advisories",
        action="store_true",
        help="Upgrade historical removed/yanked artifact errors when an emergency advisory matches",
    )

    supply_chain_explain = supply_chain_sub.add_parser("explain-policy", help="Show the effective policy for a package")
    supply_chain_explain.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_explain.add_argument("--package", required=True, help="Package name")

    supply_chain_advisory = supply_chain_sub.add_parser("advisory", help="Manage emergency package advisories")
    supply_chain_advisory_sub = supply_chain_advisory.add_subparsers(dest="supply_chain_advisory_cmd", required=True)
    supply_chain_advisory_list = supply_chain_advisory_sub.add_parser("list", help="List emergency advisories")
    supply_chain_advisory_list.add_argument("--status", default="active", help="Filter by status, or 'all'")
    supply_chain_advisory_ingest = supply_chain_advisory_sub.add_parser("ingest", help="Ingest a JSON advisory file or URL")
    supply_chain_advisory_ingest.add_argument("source", help="Path or HTTPS URL to an advisory JSON object/list")
    supply_chain_advisory_check = supply_chain_advisory_sub.add_parser("check", help="Check one package version against advisories")
    supply_chain_advisory_check.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_advisory_check.add_argument("--package", required=True, help="Package name")
    supply_chain_advisory_check.add_argument("--version", required=True, help="Package version")

    supply_chain_allowlist = supply_chain_sub.add_parser("allowlist", help="Manage supply-chain allowlist entries")
    supply_chain_allowlist_sub = supply_chain_allowlist.add_subparsers(dest="supply_chain_allowlist_cmd", required=True)
    supply_chain_allowlist_add = supply_chain_allowlist_sub.add_parser("add", help="Add a package to the allowlist")
    supply_chain_allowlist_add.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_allowlist_add.add_argument("--package", required=True, help="Package name or wildcard")
    supply_chain_allowlist_remove = supply_chain_allowlist_sub.add_parser("remove", help="Remove a package from the allowlist")
    supply_chain_allowlist_remove.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_allowlist_remove.add_argument("--package", required=True, help="Package name or wildcard")

    supply_chain_tune = supply_chain_sub.add_parser("tune", help="Tune supply-chain thresholds and rules")
    supply_chain_tune_sub = supply_chain_tune.add_subparsers(dest="supply_chain_tune_cmd", required=True)
    supply_chain_tune_rule = supply_chain_tune_sub.add_parser("rule", help="Enable/disable a rule or set its weight")
    supply_chain_tune_rule.add_argument("rule_name", help="Rule name exactly as shown in explain-verdict output")
    supply_chain_tune_rule.add_argument("--weight", type=int, help="Override the rule weight")
    rule_toggle = supply_chain_tune_rule.add_mutually_exclusive_group()
    rule_toggle.add_argument("--disable", action="store_true", help="Disable the rule")
    rule_toggle.add_argument("--enable", action="store_true", help="Enable the rule")
    supply_chain_tune_threshold = supply_chain_tune_sub.add_parser("threshold", help="Set global, ecosystem, or package threshold")
    threshold_scope = supply_chain_tune_threshold.add_mutually_exclusive_group(required=True)
    threshold_scope.add_argument("--global-threshold", action="store_true", help="Set the global malicious score threshold")
    threshold_scope.add_argument("--ecosystem", choices=["pypi", "npm"], help="Set the threshold for one ecosystem")
    threshold_scope.add_argument("--package", help="Set the threshold for one package target")
    supply_chain_tune_threshold.add_argument("--package-ecosystem", choices=["pypi", "npm"], help="Required with --package")
    supply_chain_tune_threshold.add_argument("--value", type=int, required=True, help="Threshold value")

    supply_chain_explain_verdict = supply_chain_sub.add_parser(
        "explain-verdict",
        help="Explain which rules fired for a supply-chain scan report",
    )
    supply_chain_explain_verdict.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_explain_verdict.add_argument("--package", required=True, help="Package name")
    supply_chain_explain_verdict.add_argument("--version", help="Release version to resolve from stored results")
    supply_chain_explain_verdict.add_argument("--report", help="Path to a stored report file")

    triage = sub.add_parser("triage", help="Native finding triage workflows")
    triage_sub = triage.add_subparsers(dest="triage_cmd", required=True)

    triage_list = triage_sub.add_parser("list", help="List findings for triage")
    triage_list.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    triage_list.add_argument("--status", choices=["open", "in_review", "triaged", "closed"])
    triage_list.add_argument("--category", choices=["supply_chain", "policy_denial", "exfiltration", "host"])
    triage_list.add_argument("--limit", type=int, default=50)
    triage_list.add_argument("--db-path", default=None, help="Override SQLite database path")

    triage_start = triage_sub.add_parser("start", help="Mark a finding as in review")
    triage_start.add_argument("finding_id")
    triage_start.add_argument("--author", default=None)
    triage_start.add_argument("--note", default=None)
    triage_start.add_argument("--db-path", default=None, help="Override SQLite database path")

    triage_investigate = triage_sub.add_parser("investigate", help="Gather evidence and generate a triage report")
    triage_investigate.add_argument("finding_id")
    triage_investigate.add_argument("--search-root", default=None, help="Root path to scan for dependency references")
    triage_investigate.add_argument("--report-dir", default=None, help="Directory to write triage reports")
    triage_investigate.add_argument("--author", default=None)
    triage_investigate.add_argument("--note", default=None)
    triage_investigate.add_argument("--db-path", default=None, help="Override SQLite database path")
    triage_investigate.add_argument("--session-id", default=None, help="Attach investigation output to an existing session")
    triage_investigate.add_argument("--open-session", action="store_true", help="Create a triage session automatically when investigating")
    triage_investigate.add_argument("--session-dir", default=None, help="Override session storage directory")
    triage_investigate.add_argument("--with-research", action="store_true", help="Generate and attach a source-backed research report")
    triage_investigate.add_argument("--enforce-preflight", action="store_true", help="Block investigation when freshness checks fail")

    triage_close = triage_sub.add_parser("close", help="Close a finding with analyst disposition and note")
    triage_close.add_argument("finding_id")
    triage_close.add_argument("--disposition", required=True, choices=sorted(VALID_DISPOSITIONS))
    triage_close.add_argument("--note", required=True, help="Closure note / analyst rationale")
    triage_close.add_argument("--author", default=None)
    triage_close.add_argument("--status", default="closed", choices=["triaged", "closed"])
    triage_close.add_argument("--db-path", default=None, help="Override SQLite database path")
    triage_close.add_argument("--session-id", default=None, help="Attach the closure decision to an existing session")
    triage_close.add_argument("--session-dir", default=None, help="Override session storage directory")

    triage_orchestrate = triage_sub.add_parser("orchestrate", help="Run native triage orchestration across findings")
    triage_orchestrate.add_argument("finding_ids", nargs="*", help="Optional explicit finding IDs to orchestrate")
    triage_orchestrate.add_argument("--search-root", default=None, help="Root path to scan for dependency references")
    triage_orchestrate.add_argument("--report-dir", default=None, help="Directory to write triage reports")
    triage_orchestrate.add_argument("--summary-dir", default=None, help="Directory to write orchestrator summaries")
    triage_orchestrate.add_argument("--queue-file", default=None, help="Override triage action queue JSON path")
    triage_orchestrate.add_argument("--author", default=None)
    triage_orchestrate.add_argument("--db-path", default=None, help="Override SQLite database path")
    triage_orchestrate.add_argument("--limit", type=int, default=None, help="Cap findings processed in one run")
    triage_orchestrate.add_argument("--no-auto-apply-safe", action="store_true", help="Do not auto-close low-risk findings")
    triage_orchestrate.add_argument("--enforce-preflight", action="store_true", help="Block orchestration when freshness checks fail")

    triage_queue = triage_sub.add_parser("queue", help="List queued triage actions")
    triage_queue.add_argument("--status", choices=["pending", "applied"])
    triage_queue.add_argument("--limit", type=int, default=50)
    triage_queue.add_argument("--queue-file", default=None, help="Override triage action queue JSON path")

    triage_apply = triage_sub.add_parser("apply-action", help="Apply a queued triage action")
    triage_apply.add_argument("action_id")
    triage_apply.add_argument("--queue-file", default=None, help="Override triage action queue JSON path")
    triage_apply.add_argument("--db-path", default=None, help="Override SQLite database path")
    triage_apply.add_argument("--author", default=None)
    triage_apply.add_argument("--yes", action="store_true", help="Execute the action without prompting")
    triage_apply.add_argument("--session-id", default=None, help="Attach the applied action to an existing session")
    triage_apply.add_argument("--session-dir", default=None, help="Override session storage directory")

    triage_summary = triage_sub.add_parser("summary", help="Generate a triage queue and finding summary")
    triage_summary.add_argument("--db-path", default=None, help="Override SQLite database path")
    triage_summary.add_argument("--queue-file", default=None, help="Override triage action queue JSON path")
    triage_summary.add_argument("--summary-dir", default=None, help="Directory to write summary reports")
    triage_summary.add_argument("--limit", type=int, default=20)

    session_cmd = sub.add_parser("session", help="Persist local investigation sessions, plans, and approvals")
    session_sub = session_cmd.add_subparsers(dest="session_cmd", required=True)

    session_create = session_sub.add_parser("create", help="Create a local session")
    session_create.add_argument("--kind", default="general", help="Session kind, for example general or triage")
    session_create.add_argument("--title", default=None, help="Session title")
    session_create.add_argument("--finding-id", default=None, help="Seed a triage session from an existing finding")
    session_create.add_argument("--metadata", default=None, help="Optional JSON object of session metadata")
    session_create.add_argument("--db-path", default=None, help="Override SQLite database path for finding lookups")
    session_create.add_argument("--session-dir", default=None, help="Override session storage directory")

    session_list_cmd = session_sub.add_parser("list", help="List stored sessions")
    session_list_cmd.add_argument("--kind", default=None)
    session_list_cmd.add_argument("--status", choices=["open", "closed"])
    session_list_cmd.add_argument("--finding-id", default=None)
    session_list_cmd.add_argument("--limit", type=int, default=50)
    session_list_cmd.add_argument("--session-dir", default=None, help="Override session storage directory")

    session_show = session_sub.add_parser("show", help="Show one stored session")
    session_show.add_argument("session_id")
    session_show.add_argument("--session-dir", default=None, help="Override session storage directory")

    session_note = session_sub.add_parser("note", help="Append a note to a session")
    session_note.add_argument("session_id")
    session_note.add_argument("--message", required=True)
    session_note.add_argument("--author", default=None)
    session_note.add_argument("--session-dir", default=None, help="Override session storage directory")

    session_step = session_sub.add_parser("step", help="Update a plan step in a session")
    session_step.add_argument("session_id")
    session_step.add_argument("--step", required=True, help="Step title or step_id")
    session_step.add_argument("--status", required=True, choices=["pending", "in_progress", "completed", "blocked"])
    session_step.add_argument("--note", default=None)
    session_step.add_argument("--session-dir", default=None, help="Override session storage directory")

    session_request = session_sub.add_parser("request-approval", help="Request an approval inside a session")
    session_request.add_argument("session_id")
    session_request.add_argument("--type", required=True, choices=["triage_action", "triage_close", "custom"])
    session_request.add_argument("--summary", default=None, help="Human-readable approval summary")
    session_request.add_argument("--action-id", default=None, help="Queued triage action ID for triage_action approvals")
    session_request.add_argument("--finding-id", default=None, help="Finding ID for triage_close approvals")
    session_request.add_argument("--disposition", choices=sorted(VALID_DISPOSITIONS))
    session_request.add_argument("--note", default=None, help="Closure note or approval rationale")
    session_request.add_argument("--status", default="triaged", choices=["triaged", "closed"])
    session_request.add_argument("--payload", default=None, help="Custom approval payload as a JSON object")
    session_request.add_argument("--requested-by", default=None)
    session_request.add_argument("--queue-file", default=None, help="Override triage action queue JSON path")
    session_request.add_argument("--db-path", default=None, help="Override SQLite database path for finding lookups")
    session_request.add_argument("--session-dir", default=None, help="Override session storage directory")

    session_resolve = session_sub.add_parser("resolve-approval", help="Resolve an approval inside a session")
    session_resolve.add_argument("session_id")
    session_resolve.add_argument("approval_id")
    session_resolve.add_argument("--note", default=None)
    session_resolve.add_argument("--decided-by", default=None)
    session_resolve.add_argument("--apply", action="store_true", help="Apply the approved payload immediately")
    session_resolve.add_argument("--queue-file", default=None, help="Override triage action queue JSON path")
    session_resolve.add_argument("--db-path", default=None, help="Override SQLite database path")
    session_resolve.add_argument("--session-dir", default=None, help="Override session storage directory")
    decision_group = session_resolve.add_mutually_exclusive_group(required=True)
    decision_group.add_argument("--approve", action="store_true")
    decision_group.add_argument("--reject", action="store_true")

    agent = sub.add_parser("agent", help="Local agent runtime: tool routing, compaction, loop checks, and isolated jobs")
    agent_sub = agent.add_subparsers(dest="agent_cmd", required=True)

    agent_route = agent_sub.add_parser("route", help="Route an operator task to read/write/expensive tools")
    agent_route.add_argument("--task", required=True)
    agent_route.add_argument("--allow-writes", action="store_true")
    agent_route.add_argument("--allow-expensive", action="store_true")

    agent_compact = agent_sub.add_parser("compact", help="Compact a session into resumable context")
    agent_compact.add_argument("session_id")
    agent_compact.add_argument("--session-dir", default=None, help="Override session storage directory")
    agent_compact.add_argument("--max-events", type=int, default=12)
    agent_compact.add_argument("--max-artifacts", type=int, default=12)

    agent_jobs = agent_sub.add_parser("jobs", help="List isolated agent jobs")
    agent_jobs.add_argument("--job-dir", default=None, help="Override job storage directory")
    agent_jobs.add_argument("--limit", type=int, default=20)

    agent_run_job = agent_sub.add_parser("run-job", help="Run an isolated SecOpsAI experiment job")
    agent_run_job.add_argument("--name", required=True)
    agent_run_job.add_argument("--job-dir", default=None, help="Override job storage directory")
    agent_run_job.add_argument("--cwd", default=None)
    agent_run_job.add_argument("--timeout", type=int, default=900)
    agent_run_job.add_argument("command", nargs=argparse.REMAINDER, help="Command after --, for example -- secopsai research preflight")

    sync_findings = sub.add_parser("sync-findings", help="Sync local findings into the dashboard Supabase table")
    sync_findings.add_argument("--db-path", default=None, help="Path to local SOC SQLite DB")
    sync_findings.add_argument("--findings-dir", default=None, help="Directory containing openclaw findings bundles")
    sync_findings.add_argument("--dashboard-env", default=None, help="Optional dashboard .env file for Supabase credentials")
    sync_findings.add_argument("--supabase-url", default=None, help="Override Supabase URL")
    sync_findings.add_argument("--supabase-key", default=None, help="Override Supabase API key")
    sync_findings.add_argument("--table", default=None, help="Override Supabase table name")
    sync_findings.add_argument("--schema-sql", default=None, help="Schema SQL/migration file to validate mapping against")
    sync_findings.add_argument("--skip-schema-check", action="store_true", help="Skip local schema/mapping validation")
    sync_findings.add_argument("--dry-run", action="store_true", help="Print payload summary without writing")

    adaptive_response = sub.add_parser("adaptive-response", help="Run the Adaptive Response Layer across stored findings")
    adaptive_response.add_argument("--db-path", default=None, help="Override SQLite database path")
    adaptive_response.add_argument("--memory-path", default=None, help="Override adaptive response memory path")
    adaptive_response.add_argument("--limit", type=int, default=200, help="Maximum findings to analyze")
    adaptive_response.add_argument("--persist-memory", action="store_true", help="Persist updated threat memory and confidence trails")

    return p.parse_args(argv)


def maybe_refresh(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    if getattr(args, "no_refresh", False):
        return None
    if getattr(args, "cmd", None) not in {"list", "show", "mitigate", "check"}:
        return None

    ttl = int(getattr(args, "cache_ttl", DEFAULT_TTL_SECONDS) or 0)
    if ttl > 0:
        skipped_meta = _maybe_skip_refresh(ttl, json_mode=getattr(args, "json", False))
        if skipped_meta is not None:
            return {"skipped": True, **skipped_meta}

    result = refresh_pipeline(
        skip_export=False,
        openclaw_home=getattr(args, "openclaw_home", None),
        verbose=False,
    )
    _write_last_refresh()
    return result.__dict__


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.cmd == "status":
        from scripts.secopsai_report_snapshot import build_snapshot

        workspace_logs = (
            Path(args.workspace_logs).expanduser().resolve()
            if args.workspace_logs
            else Path.home() / ".openclaw" / "workspace" / "logs"
        )
        openclaw_home = (
            Path(args.openclaw_home).expanduser().resolve()
            if args.openclaw_home
            else Path.home() / ".openclaw"
        )
        payload = build_snapshot(ROOT, workspace_logs, openclaw_home)
        if args.json:
            print(to_json(payload))
        else:
            repo = payload.get("repo", {})
            intel = payload.get("intel", {})
            telemetry = payload.get("telemetry", {})
            replay = telemetry.get("labeled_replay", {}) if isinstance(telemetry, dict) else {}
            findings = payload.get("findings", {}).get("soc_store", {})
            print(f"generated_at={payload.get('generated_at')}")
            print(f"branch={repo.get('branch')}")
            print(f"worktree_dirty={repo.get('worktree', {}).get('dirty')}")
            print(f"intel_total_iocs={intel.get('total_iocs')}")
            print(f"latest_replay_event={replay.get('latest_event_ts')}")
            print(f"open_or_in_review={findings.get('open_or_in_review')}")
            print(f"staleness_flags={','.join(payload.get('staleness_flags') or []) or 'none'}")
        return 0

    if args.cmd == "refresh":
        with _refresh_lock(args.json) as acquired:
            if not acquired:
                return 0

            if args.platform:
                res = _run_adapter_refresh(
                    args.platform,
                    skip_export=args.skip_export,
                    cache_ttl=args.cache_ttl,
                    openclaw_home=args.openclaw_home,
                    verbose=args.verbose,
                )
                if args.json:
                    print(to_json(res))
                return 0

            res = refresh_pipeline(
                skip_export=args.skip_export,
                openclaw_home=args.openclaw_home,
                verbose=args.verbose,
            )
            _write_last_refresh()
            if args.json:
                print(to_json(res.__dict__))
            else:
                print("secopsai refresh complete")
                print(f"exported={res.exported}")
                print(f"findings_db={res.findings_db}")
                print(f"findings_file={res.findings_file}")
                print(f"total_findings={res.total_findings}")
                print(f"total_detections={res.total_detections}")
            return 0

    if args.cmd == "live":
        return _run_live(args.platform, args.duration)

    if args.cmd == "correlate":
        preflight = build_preflight_report(
            workspace_logs=getattr(args, "workspace_logs", None),
            openclaw_home=getattr(args, "openclaw_home", None),
        )
        if args.enforce_preflight and _preflight_is_blocking(preflight):
            if args.json:
                print(to_json({"error": "preflight_blocked", "preflight": preflight}))
            else:
                print(_preflight_text(preflight))
            return 1
        return _run_correlate(time_window=args.window, json_output=args.json)

    if args.cmd == "research":
        if args.research_cmd == "preflight":
            payload = build_preflight_report(
                workspace_logs=args.workspace_logs,
                openclaw_home=args.openclaw_home,
            )
            if args.json:
                print(to_json(payload))
            else:
                print(_preflight_text(payload))
                if payload.get("recommendations"):
                    print("RECOMMENDATIONS:")
                    for item in payload["recommendations"]:
                        print(f"- {item}")
            return 0 if not _preflight_is_blocking(payload) else 1

        try:
            if args.research_cmd == "finding":
                payload = research_finding_report(
                    finding_id=args.finding_id,
                    db_path=args.db_path,
                    search_root=args.search_root,
                    report_dir=args.report_dir,
                )
                if args.session_id:
                    add_session_artifact(
                        args.session_id,
                        kind="research_json_report",
                        artifact_path=payload["json_report"],
                        label="Research JSON report",
                        metadata={"finding_id": args.finding_id},
                        path=args.session_dir,
                    )
                    add_session_artifact(
                        args.session_id,
                        kind="research_markdown_report",
                        artifact_path=payload["markdown_report"],
                        label="Research Markdown report",
                        metadata={"finding_id": args.finding_id},
                        path=args.session_dir,
                    )
                    add_session_event(
                        args.session_id,
                        event_type="research_report_added",
                        message=f"Attached source-backed research for {args.finding_id}.",
                        data={"finding_id": args.finding_id},
                        path=args.session_dir,
                    )
                    payload["session_id"] = args.session_id
            else:
                payload = research_package_report(
                    ecosystem=args.ecosystem,
                    package=args.package,
                    version=args.version,
                    search_root=args.search_root,
                    report_dir=args.report_dir,
                )
                if args.session_id:
                    add_session_artifact(
                        args.session_id,
                        kind="research_json_report",
                        artifact_path=payload["json_report"],
                        label="Research JSON report",
                        metadata={"package": args.package, "ecosystem": args.ecosystem},
                        path=args.session_dir,
                    )
                    add_session_artifact(
                        args.session_id,
                        kind="research_markdown_report",
                        artifact_path=payload["markdown_report"],
                        label="Research Markdown report",
                        metadata={"package": args.package, "ecosystem": args.ecosystem},
                        path=args.session_dir,
                    )
                    add_session_event(
                        args.session_id,
                        event_type="research_report_added",
                        message=f"Attached source-backed package research for {args.ecosystem}:{args.package}.",
                        data={"package": args.package, "ecosystem": args.ecosystem},
                        path=args.session_dir,
                    )
                    payload["session_id"] = args.session_id
        except Exception as exc:
            if args.json:
                print(to_json({"error": str(exc)}))
            else:
                print(f"error: {exc}")
            return 1

        if args.json:
            print(to_json(payload))
        else:
            print(f"SUMMARY: {payload.get('summary')}")
            print(f"JSON_REPORT: {payload['json_report']}")
            print(f"MARKDOWN_REPORT: {payload['markdown_report']}")
            if payload.get("session_id"):
                print(f"SESSION_ID: {payload['session_id']}")
            if payload.get("observations"):
                print("OBSERVATIONS:")
                for item in payload["observations"]:
                    print(f"- {item}")
        return 0

    if args.cmd == "blog":
        try:
            if args.blog_cmd == "draft-finding":
                payload = draft_blog_finding(args.finding_id, db_path=args.db_path)
            elif args.blog_cmd == "draft-advisory":
                payload = draft_blog_advisory(args.campaign)
            elif args.blog_cmd == "draft-news":
                payload = draft_blog_news(args.source)
            elif args.blog_cmd == "news-sources":
                payload = list_blog_news_sources()
            elif args.blog_cmd == "news-fetch":
                payload = fetch_blog_news(limit=args.limit)
            elif args.blog_cmd == "news-draft":
                payload = draft_blog_news_batch(limit=args.limit)
            elif args.blog_cmd == "news-run":
                payload = run_blog_news(limit=args.limit)
            elif args.blog_cmd == "news-review":
                if args.news_review_cmd == "list":
                    payload = list_blog_news_reviews(status=args.status)
                elif args.news_review_cmd == "show":
                    payload = show_blog_news_review(args.draft)
                elif args.news_review_cmd == "approve":
                    payload = update_blog_news_review(args.draft, status="approved", note=args.note)
                elif args.news_review_cmd == "reject":
                    payload = update_blog_news_review(args.draft, status="rejected", note=args.note)
                else:
                    payload = update_blog_news_review(args.draft, status="needs_review", note=args.note)
            elif args.blog_cmd == "news-publish-approved":
                payload = publish_approved_blog_news()
                if args.rebuild:
                    payload["rebuild"] = rebuild_blog()
            elif args.blog_cmd == "draft-daily":
                payload = draft_blog_daily(limit=args.limit)
            elif args.blog_cmd == "publish":
                payload = publish_blog_post(args.draft_or_slug, confirm=args.publish)
            elif args.blog_cmd == "rebuild-feeds":
                payload = rebuild_blog()
            else:
                import os

                payload = comments_setup_status(os.environ.keys())
        except Exception as exc:
            if args.json:
                print(to_json({"error": str(exc)}))
            else:
                print(f"error: {exc}")
            return 1

        if args.json:
            print(to_json(payload))
        elif args.blog_cmd == "news-sources":
            print(f"total={payload['total']}")
            print(f"enabled={payload['enabled']}")
            for source in payload.get("sources", []):
                state = "enabled" if source.get("enabled", True) else "disabled"
                print(f"- {source.get('name')} ({state}, {source.get('type', 'rss')}): {source.get('feed_url') or source.get('url')}")
        elif args.blog_cmd == "news-fetch":
            print(f"created={payload['created']}")
            print(f"cached={payload['cached']}")
            for error in payload.get("errors", []):
                print(f"error={error.get('source')}: {error.get('error')}")
        elif args.blog_cmd in {"news-draft", "news-publish-approved"}:
            print(f"total={payload['total']}")
            for path in payload.get("created", payload.get("published", [])):
                print(f"- {path}")
        elif args.blog_cmd == "news-run":
            print(f"fetched={payload['fetched']['created']}")
            print(f"drafted={payload['drafted']['total']}")
            for path in payload["drafted"].get("created", []):
                print(f"- {path}")
        elif args.blog_cmd == "news-review":
            if args.news_review_cmd == "list":
                print(f"total={payload['total']}")
                for draft in payload.get("drafts", []):
                    print(f"- {draft['review_status']} | {draft['severity']} | {draft['slug']}")
                    print(f"  title={draft['title']}")
                    print(f"  source={draft['source_name']}")
                    print(f"  path={draft['path']}")
            elif args.news_review_cmd == "show":
                print(f"title={payload['title']}")
                print(f"slug={payload['slug']}")
                print(f"status={payload['review_status']}")
                print(f"severity={payload['severity']}")
                print(f"source={payload['source_name']}")
                print("sources:")
                for source in payload.get("sources", []):
                    print(f"- {source}")
                print("\nbody_markdown:\n")
                print(payload.get("body_markdown", ""))
            else:
                print(f"status={payload['review_status']}")
                print(f"title={payload['title']}")
                print(f"path={payload['path']}")
        elif args.blog_cmd.startswith("draft"):
            print(f"draft_path={payload.get('draft_path')}")
            if payload.get("total") is not None:
                print(f"total={payload['total']}")
                for path in payload.get("created", []):
                    print(f"- {path}")
        elif args.blog_cmd == "publish":
            print(f"published={payload['published']}")
            if payload.get("message"):
                print(payload["message"])
            if payload.get("url"):
                print(f"url={payload['url']}")
        elif args.blog_cmd == "rebuild-feeds":
            print(f"posts={payload['posts']}")
            for path in payload["paths"]:
                print(f"- {path}")
        else:
            print(f"configured={payload['configured']}")
            if payload["required_missing"]:
                print(f"required_missing={','.join(payload['required_missing'])}")
            if payload["optional_missing"]:
                print(f"optional_missing={','.join(payload['optional_missing'])}")
        return 0

    if args.cmd == "agent":
        if args.agent_cmd == "route":
            payload = ToolRouter().route(
                args.task,
                allow_writes=args.allow_writes,
                allow_expensive=args.allow_expensive,
            )
            if args.json:
                print(to_json(payload))
            else:
                print(f"TASK: {payload['task']}")
                print("SELECTED:")
                for item in payload["selected"]:
                    tool = item["tool"]
                    print(f"- {tool['name']} ({tool['mode']}): {tool['description']}")
                if payload["blocked"]:
                    print("BLOCKED:")
                    for item in payload["blocked"]:
                        tool = item["tool"]
                        print(f"- {tool['name']} ({item['reason']}): {tool['description']}")
            return 0

        if args.agent_cmd == "compact":
            try:
                payload = compact_session_context(
                    args.session_id,
                    session_dir=args.session_dir,
                    max_events=args.max_events,
                    max_artifacts=args.max_artifacts,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "session_id": args.session_id}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                progress = payload["progress"]
                print(f"SESSION: {payload['session_id']}")
                print(f"STATUS: {payload['status']}")
                print(
                    "PROGRESS: {done}/{total} steps, {approvals} pending approvals, {artifacts} artifacts".format(
                        done=progress["plan_completed"],
                        total=progress["plan_total"],
                        approvals=progress["pending_approvals"],
                        artifacts=progress["artifact_count"],
                    )
                )
                print(f"DOOM_LOOP: {payload['doom_loop']['summary']}")
            return 0

        if args.agent_cmd == "jobs":
            rows = list_agent_jobs(path=args.job_dir, limit=args.limit)
            if args.json:
                print(to_json({"jobs": rows}))
            elif not rows:
                print("No agent jobs found.")
            else:
                for item in rows:
                    print(f"{item.get('job_id')} | {item.get('status')} | {item.get('name')} | {item.get('started_at')}")
            return 0

        if args.agent_cmd == "run-job":
            command = list(args.command or [])
            if command and command[0] == "--":
                command = command[1:]
            try:
                payload = run_isolated_job(
                    name=args.name,
                    command=command,
                    cwd=args.cwd,
                    timeout=args.timeout,
                    path=args.job_dir,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "name": args.name}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                print(f"JOB: {payload['job_id']}")
                print(f"STATUS: {payload['status']}")
                print(f"PATH: {payload['path']}")
            return 0

    if args.cmd == "sync-findings":
        try:
            summary = execute_findings_sync(args)
        except SystemExit as exc:
            if args.json:
                print(to_json({"error": str(exc)}))
            else:
                print(str(exc))
            return 1
        payload = summary.__dict__
        if args.json:
            print(to_json(payload))
        else:
            for key, value in payload.items():
                print(f"{key}={value}")
        return 0

    if args.cmd == "adaptive-response":
        rows = list_triage_findings(db_path=args.db_path, limit=args.limit)
        payload = evaluate_adaptive_response(
            rows,
            memory_path=args.memory_path,
            persist_memory=args.persist_memory,
        )
        if args.json:
            print(to_json(payload))
        else:
            posture = payload["response_posture"]
            sensing = payload["sensing"]
            print(f"ADAPTIVE_RESPONSE: {payload['design_principle']}")
            print(
                "RESPONSE_POSTURE: {mode} sensitivity={sensitivity} findings={findings} clustered_traits={clusters}".format(
                    mode=posture["mode"],
                    sensitivity=posture["sensitivity_multiplier"],
                    findings=sensing["findings"],
                    clusters=sensing["clustered_traits"],
                )
            )
            if payload.get("memory_path"):
                print(f"MEMORY_PATH: {payload['memory_path']}")
            print("TOP_FINDINGS:")
            for item in payload["findings"][:10]:
                print(
                    "- {fid} | adaptive_score={score} | state={state} | {title}".format(
                        fid=item.get("finding_id"),
                        score=item.get("adaptive_score"),
                        state=item.get("recommended_state"),
                        title=item.get("title"),
                    )
                )
            print("SAFE_PROBES:")
            for item in payload["validation_probes"]["safe_probes"][:5]:
                print(f"- {item['trait']}: {item['probe']}")
        return 0

    if args.cmd == "session":
        if args.session_cmd == "create":
            try:
                finding = None
                kind = args.kind
                subject: Dict[str, Any] = {}
                initial_plan: List[Dict[str, Any]] = []
                if args.finding_id:
                    finding = soc_store.get_finding(args.finding_id, args.db_path)
                    if not finding:
                        raise ValueError(f"finding not found: {args.finding_id}")
                    if kind == "general":
                        kind = "triage"
                    subject = _session_subject_for_finding(finding)
                    if kind == "triage":
                        initial_plan = _triage_session_plan()
                elif kind == "triage":
                    initial_plan = _triage_session_plan()

                title = _default_session_title(
                    kind=kind,
                    title=args.title,
                    finding=finding,
                    finding_id=args.finding_id,
                )
                if not title:
                    raise ValueError("--title is required when --finding-id is not supplied")

                session = create_session(
                    kind=kind,
                    title=title,
                    subject=subject,
                    metadata=_json_object(args.metadata, label="metadata"),
                    initial_plan=initial_plan,
                    path=args.session_dir,
                )
                payload = {
                    "session": session,
                    "path": str(session_path(session["session_id"], args.session_dir)),
                }
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1

            if args.json:
                print(to_json(payload))
            else:
                print(_fmt_session_detail(payload["session"]))
                print(f"PATH: {payload['path']}")
            return 0

        if args.session_cmd == "list":
            rows = list_sessions(
                kind=args.kind,
                status=args.status,
                finding_id=args.finding_id,
                limit=args.limit,
                path=args.session_dir,
            )
            if args.json:
                print(to_json({"sessions": rows}))
            else:
                print(_fmt_session_list(rows))
            return 0

        if args.session_cmd == "show":
            try:
                session = load_session(args.session_id, args.session_dir)
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "session_id": args.session_id}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json({"session": session}))
            else:
                print(_fmt_session_detail(session))
                print(f"PATH: {session_path(args.session_id, args.session_dir)}")
            return 0

        if args.session_cmd == "note":
            try:
                session = add_session_note(
                    args.session_id,
                    message=args.message,
                    author=args.author,
                    path=args.session_dir,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "session_id": args.session_id}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json({"session": session}))
            else:
                print(_fmt_session_detail(session))
            return 0

        if args.session_cmd == "step":
            try:
                session = update_session_step(
                    args.session_id,
                    step=args.step,
                    status=args.status,
                    note=args.note,
                    path=args.session_dir,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "session_id": args.session_id, "step": args.step}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json({"session": session}))
            else:
                print(_fmt_session_detail(session))
            return 0

        if args.session_cmd == "request-approval":
            try:
                payload: Dict[str, Any]
                summary = str(args.summary or "").strip()
                if args.type == "triage_action":
                    if not args.action_id:
                        raise ValueError("--action-id is required for triage_action approvals")
                    action = get_action(args.action_id, args.queue_file)
                    if not action:
                        raise ValueError(f"action not found: {args.action_id}")
                    payload = {"kind": "triage_action", "action_id": args.action_id}
                    if args.queue_file:
                        payload["queue_file"] = str(Path(args.queue_file).expanduser().resolve())
                    if not summary:
                        summary = f"Approve queued triage action {args.action_id}: {action.get('summary')}"
                elif args.type == "triage_close":
                    if not args.finding_id:
                        raise ValueError("--finding-id is required for triage_close approvals")
                    finding = soc_store.get_finding(args.finding_id, args.db_path)
                    if not finding:
                        raise ValueError(f"finding not found: {args.finding_id}")
                    if not args.disposition:
                        raise ValueError("--disposition is required for triage_close approvals")
                    if not args.note:
                        raise ValueError("--note is required for triage_close approvals")
                    payload = {
                        "kind": "triage_close",
                        "finding_id": args.finding_id,
                        "disposition": args.disposition,
                        "status": args.status,
                        "note": args.note,
                    }
                    if not summary:
                        summary = f"Approve disposition {args.disposition} for {args.finding_id}"
                else:
                    payload = _json_object(args.payload, label="payload")
                    if not payload:
                        raise ValueError("--payload is required for custom approvals")
                    if "kind" not in payload:
                        payload["kind"] = "custom"
                    if not summary:
                        raise ValueError("--summary is required for custom approvals")

                approval = request_session_approval(
                    args.session_id,
                    approval_type=args.type,
                    summary=summary,
                    payload=payload,
                    requested_by=args.requested_by,
                    path=args.session_dir,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "session_id": args.session_id}))
                else:
                    print(f"error: {exc}")
                return 1

            if args.json:
                print(to_json({"approval": approval}))
            else:
                print(
                    "{aid} | {state} | {atype} | {summary}".format(
                        aid=approval.get("approval_id"),
                        state=approval.get("state"),
                        atype=approval.get("type"),
                        summary=approval.get("summary"),
                    )
                )
            return 0

        if args.session_cmd == "resolve-approval":
            try:
                if args.apply and not args.approve:
                    raise ValueError("--apply requires --approve")
                decision = "approved" if args.approve else "rejected"
                approval = resolve_session_approval(
                    args.session_id,
                    args.approval_id,
                    decision=decision,
                    note=args.note,
                    decided_by=args.decided_by,
                    path=args.session_dir,
                )
                applied = None
                if args.apply:
                    applied = _apply_session_approval(
                        args.session_id,
                        args.approval_id,
                        session_dir=args.session_dir,
                        queue_file=args.queue_file,
                        db_path=args.db_path,
                        author=args.decided_by,
                    )
                payload = {"approval": approval, "applied": applied}
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "session_id": args.session_id, "approval_id": args.approval_id}))
                else:
                    print(f"error: {exc}")
                return 1

            if args.json:
                print(to_json(payload))
            else:
                print(
                    "{aid} | {state} | {atype} | {summary}".format(
                        aid=payload["approval"].get("approval_id"),
                        state=payload["approval"].get("state"),
                        atype=payload["approval"].get("type"),
                        summary=payload["approval"].get("summary"),
                    )
                )
                if payload["applied"]:
                    print(f"APPLIED_KIND: {payload['applied'].get('kind')}")
            return 0

    refresh_meta = maybe_refresh(args)

    if args.cmd == "list":
        rows = soc_store.list_findings()
        if args.platform:
            rows = [r for r in rows if str(r.get("platform", "")).lower() == args.platform.lower()]
        if args.severity:
            rows = [r for r in rows if _severity_at_least(str(r.get("severity", "info")), args.severity)]
        rows = rows[: args.limit]
        if args.json:
            print(to_json({"refreshed": bool(refresh_meta and not refresh_meta.get("skipped")), "refresh": refresh_meta, "findings": rows}))
        else:
            if refresh_meta and not refresh_meta.get("skipped"):
                print(
                    "refreshed: total_findings={tf} total_detections={td}\n".format(
                        tf=refresh_meta.get("total_findings"),
                        td=refresh_meta.get("total_detections"),
                    )
                )
            print(fmt_list(rows))
        return 0

    if args.cmd == "show":
        finding = soc_store.get_finding(args.finding_id)
        if not finding:
            if args.json:
                print(to_json({"error": "finding not found", "finding_id": args.finding_id}))
            else:
                print(f"error: finding not found: {args.finding_id}")
            return 1
        if args.json:
            print(to_json({"refreshed": bool(refresh_meta and not refresh_meta.get("skipped")), "refresh": refresh_meta, "finding": finding}))
        else:
            if refresh_meta and not refresh_meta.get("skipped"):
                print("refreshed before show\n")
            print(fmt_finding(finding))
        return 0

    if args.cmd == "mitigate":
        finding = soc_store.get_finding(args.finding_id)
        if not finding:
            if args.json:
                print(to_json({"error": "finding not found", "finding_id": args.finding_id}))
            else:
                print(f"error: finding not found: {args.finding_id}")
            return 1
        mitigations = openclaw_plugin._mitigations_for_finding(finding)
        payload: Dict[str, Any] = {
            "finding_id": finding.get("finding_id", args.finding_id),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "disposition": finding.get("disposition"),
            "rule_ids": finding.get("rule_ids"),
            "recommended_actions": mitigations,
        }
        if args.json:
            print(to_json({"refreshed": bool(refresh_meta and not refresh_meta.get("skipped")), "refresh": refresh_meta, "mitigation": payload}))
        else:
            if refresh_meta and not refresh_meta.get("skipped"):
                print("refreshed before mitigate\n")
            print(f"{payload['finding_id']} | {str(payload['severity']).upper()} | {payload['title']}")
            print("RECOMMENDED_ACTIONS:")
            for action in payload["recommended_actions"]:
                print(f"- {action}")
        return 0

    if args.cmd == "check":
        result = openclaw_plugin.check_presence(args.type, args.severity)
        payload = {
            "check_type": result.check_type,
            "findings_total": result.findings_total,
            "matched_count": result.matched_count,
            "high_or_above": result.high_or_above,
            "top_matches": result.top_matches,
        }
        if args.json:
            print(to_json({"refreshed": bool(refresh_meta and not refresh_meta.get("skipped")), "refresh": refresh_meta, "check": payload}))
        else:
            if refresh_meta and not refresh_meta.get("skipped"):
                print("refreshed before check\n")
            print(f"CHECK: {payload['check_type']} (min_severity={args.severity})")
            print(
                "findings_total={total} matched={matched} high_or_above={high}".format(
                    total=payload["findings_total"],
                    matched=payload["matched_count"],
                    high=payload["high_or_above"],
                )
            )
            if payload["top_matches"]:
                print("\nTOP_MATCHES:")
                for row in payload["top_matches"]:
                    print(f"- {row['finding_id']} | {str(row['severity']).upper()} | {row['title']}")
        return 0

    if args.cmd == "intel":
        if args.intel_cmd == "refresh":
            res = refresh_iocs(timeout=args.timeout)
            enrich_meta = enrich_iocs(load_iocs()) if args.enrich else None
            if args.json:
                print(to_json({"refresh": res, "enrich": enrich_meta}))
            else:
                print(f"intel refresh: total_iocs={res['total']} path={res['path']}")
                if res.get("errors"):
                    print(f"errors={res['errors']}")
                if enrich_meta:
                    print(f"intel enrich: enriched={enrich_meta['enriched']} path={enrich_meta['path']}")
            return 0

        if args.intel_cmd == "list":
            iocs = load_iocs()
            rows = [ioc.__dict__ for ioc in iocs[: args.limit]]
            if args.json:
                print(to_json({"total": len(iocs), "iocs": rows}))
            else:
                for row in rows:
                    print(f"{row['ioc_type']} {row['value']} score={row['score']} source={row['source']}")
                print(f"total_iocs={len(iocs)}")
            return 0

        if args.intel_cmd == "match":
            iocs = load_iocs()
            replay_path = Path(args.replay) if args.replay else None
            meta = match_iocs_against_replay(iocs, replay_path=replay_path, max_iocs=args.limit_iocs)
            if args.json:
                print(to_json(meta))
            else:
                print(
                    "intel match: events_total={e} iocs_considered={i} matched_findings={m} db={db}".format(
                        e=meta["events_total"],
                        i=meta["iocs_considered"],
                        m=meta["matched_findings"],
                        db=meta["db_path"],
                    )
                )
            return 0

    if args.cmd == "triage":
        if args.triage_cmd == "list":
            rows = list_triage_findings(
                db_path=args.db_path,
                severity=args.severity,
                status=args.status,
                category=args.category,
                limit=args.limit,
            )
            if args.json:
                print(to_json({"findings": rows}))
            else:
                print(fmt_list(rows))
            return 0

        if args.triage_cmd == "start":
            try:
                payload = start_finding(
                    args.finding_id,
                    author=args.author,
                    note=args.note,
                    db_path=args.db_path,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc), "finding_id": args.finding_id}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json({"finding": payload}))
            else:
                print(fmt_finding(payload))
            return 0

        if args.triage_cmd == "investigate":
            session_id = args.session_id
            try:
                preflight = build_preflight_report()
                if args.enforce_preflight and _preflight_is_blocking(preflight):
                    raise ValueError(f"preflight_blocked: {preflight['summary']}")
                if args.open_session and not session_id:
                    finding = soc_store.get_finding(args.finding_id, args.db_path)
                    if not finding:
                        raise ValueError(f"finding not found: {args.finding_id}")
                    session = create_session(
                        kind="triage",
                        title=_default_session_title(kind="triage", finding=finding),
                        subject=_session_subject_for_finding(finding),
                        metadata={"origin": "triage_investigate"},
                        initial_plan=_triage_session_plan(),
                        path=args.session_dir,
                    )
                    session_id = str(session["session_id"])
                if session_id:
                    add_session_event(
                        session_id,
                        event_type="triage_investigation_started",
                        message=f"Started investigation for {args.finding_id}.",
                        data={"finding_id": args.finding_id},
                        author=args.author,
                        path=args.session_dir,
                    )
                    update_session_step(
                        session_id,
                        step="Review finding context",
                        status="completed",
                        note=f"Loaded {args.finding_id} for investigation.",
                        path=args.session_dir,
                    )
                    update_session_step(
                        session_id,
                        step="Investigate locally",
                        status="in_progress",
                        note="Collecting local evidence and generating reports.",
                        path=args.session_dir,
                    )
                payload = investigate_finding(
                    args.finding_id,
                    db_path=args.db_path,
                    search_root=args.search_root,
                    report_dir=args.report_dir,
                    author=args.author,
                    note=args.note,
                )
                payload["preflight"] = preflight
                if args.with_research:
                    research_payload = research_finding_report(
                        finding_id=args.finding_id,
                        db_path=args.db_path,
                        search_root=args.search_root,
                        report_dir=args.report_dir,
                    )
                    payload["research"] = research_payload
                if session_id:
                    add_session_artifact(
                        session_id,
                        kind="triage_json_report",
                        artifact_path=payload["json_report"],
                        label="Investigation JSON report",
                        metadata={"finding_id": args.finding_id},
                        path=args.session_dir,
                    )
                    add_session_artifact(
                        session_id,
                        kind="triage_markdown_report",
                        artifact_path=payload["markdown_report"],
                        label="Investigation Markdown report",
                        metadata={"finding_id": args.finding_id},
                        path=args.session_dir,
                    )
                    if payload.get("research"):
                        add_session_artifact(
                            session_id,
                            kind="research_json_report",
                            artifact_path=payload["research"]["json_report"],
                            label="Research JSON report",
                            metadata={"finding_id": args.finding_id},
                            path=args.session_dir,
                        )
                        add_session_artifact(
                            session_id,
                            kind="research_markdown_report",
                            artifact_path=payload["research"]["markdown_report"],
                            label="Research Markdown report",
                            metadata={"finding_id": args.finding_id},
                            path=args.session_dir,
                        )
                    add_session_event(
                        session_id,
                        event_type="triage_investigation_completed",
                        message=f"Completed investigation for {args.finding_id}.",
                        data={
                            "finding_id": args.finding_id,
                            "recommended_disposition": payload["investigation"].get("recommended_disposition"),
                            "confidence": payload["investigation"].get("confidence"),
                        },
                        author=args.author,
                        path=args.session_dir,
                    )
                    update_session_step(
                        session_id,
                        step="Investigate locally",
                        status="completed",
                        note=payload["investigation"].get("summary"),
                        path=args.session_dir,
                    )
                    update_session_step(
                        session_id,
                        step="Decide disposition",
                        status="in_progress",
                        note="Review the recommendation and choose the final disposition.",
                        path=args.session_dir,
                    )
                    payload["session_id"] = session_id
            except Exception as exc:
                if session_id:
                    try:
                        add_session_event(
                            session_id,
                            event_type="triage_investigation_failed",
                            message=f"Investigation failed for {args.finding_id}: {exc}",
                            data={"finding_id": args.finding_id},
                            author=args.author,
                            path=args.session_dir,
                        )
                        update_session_step(
                            session_id,
                            step="Investigate locally",
                            status="blocked",
                            note=str(exc),
                            path=args.session_dir,
                        )
                    except Exception:
                        pass
                if args.json:
                    error_payload = {"error": str(exc), "finding_id": args.finding_id}
                    if session_id:
                        error_payload["session_id"] = session_id
                    print(to_json(error_payload))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                investigation = payload["investigation"]
                if payload.get("preflight") and payload["preflight"].get("status") != "pass":
                    print(_preflight_text(payload["preflight"]))
                    print("")
                print(fmt_finding(payload["finding"]))
                print("")
                print(f"CATEGORY: {payload['category']}")
                print(f"SUGGESTED_DISPOSITION: {investigation['recommended_disposition']}")
                print(f"CONFIDENCE: {investigation['confidence']}")
                print(f"SUMMARY: {investigation['summary']}")
                print(f"JSON_REPORT: {payload['json_report']}")
                print(f"MARKDOWN_REPORT: {payload['markdown_report']}")
                if payload.get("research"):
                    print(f"RESEARCH_JSON_REPORT: {payload['research']['json_report']}")
                    print(f"RESEARCH_MARKDOWN_REPORT: {payload['research']['markdown_report']}")
                if payload.get("session_id"):
                    print(f"SESSION_ID: {payload['session_id']}")
                if investigation.get("next_actions"):
                    print("NEXT_ACTIONS:")
                    for action in investigation["next_actions"]:
                        print(f"- {action}")
            return 0

        if args.triage_cmd == "close":
            try:
                payload = close_finding(
                    args.finding_id,
                    disposition=args.disposition,
                    note=args.note,
                    author=args.author,
                    status=args.status,
                    db_path=args.db_path,
                )
                if args.session_id:
                    add_session_event(
                        args.session_id,
                        event_type="triage_disposition_recorded",
                        message=f"Recorded {args.disposition} for {args.finding_id}.",
                        data={
                            "finding_id": args.finding_id,
                            "disposition": payload.get("disposition"),
                            "status": payload.get("status"),
                        },
                        author=args.author,
                        path=args.session_dir,
                    )
                    update_session_step(
                        args.session_id,
                        step="Decide disposition",
                        status="completed",
                        note=f"{payload.get('disposition')} / {payload.get('status')}",
                        path=args.session_dir,
                    )
                    update_session_step(
                        args.session_id,
                        step="Apply or queue next action",
                        status="completed",
                        note=f"Closed {args.finding_id} with disposition {payload.get('disposition')}.",
                        path=args.session_dir,
                    )
                    if str(payload.get("status") or "").lower() == "closed":
                        set_session_status(
                            args.session_id,
                            status="closed",
                            message=f"Session closed after final disposition for {args.finding_id}.",
                            path=args.session_dir,
                        )
            except Exception as exc:
                if args.json:
                    error_payload = {"error": str(exc), "finding_id": args.finding_id}
                    if args.session_id:
                        error_payload["session_id"] = args.session_id
                    print(to_json(error_payload))
                else:
                    print(f"error: {exc}")
                return 1
            if args.session_id:
                payload = {"finding": payload, "session_id": args.session_id}
            if args.json:
                print(to_json(payload if isinstance(payload, dict) and "finding" in payload else {"finding": payload}))
            else:
                finding_payload = payload["finding"] if isinstance(payload, dict) and "finding" in payload else payload
                print(fmt_finding(finding_payload))
                if isinstance(payload, dict) and payload.get("session_id"):
                    print(f"\nSESSION_ID: {payload['session_id']}")
            return 0

        if args.triage_cmd == "orchestrate":
            try:
                preflight = build_preflight_report()
                if args.enforce_preflight and _preflight_is_blocking(preflight):
                    raise ValueError(f"preflight_blocked: {preflight['summary']}")
                payload = orchestrate_findings(
                    finding_ids=args.finding_ids or None,
                    db_path=args.db_path,
                    search_root=args.search_root,
                    report_dir=args.report_dir,
                    summary_dir=args.summary_dir,
                    queue_file=args.queue_file,
                    author=args.author,
                    limit=args.limit,
                    auto_apply_safe=not args.no_auto_apply_safe,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(
                    to_json(
                        {
                            "preflight": preflight,
                            "processed": payload.processed,
                            "auto_applied": payload.auto_applied,
                            "queued": payload.queued,
                            "findings": payload.findings,
                            "queue_path": payload.queue_path,
                            "summary_json": payload.summary_json,
                            "summary_markdown": payload.summary_markdown,
                        }
                    )
                )
            else:
                if preflight.get("status") != "pass":
                    print(_preflight_text(preflight))
                print(f"processed={payload.processed}")
                print(f"auto_applied={payload.auto_applied}")
                print(f"queued={payload.queued}")
                print(f"queue_path={payload.queue_path}")
                print(f"summary_json={payload.summary_json}")
                print(f"summary_markdown={payload.summary_markdown}")
                for item in payload.findings:
                    print(
                        "{fid} | {cat} | recommended={disp} | outcome={outcome}{suffix}".format(
                            fid=item.get("finding_id"),
                            cat=item.get("category"),
                            disp=item.get("recommended_disposition"),
                            outcome=item.get("outcome"),
                            suffix=f" | action_id={item.get('action_id')}" if item.get("action_id") else "",
                        )
                    )
            return 0

        if args.triage_cmd == "queue":
            rows = list_actions(status=args.status, path=args.queue_file, limit=args.limit)
            if args.json:
                print(to_json({"actions": rows}))
            else:
                if not rows:
                    print("No queued actions.")
                for row in rows:
                    print(
                        "{aid} | {status} | {atype} | {fid} | {summary}".format(
                            aid=row.get("action_id"),
                            status=row.get("status"),
                            atype=row.get("action_type"),
                            fid=row.get("finding_id"),
                            summary=row.get("summary"),
                        )
                    )
            return 0

        if args.triage_cmd == "apply-action":
            try:
                payload = apply_action(
                    args.action_id,
                    queue_file=args.queue_file,
                    db_path=args.db_path,
                    author=args.author,
                    yes=args.yes,
                )
                if args.session_id:
                    add_session_event(
                        args.session_id,
                        event_type="triage_action_applied",
                        message=f"Applied queued action {args.action_id}.",
                        data={
                            "action_id": args.action_id,
                            "action_type": payload.get("action_type"),
                            "finding_id": payload.get("finding_id"),
                        },
                        author=args.author,
                        path=args.session_dir,
                    )
                    update_session_step(
                        args.session_id,
                        step="Apply or queue next action",
                        status="completed",
                        note=f"Applied queued action {args.action_id}.",
                        path=args.session_dir,
                    )
                    nested = payload.get("result")
                    if isinstance(nested, dict) and str(nested.get("status") or "").lower() == "closed":
                        set_session_status(
                            args.session_id,
                            status="closed",
                            message=f"Session closed after queued action {args.action_id}.",
                            path=args.session_dir,
                        )
            except Exception as exc:
                if args.json:
                    error_payload = {"error": str(exc), "action_id": args.action_id}
                    if args.session_id:
                        error_payload["session_id"] = args.session_id
                    print(to_json(error_payload))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                response_payload: Dict[str, Any] = {"action": payload}
                if args.session_id:
                    response_payload["session_id"] = args.session_id
                print(to_json(response_payload))
            else:
                print(
                    "{aid} | status={status} | type={atype} | finding_id={fid}".format(
                        aid=payload.get("action_id"),
                        status=payload.get("status"),
                        atype=payload.get("action_type"),
                        fid=payload.get("finding_id"),
                    )
                )
                if args.session_id:
                    print(f"SESSION_ID: {args.session_id}")
            return 0

        if args.triage_cmd == "summary":
            try:
                payload = generate_summary(
                    db_path=args.db_path,
                    queue_file=args.queue_file,
                    summary_dir=args.summary_dir,
                    limit=args.limit,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                print(f"open_findings={payload['open_findings']}")
                print(f"in_review_findings={payload['in_review_findings']}")
                print(f"pending_actions={payload['pending_actions']}")
                print(f"applied_actions={payload['applied_actions']}")
                print(f"queue_path={payload['queue_path']}")
                print(f"summary_json={payload['summary_json']}")
                print(f"summary_markdown={payload['summary_markdown']}")
            return 0

    if args.cmd == "supply-chain":
        if args.supply_chain_cmd == "scan":
            payload = run_scan(
                ecosystem=args.ecosystem,
                package=args.package,
                version=args.version,
                previous_version=args.previous_version,
                model=args.model,
                keep_report=not args.no_report,
                slack=args.slack,
            )
            if args.json:
                print(to_json(payload))
            else:
                result = payload["result"]
                print(
                    "supply-chain scan: {eco} {pkg}@{ver} verdict={verdict}".format(
                        eco=result["ecosystem"],
                        pkg=result["package"],
                        ver=result["new_version"],
                        verdict=result["verdict"],
                    )
                )
                if result.get("finding_id"):
                    print(f"finding_id={result['finding_id']}")
                if result.get("advisory_matches"):
                    ids = [
                        str(match.get("advisory_id") or match.get("campaign_id"))
                        for match in result["advisory_matches"]
                    ]
                    print(f"advisory_matches={','.join(ids)}")
                if result.get("report_path"):
                    print(f"report_path={result['report_path']}")
                if payload.get("db_path"):
                    print(f"db_path={payload['db_path']}")
                if payload.get("slack_alerts_sent"):
                    print(f"slack_alerts_sent={payload['slack_alerts_sent']}")
            return 0 if payload["result"]["verdict"] != "error" else 1

        if args.supply_chain_cmd == "once":
            payload = run_recent_top_scan(
                enable_pypi=not args.no_pypi,
                enable_npm=not args.no_npm,
                top=args.top,
                npm_top=args.npm_top,
                lookback_seconds=args.lookback,
                model=args.model,
                slack=args.slack,
            )
            if args.json:
                print(to_json(payload))
            else:
                print(
                    "supply-chain once: scanned={scanned} malicious={mal} benign={benign} errors={errors} skipped={skipped}".format(
                        scanned=payload["total_scanned"],
                        mal=payload["malicious"],
                        benign=payload["benign"],
                        errors=payload["errors"],
                        skipped=payload["skipped"],
                    )
                )
                if payload.get("db_path"):
                    print(f"db_path={payload['db_path']}")
                if payload.get("slack_alerts_sent"):
                    print(f"slack_alerts_sent={payload['slack_alerts_sent']}")
            return 0

        if args.supply_chain_cmd == "monitor":
            return _run_supply_chain_monitor(
                enable_pypi=not args.no_pypi,
                enable_npm=not args.no_npm,
                top=args.top,
                npm_top=args.npm_top,
                interval=args.interval,
                lookback_seconds=args.lookback,
                model=args.model,
                slack=args.slack,
                json_output=args.json,
            )

        if args.supply_chain_cmd == "list":
            payload = {"results": load_recent_results(args.limit)}
            if args.json:
                print(to_json(payload))
            else:
                for row in payload["results"]:
                    print(
                        "{ts} | {eco:4s} | {pkg}@{ver} | verdict={verdict}".format(
                            ts=row.get("recorded_at", ""),
                            eco=row.get("ecosystem", ""),
                            pkg=row.get("package", ""),
                            ver=row.get("new_version", ""),
                            verdict=row.get("verdict", ""),
                        )
                        )
            return 0

        if args.supply_chain_cmd == "reconcile-history":
            payload = reconcile_history(drop_benign=args.drop_benign, include_advisories=args.include_advisories)
            if args.json:
                print(to_json(payload))
            else:
                print(f"total_rows={payload['total_rows']}")
                print(f"reclassified={payload['reclassified']}")
                print(f"dropped={payload['dropped']}")
                print(f"removed_from_slack_state={payload['removed_from_slack_state']}")
                print(f"removed_from_db={payload['removed_from_db']}")
                if payload["changed_finding_ids"]:
                    print(f"changed_finding_ids={payload['changed_finding_ids']}")
                if payload.get("advisory_finding_ids"):
                    print(f"advisory_finding_ids={payload['advisory_finding_ids']}")
                if payload["removed_finding_ids"]:
                    print(f"removed_finding_ids={payload['removed_finding_ids']}")
            return 0

        if args.supply_chain_cmd == "advisory":
            try:
                if args.supply_chain_advisory_cmd == "list":
                    advisories = load_advisories()
                    if args.status != "all":
                        advisories = [
                            item
                            for item in advisories
                            if str(item.get("status", "active")).lower() == args.status.lower()
                        ]
                    payload = {"total": len(advisories), "advisories": advisories}
                elif args.supply_chain_advisory_cmd == "ingest":
                    payload = ingest_advisory(args.source)
                else:
                    payload = check_advisory(args.ecosystem, args.package, args.version)
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            elif args.supply_chain_advisory_cmd == "list":
                print(f"total={payload['total']}")
                for advisory in payload["advisories"]:
                    print(f"- {advisory.get('advisory_id') or advisory.get('campaign_id')}: {advisory.get('title')}")
            elif args.supply_chain_advisory_cmd == "ingest":
                print(f"ingested={payload['ingested']}")
                for path in payload["paths"]:
                    print(f"- {path}")
            else:
                print(f"target={payload['ecosystem']}:{payload['package']}@{payload['version']}")
                print(f"matched={payload['matched']}")
                for match in payload["matches"]:
                    print(f"- {match.get('advisory_id') or match.get('campaign_id')}: {match.get('title')}")
            return 0

        if args.supply_chain_cmd == "explain-policy":
            payload = explain_policy(args.ecosystem, args.package)
            if args.json:
                print(to_json(payload))
            else:
                print(f"target={payload['target']['ecosystem']}:{payload['target']['package']}")
                print(f"effective_threshold={payload['effective_threshold']}")
                print(f"precedence={','.join(payload['precedence'])}")
                if payload["allow_matches"]:
                    print(f"allow_matches={payload['allow_matches']}")
                if payload["deny_matches"]:
                    print(f"deny_matches={payload['deny_matches']}")
                if payload["ecosystem_threshold"] is not None:
                    print(f"ecosystem_threshold={payload['ecosystem_threshold']}")
                if payload["matched_package_threshold"]:
                    print(f"matched_package_threshold={payload['matched_package_threshold']}")
                if payload["disabled_rules"]:
                    print(f"disabled_rules={payload['disabled_rules']}")
                if payload["rule_weight_overrides"]:
                    print(f"rule_weight_overrides={payload['rule_weight_overrides']}")
            return 0

        if args.supply_chain_cmd == "allowlist":
            if args.supply_chain_allowlist_cmd == "add":
                payload = allowlist_add(args.ecosystem, args.package)
            else:
                payload = allowlist_remove(args.ecosystem, args.package)
            if args.json:
                print(to_json(payload))
            else:
                action = "added" if args.supply_chain_allowlist_cmd == "add" else "removed"
                print(f"{action}={payload['entry']}")
                print(f"changed={payload['changed']}")
                print(f"policy_path={payload['policy_path']}")
                print(f"effective_threshold={payload['policy']['effective_threshold']}")
                if payload["policy"]["allow_matches"]:
                    print(f"allow_matches={payload['policy']['allow_matches']}")
            return 0

        if args.supply_chain_cmd == "tune":
            try:
                if args.supply_chain_tune_cmd == "rule":
                    enabled = True if args.enable else False if args.disable else None
                    payload = tune_rule(args.rule_name, weight=args.weight, enabled=enabled)
                else:
                    if args.package and not args.package_ecosystem:
                        raise ValueError("--package-ecosystem is required with --package")
                    payload = tune_threshold(
                        global_threshold=args.value if args.global_threshold else None,
                        ecosystem=args.ecosystem,
                        package=args.package,
                        value=args.value,
                        path=None,
                    ) if not args.package else tune_threshold(
                        ecosystem=args.package_ecosystem,
                        package=args.package,
                        value=args.value,
                        path=None,
                    )
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                if args.supply_chain_tune_cmd == "rule":
                    print(f"rule={payload['rule']}")
                    print(f"enabled={payload['enabled']}")
                    print(f"weight={payload['weight']}")
                else:
                    print(f"scope={payload['scope']}")
                    print(f"target={payload['target']}")
                    print(f"value={payload['value']}")
                print(f"policy_path={payload['policy_path']}")
            return 0

        if args.supply_chain_cmd == "explain-verdict":
            report_path: Optional[Path] = None
            report_text = ""
            try:
                report_path = _resolve_supply_chain_report(
                    report_path=args.report,
                    ecosystem=args.ecosystem,
                    package=args.package,
                    version=args.version,
                )
                report_text = report_path.read_text(encoding="utf-8")
            except Exception as exc:
                advisory_payload = (
                    check_advisory(args.ecosystem, args.package, args.version)
                    if args.version
                    else {"matched": False}
                )
                if not advisory_payload.get("matched"):
                    if args.json:
                        print(to_json({"error": str(exc)}))
                    else:
                        print(f"error: {exc}")
                    return 1

            payload = explain_verdict(
                report_text,
                ecosystem=args.ecosystem,
                package=args.package,
                version=args.version,
            )
            payload["report_path"] = str(report_path) if report_path else None
            if args.version:
                payload["version"] = args.version

            if args.json:
                print(to_json(payload))
            else:
                print(f"target={args.ecosystem}:{args.package}")
                if args.version:
                    print(f"version={args.version}")
                print(f"report_path={report_path or 'none'}")
                print(f"verdict={payload['verdict']}")
                print(f"score={payload['score']}")
                print(f"effective_threshold={payload['effective_threshold']}")
                print(f"analysis={payload['analysis']}")
                if payload.get("advisory_matches"):
                    print("advisory_matches:")
                    for match in payload["advisory_matches"]:
                        advisory_id = match.get("advisory_id") or match.get("campaign_id")
                        print(
                            f"- {advisory_id} confidence={match.get('confidence')} "
                            f"severity={match.get('severity')}"
                        )
                if payload["matched_rules"]:
                    print("matched_rules:")
                    for rule in payload["matched_rules"]:
                        print(f"- {rule['rule']} weight={rule['weight']} reason={rule['reason']}")
                else:
                    print("matched_rules: none")
                if payload.get("policy"):
                    print(f"policy_precedence={','.join(payload['policy']['precedence'])}")
                    if payload["allow_matches"]:
                        print(f"allow_matches={payload['allow_matches']}")
                    if payload["deny_matches"]:
                        print(f"deny_matches={payload['deny_matches']}")
            return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
