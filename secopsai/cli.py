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
from secopsai.ai_dependency_guard import SUPPORTED_ECOSYSTEMS as AI_DEPENDENCY_GUARD_ECOSYSTEMS
from secopsai.ai_dependency_guard import run_ai_dependency_guard
from secopsai.blog import (
    attach_media as attach_blog_media,
    attach_source_media as attach_blog_source_media,
    comments_setup_status,
    draft_advisory as draft_blog_advisory,
    draft_campaign as draft_blog_campaign,
    draft_daily as draft_blog_daily,
    draft_finding as draft_blog_finding,
    draft_news as draft_blog_news,
    news_draft as draft_blog_news_batch,
    news_mark_deployed as mark_deployed_blog_news,
    news_fetch as fetch_blog_news,
    news_publish_approved as publish_approved_blog_news,
    news_review_edit as edit_blog_news_review,
    news_review_list as list_blog_news_reviews,
    news_review_show as show_blog_news_review,
    news_review_update as update_blog_news_review,
    news_run as run_blog_news,
    news_sources_list as list_blog_news_sources,
    publish as publish_blog_post,
    rebuild as rebuild_blog,
)
from secopsai.edge_sync import import_bundle as import_edge_bundle
from secopsai.edge_sync import load_bundle as load_edge_bundle
from secopsai.edge_sync import sync_from_api as sync_edge_from_api
from secopsai.edge_actions import (
    apply_edge_worker_action,
    generate_edge_report,
    normalize_edge_scan_payload,
    normalize_edge_report_payload,
    normalize_edge_worker_payload,
    queue_edge_scan,
)
from secopsai.formatters import fmt_finding, fmt_list, to_json
from secopsai.graph_store import list_assets as list_graph_assets
from secopsai.graph_store import list_changes as list_graph_changes
from secopsai.graph_store import list_sync_state as list_edge_sync_state
from secopsai.graph_store import show_node as show_graph_node
from secopsai.intelligence import ACTIONS as INTELLIGENCE_ACTIONS
from secopsai.intelligence import list_actions as list_intelligence_actions
from secopsai.intelligence import run_read_action as run_intelligence_read_action
from secopsai.intelligence_jobs import cancel_job as cancel_intelligence_job
from secopsai.intelligence_jobs import requeue_job as requeue_intelligence_job
from secopsai.intelligence_jobs import enqueue_job as enqueue_intelligence_job
from secopsai.intelligence_jobs import get_job as get_intelligence_job
from secopsai.intelligence_jobs import list_jobs as list_intelligence_jobs
from secopsai.codex_bridge import doctor as codex_bridge_doctor
from secopsai.codex_bridge import list_models as list_codex_bridge_models
from secopsai.codex_bridge import run_loop as run_codex_bridge_loop
from secopsai.codex_bridge import run_once as run_codex_bridge_once
from secopsai.codex_bridge_service import install_service as install_codex_bridge_service
from secopsai.codex_bridge_service import service_action as codex_bridge_service_action
from secopsai.intel import enrich_iocs, load_iocs, match_iocs_against_replay, refresh_iocs
from secopsai.pipeline import refresh as refresh_pipeline
from secopsai.research import (
    build_preflight_report,
    research_finding as research_finding_report,
    research_package as research_package_report,
)
from secopsai.research_cases import (
    CASE_STATUSES,
    CASE_TYPES,
    DISCLOSURE_STATUSES,
    EVIDENCE_TYPES,
    IOC_TYPES,
    RULE_TYPES,
    SEVERITIES as RESEARCH_SEVERITIES,
    SUBJECT_TYPES,
    add_case_note,
    add_evidence as add_research_evidence,
    add_local_artifact as add_research_artifact,
    add_ioc as add_research_ioc,
    add_rule as add_research_rule,
    add_subject as add_research_subject,
    create_case as create_research_case,
    draft_case_blog,
    export_case as export_research_case,
    get_case as get_research_case,
    load_rule_file as load_research_rule_file,
    link_finding as link_research_finding,
    list_cases as list_research_cases,
    retract_item as retract_research_item,
    start_package_case as start_research_package_case,
    update_case as update_research_case,
)
from secopsai.research_watchlists import promote_watchlist_packages
from secopsai.research_intake import ADAPTERS as RESEARCH_INTAKE_ADAPTERS, preview_package as preview_research_package
from secopsai.research_discovery import (
    capability_registry as research_capability_registry,
    create_monitor as create_research_monitor,
    create_watchlist as create_research_watchlist,
    get_candidate as get_research_candidate,
    ingest_registry_metadata,
    list_candidates as list_research_candidates,
    list_alerts as list_research_alerts,
    list_monitors as list_research_monitors,
    list_watchlists as list_research_watchlists,
    run_monitor as run_research_monitor,
    run_due_monitors as run_due_research_monitors,
    recover_stale_monitor_runs,
)
from secopsai.research_surveillance import (
    collector_status as registry_collector_status,
    coverage_report as registry_coverage_report,
    list_feed_events as registry_list_feed_events,
    recover_interrupted_runs as recover_interrupted_collector_runs,
    retry_dead_letters as retry_registry_dead_letters,
    run_registry_collector,
    set_collector_enabled as set_registry_collector_enabled,
)
from secopsai.research_scoring import score_pending_events as score_pending_feed_events
from secopsai.research_worker import (
    collector_schedules as research_collector_schedules,
    due_collectors as research_due_collectors,
    run_worker_cycle,
    run_worker_loop,
)
from secopsai.research_analysis import compare_intakes, compare_packages, correlate_candidates, inspect_nuget_archive, list_campaigns
from secopsai.research_sandbox import poll_sandbox_request, submit_sandbox_request, provider_status as sandbox_provider_status
from secopsai.research_delivery import send_approved_disclosure, send_research_alert
from secopsai.research_workflow import (
    attach_intake_job,
    build_evidence_matrix,
    generate_analyst_brief,
    get_research_job,
    get_sandbox_request,
    list_research_jobs,
    approve_publication_review,
    approve_sandbox_submission,
    cancel_research_job,
    recover_stale_jobs,
    retry_research_job,
    prepare_disclosure,
    publication_safety_check,
    record_verdict,
    request_sandbox,
    run_intake_job,
    set_disclosure_status,
    set_sandbox_status,
)
from secopsai.research_pipeline import (
    get_pipeline as get_research_pipeline,
    list_pipelines as list_research_pipelines,
    resume_investigation_pipeline,
    review_pipeline_item,
    auto_review_pipeline,
    start_investigation_pipeline,
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
    SUPPORTED_ECOSYSTEM_NAMES,
    allowlist_add,
    allowlist_remove,
    analyze_ecosystem_files,
    campaign_autopilot,
    campaign_intake,
    campaign_watchlist_add,
    campaign_watchlist_list,
    check_advisory,
    discover_campaigns,
    ecosystem_capabilities,
    explain_policy,
    explain_verdict,
    ingest_advisory,
    load_campaign_candidates,
    list_supported_ecosystems,
    load_advisories,
    load_recent_results,
    orchestrate_campaign_candidate,
    promote_campaign_candidate,
    reconcile_history,
    research_campaign as research_supply_chain_campaign,
    run_recent_top_scan,
    run_scan,
    tune_rule,
    tune_threshold,
    watch_npm_namespace,
    watch_packagist_namespace,
    watch_registry,
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
from secopsai.workflows import get_workflow, list_workflows, render_workflow, workflow_names

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
    try:
        passthrough_index = args.index("--")
    except ValueError:
        passthrough_index = len(args)

    prefix = args[:passthrough_index]
    passthrough = args[passthrough_index:]
    if "--json" in prefix and (not prefix or prefix[0] != "--json"):
        prefix = [a for a in prefix if a != "--json"]
        prefix.insert(0, "--json")
        args = prefix + passthrough
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
    edge_root: Optional[str] = None,
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

    if payload_kind == "edge_scan":
        normalized = normalize_edge_scan_payload(payload)
        try:
            result = queue_edge_scan(normalized, edge_root=edge_root)
        except Exception as exc:
            add_session_event(
                session_id,
                event_type="edge_scan_queue_failed",
                message="Approved Edge scan could not be queued.",
                data={"approval_id": approval_id, "error_type": type(exc).__name__},
                author=author,
                path=session_dir,
            )
            update_session_step(
                session_id,
                step="Queue approved Edge scan",
                status="blocked",
                note="The local Edge helper did not queue the scan.",
                path=session_dir,
            )
            raise
        add_session_event(
            session_id,
            event_type="edge_scan_queued",
            message=f"Queued approved Edge scan for {result['target_cidr']}.",
            data={
                "approval_id": approval_id,
                "target_cidr": result["target_cidr"],
                "include_wifi": result["include_wifi"],
            },
            author=author,
            path=session_dir,
        )
        update_session_step(
            session_id,
            step="Queue approved Edge scan",
            status="completed",
            note=f"Queued {result['target_cidr']} through the local Edge worker.",
            path=session_dir,
        )
        return {"kind": payload_kind, "result": result}

    if payload_kind in {"edge_report", "edge_worker"}:
        normalized = (
            normalize_edge_report_payload(payload)
            if payload_kind == "edge_report"
            else normalize_edge_worker_payload(payload)
        )
        try:
            result = (
                generate_edge_report(normalized, edge_root=edge_root)
                if payload_kind == "edge_report"
                else apply_edge_worker_action(normalized, edge_root=edge_root)
            )
        except Exception as exc:
            add_session_event(
                session_id,
                event_type="edge_operation_failed",
                message="Approved Edge operation could not be applied.",
                data={"approval_id": approval_id, "kind": payload_kind, "error_type": type(exc).__name__},
                author=author,
                path=session_dir,
            )
            update_session_step(
                session_id,
                step="Apply approved Edge operation",
                status="blocked",
                note="The local Edge helper did not complete the operation.",
                path=session_dir,
            )
            raise
        add_session_event(
            session_id,
            event_type="edge_operation_applied",
            message=f"Applied approved {payload_kind} operation.",
            data={"approval_id": approval_id, **result},
            author=author,
            path=session_dir,
        )
        update_session_step(
            session_id,
            step="Apply approved Edge operation",
            status="completed",
            note=f"Applied {payload_kind} through the local Edge helper.",
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

    workflow = sub.add_parser("workflow", help="List or show role-based SecOpsAI operator workflows")
    workflow_sub = workflow.add_subparsers(dest="workflow_cmd", required=True)
    workflow_sub.add_parser("list", help="List available workflows")
    workflow_show = workflow_sub.add_parser("show", help="Show one workflow checklist")
    workflow_show.add_argument("name", choices=workflow_names())

    for workflow_name in workflow_names():
        sub.add_parser(workflow_name, help=f"Show the {workflow_name} workflow checklist")

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
    refresh.add_argument("--platform", "-p", help="Adapters: openclaw,hermes,macos,linux,windows")
    refresh.add_argument("--skip-export", action="store_true", help="Skip export from ~/.openclaw")
    refresh.add_argument("--cache-ttl", type=int, default=DEFAULT_TTL_SECONDS)
    refresh.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")
    refresh.add_argument("--verbose", action="store_true", help="Verbose refresh output (future use)")

    live = sub.add_parser("live", help="Stream events in real time from platform adapters")
    live.add_argument("--platform", "-p", help="Adapters to stream: openclaw,hermes,macos,linux,windows")
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

    edge = sub.add_parser("edge", help="Import or sync SecOpsAI Edge graph and findings")
    edge_sub = edge.add_subparsers(dest="edge_cmd", required=True)
    edge_import = edge_sub.add_parser("import", help="Import a SecOpsAI Edge bundle JSON file")
    edge_import.add_argument("--bundle", required=True, help="Path to secopsai.edge.bundle.v1 JSON")
    edge_import.add_argument("--db-path", default=None, help="Override SQLite SOC/graph database path")
    edge_sync = edge_sub.add_parser("sync", help="Fetch Edge export and import it locally and/or into hosted Core")
    edge_sync.add_argument("--edge-api-url", default=None, help="SecOpsAI Edge API URL")
    edge_sync.add_argument(
        "--access-token",
        "--admin-token",
        dest="access_token",
        default=None,
        help="Workspace-scoped Edge Core export token",
    )
    edge_sync.add_argument(
        "--core-api-url",
        default=None,
        help="Hosted Core API URL; defaults to SECOPSAI_CORE_API_URL",
    )
    edge_sync.add_argument(
        "--core-ingest-token",
        default=None,
        help="Core ingest credential; prefer SECOPSAI_CORE_INGEST_TOKEN",
    )
    edge_sync.add_argument(
        "--remote-only",
        action="store_true",
        help="Send the bundle to hosted Core without updating local SQLite",
    )
    edge_sync.add_argument("--db-path", default=None, help="Override SQLite SOC/graph database path")
    edge_status = edge_sub.add_parser("status", help="Show recent Edge-to-Core sync state")
    edge_status.add_argument("--db-path", default=None, help="Override SQLite SOC/graph database path")
    edge_status.add_argument("--limit", type=int, default=20, help="Maximum sync records to show")

    graph = sub.add_parser("graph", help="Inspect the local SecOpsAI asset graph")
    graph_sub = graph.add_subparsers(dest="graph_cmd", required=True)
    graph_assets = graph_sub.add_parser("assets", help="List assets discovered by Edge")
    graph_assets.add_argument("--db-path", default=None, help="Override SQLite SOC/graph database path")
    graph_assets.add_argument("--limit", type=int, default=50)
    graph_show = graph_sub.add_parser("show", help="Show a graph node, source id, label, or asset IP")
    graph_show.add_argument("identifier")
    graph_show.add_argument("--db-path", default=None, help="Override SQLite SOC/graph database path")
    graph_changes = graph_sub.add_parser("changes", help="Show recently updated graph nodes and edges")
    graph_changes.add_argument("--db-path", default=None, help="Override SQLite SOC/graph database path")
    graph_changes.add_argument("--limit", type=int, default=20)

    intelligence = sub.add_parser("intelligence", help="Run approved read-only intelligence actions and manage the local Codex bridge")
    intelligence_sub = intelligence.add_subparsers(dest="intelligence_cmd", required=True)
    intelligence_sub.add_parser("actions", help="List approved intelligence actions and scopes")
    intelligence_status = intelligence_sub.add_parser("status", help="Show local bridge, service, action, and queue status in one request")
    intelligence_status.add_argument("--limit", type=int, default=50)
    intelligence_status.add_argument("--db-path", default=None)
    intelligence_query = intelligence_sub.add_parser("query", help="Run a deterministic read-only Core intelligence action")
    intelligence_query.add_argument("action", choices=[name for name, item in INTELLIGENCE_ACTIONS.items() if not item.requires_bridge])
    intelligence_query.add_argument("--target-id", default="")
    intelligence_query.add_argument("--inputs-json", default="{}", help="Additional bounded JSON object inputs")
    intelligence_query.add_argument("--db-path", default=None)
    intelligence_enqueue = intelligence_sub.add_parser("enqueue", help="Queue an approved action for the local subscription-backed Codex bridge")
    intelligence_enqueue.add_argument("--action", required=True, choices=[name for name, item in INTELLIGENCE_ACTIONS.items() if item.requires_bridge])
    intelligence_enqueue.add_argument("--target-id", default="")
    intelligence_enqueue.add_argument("--inputs-json", default="{}", help="Additional bounded JSON object inputs")
    intelligence_enqueue.add_argument("--requested-by", default="operator")
    intelligence_enqueue.add_argument("--idempotency-key", default="")
    intelligence_enqueue.add_argument("--db-path", default=None)
    intelligence_jobs = intelligence_sub.add_parser("jobs", help="List, show, or cancel local intelligence jobs")
    intelligence_jobs_sub = intelligence_jobs.add_subparsers(dest="intelligence_jobs_cmd", required=True)
    intelligence_jobs_list = intelligence_jobs_sub.add_parser("list")
    intelligence_jobs_list.add_argument("--status", default="")
    intelligence_jobs_list.add_argument("--limit", type=int, default=100)
    intelligence_jobs_list.add_argument("--db-path", default=None)
    intelligence_jobs_show = intelligence_jobs_sub.add_parser("show")
    intelligence_jobs_show.add_argument("job_id")
    intelligence_jobs_show.add_argument("--db-path", default=None)
    intelligence_jobs_cancel = intelligence_jobs_sub.add_parser("cancel")
    intelligence_jobs_cancel.add_argument("job_id")
    intelligence_jobs_cancel.add_argument("--actor", default="operator")
    intelligence_jobs_cancel.add_argument("--db-path", default=None)
    intelligence_jobs_requeue = intelligence_jobs_sub.add_parser(
        "requeue",
        help="Requeue a failed intelligence job so another model can process it",
    )
    intelligence_jobs_requeue.add_argument("job_id")
    intelligence_jobs_requeue.add_argument("--actor", default="operator")
    intelligence_jobs_requeue.add_argument("--db-path", default=None)
    intelligence_bridge = intelligence_sub.add_parser(
        "bridge",
        help="Inspect or run the local OpenCodex/Codex intelligence bridge",
    )
    intelligence_bridge_sub = intelligence_bridge.add_subparsers(dest="intelligence_bridge_cmd", required=True)
    intelligence_bridge_sub.add_parser("doctor")
    intelligence_bridge_sub.add_parser(
        "models",
        help="List OpenCodex/Codex models available for research analysis",
    )
    intelligence_bridge_run = intelligence_bridge_sub.add_parser("run")
    intelligence_bridge_run.add_argument("--once", action="store_true")
    intelligence_bridge_run.add_argument("--max-iterations", type=int, default=0)
    intelligence_bridge_run.add_argument(
        "--model",
        default="",
        help="OpenCodex model id, e.g. kimi/kimi-k2.7-code or xai/grok-4.5",
    )
    intelligence_bridge_run.add_argument("--db-path", default=None)
    intelligence_bridge_service = intelligence_bridge_sub.add_parser("service", help="Install or control the user-level bridge background service")
    intelligence_bridge_service.add_argument("action", choices=["install", "start", "stop", "status", "logs", "uninstall"])
    intelligence_bridge_service.add_argument("--db-path", default=None)
    intelligence_bridge_service.add_argument("--no-start", action="store_true")
    intelligence_bridge_service.add_argument("--tail", type=int, default=80)

    research = sub.add_parser("research", help="Generate source-backed research reports and preflight checks")
    research_sub = research.add_subparsers(dest="research_cmd", required=True)

    research_ecosystems = research_sub.add_parser("ecosystems", help="Show research ecosystem capabilities and coverage modes")

    research_watchlist = research_sub.add_parser("watchlist", help="Manage cross-ecosystem research watchlists")
    research_watchlist_sub = research_watchlist.add_subparsers(dest="research_watchlist_cmd", required=True)
    research_watchlist_sub.add_parser("list", help="List active research watchlists").add_argument("--ecosystem", default=None)
    research_watchlist_add = research_watchlist_sub.add_parser("add", help="Add a package, brand, publisher, or namespace watchlist")
    research_watchlist_add.add_argument("--ecosystem", required=True)
    research_watchlist_add.add_argument("--watch-type", choices=["package", "namespace", "publisher", "brand", "repository", "organization"], default="package")
    research_watchlist_add.add_argument("--identifier", required=True)
    research_watchlist_add.add_argument("--brand", default="")
    research_watchlist_add.add_argument("--known-publisher", action="append", default=[])
    research_watchlist_add.add_argument("--known-repository", action="append", default=[])
    research_watchlist_add.add_argument("--threshold", type=float, default=70.0)
    research_watchlist_add.add_argument("--priority", choices=["low", "normal", "high", "critical"], default="normal")
    research_watchlist_add.add_argument("--owner", default="")
    research_watchlist_add.add_argument("--reason", default="")
    research_watchlist_add.add_argument("--db-path", default=None)

    research_monitor = research_sub.add_parser("monitor", help="Manage durable registry monitors")
    research_monitor_sub = research_monitor.add_subparsers(dest="research_monitor_cmd", required=True)
    monitor_list = research_monitor_sub.add_parser("list")
    monitor_list.add_argument("--ecosystem", default=None)
    monitor_list.add_argument("--db-path", default=None)
    monitor_create = research_monitor_sub.add_parser("create")
    monitor_create.add_argument("--ecosystem", required=True)
    monitor_create.add_argument("--watchlist-id", default=None)
    monitor_create.add_argument("--name", default="")
    monitor_create.add_argument("--interval-seconds", type=int, default=3600)
    monitor_create.add_argument("--priority", choices=["low", "normal", "high", "critical"], default="normal")
    monitor_create.add_argument("--db-path", default=None)
    monitor_run = research_monitor_sub.add_parser("run")
    monitor_run.add_argument("monitor_id")
    monitor_run.add_argument("--db-path", default=None)
    monitor_due = research_monitor_sub.add_parser("run-due")
    monitor_due.add_argument("--limit", type=int, default=25)
    monitor_due.add_argument("--db-path", default=None)
    monitor_recover = research_monitor_sub.add_parser("recover-stale")
    monitor_recover.add_argument("--max-age-seconds", type=int, default=3600)
    monitor_recover.add_argument("--db-path", default=None)

    research_candidate = research_sub.add_parser("candidate", help="Review registry research candidates")
    research_candidate_sub = research_candidate.add_subparsers(dest="research_candidate_cmd", required=True)
    candidate_list = research_candidate_sub.add_parser("list")
    candidate_list.add_argument("--status", default=None)
    candidate_list.add_argument("--ecosystem", default=None)
    candidate_list.add_argument("--limit", type=int, default=100)
    candidate_list.add_argument("--db-path", default=None)
    candidate_show = research_candidate_sub.add_parser("show")
    candidate_show.add_argument("candidate_id")
    candidate_show.add_argument("--db-path", default=None)

    research_collect = research_sub.add_parser("collect", help="Run global registry feed collectors")
    research_collect_sub = research_collect.add_subparsers(dest="research_collect_cmd", required=True)
    collect_status = research_collect_sub.add_parser("status", help="Show collector cursors, lag, gaps, and failures")
    collect_status.add_argument("--ecosystem", default=None)
    collect_status.add_argument("--db-path", default=None)
    collect_run = research_collect_sub.add_parser("run", help="Run one bounded global feed ingestion pass")
    collect_run.add_argument("--ecosystem", default="nuget")
    collect_run.add_argument("--since", default=None, help="Backfill cursor start (ISO 8601); can only move the cursor backward")
    collect_run.add_argument("--max-pages", type=int, default=10)
    collect_run.add_argument("--fetch-leaves", action="store_true", help="Enrich stored events with catalog leaf metadata")
    collect_run.add_argument("--db-path", default=None)
    collect_retry = research_collect_sub.add_parser("retry-failures", help="Retry due dead-lettered pages and leaves")
    collect_retry.add_argument("--limit", type=int, default=25)
    collect_retry.add_argument("--db-path", default=None)
    collect_coverage = research_collect_sub.add_parser("coverage", help="Show recent coverage windows, gaps first")
    collect_coverage.add_argument("--days", type=int, default=7)
    collect_coverage.add_argument("--db-path", default=None)
    collect_recover = research_collect_sub.add_parser("recover-stale", help="Mark dead collector runs as interrupted")
    collect_recover.add_argument("--max-age-seconds", type=int, default=3600)
    collect_recover.add_argument("--db-path", default=None)
    collect_events = research_collect_sub.add_parser("events", help="Inspect the stored feed-event ledger")
    collect_events.add_argument("--collector-id", default=None)
    collect_events.add_argument("--package", default=None)
    collect_events.add_argument("--limit", type=int, default=100)
    collect_events.add_argument("--db-path", default=None)
    collect_pause = research_collect_sub.add_parser("pause", help="Pause a collector without losing its cursor")
    collect_pause.add_argument("--ecosystem", required=True)
    collect_pause.add_argument("--db-path", default=None)
    collect_resume = research_collect_sub.add_parser("resume", help="Resume a paused collector")
    collect_resume.add_argument("--ecosystem", required=True)
    collect_resume.add_argument("--db-path", default=None)

    research_score = research_sub.add_parser("score", help="Score pending feed events into candidates")
    research_score_sub = research_score.add_subparsers(dest="research_score_cmd", required=True)
    score_run = research_score_sub.add_parser("run", help="Score pending surveillance events against active watchlists")
    score_run.add_argument("--ecosystem", default=None)
    score_run.add_argument("--limit", type=int, default=200)
    score_run.add_argument("--db-path", default=None)

    research_worker = research_sub.add_parser("worker", help="Run the continuous surveillance worker")
    research_worker_sub = research_worker.add_subparsers(dest="research_worker_cmd", required=True)
    worker_run = research_worker_sub.add_parser("run", help="Run worker cycles")
    worker_run.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    worker_run.add_argument("--interval", type=int, default=60, help="Seconds between cycles in loop mode")
    worker_run.add_argument("--max-cycles", type=int, default=None, help="Stop after N cycles (loop mode)")
    worker_run.add_argument("--db-path", default=None)
    worker_due = research_worker_sub.add_parser("due", help="Show which collectors are due")
    worker_due.add_argument("--db-path", default=None)

    research_compare = research_sub.add_parser("compare", help="Compare two normalized, statically collected package intake JSON files")
    research_compare.add_argument("--left", required=True, help="Path to the first normalized intake JSON")
    research_compare.add_argument("--right", required=True, help="Path to the second normalized intake JSON")
    research_compare.add_argument("--db-path", default=None)
    research_compare_packages = research_sub.add_parser("compare-packages", help="Safely collect and compare two exact package targets")
    for prefix in ("left", "right"):
        research_compare_packages.add_argument(f"--{prefix}-ecosystem", required=True)
        research_compare_packages.add_argument(f"--{prefix}-package", required=True)
        research_compare_packages.add_argument(f"--{prefix}-version", default="")
    research_compare_packages.add_argument("--db-path", default=None)

    research_campaign = research_sub.add_parser("campaign", help="Correlate candidate evidence into reviewable campaign links")
    research_campaign_sub = research_campaign.add_subparsers(dest="research_campaign_cmd", required=True)
    campaign_correlate = research_campaign_sub.add_parser("correlate")
    campaign_correlate.add_argument("--db-path", default=None)
    campaign_list = research_campaign_sub.add_parser("list")
    campaign_list.add_argument("--limit", type=int, default=100)
    campaign_list.add_argument("--db-path", default=None)

    research_sandbox = research_sub.add_parser("sandbox", help="Inspect and operate approval-gated sandbox requests")
    research_sandbox_sub = research_sandbox.add_subparsers(dest="research_sandbox_cmd", required=True)
    research_sandbox_sub.add_parser("status")
    sandbox_submit = research_sandbox_sub.add_parser("submit")
    sandbox_submit.add_argument("request_id")
    sandbox_submit.add_argument("--public-submission-acknowledged", action="store_true")
    sandbox_submit.add_argument("--db-path", default=None)
    sandbox_poll = research_sandbox_sub.add_parser("poll")
    sandbox_poll.add_argument("request_id")
    sandbox_poll.add_argument("--db-path", default=None)

    research_disclosure = research_sub.add_parser("disclosure", help="Deliver approved research disclosures")
    research_disclosure_sub = research_disclosure.add_subparsers(dest="research_disclosure_cmd", required=True)
    disclosure_send = research_disclosure_sub.add_parser("send")
    disclosure_send.add_argument("disclosure_id")
    disclosure_send.add_argument("--channel", choices=["email", "webhook"], default="email")
    disclosure_send.add_argument("--db-path", default=None)

    research_alert = research_sub.add_parser("alert", help="Review research discovery alerts")
    research_alert_sub = research_alert.add_subparsers(dest="research_alert_cmd", required=True)
    alert_list = research_alert_sub.add_parser("list")
    alert_list.add_argument("--status", default=None)
    alert_list.add_argument("--limit", type=int, default=100)
    alert_list.add_argument("--db-path", default=None)
    alert_deliver = research_alert_sub.add_parser("deliver")
    alert_deliver.add_argument("alert_id")
    alert_deliver.add_argument("--channel", choices=["email", "webhook"], default="email")
    alert_deliver.add_argument("--db-path", default=None)

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
    research_package_cmd.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
    research_package_cmd.add_argument("--package", required=True, help="Package name")
    research_package_cmd.add_argument("--version", default=None, help="Optional version hint")
    research_package_cmd.add_argument("--search-root", default=None, help="Root path to scan for local references")
    research_package_cmd.add_argument("--report-dir", default=None, help="Directory to write research reports")
    research_package_cmd.add_argument("--session-id", default=None, help="Attach the report to an existing session")
    research_package_cmd.add_argument("--session-dir", default=None, help="Override session storage directory")

    research_case = research_sub.add_parser("case", help="Manage durable independent-research cases")
    research_case_sub = research_case.add_subparsers(dest="research_case_cmd", required=True)

    case_create = research_case_sub.add_parser("create", help="Create a research case")
    case_create.add_argument("--title", required=True)
    case_create.add_argument("--summary", default="")
    case_create.add_argument("--type", dest="case_type", choices=sorted(CASE_TYPES), default="other")
    case_create.add_argument("--severity", choices=sorted(RESEARCH_SEVERITIES), default="medium")
    case_create.add_argument("--confidence", default="0", help="0-100 or low/medium/high/confirmed")
    case_create.add_argument("--owner", default="")
    case_create.add_argument("--db-path", default=None)

    case_list = research_case_sub.add_parser("list", help="List research cases")
    case_list.add_argument("--status", choices=sorted(CASE_STATUSES), default=None)
    case_list.add_argument("--type", dest="case_type", choices=sorted(CASE_TYPES), default=None)
    case_list.add_argument("--limit", type=int, default=100)
    case_list.add_argument("--db-path", default=None)

    case_show = research_case_sub.add_parser("show", help="Show one research case with evidence and timeline")
    case_show.add_argument("case_id")
    case_show.add_argument("--db-path", default=None)

    case_update = research_case_sub.add_parser("update", help="Update research case state and disclosure")
    case_update.add_argument("case_id")
    case_update.add_argument("--title")
    case_update.add_argument("--summary")
    case_update.add_argument("--type", dest="case_type", choices=sorted(CASE_TYPES))
    case_update.add_argument("--severity", choices=sorted(RESEARCH_SEVERITIES))
    case_update.add_argument("--confidence", help="0-100 or low/medium/high/confirmed")
    case_update.add_argument("--status", choices=sorted(CASE_STATUSES))
    case_update.add_argument("--owner")
    case_update.add_argument("--disclosure-status", choices=sorted(DISCLOSURE_STATUSES))
    case_update.add_argument("--embargo-until")
    case_update.add_argument("--actor", default="analyst")
    case_update.add_argument("--db-path", default=None)

    case_subject = research_case_sub.add_parser("add-subject", help="Attach a package, brand, repository, or infrastructure subject")
    case_subject.add_argument("case_id")
    case_subject.add_argument("--subject-type", required=True, choices=sorted(SUBJECT_TYPES))
    case_subject.add_argument("--name", required=True)
    case_subject.add_argument("--ecosystem", default="")
    case_subject.add_argument("--version", default="")
    case_subject.add_argument("--publisher", default="")
    case_subject.add_argument("--actor", default="analyst")
    case_subject.add_argument("--db-path", default=None)

    case_start_package = research_case_sub.add_parser(
        "start-package",
        help="Start a package research case from analyst metadata without fetching or executing anything",
    )
    case_start_package.add_argument("--package", required=True)
    case_start_package.add_argument("--ecosystem", required=True)
    case_start_package.add_argument("--version", default="")
    case_start_package.add_argument("--title", default="")
    case_start_package.add_argument("--summary", default="")
    case_start_package.add_argument("--type", dest="case_type", choices=sorted(CASE_TYPES), default="malicious_package")
    case_start_package.add_argument("--severity", choices=sorted(RESEARCH_SEVERITIES), default="medium")
    case_start_package.add_argument("--confidence", default="0", help="0-100 or low/medium/high/confirmed")
    case_start_package.add_argument("--owner", default="")
    case_start_package.add_argument("--publisher", default="")
    case_start_package.add_argument("--source-url", default="", help="Record a public source URL without fetching it")
    case_start_package.add_argument("--artifact", default="", help="Hash a local regular file without executing or unpacking it")
    case_start_package.add_argument("--artifact-title", default="")
    case_start_package.add_argument("--actor", default="analyst")
    case_start_package.add_argument("--db-path", default=None)

    case_from_watchlist = research_case_sub.add_parser(
        "from-watchlist",
        help="Preview or promote selected npm campaign-watchlist packages into research cases",
    )
    case_from_watchlist.add_argument("--ecosystem", required=True, choices=["npm"])
    case_from_watchlist.add_argument("--package", action="append", default=[], help="Watchlist package; repeat for multiple packages")
    case_from_watchlist.add_argument("--all", dest="select_all", action="store_true", help="Select every npm package in the watchlist")
    case_from_watchlist.add_argument("--create", action="store_true", help="Create cases; without this flag only preview the selection")
    case_from_watchlist.add_argument("--title-prefix", default="Watchlist research")
    case_from_watchlist.add_argument("--severity", choices=sorted(RESEARCH_SEVERITIES), default="medium")
    case_from_watchlist.add_argument("--owner", default="")
    case_from_watchlist.add_argument("--source-url", default="", help="Optional public source URL to record without fetching")
    case_from_watchlist.add_argument("--actor", default="analyst")
    case_from_watchlist.add_argument("--watchlist-path", default=None, help="Override campaign watchlist JSON path")
    case_from_watchlist.add_argument("--db-path", default=None)

    case_evidence = research_case_sub.add_parser("add-evidence", help="Attach a source or analysis evidence record")
    case_evidence.add_argument("case_id")
    case_evidence.add_argument("--evidence-type", required=True, choices=sorted(EVIDENCE_TYPES))
    case_evidence.add_argument("--title", required=True)
    case_evidence.add_argument("--locator", default="")
    case_evidence.add_argument("--sha256", default="")
    case_evidence.add_argument("--provenance", default="")
    case_evidence.add_argument("--notes", default="")
    case_evidence.add_argument("--collected-at", default=None)
    case_evidence.add_argument("--actor", default="analyst")
    case_evidence.add_argument("--db-path", default=None)

    case_artifact = research_case_sub.add_parser(
        "add-artifact",
        help="Hash a local regular file as package evidence without executing or unpacking it",
    )
    case_artifact.add_argument("case_id")
    case_artifact.add_argument("--artifact", required=True)
    case_artifact.add_argument("--title", default="")
    case_artifact.add_argument("--locator", default="")
    case_artifact.add_argument("--provenance", default="")
    case_artifact.add_argument("--notes", default="")
    case_artifact.add_argument("--actor", default="analyst")
    case_artifact.add_argument("--db-path", default=None)

    case_ioc = research_case_sub.add_parser("add-ioc", help="Attach a normalized indicator of compromise")
    case_ioc.add_argument("case_id")
    case_ioc.add_argument("--ioc-type", required=True, choices=sorted(IOC_TYPES))
    case_ioc.add_argument("--value", required=True)
    case_ioc.add_argument("--confidence", default="50")
    case_ioc.add_argument("--source-evidence-id", default=None)
    case_ioc.add_argument("--first-seen", default=None)
    case_ioc.add_argument("--last-seen", default=None)
    case_ioc.add_argument("--tag", action="append", default=[])
    case_ioc.add_argument("--actor", default="analyst")
    case_ioc.add_argument("--db-path", default=None)

    case_rule = research_case_sub.add_parser(
        "add-rule",
        help="Attach a YARA, Sigma, or Semgrep rule after structural validation",
    )
    case_rule.add_argument("case_id")
    case_rule.add_argument("--rule-type", required=True, choices=sorted(RULE_TYPES))
    case_rule.add_argument("--name", required=True)
    content_group = case_rule.add_mutually_exclusive_group(required=True)
    content_group.add_argument("--content", default="")
    content_group.add_argument("--file", default="", help="Read rule text from a UTF-8 file")
    case_rule.add_argument("--purpose", default="")
    case_rule.add_argument("--source-evidence-id", default=None)
    case_rule.add_argument("--actor", default="analyst")
    case_rule.add_argument("--db-path", default=None)

    case_link = research_case_sub.add_parser("link-finding", help="Link a SOC finding to a research case")
    case_link.add_argument("case_id")
    case_link.add_argument("finding_id")
    case_link.add_argument("--relationship", choices=["supports", "related", "derived_from", "impacts"], default="supports")
    case_link.add_argument("--actor", default="analyst")
    case_link.add_argument("--db-path", default=None)

    case_note = research_case_sub.add_parser("note", help="Add an immutable analyst note to the case timeline")
    case_note.add_argument("case_id")
    case_note.add_argument("--note", required=True)
    case_note.add_argument("--actor", default="analyst")
    case_note.add_argument("--db-path", default=None)

    case_retract = research_case_sub.add_parser("retract", help="Retract an incorrect subject, evidence record, or IOC without deleting history")
    case_retract.add_argument("case_id")
    case_retract.add_argument("--item-type", required=True, choices=["subject", "evidence", "ioc", "rule"])
    case_retract.add_argument("--item-id", required=True)
    case_retract.add_argument("--reason", required=True)
    case_retract.add_argument("--actor", default="analyst")
    case_retract.add_argument("--db-path", default=None)

    case_export = research_case_sub.add_parser("export", help="Export deterministic JSON and Markdown case reports")
    case_export.add_argument("case_id")
    case_export.add_argument("--output-dir", default=None)
    case_export.add_argument("--db-path", default=None)

    case_draft = research_case_sub.add_parser("draft-blog", help="Create a review-only blog draft after readiness checks pass")
    case_draft.add_argument("case_id")
    case_draft.add_argument("--db-path", default=None)

    intake = research_sub.add_parser("intake", help="Safely collect and statically inspect a package without executing it")
    intake_sub = intake.add_subparsers(dest="research_intake_cmd", required=True)
    intake_preview = intake_sub.add_parser("preview", help="Fetch official metadata only and show the planned intake")
    intake_preview.add_argument("--ecosystem", required=True, choices=sorted(RESEARCH_INTAKE_ADAPTERS))
    intake_preview.add_argument("--package", required=True)
    intake_preview.add_argument("--version", default="")
    intake_run = intake_sub.add_parser("run", help="Collect an artifact into quarantine and run bounded static inspection")
    intake_run.add_argument("--case", required=True, dest="case_id")
    intake_run.add_argument("--ecosystem", required=True, choices=sorted(RESEARCH_INTAKE_ADAPTERS))
    intake_run.add_argument("--package", required=True)
    intake_run.add_argument("--version", default="")
    intake_run.add_argument("--attach", action="store_true", help="Attach normalized evidence immediately; omit for operator review")
    intake_run.add_argument("--actor", default="operator")
    intake_run.add_argument("--db-path", default=None)
    intake_attach = intake_sub.add_parser("attach", help="Attach a reviewed quarantined intake result to its case")
    intake_attach.add_argument("job_id")
    intake_attach.add_argument("--actor", default="operator")
    intake_attach.add_argument("--db-path", default=None)

    jobs = research_sub.add_parser("jobs", help="Inspect durable research jobs")
    jobs_sub = jobs.add_subparsers(dest="research_jobs_cmd", required=True)
    jobs_list = jobs_sub.add_parser("list")
    jobs_list.add_argument("--case", dest="case_id", default=None)
    jobs_list.add_argument("--status", choices=["queued", "running", "awaiting_review", "awaiting_approval", "succeeded", "failed", "canceled", "expired"], default=None)
    jobs_list.add_argument("--limit", type=int, default=100)
    jobs_list.add_argument("--db-path", default=None)
    jobs_show = jobs_sub.add_parser("show")
    jobs_show.add_argument("job_id")
    jobs_show.add_argument("--db-path", default=None)
    jobs_retry = jobs_sub.add_parser("retry")
    jobs_retry.add_argument("job_id")
    jobs_retry.add_argument("--actor", default="operator")
    jobs_retry.add_argument("--db-path", default=None)
    jobs_cancel = jobs_sub.add_parser("cancel")
    jobs_cancel.add_argument("job_id")
    jobs_cancel.add_argument("--actor", default="operator")
    jobs_cancel.add_argument("--db-path", default=None)
    jobs_recover = jobs_sub.add_parser("recover")
    jobs_recover.add_argument("--max-age-seconds", type=int, default=3600)
    jobs_recover.add_argument("--actor", default="research-worker")
    jobs_recover.add_argument("--db-path", default=None)

    research_pipeline = research_sub.add_parser("pipeline", help="Run and review the resumable Local Codex research pipeline")
    research_pipeline_sub = research_pipeline.add_subparsers(dest="research_pipeline_cmd", required=True)
    pipeline_start = research_pipeline_sub.add_parser("start", help="Collect static evidence and queue minimized Local Codex analysis")
    pipeline_start.add_argument("case_id")
    pipeline_start.add_argument("--reference-ecosystem", default="")
    pipeline_start.add_argument("--reference-package", default="")
    pipeline_start.add_argument("--reference-version", default="")
    pipeline_start.add_argument("--actor", default="operator")
    pipeline_start.add_argument("--db-path", default=None)
    pipeline_resume = research_pipeline_sub.add_parser("resume", help="Resume or retry a durable investigation pipeline")
    pipeline_resume.add_argument("pipeline_id")
    pipeline_resume.add_argument("--reference-ecosystem", default="")
    pipeline_resume.add_argument("--reference-package", default="")
    pipeline_resume.add_argument("--reference-version", default="")
    pipeline_resume.add_argument("--actor", default="operator")
    pipeline_resume.add_argument("--db-path", default=None)
    pipeline_show = research_pipeline_sub.add_parser("show", help="Show pipeline progress and review proposals")
    pipeline_show.add_argument("pipeline_id")
    pipeline_show.add_argument("--db-path", default=None)
    pipeline_list = research_pipeline_sub.add_parser("list", help="List investigation pipelines")
    pipeline_list.add_argument("--case", dest="case_id", default="")
    pipeline_list.add_argument("--limit", type=int, default=50)
    pipeline_list.add_argument("--db-path", default=None)
    pipeline_review = research_pipeline_sub.add_parser("review", help="Accept or reject one structured pipeline proposal")
    pipeline_review.add_argument("pipeline_id")
    pipeline_review.add_argument("item_id")
    pipeline_review.add_argument("--decision", required=True, choices=["accepted", "rejected"])
    pipeline_review.add_argument("--edited-content", default="")
    pipeline_review.add_argument("--review-note", default="")
    pipeline_review.add_argument("--actor", default="analyst")
    pipeline_review.add_argument("--db-path", default=None)
    pipeline_auto = research_pipeline_sub.add_parser("auto-review", help="Automatically accept all safe/ai-generated proposals for a pipeline")
    pipeline_auto.add_argument("pipeline_id")
    pipeline_auto.add_argument("--actor", default="analyst")
    pipeline_auto.add_argument("--db-path", default=None)

    workflow = research_sub.add_parser("workflow", help="Evidence, verdict, disclosure, publication, and sandbox gates")
    workflow_sub = workflow.add_subparsers(dest="research_workflow_cmd", required=True)
    matrix = workflow_sub.add_parser("evidence-matrix")
    matrix.add_argument("case_id")
    matrix.add_argument("--no-persist", action="store_true")
    matrix.add_argument("--actor", default="analyst")
    matrix.add_argument("--db-path", default=None)
    brief = workflow_sub.add_parser("analyst-brief")
    brief.add_argument("case_id")
    brief.add_argument("--actor", default="analyst")
    brief.add_argument("--db-path", default=None)
    verdict = workflow_sub.add_parser("verdict")
    verdict.add_argument("case_id")
    verdict.add_argument("--verdict", required=True, choices=["credible", "likely", "inconclusive", "not_substantiated", "benign", "retracted"])
    verdict.add_argument("--confidence", required=True, type=int)
    verdict.add_argument("--rationale", required=True)
    verdict.add_argument("--evidence-id", action="append", required=True)
    verdict.add_argument("--actor", default="analyst")
    verdict.add_argument("--db-path", default=None)
    pubcheck = workflow_sub.add_parser("publication-check")
    pubcheck.add_argument("case_id")
    pubcheck.add_argument("--actor", default="analyst")
    pubcheck.add_argument("--db-path", default=None)
    pubapprove = workflow_sub.add_parser("publication-approve")
    pubapprove.add_argument("case_id")
    pubapprove.add_argument("--review-id", default="")
    pubapprove.add_argument("--waiver", action="append", default=[])
    pubapprove.add_argument("--actor", default="publisher")
    pubapprove.add_argument("--db-path", default=None)
    disclosure = workflow_sub.add_parser("prepare-disclosure")
    disclosure.add_argument("case_id")
    disclosure.add_argument("--recipient", required=True)
    disclosure.add_argument("--subject", default="")
    disclosure.add_argument("--body", default="")
    disclosure.add_argument("--embargo-until", default=None)
    disclosure.add_argument("--actor", default="analyst")
    disclosure.add_argument("--db-path", default=None)
    disclosure_status = workflow_sub.add_parser("disclosure-status")
    disclosure_status.add_argument("disclosure_id")
    disclosure_status.add_argument("--status", required=True, choices=["draft", "approved", "sent", "acknowledged", "coordinating", "closed", "canceled"])
    disclosure_status.add_argument("--actor", default="analyst")
    disclosure_status.add_argument("--db-path", default=None)
    sandbox = workflow_sub.add_parser("request-sandbox")
    sandbox.add_argument("case_id")
    sandbox.add_argument("--artifact-sha256", required=True)
    sandbox.add_argument("--justification", required=True)
    sandbox.add_argument("--behavior", action="append", default=[])
    sandbox.add_argument("--provider", choices=["manual-result-import", "disabled", "external-isolated-runner"], default="manual-result-import")
    sandbox.add_argument("--actor", default="analyst")
    sandbox.add_argument("--db-path", default=None)
    sandbox_status = workflow_sub.add_parser("sandbox-status")
    sandbox_status.add_argument("request_id")
    sandbox_status.add_argument("--status", required=True, choices=["pending_approval", "approved", "submitted", "completed", "rejected", "failed"])
    sandbox_status.add_argument("--result-json", default="")
    sandbox_status.add_argument("--actor", default="analyst")
    sandbox_status.add_argument("--db-path", default=None)
    sandbox_approve = workflow_sub.add_parser("approve-sandbox")
    sandbox_approve.add_argument("request_id")
    sandbox_approve.add_argument("--public-submission-acknowledged", action="store_true")
    sandbox_approve.add_argument("--actor", default="reviewer")
    sandbox_approve.add_argument("--db-path", default=None)

    blog = sub.add_parser("blog", help="Draft, publish, and verify SecOpsAI security blog posts")
    blog_sub = blog.add_subparsers(dest="blog_cmd", required=True)

    blog_finding = blog_sub.add_parser("draft-finding", help="Create a moderated blog draft from one SOC finding")
    blog_finding.add_argument("finding_id")
    blog_finding.add_argument("--db-path", default=None, help="Override SQLite findings DB path")

    blog_advisory = blog_sub.add_parser("draft-advisory", help="Create a moderated blog draft from an advisory")
    blog_advisory.add_argument("--campaign", required=True, help="Campaign id or advisory id")
    blog_campaign = blog_sub.add_parser("draft-campaign", help="Create a review-only blog draft from a campaign research result")
    blog_campaign.add_argument("--campaign", required=True, help="Campaign id, advisory id, or campaign research JSON path")

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
    news_review_list.add_argument(
        "--status",
        default=None,
        choices=["needs_review", "approved", "reviewed", "rejected", "deployed", "published"],
        help="Filter by review status",
    )
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
    news_review_edit = news_review_sub.add_parser("edit", help="Edit draft title, summary, severity, tags, references, and body")
    news_review_edit.add_argument("draft", help="Draft path, slug, or unique slug fragment")
    news_review_edit.add_argument("--title", default=None, help="Replacement title")
    news_review_edit.add_argument("--summary", default=None, help="Replacement summary")
    news_review_edit.add_argument("--severity", default=None, choices=["critical", "high", "medium", "low", "info"], help="Replacement severity")
    news_review_edit.add_argument("--categories", default=None, help="Comma- or newline-separated category/tag list")
    news_review_edit.add_argument("--references", default=None, help="Comma- or newline-separated http(s) reference URLs")
    news_review_edit.add_argument("--body", default=None, help="Replacement body markdown")
    news_review_edit.add_argument("--body-file", default=None, help="Path to replacement body markdown")
    news_review_edit.add_argument("--note", default=None, help="Optional edit note")

    blog_news_publish = blog_sub.add_parser("news-publish-approved", help="Publish only external-news drafts marked approved/reviewed")
    blog_news_publish.add_argument("--rebuild", action="store_true", help="Rebuild index, RSS, and JSON feeds after publishing")
    blog_sub.add_parser("news-mark-deployed", help="Mark approved/reviewed external-news drafts as deployed after a successful blog deploy")

    blog_daily = blog_sub.add_parser("draft-daily", help="Automation-ready draft generation without autopublishing")
    blog_daily.add_argument("--limit", type=int, default=5, help="Maximum advisory drafts to create")

    blog_publish = blog_sub.add_parser("publish", help="Publish a reviewed draft and rebuild feeds")
    blog_publish.add_argument("draft_or_slug", help="Path to draft JSON or draft slug")
    blog_publish.add_argument("--publish", action="store_true", help="Required confirmation to write public files")

    blog_attach_media = blog_sub.add_parser("attach-media", help="Copy an approved local image/screenshot into a blog draft")
    blog_attach_media.add_argument("draft", help="Draft path, slug, or unique slug fragment")
    blog_attach_media.add_argument("--file", required=True, help="Local image/screenshot file to copy into blog assets")
    blog_attach_media.add_argument("--alt", required=True, help="Accessible alt text for the image")
    blog_attach_media.add_argument("--caption", default=None, help="Optional public caption")
    blog_attach_media.add_argument("--kind", default="screenshot", help="Media kind, e.g. screenshot, terminal, alert, photo")
    blog_attach_media.add_argument("--source-name", default="SecOpsAI", help="Source label for attribution")
    blog_attach_media.add_argument("--source-url", default=None, help="Optional http(s) source URL")
    blog_attach_source_media = blog_sub.add_parser("attach-source-media", help="Fetch and attach an approved source image candidate to a blog draft")
    blog_attach_source_media.add_argument("draft", help="Draft path, slug, or unique slug fragment")
    blog_attach_source_media.add_argument("--url", default=None, help="Approved http(s) source image URL to fetch")
    blog_attach_source_media.add_argument("--media-index", type=int, default=None, help="Media candidate index from the draft")
    blog_attach_source_media.add_argument("--alt", default=None, help="Accessible alt text for the image")
    blog_attach_source_media.add_argument("--caption", default=None, help="Optional public caption")
    blog_attach_source_media.add_argument("--kind", default="source-image", help="Media kind, e.g. source-image or source-screenshot")
    blog_attach_source_media.add_argument("--source-name", default=None, help="Source label for attribution")
    blog_attach_source_media.add_argument("--source-url", default=None, help="Optional source article URL")

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

    supply_chain = sub.add_parser("supply-chain", help="Monitor package releases for supply-chain compromise")
    supply_chain_sub = supply_chain.add_subparsers(dest="supply_chain_cmd", required=True)

    supply_chain_ecosystems = supply_chain_sub.add_parser("ecosystems", help="List supported supply-chain ecosystems and capabilities")
    supply_chain_ecosystems.add_argument("--ecosystem", choices=SUPPORTED_ECOSYSTEM_NAMES, help="Show one ecosystem")

    supply_chain_scan = supply_chain_sub.add_parser("scan", help="Scan a specific package release")
    supply_chain_scan.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
    supply_chain_scan.add_argument("--package", required=True, help="Package name")
    supply_chain_scan.add_argument("--version", required=True, help="New version to review")
    supply_chain_scan.add_argument("--previous-version", help="Override previous version instead of auto-discovery")
    supply_chain_scan.add_argument("--fixture-json", help="Analyze a local JSON object of path-to-text files instead of fetching artifacts")
    supply_chain_scan.add_argument("--artifact", help="Analyze a local artifact archive instead of fetching from a registry")
    supply_chain_scan.add_argument("--previous-artifact", help="Optional previous local artifact archive for a local diff")
    supply_chain_scan.add_argument("--metadata-only", action="store_true", help="Prefer metadata/file-list analysis where full artifact download is unsafe")
    supply_chain_scan.add_argument("--max-download-mb", type=int, default=50, help="Maximum live artifact download size in MB")
    supply_chain_scan.add_argument("--max-files", type=int, default=5000, help="Maximum unpacked file count per artifact")
    supply_chain_scan.add_argument("--timeout", type=int, default=30, help="Registry/download timeout in seconds")
    supply_chain_scan.add_argument("--model", help="Override analysis model passed to Cursor Agent CLI")
    supply_chain_scan.add_argument("--no-report", action="store_true", help="Do not persist the diff report to disk")
    supply_chain_scan.add_argument("--slack", action="store_true", help="Send Slack alert when verdict is malicious")

    supply_chain_ai_guard = supply_chain_sub.add_parser(
        "ai-dependency-guard",
        help="Scan AI-built code and agent logs for hallucinated or slopsquatted dependencies",
    )
    supply_chain_ai_guard.add_argument("--path", default=".", help="Repository or file path to scan")
    supply_chain_ai_guard.add_argument(
        "--include-agent-logs",
        action="store_true",
        help="Also scan local OpenClaw/Hermes/session agent telemetry for AI-suggested dependencies",
    )
    supply_chain_ai_guard.add_argument(
        "--agent-source",
        choices=["auto", "openclaw", "hermes", "sessions"],
        default="auto",
        help="Agent telemetry source to scan when --include-agent-logs is set",
    )
    supply_chain_ai_guard.add_argument(
        "--ecosystem",
        action="append",
        choices=AI_DEPENDENCY_GUARD_ECOSYSTEMS,
        default=[],
        help="Limit checks to one ecosystem; repeat for multiple ecosystems",
    )
    supply_chain_ai_guard.add_argument(
        "--fail-on",
        choices=["high", "critical"],
        help="Return non-zero when a candidate reaches this severity",
    )
    supply_chain_ai_guard.add_argument(
        "--persist-findings",
        action="store_true",
        help="Persist high-confidence AI Dependency Guard findings to the local SOC store",
    )
    supply_chain_ai_guard.add_argument("--report-path", help="Write full JSON report to this path")
    supply_chain_ai_guard.add_argument("--timeout", type=int, default=8, help="Registry metadata timeout seconds")

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

    supply_chain_watch = supply_chain_sub.add_parser(
        "watch-registry",
        help="Analyze recent package publishes from registry metadata without running package code",
    )
    supply_chain_watch.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
    supply_chain_watch.add_argument("--package", help="Package name to watch")
    supply_chain_watch.add_argument("--namespace", help="npm scope or Packagist namespace/vendor to watch, for example redhat-cloud-services or laravel-lang")
    supply_chain_watch.add_argument("--since", default="10m", help="Look back duration, for example 10m, 2h, or 1d")
    supply_chain_watch.add_argument("--limit", type=int, default=20, help="Maximum recent versions to analyze")
    supply_chain_watch.add_argument("--dry-run", action="store_true", help="Analyze without persisting reports/findings")
    supply_chain_watch.add_argument("--persist", action="store_true", help="Persist scan history and SOC findings")
    supply_chain_watch.add_argument("--model", help="Override analysis model passed to Cursor Agent CLI")

    supply_chain_campaign = supply_chain_sub.add_parser("research-campaign", help="Research and correlate a cross-ecosystem supply-chain campaign")
    supply_chain_campaign.add_argument("--input", help="Campaign JSON input file")
    supply_chain_campaign.add_argument("--campaign-id", help="Campaign identifier")
    supply_chain_campaign.add_argument("--title", help="Campaign title")
    supply_chain_campaign.add_argument("--summary", help="Campaign summary")
    supply_chain_campaign.add_argument("--source-url", action="append", default=[], help="Source/reference URL")
    supply_chain_campaign.add_argument("--source-name", action="append", default=[], help="Source/reference name")
    supply_chain_campaign.add_argument("--actor", action="append", default=[], help="Actor label")
    supply_chain_campaign.add_argument("--publisher", action="append", default=[], help="Publisher/maintainer/namespace")
    supply_chain_campaign.add_argument("--ioc", action="append", default=[], help="Known IOC or hunt string")
    supply_chain_campaign.add_argument("--behavior", action="append", default=[], help="Known behavioral indicator")
    supply_chain_campaign.add_argument("--package", action="append", default=[], help="Package spec: ecosystem:package:version")
    supply_chain_campaign.add_argument("--search-root", help="Root path to scan for local usage")
    supply_chain_campaign.add_argument("--dry-run", action="store_true", help="Do not persist SOC findings")
    supply_chain_campaign.add_argument("--persist", action="store_true", help="Persist SOC findings")
    supply_chain_campaign.add_argument("--no-fetch", action="store_true", help="Do not fetch live registry artifacts")
    supply_chain_campaign.add_argument("--create-blog-draft", action="store_true", help="Create a review-only campaign blog draft")

    supply_chain_discover = supply_chain_sub.add_parser("discover-campaigns", help="Discover supply-chain campaign candidates from trusted sources")
    supply_chain_discover.add_argument("--since", default="24h", help="Look back duration, for example 24h, 2h, or 7d")
    supply_chain_discover.add_argument("--source", default="all", help="Source name filter or all")
    supply_chain_discover.add_argument("--limit", type=int, default=50, help="Maximum candidates to return")
    supply_chain_discover.add_argument("--no-save", action="store_true", help="Do not update the local candidate cache")
    supply_chain_discover.add_argument("--orchestrate", action="store_true", help="Include deterministic orchestrator review output (default)")

    supply_chain_orchestrate = supply_chain_sub.add_parser("orchestrate-candidate", help="Classify, clean, and route one discovery candidate JSON")
    supply_chain_orchestrate.add_argument("--input", required=True, help="Candidate JSON input file")

    supply_chain_intake = supply_chain_sub.add_parser("campaign-intake", help="Build campaign JSON from a URL or text file")
    supply_chain_intake.add_argument("--url", help="Trusted source URL to fetch and extract")
    supply_chain_intake.add_argument("--text", help="Local text file containing source/report text")
    supply_chain_intake.add_argument("--source-name", help="Source/report name")
    supply_chain_intake.add_argument("--title", help="Override extracted campaign title")

    supply_chain_watchlist = supply_chain_sub.add_parser("campaign-watchlist", help="Manage autonomous campaign discovery watchlist")
    supply_chain_watchlist_sub = supply_chain_watchlist.add_subparsers(dest="campaign_watchlist_cmd", required=True)
    supply_chain_watchlist_add = supply_chain_watchlist_sub.add_parser("add", help="Add package, publisher, IOC, or source URL to the watchlist")
    supply_chain_watchlist_add.add_argument("--package", help="Package spec or name to watch, for example npm:axios")
    supply_chain_watchlist_add.add_argument("--publisher", help="Publisher, maintainer, namespace, or actor to watch")
    supply_chain_watchlist_add.add_argument("--ioc", help="IOC/C2/domain/IP/string to watch")
    supply_chain_watchlist_add.add_argument("--source-url", help="Trusted source URL to watch")
    supply_chain_watchlist_sub.add_parser("list", help="List campaign discovery watchlist")

    supply_chain_autopilot = supply_chain_sub.add_parser("campaign-autopilot", help="Discover, research, and optionally persist campaign candidates")
    supply_chain_autopilot.add_argument("--since", default="24h", help="Look back duration, for example 24h, 2h, or 7d")
    supply_chain_autopilot.add_argument("--limit", type=int, default=10, help="Maximum candidates to research")
    supply_chain_autopilot.add_argument("--min-score", type=int, default=35, help="Minimum candidate score to research")
    supply_chain_autopilot.add_argument("--search-root", help="Root path to scan for local usage")
    supply_chain_autopilot.add_argument("--dry-run", action="store_true", help="Do not persist SOC findings or drafts")
    supply_chain_autopilot.add_argument("--persist", action="store_true", help="Persist SOC findings")
    supply_chain_autopilot.add_argument("--create-drafts", action="store_true", help="Create review-only blog drafts when persisting")
    supply_chain_autopilot.add_argument("--orchestrate", action="store_true", help="Use deterministic orchestrator routing (default)")

    supply_chain_candidates = supply_chain_sub.add_parser("campaign-candidates", help="Inspect or promote cached discovery candidates")
    supply_chain_candidates_sub = supply_chain_candidates.add_subparsers(dest="campaign_candidates_cmd", required=True)
    supply_chain_candidates_sub.add_parser("list", help="List cached campaign candidates")
    supply_chain_candidates_promote = supply_chain_candidates_sub.add_parser("promote", help="Return campaign JSON for a candidate")
    supply_chain_candidates_promote.add_argument("candidate_id")

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
    supply_chain_explain.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
    supply_chain_explain.add_argument("--package", required=True, help="Package name")

    supply_chain_advisory = supply_chain_sub.add_parser("advisory", help="Manage emergency package advisories")
    supply_chain_advisory_sub = supply_chain_advisory.add_subparsers(dest="supply_chain_advisory_cmd", required=True)
    supply_chain_advisory_list = supply_chain_advisory_sub.add_parser("list", help="List emergency advisories")
    supply_chain_advisory_list.add_argument("--status", default="active", help="Filter by status, or 'all'")
    supply_chain_advisory_ingest = supply_chain_advisory_sub.add_parser("ingest", help="Ingest a JSON advisory file or URL")
    supply_chain_advisory_ingest.add_argument("source", help="Path or HTTPS URL to an advisory JSON object/list")
    supply_chain_advisory_check = supply_chain_advisory_sub.add_parser("check", help="Check one package version against advisories")
    supply_chain_advisory_check.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
    supply_chain_advisory_check.add_argument("--package", required=True, help="Package name")
    supply_chain_advisory_check.add_argument("--version", required=True, help="Package version")

    supply_chain_allowlist = supply_chain_sub.add_parser("allowlist", help="Manage supply-chain allowlist entries")
    supply_chain_allowlist_sub = supply_chain_allowlist.add_subparsers(dest="supply_chain_allowlist_cmd", required=True)
    supply_chain_allowlist_add = supply_chain_allowlist_sub.add_parser("add", help="Add a package to the allowlist")
    supply_chain_allowlist_add.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
    supply_chain_allowlist_add.add_argument("--package", required=True, help="Package name or wildcard")
    supply_chain_allowlist_remove = supply_chain_allowlist_sub.add_parser("remove", help="Remove a package from the allowlist")
    supply_chain_allowlist_remove.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
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
    threshold_scope.add_argument("--ecosystem", choices=SUPPORTED_ECOSYSTEM_NAMES, help="Set the threshold for one ecosystem")
    threshold_scope.add_argument("--package", help="Set the threshold for one package target")
    supply_chain_tune_threshold.add_argument("--package-ecosystem", choices=SUPPORTED_ECOSYSTEM_NAMES, help="Required with --package")
    supply_chain_tune_threshold.add_argument("--value", type=int, required=True, help="Threshold value")

    supply_chain_explain_verdict = supply_chain_sub.add_parser(
        "explain-verdict",
        help="Explain which rules fired for a supply-chain scan report",
    )
    supply_chain_explain_verdict.add_argument("--ecosystem", required=True, choices=SUPPORTED_ECOSYSTEM_NAMES)
    supply_chain_explain_verdict.add_argument("--package", required=True, help="Package name")
    supply_chain_explain_verdict.add_argument("--version", help="Release version to resolve from stored results")
    supply_chain_explain_verdict.add_argument("--report", help="Path to a stored report file")

    triage = sub.add_parser("triage", help="Native finding triage workflows")
    triage_sub = triage.add_subparsers(dest="triage_cmd", required=True)

    triage_list = triage_sub.add_parser("list", help="List findings for triage")
    triage_list.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    triage_list.add_argument("--status", choices=["open", "in_review", "triaged", "closed"])
    triage_list.add_argument("--source", default=None, help="Filter findings by source, for example secopsai_edge")
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
    session_resolve.add_argument("--edge-root", default=None, help="SecOpsAI Edge root used by approved Edge actions")
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


def _run_research_automation_command(args: argparse.Namespace) -> int:
    try:
        if args.research_cmd == "ecosystems":
            payload = research_capability_registry()
        elif args.research_cmd == "watchlist":
            if args.research_watchlist_cmd == "list":
                payload = {"watchlists": list_research_watchlists(ecosystem=args.ecosystem, db_path=getattr(args, "db_path", None))}
            else:
                payload = create_research_watchlist(
                    ecosystem=args.ecosystem,
                    watch_type=args.watch_type,
                    identifier=args.identifier,
                    brand=args.brand,
                    known_publishers=args.known_publisher,
                    known_repositories=args.known_repository,
                    threshold=args.threshold,
                    priority=args.priority,
                    owner=args.owner,
                    reason=args.reason,
                    db_path=args.db_path,
                )
        elif args.research_cmd == "monitor":
            if args.research_monitor_cmd == "list":
                payload = {"monitors": list_research_monitors(ecosystem=args.ecosystem, db_path=args.db_path)}
            elif args.research_monitor_cmd == "create":
                payload = create_research_monitor(ecosystem=args.ecosystem, watchlist_id=args.watchlist_id, name=args.name, interval_seconds=args.interval_seconds, priority=args.priority, db_path=args.db_path)
            elif args.research_monitor_cmd == "run-due":
                payload = run_due_research_monitors(limit=args.limit, db_path=args.db_path)
            elif args.research_monitor_cmd == "recover-stale":
                payload = recover_stale_monitor_runs(max_age_seconds=args.max_age_seconds, db_path=args.db_path)
            else:
                payload = run_research_monitor(args.monitor_id, db_path=args.db_path)
        elif args.research_cmd == "candidate":
            if args.research_candidate_cmd == "list":
                payload = {"candidates": list_research_candidates(status=args.status, ecosystem=args.ecosystem, limit=args.limit, db_path=args.db_path)}
            else:
                payload = get_research_candidate(args.candidate_id, db_path=args.db_path)
        elif args.research_cmd == "collect":
            if args.research_collect_cmd == "status":
                payload = {"collectors": registry_collector_status(ecosystem=args.ecosystem, db_path=args.db_path)}
            elif args.research_collect_cmd == "run":
                payload = run_registry_collector(ecosystem=args.ecosystem, since=args.since, max_pages=args.max_pages, fetch_leaves=args.fetch_leaves, db_path=args.db_path)
            elif args.research_collect_cmd == "retry-failures":
                payload = retry_registry_dead_letters(limit=args.limit, db_path=args.db_path)
            elif args.research_collect_cmd == "coverage":
                payload = {"windows": registry_coverage_report(days=args.days, db_path=args.db_path)}
            elif args.research_collect_cmd == "events":
                payload = {"events": registry_list_feed_events(collector_id=args.collector_id, package=args.package, limit=args.limit, db_path=args.db_path)}
            elif args.research_collect_cmd == "pause":
                payload = set_registry_collector_enabled(ecosystem=args.ecosystem, enabled=False, db_path=args.db_path)
            elif args.research_collect_cmd == "resume":
                payload = set_registry_collector_enabled(ecosystem=args.ecosystem, enabled=True, db_path=args.db_path)
            else:
                payload = recover_interrupted_collector_runs(max_age_seconds=args.max_age_seconds, db_path=args.db_path)
        elif args.research_cmd == "score":
            payload = score_pending_feed_events(ecosystem=args.ecosystem, limit=args.limit, db_path=args.db_path)
        elif args.research_cmd == "worker":
            if args.research_worker_cmd == "due":
                payload = {"schedules": research_collector_schedules(), "collectors": research_due_collectors(db_path=args.db_path)}
            elif args.once:
                payload = run_worker_cycle(db_path=args.db_path)
            else:
                payload = run_worker_loop(db_path=args.db_path, interval_seconds=args.interval, max_cycles=args.max_cycles, on_cycle=lambda summary: print(json.dumps({"cycle": summary}, sort_keys=True), flush=True))
        elif args.research_cmd == "compare":
            with open(args.left, "r", encoding="utf-8") as left_handle:
                left_payload = json.load(left_handle)
            with open(args.right, "r", encoding="utf-8") as right_handle:
                right_payload = json.load(right_handle)
            if not isinstance(left_payload, dict) or not isinstance(right_payload, dict):
                raise ValueError("comparison inputs must be JSON objects")
            payload = compare_intakes(left_payload, right_payload, db_path=args.db_path)
        elif args.research_cmd == "compare-packages":
            payload = compare_packages(left_ecosystem=args.left_ecosystem, left_package=args.left_package, left_version=args.left_version, right_ecosystem=args.right_ecosystem, right_package=args.right_package, right_version=args.right_version, db_path=args.db_path)
        elif args.research_cmd == "campaign":
            if args.research_campaign_cmd == "correlate":
                payload = {"campaigns": correlate_candidates(db_path=args.db_path)}
            elif args.research_campaign_cmd == "list":
                payload = {"campaigns": list_campaigns(db_path=args.db_path, limit=args.limit)}
            else:
                raise ValueError("unsupported campaign command")
        elif args.research_cmd == "sandbox":
            if args.research_sandbox_cmd == "status":
                payload = sandbox_provider_status()
            elif args.research_sandbox_cmd == "submit":
                payload = submit_sandbox_request(args.request_id, db_path=args.db_path, public_acknowledged=args.public_submission_acknowledged)
            else:
                payload = poll_sandbox_request(args.request_id, db_path=args.db_path)
        elif args.research_cmd == "disclosure":
            if args.research_disclosure_cmd != "send":
                raise ValueError("unsupported disclosure command")
            payload = send_approved_disclosure(args.disclosure_id, channel=args.channel, db_path=args.db_path)
        elif args.research_cmd == "alert":
            if args.research_alert_cmd == "list":
                payload = {"alerts": list_research_alerts(status=args.status, limit=args.limit, db_path=args.db_path)}
            else:
                payload = send_research_alert(args.alert_id, channel=args.channel, db_path=args.db_path)
        elif args.research_cmd == "intake":
            if args.research_intake_cmd == "preview":
                payload = preview_research_package(ecosystem=args.ecosystem, package=args.package, version=args.version)
            elif args.research_intake_cmd == "run":
                payload = run_intake_job(case_id=args.case_id, ecosystem=args.ecosystem, package=args.package, version=args.version, attach=args.attach, requested_by=args.actor, db_path=args.db_path)
            else:
                payload = attach_intake_job(args.job_id, actor=args.actor, db_path=args.db_path)
        elif args.research_cmd == "jobs":
            if args.research_jobs_cmd == "list":
                payload = {"jobs": list_research_jobs(case_id=args.case_id, status=args.status, limit=args.limit, db_path=args.db_path)}
            elif args.research_jobs_cmd == "show":
                payload = get_research_job(args.job_id, db_path=args.db_path)
            elif args.research_jobs_cmd == "retry":
                payload = retry_research_job(args.job_id, actor=args.actor, db_path=args.db_path)
            elif args.research_jobs_cmd == "cancel":
                payload = cancel_research_job(args.job_id, actor=args.actor, db_path=args.db_path)
            else:
                payload = recover_stale_jobs(max_age_seconds=args.max_age_seconds, actor=args.actor, db_path=args.db_path)
        elif args.research_cmd == "pipeline":
            if args.research_pipeline_cmd == "start":
                payload = start_investigation_pipeline(
                    args.case_id,
                    reference_ecosystem=args.reference_ecosystem,
                    reference_package=args.reference_package,
                    reference_version=args.reference_version,
                    actor=args.actor,
                    db_path=args.db_path,
                )
            elif args.research_pipeline_cmd == "resume":
                payload = resume_investigation_pipeline(
                    args.pipeline_id,
                    reference_ecosystem=args.reference_ecosystem,
                    reference_package=args.reference_package,
                    reference_version=args.reference_version,
                    actor=args.actor,
                    db_path=args.db_path,
                )
            elif args.research_pipeline_cmd == "show":
                payload = get_research_pipeline(args.pipeline_id, db_path=args.db_path)
            elif args.research_pipeline_cmd == "list":
                payload = {"pipelines": list_research_pipelines(case_id=args.case_id, limit=args.limit, db_path=args.db_path)}
            elif args.research_pipeline_cmd == "auto-review":
                payload = auto_review_pipeline(
                    args.pipeline_id,
                    actor=args.actor,
                    db_path=args.db_path,
                )
            else:
                payload = review_pipeline_item(
                    args.pipeline_id,
                    args.item_id,
                    decision=args.decision,
                    edited_content=args.edited_content,
                    review_note=args.review_note,
                    actor=args.actor,
                    db_path=args.db_path,
                )
        elif args.research_cmd == "workflow":
            command = args.research_workflow_cmd
            if command == "evidence-matrix":
                payload = build_evidence_matrix(args.case_id, persist=not args.no_persist, actor=args.actor, db_path=args.db_path)
            elif command == "analyst-brief":
                payload = generate_analyst_brief(args.case_id, actor=args.actor, db_path=args.db_path)
            elif command == "verdict":
                payload = record_verdict(args.case_id, verdict=args.verdict, confidence=args.confidence, rationale=args.rationale, evidence_ids=args.evidence_id, actor=args.actor, db_path=args.db_path)
            elif command == "publication-check":
                payload = publication_safety_check(args.case_id, actor=args.actor, db_path=args.db_path)
            elif command == "publication-approve":
                payload = approve_publication_review(args.case_id, review_id=args.review_id, waivers=args.waiver, actor=args.actor, db_path=args.db_path)
            elif command == "prepare-disclosure":
                payload = prepare_disclosure(args.case_id, recipient=args.recipient, subject=args.subject, body=args.body, embargo_until=args.embargo_until, actor=args.actor, db_path=args.db_path)
            elif command == "disclosure-status":
                payload = set_disclosure_status(args.disclosure_id, args.status, actor=args.actor, db_path=args.db_path)
            elif command == "request-sandbox":
                payload = request_sandbox(args.case_id, artifact_sha256=args.artifact_sha256, justification=args.justification, behaviors=args.behavior, provider=args.provider, actor=args.actor, db_path=args.db_path)
            elif command == "sandbox-status":
                result = None
                if args.result_json:
                    result = json.loads(args.result_json)
                    if not isinstance(result, dict):
                        raise ValueError("sandbox result must be a JSON object")
                payload = set_sandbox_status(args.request_id, args.status, actor=args.actor, result=result, db_path=args.db_path)
            elif command == "approve-sandbox":
                payload = approve_sandbox_submission(args.request_id, actor=args.actor, public_submission_acknowledged=args.public_submission_acknowledged, db_path=args.db_path)
            else:  # pragma: no cover
                raise ValueError(f"unsupported research workflow command: {command}")
        else:  # pragma: no cover
            raise ValueError("unsupported research automation command")
    except Exception as exc:
        if getattr(args, "json", False):
            print(to_json({"ok": False, "error": str(exc)}))
        else:
            print(f"error: {exc}")
        return 1
    if getattr(args, "json", False):
        print(to_json(payload))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _run_research_case_command(args: argparse.Namespace) -> int:
    command = args.research_case_cmd
    try:
        if command == "create":
            payload: Dict[str, Any] = create_research_case(
                title=args.title,
                summary=args.summary,
                case_type=args.case_type,
                severity=args.severity,
                confidence=args.confidence,
                owner=args.owner,
                db_path=args.db_path,
            )
        elif command == "start-package":
            payload = start_research_package_case(
                package=args.package,
                ecosystem=args.ecosystem,
                version=args.version,
                title=args.title,
                summary=args.summary,
                case_type=args.case_type,
                severity=args.severity,
                confidence=args.confidence,
                owner=args.owner,
                publisher=args.publisher,
                source_url=args.source_url,
                artifact_path=args.artifact,
                artifact_title=args.artifact_title,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "from-watchlist":
            payload = promote_watchlist_packages(
                ecosystem=args.ecosystem,
                packages=args.package,
                select_all=args.select_all,
                create=args.create,
                title_prefix=args.title_prefix,
                severity=args.severity,
                owner=args.owner,
                source_url=args.source_url,
                actor=args.actor,
                db_path=args.db_path,
                watchlist_path=args.watchlist_path,
            )
        elif command == "list":
            payload = {
                "cases": list_research_cases(
                    db_path=args.db_path,
                    status=args.status,
                    case_type=args.case_type,
                    limit=args.limit,
                )
            }
        elif command == "show":
            payload = get_research_case(args.case_id, db_path=args.db_path)
        elif command == "update":
            payload = update_research_case(
                args.case_id,
                db_path=args.db_path,
                actor=args.actor,
                title=args.title,
                summary=args.summary,
                case_type=args.case_type,
                severity=args.severity,
                confidence=args.confidence,
                status=args.status,
                owner=args.owner,
                disclosure_status=args.disclosure_status,
                embargo_until=args.embargo_until,
            )
        elif command == "add-subject":
            payload = add_research_subject(
                args.case_id,
                subject_type=args.subject_type,
                name=args.name,
                ecosystem=args.ecosystem,
                version=args.version,
                publisher=args.publisher,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "add-evidence":
            payload = add_research_evidence(
                args.case_id,
                evidence_type=args.evidence_type,
                title=args.title,
                locator=args.locator,
                sha256=args.sha256,
                provenance=args.provenance,
                notes=args.notes,
                collected_at=args.collected_at,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "add-artifact":
            payload = add_research_artifact(
                args.case_id,
                artifact_path=args.artifact,
                title=args.title,
                locator=args.locator,
                provenance=args.provenance,
                notes=args.notes,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "add-ioc":
            payload = add_research_ioc(
                args.case_id,
                ioc_type=args.ioc_type,
                value=args.value,
                confidence=args.confidence,
                source_evidence_id=args.source_evidence_id,
                first_seen=args.first_seen,
                last_seen=args.last_seen,
                tags=args.tag,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "add-rule":
            content = load_research_rule_file(args.file) if args.file else args.content
            payload = add_research_rule(
                args.case_id,
                rule_type=args.rule_type,
                name=args.name,
                content=content,
                purpose=args.purpose,
                source_evidence_id=args.source_evidence_id,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "link-finding":
            payload = link_research_finding(
                args.case_id,
                args.finding_id,
                relationship=args.relationship,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "note":
            payload = add_case_note(
                args.case_id,
                args.note,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "retract":
            payload = retract_research_item(
                args.case_id,
                item_type=args.item_type,
                item_id=args.item_id,
                reason=args.reason,
                actor=args.actor,
                db_path=args.db_path,
            )
        elif command == "export":
            payload = export_research_case(
                args.case_id,
                output_dir=args.output_dir,
                db_path=args.db_path,
            )
        elif command == "draft-blog":
            payload = draft_case_blog(args.case_id, db_path=args.db_path)
        else:  # pragma: no cover - argparse enforces the command set
            raise ValueError(f"unsupported research case command: {command}")
    except Exception as exc:
        if args.json:
            print(to_json({"error": str(exc)}))
        else:
            print(f"error: {exc}")
        return 1

    if args.json:
        print(to_json(payload))
    elif command == "list":
        for item in payload["cases"]:
            print(
                f"{item['case_id']} | {item['severity'].upper():8s} | "
                f"status={item['status']} | confidence={item['confidence']:3d} | {item['title']}"
            )
        print(f"total_cases={len(payload['cases'])}")
    elif command == "export":
        print(f"CASE_ID: {payload['case_id']}")
        print(f"JSON_REPORT: {payload['json_report']}")
        print(f"MARKDOWN_REPORT: {payload['markdown_report']}")
        print(f"MANIFEST: {payload['manifest']}")
        print(f"PUBLICATION_READY: {str(payload['publication_readiness']['ready']).lower()}")
    elif command == "draft-blog":
        print(f"CASE_ID: {payload['case_id']}")
        print(f"DRAFT_PATH: {payload.get('draft_path')}")
        print("REVIEW_REQUIRED: true")
    elif command == "from-watchlist":
        print(f"ECOSYSTEM: {payload['ecosystem']}")
        print(f"DRY_RUN: {str(payload['dry_run']).lower()}")
        print(f"SELECTED: {len(payload['selected'])}")
        print(f"CREATED: {len(payload['created'])}")
        print(f"EXISTING: {len(payload['existing'])}")
        for item in [*payload["created"], *payload["existing"]]:
            print(f"{item['package']} -> {item['case_id']} ({item['status']})")
    else:
        readiness = payload.get("publication_readiness") or {}
        print(f"CASE_ID: {payload['case_id']}")
        print(f"STATUS: {payload['status']}")
        print(f"TITLE: {payload['title']}")
        print(f"PUBLICATION_READY: {str(bool(readiness.get('ready'))).lower()}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.cmd == "workflow":
        if args.workflow_cmd == "list":
            payload = {"workflows": list_workflows()}
            if args.json:
                print(to_json(payload))
            else:
                for workflow in payload["workflows"]:
                    print(f"{workflow['name']}: {workflow['role']} - {workflow['purpose']}")
            return 0
        if args.workflow_cmd == "show":
            payload = {"workflow": get_workflow(args.name)}
            if args.json:
                print(to_json(payload))
            else:
                print(render_workflow(payload["workflow"]))
            return 0

    if args.cmd in workflow_names():
        payload = {"workflow": get_workflow(args.cmd)}
        if args.json:
            print(to_json(payload))
        else:
            print(render_workflow(payload["workflow"]))
        return 0

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

        if args.research_cmd in {"ecosystems", "watchlist", "monitor", "candidate", "collect", "score", "worker", "compare", "compare-packages", "campaign", "sandbox", "disclosure", "alert", "intake", "jobs", "pipeline", "workflow"}:
            return _run_research_automation_command(args)

        if args.research_cmd == "case":
            return _run_research_case_command(args)

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
            elif args.blog_cmd == "draft-campaign":
                payload = draft_blog_campaign(args.campaign)
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
                elif args.news_review_cmd == "edit":
                    body_markdown = args.body
                    if args.body_file:
                        body_markdown = Path(args.body_file).read_text(encoding="utf-8")
                    payload = edit_blog_news_review(
                        args.draft,
                        title=args.title,
                        summary=args.summary,
                        severity=args.severity,
                        categories=args.categories,
                        references=args.references,
                        body_markdown=body_markdown,
                        note=args.note,
                    )
                else:
                    payload = update_blog_news_review(args.draft, status="needs_review", note=args.note)
            elif args.blog_cmd == "news-publish-approved":
                payload = publish_approved_blog_news()
                if args.rebuild:
                    payload["rebuild"] = rebuild_blog()
            elif args.blog_cmd == "news-mark-deployed":
                payload = mark_deployed_blog_news()
            elif args.blog_cmd == "draft-daily":
                payload = draft_blog_daily(limit=args.limit)
            elif args.blog_cmd == "publish":
                payload = publish_blog_post(args.draft_or_slug, confirm=args.publish)
            elif args.blog_cmd == "attach-media":
                payload = attach_blog_media(
                    args.draft,
                    file_path=args.file,
                    alt=args.alt,
                    caption=args.caption,
                    kind=args.kind,
                    source_name=args.source_name,
                    source_url=args.source_url,
                )
            elif args.blog_cmd == "attach-source-media":
                payload = attach_blog_source_media(
                    args.draft,
                    url=args.url,
                    media_index=args.media_index,
                    alt=args.alt,
                    caption=args.caption,
                    kind=args.kind,
                    source_name=args.source_name,
                    source_url=args.source_url,
                )
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
        elif args.blog_cmd in {"news-draft", "news-publish-approved", "news-mark-deployed"}:
            print(f"total={payload['total']}")
            for path in payload.get("created", payload.get("published", [])):
                print(f"- {path}")
            for url in payload.get("ready_for_deploy", []):
                print(f"ready_for_deploy={url}")
            for url in payload.get("deployed", []):
                print(f"deployed={url}")
            for blocked in payload.get("blocked", []):
                print(f"blocked={blocked.get('slug')}")
                for reason in blocked.get("reasons", []):
                    print(f"  - {reason}")
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
        elif args.blog_cmd in {"attach-media", "attach-source-media"}:
            print(f"draft_path={payload['draft_path']}")
            print(f"media={payload['media']['src']}")
            print(f"alt={payload['media']['alt']}")
            if payload.get("source_media_url"):
                print(f"source_media_url={payload['source_media_url']}")
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
        if args.blog_cmd == "news-publish-approved" and payload.get("blocked"):
            return 1
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

    if args.cmd == "edge":
        try:
            if args.edge_cmd == "import":
                payload = import_edge_bundle(load_edge_bundle(args.bundle), db_path=args.db_path)
            elif args.edge_cmd == "sync":
                payload = sync_edge_from_api(
                    edge_api_url=args.edge_api_url,
                    access_token=args.access_token,
                    core_api_url=args.core_api_url,
                    core_ingest_token=args.core_ingest_token,
                    remote_only=args.remote_only,
                    db_path=args.db_path,
                )
            elif args.edge_cmd == "status":
                payload = {"sync_state": list_edge_sync_state(db_path=args.db_path, limit=args.limit)}
            else:
                raise ValueError(f"unsupported edge command: {args.edge_cmd}")
        except Exception as exc:
            if args.json:
                print(to_json({"error": str(exc), "command": args.edge_cmd}))
            else:
                print(f"error: {exc}")
            return 1

        if args.json:
            print(to_json(payload))
        elif args.edge_cmd == "status":
            records = payload["sync_state"]
            if not records:
                print("No Edge-to-Core sync records found.")
            for record in records:
                print(
                    "SYNC: {source} | last={last} | bundle={bundle} | schema={schema}".format(
                        source=record["source_instance"],
                        last=record["last_synced_at"],
                        bundle=record["bundle_exported_at"] or "unknown",
                        schema=record["schema_version"],
                    )
                )
        else:
            print(
                "EDGE_SYNC: schema={schema} nodes={nodes} edges={edges} findings={findings}".format(
                    schema=payload["schema_version"],
                    nodes=payload["nodes"],
                    edges=payload["edges"],
                    findings=payload["findings"],
                )
            )
            print(f"DB: {payload['db_path']}")
        return 0

    if args.cmd == "intelligence":
        try:
            if args.intelligence_cmd == "actions":
                payload = list_intelligence_actions()
            elif args.intelligence_cmd == "status":
                payload = {
                    "schema_version": "secopsai.intelligence.status.v1",
                    "generated_at": soc_store.utc_now(),
                    "actions": list_intelligence_actions(),
                    "jobs": {"jobs": list_intelligence_jobs(limit=args.limit, db_path=args.db_path)},
                    "bridge": codex_bridge_doctor(),
                    "service": codex_bridge_service_action("status"),
                }
            elif args.intelligence_cmd == "query":
                inputs = _json_object(args.inputs_json, label="intelligence inputs")
                if args.target_id:
                    inputs.setdefault("target_id", args.target_id)
                payload = run_intelligence_read_action(args.action, inputs, db_path=args.db_path)
            elif args.intelligence_cmd == "enqueue":
                inputs = _json_object(args.inputs_json, label="intelligence inputs")
                payload = enqueue_intelligence_job(
                    action=args.action,
                    target_id=args.target_id,
                    inputs=inputs,
                    requested_by=args.requested_by,
                    idempotency_key=args.idempotency_key,
                    db_path=args.db_path,
                )
            elif args.intelligence_cmd == "jobs":
                if args.intelligence_jobs_cmd == "list":
                    payload = {"jobs": list_intelligence_jobs(status=args.status, limit=args.limit, db_path=args.db_path)}
                elif args.intelligence_jobs_cmd == "show":
                    payload = get_intelligence_job(args.job_id, db_path=args.db_path)
                elif args.intelligence_jobs_cmd == "cancel":
                    payload = cancel_intelligence_job(args.job_id, actor=args.actor, db_path=args.db_path)
                elif args.intelligence_jobs_cmd == "requeue":
                    payload = requeue_intelligence_job(args.job_id, actor=args.actor, db_path=args.db_path)
                else:
                    raise ValueError(f"unsupported intelligence jobs command: {args.intelligence_jobs_cmd}")
            elif args.intelligence_cmd == "bridge":
                if args.intelligence_bridge_cmd == "doctor":
                    payload = codex_bridge_doctor()
                elif args.intelligence_bridge_cmd == "models":
                    payload = list_codex_bridge_models()
                elif args.intelligence_bridge_cmd == "run":
                    selected_model = str(getattr(args, "model", "") or "").strip() or None
                    if args.once:
                        payload = run_codex_bridge_once(db_path=args.db_path, model=selected_model)
                    else:
                        payload = run_codex_bridge_loop(
                            db_path=args.db_path,
                            max_iterations=args.max_iterations,
                            model=selected_model,
                        )
                elif args.intelligence_bridge_cmd == "service":
                    if args.action == "install":
                        payload = install_codex_bridge_service(db_path=args.db_path, start=not args.no_start)
                    else:
                        payload = codex_bridge_service_action(args.action, tail=args.tail)
                else:
                    raise ValueError(f"unsupported intelligence bridge command: {args.intelligence_bridge_cmd}")
            else:
                raise ValueError(f"unsupported intelligence command: {args.intelligence_cmd}")
        except Exception as exc:
            if args.json:
                print(to_json({"error": str(exc), "command": args.intelligence_cmd}))
            else:
                print(f"error: {exc}")
            return 1
        if args.json:
            print(to_json(payload))
        else:
            print(to_json(payload))
        return 0

    if args.cmd == "graph":
        try:
            if args.graph_cmd == "assets":
                payload = {"assets": list_graph_assets(db_path=args.db_path, limit=args.limit)}
            elif args.graph_cmd == "show":
                node = show_graph_node(args.identifier, db_path=args.db_path)
                if node is None:
                    if args.json:
                        print(to_json({"error": "graph node not found", "identifier": args.identifier}))
                    else:
                        print(f"error: graph node not found: {args.identifier}")
                    return 1
                payload = node
            elif args.graph_cmd == "changes":
                payload = list_graph_changes(db_path=args.db_path, limit=args.limit)
            else:
                raise ValueError(f"unsupported graph command: {args.graph_cmd}")
        except Exception as exc:
            if args.json:
                print(to_json({"error": str(exc), "command": args.graph_cmd}))
            else:
                print(f"error: {exc}")
            return 1

        if args.json:
            print(to_json(payload))
        elif args.graph_cmd == "assets":
            rows = payload["assets"]
            if not rows:
                print("No Edge assets found in the SecOpsAI graph.")
            for row in rows:
                print(
                    "{ip} | {status} | {vendor} | {host} | {node}".format(
                        ip=row.get("ip_address") or "unknown-ip",
                        status=row.get("status") or "unknown",
                        vendor=row.get("vendor") or "unknown-vendor",
                        host=row.get("hostname") or row.get("label") or "unknown-host",
                        node=row.get("node_id"),
                    )
                )
        elif args.graph_cmd == "show":
            node = payload["node"]
            print(f"NODE: {node['node_id']} | {node['type']} | {node['label']}")
            for key, value in node.get("properties", {}).items():
                print(f"{key}={value}")
            print("EDGES:")
            for edge in payload.get("edges", []):
                print(f"- {edge['type']} | {edge['from']} -> {edge['to']}")
        else:
            print("NODES:")
            for node in payload.get("nodes", []):
                print(f"- {node['updated_at']} | {node['type']} | {node['label']} | {node['node_id']}")
            print("EDGES:")
            for edge in payload.get("edges", []):
                print(f"- {edge['last_seen']} | {edge['type']} | {edge['from']} -> {edge['to']}")
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
                    if payload.get("kind") == "edge_scan":
                        payload = normalize_edge_scan_payload(payload)
                    elif payload.get("kind") == "edge_report":
                        payload = normalize_edge_report_payload(payload)
                    elif payload.get("kind") == "edge_worker":
                        payload = normalize_edge_worker_payload(payload)

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
                        edge_root=args.edge_root,
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
                source=args.source,
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
        if args.supply_chain_cmd == "ecosystems":
            payload = (
                ecosystem_capabilities(args.ecosystem)
                if args.ecosystem
                else list_supported_ecosystems()
            )
            if args.json:
                print(to_json(payload))
            elif args.ecosystem:
                print(f"ecosystem={payload['ecosystem']}")
                print(f"display_name={payload.get('display_name')}")
                print(f"supported={payload['supported']}")
                print(f"identifier={payload.get('identifier')}")
                for feature, enabled in payload.get("features", {}).items():
                    print(f"{feature}={enabled}")
                if payload.get("limitations"):
                    print("limitations:")
                    for item in payload["limitations"]:
                        print(f"- {item}")
            else:
                print(f"total={payload['total']}")
                for item in payload["ecosystems"]:
                    features = ",".join(
                        name for name, enabled in item.get("features", {}).items() if enabled
                    )
                    print(f"- {item['ecosystem']} ({item['display_name']}): {features}")
            return 0

        if args.supply_chain_cmd == "scan":
            if args.fixture_json:
                files = json.loads(Path(args.fixture_json).read_text(encoding="utf-8"))
                payload = {
                    "result": analyze_ecosystem_files(args.ecosystem, files),
                    "db_path": None,
                    "slack_alerts_sent": 0,
                }
                payload["result"].update({
                    "package": args.package,
                    "new_version": args.version,
                    "old_version": args.previous_version,
                })
            else:
                payload = run_scan(
                    ecosystem=args.ecosystem,
                    package=args.package,
                    version=args.version,
                    previous_version=args.previous_version,
                    model=args.model,
                    keep_report=not args.no_report,
                    slack=args.slack,
                    artifact=Path(args.artifact) if args.artifact else None,
                    previous_artifact=Path(args.previous_artifact) if args.previous_artifact else None,
                    metadata_only=args.metadata_only,
                    max_download_mb=args.max_download_mb,
                    max_files=args.max_files,
                    timeout=args.timeout,
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

        if args.supply_chain_cmd == "ai-dependency-guard":
            try:
                payload = run_ai_dependency_guard(
                    path=args.path,
                    include_agent_logs=args.include_agent_logs,
                    agent_source=args.agent_source,
                    ecosystems=args.ecosystem or None,
                    fail_on=args.fail_on,
                    persist_findings=args.persist_findings,
                    report_path=args.report_path,
                    timeout=args.timeout,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"ok": False, "error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                summary = payload["summary"]
                print(
                    "ai-dependency-guard: candidates={total} verified={verified} missing={missing} newly_registered={new} high_risk={high}".format(
                        total=summary["total_candidates"],
                        verified=summary["verified"],
                        missing=summary["missing_or_hallucinated"],
                        new=summary["newly_registered"],
                        high=summary["high_risk"],
                    )
                )
                for candidate in payload.get("candidates", []):
                    if candidate.get("severity") in {"high", "critical"}:
                        print(
                            "- {eco}:{pkg} classification={cls} severity={sev} confidence={conf}".format(
                                eco=candidate.get("ecosystem"),
                                pkg=candidate.get("package"),
                                cls=candidate.get("classification"),
                                sev=candidate.get("severity"),
                                conf=candidate.get("confidence"),
                            )
                        )
                if payload.get("db_path"):
                    print(f"db_path={payload['db_path']}")
                if payload.get("report_path"):
                    print(f"report_path={payload['report_path']}")
            return 1 if payload.get("would_fail") else 0

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

        if args.supply_chain_cmd == "watch-registry":
            try:
                if args.dry_run and args.persist:
                    raise ValueError("--dry-run and --persist are mutually exclusive")
                if not args.package and not args.namespace:
                    raise ValueError("--package or --namespace is required")
                if args.namespace and args.ecosystem not in {"npm", "packagist"}:
                    raise ValueError("--namespace is currently supported for --ecosystem npm or packagist")
                capabilities = ecosystem_capabilities(args.ecosystem)
                if not capabilities.get("features", {}).get("monitor", False):
                    payload = {
                        "ecosystem": capabilities["ecosystem"],
                        "package": args.package,
                        "since": args.since,
                        "dry_run": True,
                        "persist": False,
                        "recent_versions": [],
                        "scanned": [],
                        "total_scanned": 0,
                        "malicious": 0,
                        "errors": 0,
                        "db_path": None,
                        "supported": False,
                        "limitations": capabilities.get("limitations", []),
                    }
                    if args.json:
                        print(to_json(payload))
                    else:
                        print(
                            f"watch-registry unsupported for {capabilities['ecosystem']}; "
                            "advisory matching and local fixture rules are available."
                        )
                        for item in payload["limitations"]:
                            print(f"- {item}")
                    return 0
                if args.namespace and args.ecosystem == "npm":
                    payload = watch_npm_namespace(
                        namespace=args.namespace,
                        since=args.since,
                        dry_run=not args.persist,
                        persist=args.persist,
                        limit=args.limit,
                        model=args.model,
                    )
                elif args.namespace:
                    payload = watch_packagist_namespace(
                        namespace=args.namespace,
                        since=args.since,
                        dry_run=not args.persist,
                        persist=args.persist,
                        limit=args.limit,
                        model=args.model,
                    )
                else:
                    payload = watch_registry(
                        ecosystem=args.ecosystem,
                        package=args.package,
                        since=args.since,
                        dry_run=not args.persist,
                        persist=args.persist,
                        limit=args.limit,
                        model=args.model,
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
                target = payload.get("package") or f"{payload.get('namespace')}/*"
                print(
                    "supply-chain watch-registry: {eco} {target} scanned={scanned} malicious={malicious} errors={errors} dry_run={dry_run}".format(
                        eco=payload["ecosystem"],
                        target=target,
                        scanned=payload["total_scanned"],
                        malicious=payload["malicious"],
                        errors=payload["errors"],
                        dry_run=payload["dry_run"],
                    )
                )
                rows = payload.get("scanned", [])
                if not rows and payload.get("results"):
                    for result_payload in payload["results"]:
                        rows.extend(result_payload.get("scanned", []))
                for row in rows:
                    result = row["result"]
                    print(
                        "- {pkg}@{ver} previous={prev} verdict={verdict}".format(
                            pkg=row["package"],
                            ver=row["version"],
                            prev=row.get("previous_version") or "unknown",
                            verdict=result.get("verdict"),
                        )
                    )
                if payload.get("db_path"):
                    print(f"db_path={payload['db_path']}")
            return 0

        if args.supply_chain_cmd == "research-campaign":
            try:
                if args.dry_run and args.persist:
                    raise ValueError("--dry-run and --persist are mutually exclusive")
                campaign_payload: Dict[str, Any] = {}
                if args.input:
                    campaign_payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
                    if not isinstance(campaign_payload, dict):
                        raise ValueError("--input must contain a JSON object")
                if args.campaign_id:
                    campaign_payload["campaign_id"] = args.campaign_id
                if args.title:
                    campaign_payload["title"] = args.title
                if args.summary:
                    campaign_payload["summary"] = args.summary
                if args.source_url:
                    campaign_payload.setdefault("source_urls", [])
                    campaign_payload["source_urls"].extend(args.source_url)
                if args.source_name:
                    campaign_payload.setdefault("source_names", [])
                    campaign_payload["source_names"].extend(args.source_name)
                if args.actor:
                    campaign_payload.setdefault("actors", [])
                    campaign_payload["actors"].extend(args.actor)
                if args.publisher:
                    campaign_payload.setdefault("publishers", [])
                    campaign_payload["publishers"].extend(args.publisher)
                if args.behavior:
                    campaign_payload.setdefault("behavioral_indicators", [])
                    campaign_payload["behavioral_indicators"].extend(args.behavior)
                if args.ioc:
                    campaign_payload.setdefault("iocs", {})
                    campaign_payload["iocs"].setdefault("operator_supplied", [])
                    campaign_payload["iocs"]["operator_supplied"].extend(args.ioc)
                if args.package:
                    campaign_payload.setdefault("packages", [])
                    campaign_payload["packages"].extend(args.package)
                if not campaign_payload.get("packages"):
                    raise ValueError("campaign research requires at least one package")
                payload = research_supply_chain_campaign(
                    campaign=campaign_payload,
                    search_root=args.search_root,
                    dry_run=args.dry_run or not args.persist,
                    persist=args.persist,
                    no_fetch=args.no_fetch or args.dry_run or not args.persist,
                    create_blog_draft=args.create_blog_draft,
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
                print(f"campaign_id={payload['campaign_id']}")
                print(f"campaign_verdict={payload['campaign_verdict']}")
                print(f"confidence={payload['confidence']}")
                print(f"score={payload['score']}")
                print(f"packages={len(payload['packages'])}")
                print(f"environment_impact={payload['environment_impact']['status']}")
                if payload.get("finding_ids"):
                    print(f"finding_ids={','.join(payload['finding_ids'])}")
                if payload.get("db_path"):
                    print(f"db_path={payload['db_path']}")
                if payload.get("blog_draft"):
                    print(f"blog_draft={payload['blog_draft']['draft_path']}")
            return 0

        if args.supply_chain_cmd == "discover-campaigns":
            try:
                payload = discover_campaigns(
                    since=args.since,
                    source=args.source,
                    limit=args.limit,
                    save=not args.no_save,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"ok": False, "error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                print(f"campaign_candidates={payload['total_candidates']}")
                for candidate in payload.get("candidates", [])[: args.limit]:
                    campaign = candidate.get("campaign", {})
                    packages = ", ".join(
                        f"{pkg.get('ecosystem')}:{pkg.get('package')}@{pkg.get('version')}"
                        for pkg in campaign.get("packages", [])[:5]
                    )
                    print(f"- {candidate.get('candidate_id')} score={candidate.get('score')} packages={packages}")
                if payload.get("saved_to"):
                    print(f"saved_to={payload['saved_to']}")
            return 0

        if args.supply_chain_cmd == "campaign-intake":
            try:
                text = Path(args.text).read_text(encoding="utf-8") if args.text else None
                if not args.url and text is None:
                    raise ValueError("campaign-intake requires --url or --text")
                payload = campaign_intake(
                    url=args.url,
                    text=text,
                    source_name=args.source_name,
                    title=args.title,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"ok": False, "error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                print(f"candidate_id={payload['candidate_id']}")
                print(f"score={payload['score']}")
                print(f"packages={len(payload.get('campaign', {}).get('packages', []))}")
                print(json.dumps(payload["campaign"], indent=2, sort_keys=True))
            return 0

        if args.supply_chain_cmd == "orchestrate-candidate":
            try:
                candidate = json.loads(Path(args.input).read_text(encoding="utf-8"))
                if not isinstance(candidate, dict):
                    raise ValueError("orchestrate-candidate input must be a JSON object")
                payload = orchestrate_campaign_candidate(candidate)
            except Exception as exc:
                if args.json:
                    print(to_json({"ok": False, "error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json({"ok": True, **payload}))
            else:
                review = payload.get("orchestrator", {})
                print(f"candidate_id={payload.get('candidate_id')}")
                print(f"campaign_type={review.get('campaign_type')}")
                print(f"recommended_route={review.get('recommended_route')}")
                print(f"supply_chain_relevance={review.get('supply_chain_relevance')}")
                print(f"validated_packages={len(review.get('validated_packages', []))}")
                if review.get("route_blockers"):
                    print(f"route_blockers={'; '.join(review['route_blockers'])}")
            return 0

        if args.supply_chain_cmd == "campaign-watchlist":
            try:
                if args.campaign_watchlist_cmd == "add":
                    if not any([args.package, args.publisher, args.ioc, args.source_url]):
                        raise ValueError("campaign-watchlist add requires at least one value")
                    payload = campaign_watchlist_add(
                        package=args.package,
                        publisher=args.publisher,
                        ioc=args.ioc,
                        source_url=args.source_url,
                    )
                else:
                    payload = campaign_watchlist_list()
            except Exception as exc:
                if args.json:
                    print(to_json({"ok": False, "error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                print(f"packages={len(payload.get('packages', []))}")
                print(f"publishers={len(payload.get('publishers', []))}")
                print(f"iocs={len(payload.get('iocs', []))}")
                print(f"source_urls={len(payload.get('source_urls', []))}")
            return 0

        if args.supply_chain_cmd == "campaign-autopilot":
            try:
                if args.dry_run and args.persist:
                    raise ValueError("--dry-run and --persist are mutually exclusive")
                payload = campaign_autopilot(
                    since=args.since,
                    dry_run=args.dry_run or not args.persist,
                    persist=args.persist,
                    create_drafts=args.create_drafts,
                    search_root=args.search_root,
                    limit=args.limit,
                    min_score=args.min_score,
                )
            except Exception as exc:
                if args.json:
                    print(to_json({"ok": False, "error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            else:
                print(f"selected_candidates={payload['selected_candidates']}")
                print(f"dry_run={payload['dry_run']}")
                for row in payload.get("results", []):
                    print(f"- {row.get('campaign_id')} verdict={row.get('campaign_verdict')} score={row.get('score')}")
            return 0

        if args.supply_chain_cmd == "campaign-candidates":
            try:
                if args.campaign_candidates_cmd == "list":
                    payload = load_campaign_candidates()
                else:
                    payload = promote_campaign_candidate(args.candidate_id)
            except Exception as exc:
                if args.json:
                    print(to_json({"ok": False, "error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1
            if args.json:
                print(to_json(payload))
            elif args.campaign_candidates_cmd == "list":
                print(f"candidates={len(payload.get('candidates', []))}")
                for candidate in payload.get("candidates", [])[:20]:
                    print(f"- {candidate.get('candidate_id')} score={candidate.get('score')}")
            else:
                print(json.dumps(payload.get("campaign", {}), indent=2, sort_keys=True))
            return 0

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
                    capabilities = ecosystem_capabilities(args.ecosystem)
                    if not capabilities.get("features", {}).get("artifact_fetch", False):
                        report_text = "## Ecosystem Findings\n\n"
                    else:
                        if args.json:
                            print(to_json({"error": str(exc)}))
                        else:
                            print(f"error: {exc}")
                        return 1
                else:
                    report_text = ""

            payload = explain_verdict(
                report_text,
                ecosystem=args.ecosystem,
                package=args.package,
                version=args.version,
            )
            payload["report_path"] = str(report_path) if report_path else None
            payload["ecosystem_capabilities"] = ecosystem_capabilities(args.ecosystem)
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
                if payload.get("environment_impact"):
                    impact = payload["environment_impact"]
                    print(f"environment_impact={impact.get('status')}: {impact.get('guidance')}")
                if payload.get("mitigation"):
                    print("mitigation:")
                    for step in payload["mitigation"]:
                        print(f"- {step}")
                if payload.get("ecosystem_capabilities", {}).get("limitations"):
                    print("limitations:")
                    for item in payload["ecosystem_capabilities"]["limitations"]:
                        print(f"- {item}")
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
