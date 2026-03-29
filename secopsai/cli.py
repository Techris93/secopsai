from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import openclaw_plugin
import soc_store
from adapters import AdapterRegistry
from correlation import run_correlation
from detect import run_detection

from secopsai.formatters import fmt_finding, fmt_list, to_json
from secopsai.intel import enrich_iocs, load_iocs, match_iocs_against_replay, refresh_iocs
from secopsai.pipeline import refresh as refresh_pipeline
from scripts.sync_findings_to_supabase import execute_sync as execute_findings_sync
from scripts.sync_findings_to_supabase import parse_args as parse_findings_sync_args

ROOT = Path(__file__).resolve().parents[1]
CACHE_FILE = ROOT / "data" / ".last_refresh"
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

    for platform_name in selected:
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
        db_path = persist_findings(all_findings, source="secopsai_cli")
        print(f"  ✓ Saved to {db_path}")

    _write_last_refresh()
    summary = {
        "mode": "adapter_refresh",
        "platforms": selected,
        "platform_results": platform_results,
        "total_findings": len(all_findings),
        "findings_db": db_path,
    }
    print(f"\n{'=' * 60}")
    print(f"TOTAL: {len(all_findings)} findings from {len(selected)} platform(s)")
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

    results = run_correlation(findings, time_window)

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


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    argv = _normalize_global_flags(argv)
    p = argparse.ArgumentParser(
        prog="secopsai",
        description="SecOpsAI unified CLI (OpenClaw pipeline + cross-platform adapters)",
    )
    p.add_argument("--json", action="store_true", help="Output JSON instead of pretty text")

    sub = p.add_subparsers(dest="cmd", required=True)

    refresh = sub.add_parser(
        "refresh",
        help="Run the OpenClaw pipeline or adapter refresh when --platform is supplied",
    )
    refresh.add_argument("--platform", "-p", help="Adapters: openclaw,macos,linux,windows")
    refresh.add_argument("--skip-export", action="store_true", help="Skip export from ~/.openclaw")
    refresh.add_argument("--cache-ttl", type=int, default=DEFAULT_TTL_SECONDS)
    refresh.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")
    refresh.add_argument("--verbose", action="store_true", help="Verbose refresh output (future use)")

    sync_findings = sub.add_parser("sync-findings", help="Sync persisted findings to the dashboard Supabase table")
    sync_findings.add_argument("--db-path", default=str(ROOT / "data" / "openclaw" / "findings" / "openclaw_soc.db"))
    sync_findings.add_argument("--findings-dir", default=str(ROOT / "data" / "openclaw" / "findings"))
    sync_findings.add_argument("--dashboard-env", default=str(ROOT.parent / "secopsai-dashboard" / ".env"))
    sync_findings.add_argument("--supabase-url", default=None)
    sync_findings.add_argument("--supabase-key", default=None)
    sync_findings.add_argument("--table", default="findings")
    sync_findings.add_argument("--schema-sql", default=str(ROOT.parent / "secopsai-dashboard" / "supabase_migrations" / "2026-03-28_findings.sql"))
    sync_findings.add_argument("--skip-schema-check", action="store_true")
    sync_findings.add_argument("--dry-run", action="store_true")

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

    if args.cmd == "refresh":
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
            print(f"sync_attempted={res.sync_attempted}")
            print(f"sync_succeeded={res.sync_succeeded}")
        return 0

    if args.cmd == "sync-findings":
        summary = execute_findings_sync(args)
        payload = {
            "source_kind": summary.source_kind,
            "source_path": summary.source_path,
            "local_findings": summary.local_findings,
            "normalized_rows": summary.normalized_rows,
            "schema_checked": summary.schema_checked,
            "schema_ok": summary.schema_ok,
            "validated_columns": summary.validated_columns,
            "synced_rows": summary.synced_rows,
            "dry_run": summary.dry_run,
            "table": summary.table,
        }
        if args.json:
            print(to_json(payload))
        else:
            print("secopsai sync-findings complete")
            for key, value in payload.items():
                print(f"{key}={value}")
        return 0

    if args.cmd == "live":
        return _run_live(args.platform, args.duration)

    if args.cmd == "correlate":
        return _run_correlate(time_window=args.window, json_output=args.json)

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
                    "refreshed: total_findings={tf} total_detections={td} sync_attempted={sa} sync_succeeded={ss}\n".format(
                        tf=refresh_meta.get("total_findings"),
                        td=refresh_meta.get("total_detections"),
                        sa=refresh_meta.get("sync_attempted"),
                        ss=refresh_meta.get("sync_succeeded"),
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
                print("refreshed before show")
                print(
                    "sync_status: attempted={sa} succeeded={ss}\n".format(
                        sa=refresh_meta.get("sync_attempted"),
                        ss=refresh_meta.get("sync_succeeded"),
                    )
                )
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
                print("refreshed before mitigate")
                print(
                    "sync_status: attempted={sa} succeeded={ss}\n".format(
                        sa=refresh_meta.get("sync_attempted"),
                        ss=refresh_meta.get("sync_succeeded"),
                    )
                )
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
                print("refreshed before check")
                print(
                    "sync_status: attempted={sa} succeeded={ss}\n".format(
                        sa=refresh_meta.get("sync_attempted"),
                        ss=refresh_meta.get("sync_succeeded"),
                    )
                )
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

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
