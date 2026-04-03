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

try:
    from secopsai.supply_chain_enhanced import (
        explain_policy,
        explain_verdict,
        load_recent_results,
        reconcile_history,
        run_recent_top_scan,
        run_scan,
    )
except Exception:
    from secopsai.supply_chain import (
        explain_policy,
        explain_verdict,
        load_recent_results,
        reconcile_history,
        run_recent_top_scan,
        run_scan,
    )

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

    supply_chain_explain = supply_chain_sub.add_parser("explain-policy", help="Show the effective policy for a package")
    supply_chain_explain.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_explain.add_argument("--package", required=True, help="Package name")

    supply_chain_explain_verdict = supply_chain_sub.add_parser(
        "explain-verdict",
        help="Explain which rules fired for a supply-chain scan report",
    )
    supply_chain_explain_verdict.add_argument("--ecosystem", required=True, choices=["pypi", "npm"])
    supply_chain_explain_verdict.add_argument("--package", required=True, help="Package name")
    supply_chain_explain_verdict.add_argument("--version", help="Release version to resolve from stored results")
    supply_chain_explain_verdict.add_argument("--report", help="Path to a stored report file")

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
            payload = reconcile_history(drop_benign=args.drop_benign)
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
                if payload["removed_finding_ids"]:
                    print(f"removed_finding_ids={payload['removed_finding_ids']}")
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

        if args.supply_chain_cmd == "explain-verdict":
            try:
                report_path = _resolve_supply_chain_report(
                    report_path=args.report,
                    ecosystem=args.ecosystem,
                    package=args.package,
                    version=args.version,
                )
                report_text = report_path.read_text(encoding="utf-8")
            except Exception as exc:
                if args.json:
                    print(to_json({"error": str(exc)}))
                else:
                    print(f"error: {exc}")
                return 1

            payload = explain_verdict(
                report_text,
                ecosystem=args.ecosystem,
                package=args.package,
            )
            payload["report_path"] = str(report_path)
            if args.version:
                payload["version"] = args.version

            if args.json:
                print(to_json(payload))
            else:
                print(f"target={args.ecosystem}:{args.package}")
                if args.version:
                    print(f"version={args.version}")
                print(f"report_path={report_path}")
                print(f"verdict={payload['verdict']}")
                print(f"score={payload['score']}")
                print(f"effective_threshold={payload['effective_threshold']}")
                print(f"analysis={payload['analysis']}")
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
