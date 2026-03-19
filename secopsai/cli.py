from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import soc_store
import openclaw_plugin

from secopsai.pipeline import refresh as refresh_pipeline
from secopsai.formatters import fmt_list, fmt_finding, to_json


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
        # Cache failure should never break the CLI
        pass


def _maybe_skip_refresh(ttl: int, json_mode: bool) -> Optional[Dict[str, Any]]:
    """Return metadata if refresh should be skipped, otherwise None."""
    now = int(time.time())
    last = _read_last_refresh()
    if last is None:
        return None
    if now - last >= ttl:
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


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="secopsai", description="secopsai CLI (OpenClaw SecOps pipeline)"
    )
    p.add_argument("--json", action="store_true", help="Output JSON instead of pretty text")

    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("refresh", help="Run the full OpenClaw live pipeline and persist findings")
    r.add_argument("--skip-export", action="store_true", help="Skip export from ~/.openclaw")
    r.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")
    r.add_argument("--verbose", action="store_true", help="Verbose refresh output (future use)")

    l = sub.add_parser("list", help="List findings")
    l.add_argument("--severity", default=None, choices=["info", "low", "medium", "high", "critical"])
    l.add_argument("--limit", type=int, default=50)
    l.add_argument("--no-refresh", action="store_true", help="Do not auto-refresh before listing")
    l.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    l.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    s = sub.add_parser("show", help="Show a finding")
    s.add_argument("finding_id")
    s.add_argument("--no-refresh", action="store_true")
    s.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    s.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    m = sub.add_parser("mitigate", help="Show mitigation recommendations for a finding")
    m.add_argument("finding_id")
    m.add_argument("--no-refresh", action="store_true")
    m.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    m.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    c = sub.add_parser("check", help="Presence checks (malware/exfil/both)")
    c.add_argument("--type", required=True, choices=["malware", "exfil", "both"])
    c.add_argument("--severity", default="low", choices=["info", "low", "medium", "high", "critical"])
    c.add_argument("--no-refresh", action="store_true")
    c.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help=f"Minimum seconds between auto-refresh runs (default: {DEFAULT_TTL_SECONDS})",
    )
    c.add_argument("--openclaw-home", help="Override OPENCLAW_HOME")

    return p.parse_args(argv)


def maybe_refresh(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    if getattr(args, "no_refresh", False):
        return None

    # Only list/show/mitigate/check auto-refresh; refresh command is explicit.
    if getattr(args, "cmd", None) not in {"list", "show", "mitigate", "check"}:
        return None

    # Cache-aware auto-refresh: if a recent refresh was done, re-use it.
    ttl = int(getattr(args, "cache_ttl", DEFAULT_TTL_SECONDS) or 0)
    if ttl > 0:
        skipped_meta = _maybe_skip_refresh(ttl, json_mode=getattr(args, "json", False))
        if skipped_meta is not None:
            # Indicate that we did not re-run the pipeline.
            return {"skipped": True, **skipped_meta}

    # No recent refresh (or ttl <= 0): run the full pipeline.
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

    # auto refresh for the rest
    refresh_meta = maybe_refresh(args)

    if args.cmd == "list":
        rows = soc_store.list_findings()
        if args.severity:
            rows = [
                r
                for r in rows
                if _severity_at_least(str(r.get("severity", "info")), args.severity)
            ]
        rows = rows[: args.limit]

        if args.json:
            out: Dict[str, Any] = {
                "refreshed": bool(refresh_meta and not refresh_meta.get("skipped")),
                "refresh": refresh_meta,
                "findings": rows,
            }
            print(to_json(out))
        else:
            if refresh_meta and not refresh_meta.get("skipped"):
                print(
                    "refreshed: total_findings={tf} total_detections={td}".format(
                        tf=refresh_meta.get("total_findings"),
                        td=refresh_meta.get("total_detections"),
                    )
                )
                print("")
            print(fmt_list(rows))
        return 0

    if args.cmd == "show":
        finding = soc_store.get_finding(args.finding_id)
        if not finding:
            if args.json:
                print(
                    to_json(
                        {
                            "error": "finding not found",
                            "finding_id": args.finding_id,
                        }
                    )
                )
            else:
                print(f"error: finding not found: {args.finding_id}")
            return 1

        if args.json:
            print(
                to_json(
                    {
                        "refreshed": bool(refresh_meta and not refresh_meta.get("skipped")),
                        "refresh": refresh_meta,
                        "finding": finding,
                    }
                )
            )
        else:
            if refresh_meta and not refresh_meta.get("skipped"):
                print("refreshed before show\n")
            print(fmt_finding(finding))
        return 0

    if args.cmd == "mitigate":
        finding = soc_store.get_finding(args.finding_id)
        if not finding:
            if args.json:
                print(
                    to_json(
                        {
                            "error": "finding not found",
                            "finding_id": args.finding_id,
                        }
                    )
                )
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
            print(
                to_json(
                    {
                        "refreshed": bool(refresh_meta and not refresh_meta.get("skipped")),
                        "refresh": refresh_meta,
                        "mitigation": payload,
                    }
                )
            )
        else:
            if refresh_meta and not refresh_meta.get("skipped"):
                print("refreshed before mitigate\n")
            print(
                f"{payload['finding_id']} | {str(payload['severity']).upper()} | {payload['title']}"
            )
            print("RECOMMENDED_ACTIONS:")
            for a in payload["recommended_actions"]:
                print(f"- {a}")
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
            print(
                to_json(
                    {
                        "refreshed": bool(refresh_meta and not refresh_meta.get("skipped")),
                        "refresh": refresh_meta,
                        "check": payload,
                    }
                )
            )
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
                    print(
                        f"- {row['finding_id']} | {str(row['severity']).upper()} | {row['title']}"
                    )
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
