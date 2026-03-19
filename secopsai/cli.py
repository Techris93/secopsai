#!/usr/bin/env python3
"""Command-line entrypoint for secopsai.

SPDX-FileCopyrightText: 2026 Techris93
SPDX-License-Identifier: MIT

This CLI provides safe thin wrappers around existing top-level scripts
to avoid risky refactors. It calls the underlying scripts using the
current Python executable so behavior remains identical for users.

Subcommands: refresh, list, show, mitigate, check
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import soc_store
import openclaw_plugin

ROOT = Path(__file__).resolve().parents[1]


def run_script(script: str, args: list[str]) -> int:
    cmd = [sys.executable, str(ROOT / script)] + args
    proc = subprocess.run(cmd)
    return proc.returncode


def to_json(obj: dict) -> str:
    return json.dumps(obj, indent=2)


def cmd_refresh(args: argparse.Namespace) -> int:
    cache_file = ROOT / "data" / ".last_refresh"

    # If cache indicates a recent successful run and the caller did not force,
    # skip running the exporter.
    if _should_skip_refresh(args, cache_file):
        return 0

    call = ["--verbose"]
    if args.skip_export:
        call.append("--skip-export")

    rc = run_script("run_openclaw_live.py", call)
    if rc == 0:
        try:
            (ROOT / "data").mkdir(parents=True, exist_ok=True)
            cache_file.write_text(str(int(time.time())))
        except Exception:
            pass
    return rc


def _should_skip_refresh(args: argparse.Namespace, cache_file: Path) -> bool:
    ttl = int(getattr(args, "cache_ttl", 60) or 0)
    now = int(time.time())
    if getattr(args, "force", False):
        return False
    if not cache_file.exists():
        return False
    try:
        last = int(cache_file.read_text().strip())
    except Exception:
        return False

    if now - last < ttl:
        if getattr(args, "json", False):
            print(to_json({"skipped": True, "last_refresh": last, "ttl": ttl}))
        else:
            print(f"Skipped refresh: last run {now-last}s ago (<{ttl}s)")
        return True
    return False


def _severity_at_least_local(sev: str, thresh: str) -> bool:
    try:
        return openclaw_plugin._severity_at_least(sev, thresh)
    except Exception:
        return True


def _ensure_refresh(no_refresh: bool) -> int:
    if no_refresh:
        return 0
    refresh_args = SimpleNamespace(skip_export=False, force=False, cache_ttl=60, json=False)
    return cmd_refresh(refresh_args)


def cmd_list(args: argparse.Namespace) -> int:
    rc = _ensure_refresh(getattr(args, "no_refresh", False))
    if rc != 0:
        return rc

    findings = soc_store.list_findings()
    if args.severity:
        findings = [f for f in findings if _severity_at_least_local(str(f.get("severity", "info")), args.severity)]

    if args.json:
        print(to_json({"total_findings": len(findings), "findings": findings}))
        return 0

    for finding in findings:
        print(soc_store.format_finding_row(finding))
    print(f"total_findings={len(findings)}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    rc = _ensure_refresh(getattr(args, "no_refresh", False))
    if rc != 0:
        return rc

    finding = soc_store.get_finding(args.finding_id)
    if finding is None:
        if args.json:
            print(to_json({"error": "finding not found", "finding_id": args.finding_id}))
        else:
            print(f"error: finding not found: {args.finding_id}")
        return 1

    if args.json:
        print(to_json({"finding": finding}))
    else:
        print(json.dumps(finding, indent=2))
    return 0


def cmd_mitigate(args: argparse.Namespace) -> int:
    rc = _ensure_refresh(getattr(args, "no_refresh", False))
    if rc != 0:
        return rc

    finding = soc_store.get_finding(args.finding_id)
    if not finding:
        if args.json:
            print(to_json({"error": "finding not found", "finding_id": args.finding_id}))
        else:
            print(f"error: finding not found: {args.finding_id}")
        return 1

    mitigations = openclaw_plugin._mitigations_for_finding(finding)
    payload = {
        "finding_id": finding.get("finding_id", args.finding_id),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "status": finding.get("status"),
        "disposition": finding.get("disposition"),
        "rule_ids": finding.get("rule_ids"),
        "recommended_actions": mitigations,
    }

    if args.json:
        print(to_json({"mitigation": payload}))
    else:
        print(f"{payload['finding_id']} | {str(payload['severity']).upper()} | {payload['title']}")
        print("RECOMMENDED_ACTIONS:")
        for a in payload["recommended_actions"]:
            print(f"- {a}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    rc = _ensure_refresh(getattr(args, "no_refresh", False))
    if rc != 0:
        return rc

    check_type = args.type or "malware"
    min_sev = args.severity or "low"
    result = openclaw_plugin.check_presence(check_type, min_sev)
    payload = {
        "check_type": result.check_type,
        "findings_total": result.findings_total,
        "matched_count": result.matched_count,
        "high_or_above": result.high_or_above,
        "top_matches": result.top_matches,
    }

    if args.json:
        print(to_json({"check": payload}))
    else:
        print(f"CHECK: {payload['check_type']} (min_severity={min_sev})")
        print(
            "findings_total={total} matched={matched} high_or_above={high}".format(
                total=payload["findings_total"], matched=payload["matched_count"], high=payload["high_or_above"]
            )
        )
        if payload["top_matches"]:
            print("\nTOP_MATCHES:")
            for row in payload["top_matches"]:
                print(
                    "- {id} | {sev} | {title}".format(
                        id=row["finding_id"], sev=str(row["severity"]).upper(), title=row["title"]
                    )
                )
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    p = argparse.ArgumentParser(prog="secopsai")
    p.add_argument("--json", action="store_true", help="output JSON")

    sub = p.add_subparsers(dest="cmd", required=True)

    s_refresh = sub.add_parser("refresh", help="run live pipeline and export findings")
    s_refresh.add_argument("--skip-export", action="store_true", help="skip re-exporting native files")
    s_refresh.add_argument("--force", action="store_true", help="force refresh ignoring cache")
    s_refresh.add_argument("--cache-ttl", type=int, default=60, help="cache TTL in seconds (default: 60)")
    s_refresh.set_defaults(func=cmd_refresh)

    s_list = sub.add_parser("list", help="list findings from store")
    s_list.add_argument("--severity", help="minimum severity to show")
    s_list.add_argument("--no-refresh", action="store_true", help="do not auto-refresh before listing")
    s_list.set_defaults(func=cmd_list)

    s_show = sub.add_parser("show", help="show a finding by id")
    s_show.add_argument("finding_id", help="finding id (OCF-XXXX)")
    s_show.add_argument("--no-refresh", action="store_true", help="do not auto-refresh before showing")
    s_show.set_defaults(func=cmd_show)

    s_mit = sub.add_parser("mitigate", help="recommend mitigations for finding")
    s_mit.add_argument("finding_id", help="finding id (OCF-XXXX)")
    s_mit.add_argument("--no-refresh", action="store_true", help="do not auto-refresh before mitigating")
    s_mit.set_defaults(func=cmd_mitigate)

    s_check = sub.add_parser("check", help="check for malware/exfil presence")
    s_check.add_argument("--type", choices=["malware", "exfil", "both"], help="check type")
    s_check.add_argument("--severity", help="minimum severity")
    s_check.add_argument("--no-refresh", action="store_true", help="do not auto-refresh before check")
    s_check.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
