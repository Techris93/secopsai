#!/usr/bin/env python3
"""Command-line entrypoint for secopsai.

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

ROOT = Path(__file__).resolve().parents[1]


def run_script(script: str, args: list[str]) -> int:
    cmd = [sys.executable, str(ROOT / script)] + args
    proc = subprocess.run(cmd)
    return proc.returncode


def to_json(obj: dict) -> str:
    return json.dumps(obj, indent=2)


def cmd_refresh(args: argparse.Namespace) -> int:
    # simple file-backed cache to avoid frequent re-exports
    cache_file = ROOT / "data" / ".last_refresh"
    ttl = int(getattr(args, "cache_ttl", 60) or 0)
    now = int(time.time())

    if not getattr(args, "force", False) and cache_file.exists():
        try:
            last = int(cache_file.read_text().strip())
            if now - last < ttl:
                if args.json:
                    print(to_json({"skipped": True, "last_refresh": last, "ttl": ttl}))
                else:
                    print(f"Skipped refresh: last run {now-last}s ago (<{ttl}s)")
                return 0
        except Exception:
            # ignore malformed cache file and continue
            pass

    call = ["--verbose"]
    if args.skip_export:
        call.append("--skip-export")
    if args.json:
        call.append("--json")

    rc = run_script("run_openclaw_live.py", call)
    if rc == 0:
        try:
            (ROOT / "data").mkdir(parents=True, exist_ok=True)
            cache_file.write_text(str(int(time.time())))
        except Exception:
            pass
    return rc


def cmd_list(args: argparse.Namespace) -> int:
    call = []
    if args.severity:
        call += ["--severity", args.severity]
    if args.json:
        call.append("--json")
    return run_script("soc_store.py", ["list"] + call)


def cmd_show(args: argparse.Namespace) -> int:
    call = ["show", args.finding_id]
    if args.json:
        call.append("--json")
    return run_script("soc_store.py", call)


def cmd_mitigate(args: argparse.Namespace) -> int:
    call = ["mitigate", args.finding_id]
    if args.json:
        call.append("--json")
    return run_script("openclaw_plugin.py", call)


def cmd_check(args: argparse.Namespace) -> int:
    call = ["check", "--type", args.type or "malware", "--severity", args.severity or "high"]
    if args.json:
        call.append("--json")
    return run_script("openclaw_plugin.py", call)


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
    s_list.set_defaults(func=cmd_list)

    s_show = sub.add_parser("show", help="show a finding by id")
    s_show.add_argument("finding_id", help="finding id (OCF-XXXX)")
    s_show.set_defaults(func=cmd_show)

    s_mit = sub.add_parser("mitigate", help="recommend mitigations for finding")
    s_mit.add_argument("finding_id", help="finding id (OCF-XXXX)")
    s_mit.set_defaults(func=cmd_mitigate)

    s_check = sub.add_parser("check", help="check for malware/exfil presence")
    s_check.add_argument("--type", choices=["malware", "exfil"], help="check type")
    s_check.add_argument("--severity", help="minimum severity")
    s_check.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
