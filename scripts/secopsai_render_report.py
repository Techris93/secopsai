#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secopsai.report_renderers import (  # noqa: E402
    DEFAULT_TIMEZONE,
    render_daily_brief,
    render_daily_intel,
    render_status_summary,
)

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from secopsai_report_snapshot import build_snapshot  # noqa: E402


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _python_bin(repo: Path) -> str:
    venv_python = repo / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def _run_json_command(repo: Path, args: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        args,
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = _load_json(proc.stdout)
    status = "succeeded" if proc.returncode == 0 and payload is not None else "failed"
    result: dict[str, Any] = {
        "status": status,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    if payload is not None:
        result["payload"] = payload
    return result


def _write_json(path: Path | None, payload: Any) -> None:
    if path is None:
        return
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render deterministic SecOpsAI report text")
    parser.add_argument("--kind", required=True, choices=["daily-intel", "status-summary", "daily-brief"])
    parser.add_argument("--repo", default=str(ROOT))
    parser.add_argument(
        "--workspace-logs",
        default=str(Path.home() / ".openclaw" / "workspace" / "logs"),
    )
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE)
    parser.add_argument("--limit-iocs", type=int, default=500)
    parser.add_argument("--snapshot-out", default="/tmp/secopsai_snapshot.json")
    parser.add_argument("--refresh-out", default="/tmp/secopsai_intel_refresh.json")
    parser.add_argument("--match-out", default="/tmp/secopsai_ioc_match.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).expanduser().resolve()
    workspace_logs = Path(args.workspace_logs).expanduser().resolve()
    python_bin = _python_bin(repo)

    if args.kind == "status-summary":
        snapshot = build_snapshot(repo, workspace_logs)
        snapshot_out = Path(args.snapshot_out) if args.snapshot_out else None
        _write_json(snapshot_out, snapshot)
        print(render_status_summary(snapshot, tz_name=args.timezone))
        return 0

    if args.kind == "daily-brief":
        snapshot = build_snapshot(repo, workspace_logs)
        snapshot_out = Path(args.snapshot_out) if args.snapshot_out else None
        _write_json(snapshot_out, snapshot)
        print(render_daily_brief(snapshot, tz_name=args.timezone))
        return 0

    refresh_result = _run_json_command(repo, [python_bin, "-m", "secopsai.cli", "intel", "refresh", "--json"])
    match_result = _run_json_command(
        repo,
        [python_bin, "-m", "secopsai.cli", "intel", "match", "--limit-iocs", str(args.limit_iocs), "--json"],
    )

    refresh_payload = refresh_result.get("payload")
    match_payload = match_result.get("payload")
    refresh_out = Path(args.refresh_out) if args.refresh_out else None
    match_out = Path(args.match_out) if args.match_out else None
    _write_json(refresh_out, refresh_payload if refresh_payload is not None else refresh_result)
    _write_json(match_out, match_payload if match_payload is not None else match_result)

    snapshot = build_snapshot(repo, workspace_logs)
    snapshot_out = Path(args.snapshot_out) if args.snapshot_out else None
    _write_json(snapshot_out, snapshot)

    command_status = {
        "refresh": refresh_result["status"],
        "match": match_result["status"],
        "refresh_metrics": refresh_payload,
        "match_metrics": match_payload,
    }
    print(render_daily_intel(snapshot, command_status=command_status, tz_name=args.timezone))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
