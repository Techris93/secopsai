#!/usr/bin/env python3
"""Docs QA agent for source-backed SecOpsAI docs verification."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "reports" / "docs"


def run_command(command: List[str]) -> Dict[str, Any]:
    result = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True, check=False)
    return {
        "command": command,
        "returncode": result.returncode,
        "ok": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def build_report(*, run_build: bool = False) -> Dict[str, Any]:
    checks = [
        run_command([sys.executable, "scripts/verify_docs_examples.py"]),
    ]
    if run_build:
        mkdocs_bin = ROOT / ".venv" / "bin" / "mkdocs"
        command = [str(mkdocs_bin if mkdocs_bin.exists() else "mkdocs"), "build"]
        checks.append(run_command(command))
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ok": all(item["ok"] for item in checks),
        "sources": [
            "docs/index.md",
            "docs/research-and-verification.md",
            "docs/OpenClaw-Plugin.md",
            "scripts/verify_docs_examples.py",
            "mkdocs.yml",
        ],
        "checks": checks,
        "recommended_actions": [
            "Fix any failed CLI example before publishing docs.",
            "Update docs/OpenClaw-Plugin.md whenever plugin tool names change.",
            "Run mkdocs build before publishing docs.secopsai.dev.",
        ],
    }


def write_report(payload: Dict[str, Any], output_dir: Path = REPORT_DIR) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    json_path = output_dir / f"docs-qa-{stamp}.json"
    md_path = output_dir / f"docs-qa-{stamp}.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        "# SecOpsAI Docs QA Agent Report",
        "",
        f"- Generated at: {payload['generated_at']}",
        f"- Status: {'pass' if payload['ok'] else 'fail'}",
        "",
        "## Checks",
        "",
    ]
    for check in payload["checks"]:
        lines.append(f"- {'pass' if check['ok'] else 'fail'}: `{' '.join(check['command'])}`")
    lines.extend(["", "## Sources", ""])
    lines.extend(f"- `{source}`" for source in payload["sources"])
    lines.extend(["", "## Recommended Actions", ""])
    lines.extend(f"- {item}" for item in payload["recommended_actions"])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"json_report": str(json_path), "markdown_report": str(md_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run source-backed docs QA checks and write a report.")
    parser.add_argument("--build", action="store_true", help="Also run mkdocs build")
    parser.add_argument("--output-dir", default=str(REPORT_DIR), help="Report output directory")
    args = parser.parse_args(argv)
    payload = build_report(run_build=args.build)
    paths = write_report(payload, Path(args.output_dir).expanduser().resolve())
    print(json.dumps({**payload, **paths}, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
