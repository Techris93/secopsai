#!/usr/bin/env python3
"""Verify SecOpsAI docs examples and plugin tool references stay current."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Iterable, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secopsai.cli import parse_args  # noqa: E402


DEFAULT_DOCS = [
    Path("docs/index.md"),
    Path("docs/getting-started.md"),
    Path("docs/findings-triage-guide.md"),
    Path("docs/research-and-verification.md"),
    Path("docs/OpenClaw-Plugin.md"),
]
DEFAULT_PLUGIN_INDEX = ROOT.parent / "openclaw-secopsai-plugin" / "index.ts"
COMMAND_PREFIXES = ("secopsai ",)
TOOL_NAME_RE = re.compile(r"`(secopsai_[a-z0-9_]+)`")
TS_TOOL_NAME_RE = re.compile(r'name:\s*"([^"]+)"')


def extract_fenced_commands(markdown: str) -> List[str]:
    commands: List[str] = []
    in_shell_block = False
    for raw_line in markdown.splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("```"):
            fence = stripped[3:].strip().lower()
            if in_shell_block:
                in_shell_block = False
            else:
                in_shell_block = fence in {"", "bash", "sh", "shell", "zsh"}
            continue
        if not in_shell_block:
            continue
        normalized = stripped
        if not normalized or normalized.startswith("#"):
            continue
        normalized = re.sub(r"\s+#.*$", "", normalized).strip()
        if not normalized:
            continue
        if normalized.startswith(COMMAND_PREFIXES):
            commands.append(normalized)
    return commands


def normalize_example_command(command: str) -> str:
    replacements = {
        "<FINDING_ID>": "SCM-EXAMPLE0001",
        "<finding_id>": "SCM-EXAMPLE0001",
        "<ACTION_ID>": "ACT-0001",
        "<action_id>": "ACT-0001",
        "<SESSION_ID>": "SES-1234567890ab",
        "<session_id>": "SES-1234567890ab",
    }
    normalized = command
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)
    return normalized


def validate_secopsai_command(command: str) -> dict:
    normalized = normalize_example_command(command)
    argv = shlex.split(normalized)
    if not argv or argv[0] != "secopsai":
        return {"command": command, "normalized": normalized, "ok": False, "error": "Not a secopsai command"}
    try:
        parse_args(argv[1:])
        return {"command": command, "normalized": normalized, "ok": True}
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        return {
            "command": command,
            "normalized": normalized,
            "ok": code == 0,
            "error": f"argparse exit {code}",
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {"command": command, "normalized": normalized, "ok": False, "error": str(exc)}


def extract_doc_tool_names(markdown: str) -> List[str]:
    tools = {match.group(1) for match in TOOL_NAME_RE.finditer(markdown)}
    return sorted(tools)


def extract_plugin_tool_names(typescript_source: str) -> List[str]:
    tools = {match.group(1) for match in TS_TOOL_NAME_RE.finditer(typescript_source) if match.group(1).startswith("secopsai_")}
    return sorted(tools)


def verify_docs(doc_paths: Iterable[Path]) -> list[dict]:
    rows = []
    for doc_path in doc_paths:
        absolute = doc_path if doc_path.is_absolute() else ROOT / doc_path
        markdown = absolute.read_text(encoding="utf-8")
        commands = extract_fenced_commands(markdown)
        checks = [validate_secopsai_command(command) for command in commands]
        rows.append(
            {
                "path": str(absolute),
                "commands_checked": len(checks),
                "commands": checks,
                "errors": [item for item in checks if not item.get("ok")],
            }
        )
    return rows


def verify_plugin_doc(doc_path: Path, plugin_index: Path) -> dict:
    absolute_doc = doc_path if doc_path.is_absolute() else ROOT / doc_path
    doc_tools = extract_doc_tool_names(absolute_doc.read_text(encoding="utf-8"))
    if not plugin_index.exists():
        return {
            "doc_path": str(absolute_doc),
            "plugin_index": str(plugin_index),
            "documented_tools": doc_tools,
            "plugin_tools": [],
            "missing_from_docs": [],
            "stale_in_docs": [],
            "skipped": True,
            "reason": "plugin index file not found",
        }
    plugin_tools = extract_plugin_tool_names(plugin_index.read_text(encoding="utf-8"))
    return {
        "doc_path": str(absolute_doc),
        "plugin_index": str(plugin_index),
        "documented_tools": doc_tools,
        "plugin_tools": plugin_tools,
        "missing_from_docs": [tool for tool in plugin_tools if tool not in doc_tools],
        "stale_in_docs": [tool for tool in doc_tools if tool not in plugin_tools],
        "skipped": False,
    }


def build_report(doc_paths: Iterable[Path], plugin_doc: Path, plugin_index: Path) -> dict:
    docs_report = verify_docs(doc_paths)
    plugin_report = verify_plugin_doc(plugin_doc, plugin_index)
    ok = not any(item["errors"] for item in docs_report) and not plugin_report["missing_from_docs"] and not plugin_report["stale_in_docs"]
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ok": ok,
        "docs": docs_report,
        "plugin_doc": plugin_report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify docs examples and plugin tool references stay current.")
    parser.add_argument("--plugin-index", default=str(DEFAULT_PLUGIN_INDEX), help="Path to the OpenClaw plugin index.ts file")
    parser.add_argument(
        "--plugin-doc",
        default="docs/OpenClaw-Plugin.md",
        help="Plugin docs page to compare against the plugin tool registry",
    )
    parser.add_argument(
        "docs",
        nargs="*",
        help="Optional docs files to validate. Defaults to the main getting-started/triage/plugin pages.",
    )
    args = parser.parse_args(argv)

    doc_paths = [Path(item) for item in args.docs] if args.docs else DEFAULT_DOCS
    plugin_index = Path(args.plugin_index).expanduser().resolve()
    report = build_report(doc_paths, Path(args.plugin_doc), plugin_index)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
