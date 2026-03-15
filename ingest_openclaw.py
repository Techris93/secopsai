"""
Batch OpenClaw surface ingester.

Reads JSONL exports from OpenClaw native surfaces and writes an
openclaw-audit-v1 JSONL bundle that can be fed into openclaw_prepare.py.
"""

from __future__ import annotations

import argparse
import os
from collections import Counter
from typing import Callable, Dict, Iterable, List

import openclaw_prepare
from openclaw_adapters import common, config_events, restart_events, session_hooks, subagent_hooks, tool_events


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT = os.path.join(ROOT_DIR, "data", "openclaw", "raw", "audit.jsonl")
DEFAULT_HOST = os.uname().nodename

ADAPTERS: Dict[str, tuple[str, Callable[..., List[dict[str, object]]]]] = {
    "agent_events": ("agent-events.jsonl", tool_events.adapt),
    "session_hooks": ("session-hooks.jsonl", session_hooks.adapt),
    "subagent_hooks": ("subagent-hooks.jsonl", subagent_hooks.adapt),
    "config_audit": ("config-audit.jsonl", config_events.adapt),
    "restart_sentinels": ("restart-sentinels.jsonl", restart_events.adapt),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest OpenClaw native surfaces into audit.jsonl")
    parser.add_argument("--input-root", help="Directory containing native surface JSONL exports")
    parser.add_argument("--agent-events", action="append", default=[], help="Path to agent event JSONL (repeatable)")
    parser.add_argument("--session-hooks", action="append", default=[], help="Path to session hook JSONL (repeatable)")
    parser.add_argument("--subagent-hooks", action="append", default=[], help="Path to subagent hook JSONL (repeatable)")
    parser.add_argument("--config-audit", action="append", default=[], help="Path to config audit JSONL (repeatable)")
    parser.add_argument("--restart-sentinels", action="append", default=[], help="Path to restart sentinel JSONL (repeatable)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output audit JSONL path")
    parser.add_argument("--append", action="store_true", help="Append to the output file instead of replacing it")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host name to stamp into collector metadata")
    parser.add_argument("--privacy-profile", default="openclaw-local-v1", help="Collector privacy profile")
    parser.add_argument("--collected-from", default="ingest_openclaw.py", help="Collector source label")
    parser.add_argument("--stats", action="store_true", help="Print counts by surface and source path")
    return parser.parse_args()


def _resolve_surface_paths(args: argparse.Namespace) -> Dict[str, List[str]]:
    surface_paths = {
        "agent_events": list(args.agent_events),
        "session_hooks": list(args.session_hooks),
        "subagent_hooks": list(args.subagent_hooks),
        "config_audit": list(args.config_audit),
        "restart_sentinels": list(args.restart_sentinels),
    }

    if args.input_root:
        for surface_name, (default_filename, _adapter) in ADAPTERS.items():
            inferred = os.path.join(args.input_root, default_filename)
            if os.path.exists(inferred):
                surface_paths[surface_name].append(inferred)

    return {surface: paths for surface, paths in surface_paths.items() if paths}


def collect_records(surface_paths: Dict[str, List[str]], host: str, privacy_profile: str, collected_from: str) -> List[dict[str, object]]:
    audit_schema = openclaw_prepare.load_json(os.path.join(ROOT_DIR, "schemas", "openclaw_audit.schema.json"))
    collected: List[dict[str, object]] = []

    for surface_name, paths in surface_paths.items():
        _default_filename, adapter = ADAPTERS[surface_name]
        for path in paths:
            native_records = common.load_jsonl(path)
            adapted = adapter(native_records, path, collected_from, host, privacy_profile)
            for record in adapted:
                openclaw_prepare.validate_adapter_record(record, audit_schema)
            collected.extend(adapted)

    collected.sort(key=lambda record: str(record["ts"]))
    return collected


def print_stats(records: Iterable[dict[str, object]]) -> None:
    records = list(records)
    surface_counter = Counter(str(record.get("surface", "unknown")) for record in records)
    origin_counter = Counter(str(record.get("openclaw", {}).get("origin", "unknown")) for record in records)

    print(f"records={len(records)}")
    print("surfaces:")
    for surface, count in sorted(surface_counter.items()):
        print(f"  {surface}: {count}")
    print("origins:")
    for origin, count in sorted(origin_counter.items()):
        print(f"  {origin}: {count}")


def main() -> int:
    args = parse_args()
    surface_paths = _resolve_surface_paths(args)
    if not surface_paths:
        print("error: no input surface files were provided or discovered")
        return 1

    records = collect_records(surface_paths, args.host, args.privacy_profile, args.collected_from)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    common.write_jsonl(args.output, records, append=args.append)

    if args.stats:
        print_stats(records)

    print(f"wrote_records={len(records)}")
    print(f"output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())