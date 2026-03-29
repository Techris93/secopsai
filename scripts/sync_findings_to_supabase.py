#!/usr/bin/env python3
"""Sync local SecOpsAI findings into the dashboard Supabase `findings` table.

Source priority:
1. Local SOC SQLite store (`soc_store.py` schema)
2. Latest generated findings bundle JSON (`openclaw-findings-*.json`)

Environment:
- SUPABASE_URL (required)
- SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY (required)

Examples:
  python3 scripts/sync_findings_to_supabase.py
  SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... python3 scripts/sync_findings_to_supabase.py
  python3 scripts/sync_findings_to_supabase.py --dashboard-env ../secopsai-dashboard/.env
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable
from urllib import error, parse, request

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_FINDINGS_DIR = ROOT_DIR / "data" / "openclaw" / "findings"
DEFAULT_SOC_DB = DEFAULT_FINDINGS_DIR / "openclaw_soc.db"
DEFAULT_DASHBOARD_ENV = ROOT_DIR.parent / "secopsai-dashboard" / ".env"


@dataclass
class LoadResult:
    source_kind: str
    source_path: str | None
    findings: list[dict[str, Any]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync SecOpsAI findings to Supabase")
    parser.add_argument("--db-path", default=str(DEFAULT_SOC_DB), help="Path to local SOC SQLite DB")
    parser.add_argument("--findings-dir", default=str(DEFAULT_FINDINGS_DIR), help="Directory containing openclaw-findings-*.json bundles")
    parser.add_argument("--dashboard-env", default=str(DEFAULT_DASHBOARD_ENV), help="Optional .env file to load Supabase credentials from")
    parser.add_argument("--supabase-url", default=None, help="Override Supabase URL")
    parser.add_argument("--supabase-key", default=None, help="Override Supabase API key (service role preferred)")
    parser.add_argument("--table", default="findings", help="Supabase table name")
    parser.add_argument("--dry-run", action="store_true", help="Print payload summary without writing")
    return parser.parse_args()


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    loaded: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        loaded[key.strip()] = value.strip().strip('"').strip("'")
    return loaded


def resolve_supabase_config(args: argparse.Namespace) -> tuple[str, str]:
    env_from_file = load_env_file(Path(args.dashboard_env)) if args.dashboard_env else {}
    url = args.supabase_url or os.environ.get("SUPABASE_URL") or env_from_file.get("SUPABASE_URL")
    key = (
        args.supabase_key
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or env_from_file.get("SUPABASE_SERVICE_ROLE_KEY")
        or os.environ.get("SUPABASE_ANON_KEY")
        or env_from_file.get("SUPABASE_ANON_KEY")
    )
    if not url:
        raise SystemExit("Missing SUPABASE_URL. Pass --supabase-url, export it, or provide it in dashboard .env.")
    if not key:
        raise SystemExit("Missing Supabase key. Prefer SUPABASE_SERVICE_ROLE_KEY; SUPABASE_ANON_KEY is accepted as fallback.")
    return url.rstrip("/"), key


def load_findings_from_db(db_path: Path) -> LoadResult | None:
    if not db_path.exists():
        return None
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            select finding_id, title, summary, severity, severity_score, status,
                   disposition, source, first_seen, last_seen, created_at, updated_at, payload_json
            from findings
            order by updated_at desc, created_at desc
            """
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise SystemExit(f"Failed to read findings DB {db_path}: {exc}") from exc
    finally:
        connection.close()

    findings: list[dict[str, Any]] = []
    for row in rows:
        payload: dict[str, Any] = {}
        raw_payload = row["payload_json"]
        if raw_payload:
            try:
                payload = json.loads(str(raw_payload))
            except json.JSONDecodeError:
                payload = {}
        merged = dict(payload)
        merged.update({
            "finding_id": row["finding_id"],
            "title": row["title"],
            "summary": row["summary"],
            "severity": row["severity"],
            "severity_score": row["severity_score"],
            "status": row["status"],
            "disposition": row["disposition"],
            "source": row["source"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
        findings.append(merged)

    return LoadResult("sqlite", str(db_path), findings)


def load_findings_from_latest_bundle(findings_dir: Path) -> LoadResult | None:
    if not findings_dir.exists():
        return None
    bundles = sorted(findings_dir.glob("openclaw-findings-*.json"))
    if not bundles:
        return None
    latest = bundles[-1]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse findings bundle {latest}: {exc}") from exc
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        findings = []
    return LoadResult("bundle", str(latest), findings)


def load_local_findings(db_path: Path, findings_dir: Path) -> LoadResult:
    db_result = load_findings_from_db(db_path)
    if db_result and db_result.findings:
        return db_result
    bundle_result = load_findings_from_latest_bundle(findings_dir)
    if bundle_result and bundle_result.findings:
        return bundle_result
    if db_result:
        return db_result
    if bundle_result:
        return bundle_result
    return LoadResult("none", None, [])


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value


def compact_fingerprint(finding: dict[str, Any]) -> str | None:
    for key in ("fingerprint", "dedupe_key", "finding_id", "rule_id"):
        value = finding.get(key)
        if value:
            return str(value)
    event_ids = finding.get("event_ids")
    if isinstance(event_ids, list) and event_ids:
        return ",".join(str(v) for v in event_ids[:3])
    return None


def normalize_confidence(finding: dict[str, Any]) -> float | None:
    for key in ("confidence", "confidence_score", "score"):
        value = finding.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def normalize_row(finding: dict[str, Any]) -> dict[str, Any] | None:
    external_finding_id = finding.get("finding_id") or finding.get("id")
    if not external_finding_id:
        return None

    source = finding.get("source")
    source_name = None
    if isinstance(source, str) and source:
        source_name = Path(source).name

    row = {
        "external_finding_id": str(external_finding_id),
        "title": str(finding.get("title") or finding.get("rule_name") or finding.get("name") or "Untitled finding"),
        "summary": finding.get("summary") or finding.get("description") or None,
        "severity": str(finding.get("severity") or "low"),
        "severity_score": finding.get("severity_score"),
        "status": str(finding.get("status") or finding.get("triage_status") or "open"),
        "disposition": finding.get("disposition"),
        "confidence": normalize_confidence(finding),
        "source": source,
        "source_name": source_name,
        "detector": finding.get("rule_name") or finding.get("detector") or None,
        "fingerprint": compact_fingerprint(finding),
        "dedupe_key": finding.get("dedupe_key") or finding.get("finding_id") or None,
        "detected_at": finding.get("first_seen") or finding.get("detected_at") or finding.get("created_at"),
        "first_seen_at": finding.get("first_seen") or finding.get("detected_at") or finding.get("created_at"),
        "last_seen_at": finding.get("last_seen") or finding.get("updated_at") or finding.get("created_at"),
        "rule_id": finding.get("rule_id"),
        "rule_name": finding.get("rule_name"),
        "mitre": finding.get("mitre"),
        "event_count": finding.get("event_count"),
        "event_ids": to_jsonable(finding.get("event_ids") or []),
        "recommended_actions": to_jsonable(finding.get("recommended_actions") or []),
        "raw_payload": to_jsonable(finding),
    }
    return row


def chunked(values: Iterable[dict[str, Any]], size: int) -> Iterable[list[dict[str, Any]]]:
    batch: list[dict[str, Any]] = []
    for value in values:
        batch.append(value)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def postgrest_upsert(url: str, key: str, table: str, rows: list[dict[str, Any]]) -> tuple[int, str]:
    endpoint = f"{url}/rest/v1/{table}?on_conflict=external_finding_id"
    data = json.dumps(rows).encode("utf-8")
    req = request.Request(
        endpoint,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        },
    )
    try:
        with request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Supabase upsert failed ({exc.code}): {body}") from exc
    except error.URLError as exc:
        raise SystemExit(f"Supabase request failed: {exc}") from exc


def main() -> int:
    args = parse_args()
    result = load_local_findings(Path(args.db_path), Path(args.findings_dir))
    normalized = [row for row in (normalize_row(f) for f in result.findings) if row]

    print(f"source_kind={result.source_kind}")
    print(f"source_path={result.source_path or ''}")
    print(f"local_findings={len(result.findings)}")
    print(f"normalized_rows={len(normalized)}")

    if not normalized:
        print("No local findings found. Nothing to sync.")
        return 0

    if args.dry_run:
        sample = normalized[0]
        print("dry_run=true")
        print("sample_external_finding_id=" + str(sample.get("external_finding_id", "")))
        print("sample_title=" + str(sample.get("title", "")))
        return 0

    url, key = resolve_supabase_config(args)

    synced = 0
    for batch in chunked(normalized, 100):
        status, _body = postgrest_upsert(url, key, args.table, batch)
        if status not in (200, 201, 204):
            raise SystemExit(f"Unexpected Supabase status: {status}")
        synced += len(batch)

    print(f"synced_rows={synced}")
    print(f"supabase_table={args.table}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
