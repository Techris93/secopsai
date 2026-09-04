#!/usr/bin/env python3
"""Build a D1 SQL import from a sanitized Core workspace backup."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def quote(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def record_id(kind: str, row: dict[str, Any], index: int) -> str:
    for key in ("finding_id", "node_id", "source_instance", "id"):
        if row.get(key):
            return str(row[key])
    return f"{kind}-{index}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=Path)
    parser.add_argument("audit_logs", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    workspace = json.loads(args.workspace.read_text(encoding="utf-8"))
    audit = json.loads(args.audit_logs.read_text(encoding="utf-8"))
    generated_at = str(workspace.get("generated_at") or "")
    # Wrangler executes uploaded D1 files atomically and rejects explicit
    # transaction statements in import SQL.
    lines: list[str] = []
    for key in ("schema_version", "data_classification", "summary", "changes"):
        lines.append(
            "INSERT INTO core_metadata(key,value_json,updated_at) VALUES "
            f"({quote(key)},{quote(json.dumps(workspace.get(key), separators=(',', ':')))},{quote(generated_at)}) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at;"
        )
    for kind in ("assets", "findings", "sites", "sensors", "services", "wifi_networks", "sync_state"):
        for index, row in enumerate(workspace.get(kind) or []):
            updated_at = str(row.get("updated_at") or row.get("last_seen") or generated_at)
            lines.append(
                "INSERT INTO workspace_records(record_type,record_id,payload_json,updated_at) VALUES "
                f"({quote(kind)},{quote(record_id(kind, row, index))},{quote(json.dumps(row, separators=(',', ':')))},{quote(updated_at)}) "
                "ON CONFLICT(record_type,record_id) DO UPDATE SET payload_json=excluded.payload_json,updated_at=excluded.updated_at;"
            )
    for row in workspace.get("research_alerts") or []:
        evidence = json.dumps(row.get("evidence") or {}, separators=(",", ":"))
        occurred_at = str(row.get("occurred_at") or row.get("created_at") or generated_at)
        created_at = str(row.get("created_at") or generated_at)
        updated_at = str(row.get("updated_at") or created_at)
        alert_id = str(row.get("alert_id") or "")
        lines.append(
            "INSERT INTO research_alerts(alert_id,source_alert_id,alert_type,severity,candidate_id,campaign_id,reason,evidence_json,status,owner,occurred_at,created_at,updated_at) VALUES "
            f"({quote(alert_id)},{quote(alert_id)},{quote(row.get('alert_type',''))},{quote(row.get('severity',''))},'', '',{quote(row.get('reason',''))},{quote(evidence)},{quote(row.get('status','open'))},{quote(row.get('owner',''))},{quote(occurred_at)},{quote(created_at)},{quote(updated_at)}) "
            "ON CONFLICT(source_alert_id) DO NOTHING;"
        )
    for row in audit.get("audit_logs") or []:
        details = row.get("details") if "details" in row else row.get("details_json", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {"message": details}
        lines.append(
            "INSERT INTO audit_logs(request_id,action,actor_role,result,source_instance,details_json,created_at) VALUES "
            f"({quote(row.get('request_id','migration'))},{quote(row.get('action','legacy.import'))},{quote(row.get('actor_role','migration'))},{quote(row.get('result','imported'))},{quote(row.get('source_instance','render-core-api'))},{quote(json.dumps(details, separators=(',', ':')))},{quote(row.get('created_at',generated_at))});"
        )
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "workspace_records": sum(len(workspace.get(kind) or []) for kind in ("assets", "findings", "sites", "sensors", "services", "wifi_networks", "sync_state")), "research_alerts": len(workspace.get("research_alerts") or []), "audit_logs": len(audit.get("audit_logs") or [])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
