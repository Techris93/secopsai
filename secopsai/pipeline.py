from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import export_real_openclaw_native
import ingest_openclaw
import openclaw_prepare
import evaluate_openclaw
import openclaw_findings


@dataclass
class RefreshResult:
    exported: bool
    wrote_audit_jsonl: str
    wrote_labeled: str
    wrote_unlabeled: str
    findings_file: str
    findings_db: str
    total_findings: int
    total_detections: int
    sync_attempted: bool
    sync_succeeded: bool


def refresh(
    *,
    skip_export: bool = False,
    verbose: bool = False,
    openclaw_home: Optional[str] = None,
) -> RefreshResult:
    """Run the local OpenClaw live pipeline end-to-end and persist findings.

    Pretty output is handled by the CLI; this returns structured results.
    """
    if openclaw_home:
        os.environ["OPENCLAW_HOME"] = openclaw_home

    if not skip_export:
        export_real_openclaw_native.main()
        exported = True
    else:
        exported = False

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    native_dir = os.path.join(root_dir, "data", "openclaw", "native")
    raw_audit = os.path.join(root_dir, "data", "openclaw", "raw", "audit.jsonl")
    labeled_out = os.path.join(root_dir, "data", "openclaw", "replay", "labeled", "current.json")
    unlabeled_out = os.path.join(root_dir, "data", "openclaw", "replay", "unlabeled", "current.json")

    surface_paths = ingest_openclaw._resolve_surface_paths(  # type: ignore[attr-defined]
        type(
            "Args",
            (),
            {
                "input_root": native_dir,
                "agent_events": [],
                "session_hooks": [],
                "subagent_hooks": [],
                "pairing_events": [],
                "skills_events": [],
                "config_audit": [],
                "exec_events": [],
                "restart_sentinels": [],
            },
        )()
    )
    records = ingest_openclaw.collect_records(  # type: ignore[attr-defined]
        surface_paths,
        host=ingest_openclaw.DEFAULT_HOST,  # type: ignore[attr-defined]
        privacy_profile="openclaw-local-v1",
        collected_from="secopsai.refresh",
    )
    os.makedirs(os.path.dirname(raw_audit), exist_ok=True)
    ingest_openclaw.common.write_jsonl(raw_audit, records, append=False)  # type: ignore[attr-defined]

    audit_schema = openclaw_prepare.load_json(
        os.path.join(root_dir, "schemas", "openclaw_audit.schema.json")
    )
    normalized_schema = openclaw_prepare.load_json(
        os.path.join(root_dir, "schemas", "normalized_event.schema.json")
    )
    raw_records = openclaw_prepare.load_records(raw_audit)

    flat_records = []
    for record in raw_records:
        openclaw_prepare.validate_adapter_record(record, audit_schema)
        normalized, flat = openclaw_prepare.normalize_record(record)
        openclaw_prepare.validate_normalized_record(normalized, normalized_schema)
        flat_records.append(flat)

    os.makedirs(os.path.dirname(labeled_out), exist_ok=True)
    openclaw_prepare.secure_write_json(labeled_out, flat_records, indent=2)
    openclaw_prepare.secure_write_json(
        unlabeled_out, openclaw_prepare.strip_labels(flat_records), indent=2
    )

    detection_result = evaluate_openclaw.run_detection(flat_records)
    total_detections = detection_result["total_detections"]

    bundle = openclaw_findings.build_bundle(labeled_out, flat_records)
    findings_dir = openclaw_findings.default_output_dir()
    findings_file = openclaw_findings.write_bundle(findings_dir, bundle)
    findings_db = openclaw_findings.soc_store.persist_findings(
        bundle["findings"],
        bundle["source"],
        openclaw_findings.default_db_path(findings_dir),
    )
    sync_attempted = openclaw_findings.auto_sync_config_available()
    sync_succeeded = openclaw_findings.maybe_sync_findings_to_supabase(
        db_path=findings_db,
        findings_dir=findings_dir,
    )

    return RefreshResult(
        exported=exported,
        wrote_audit_jsonl=raw_audit,
        wrote_labeled=labeled_out,
        wrote_unlabeled=unlabeled_out,
        findings_file=findings_file,
        findings_db=findings_db,
        total_findings=bundle["total_findings"],
        total_detections=total_detections,
        sync_attempted=sync_attempted,
        sync_succeeded=sync_succeeded,
    )
