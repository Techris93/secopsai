"""Consistent recovery drills and a measured storage migration assessment.

The current single-writer checkpoint remains authoritative. This module
measures a candidate restore without replacing it or advancing source cursors.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import soc_store
from secopsai.research_operation_store import append, text
from secopsai.sqlite_writer_lock import sqlite_writer_lock


def storage_assessment(*, db_path=None) -> dict:
    path = Path(db_path or soc_store.default_db_path())
    with closing(soc_store.connect(str(path))) as conn:
        sizes = {r["name"]: r["bytes"] for r in conn.execute("SELECT name,sum(pgsize) AS bytes FROM dbstat GROUP BY name ORDER BY bytes DESC LIMIT 15")}
        snapshots = conn.execute("SELECT count(*),COALESCE(sum(length(content)),0) FROM research_source_snapshots").fetchone()
    return {"ledger_bytes": path.stat().st_size, "largest_objects_bytes": sizes,
            "source_snapshots": snapshots[0], "source_snapshot_bytes": snapshots[1],
            "metadata_journal": "research_operation_records", "candidate_metadata_store": "persistent transactional SQLite/PostgreSQL with separately durable content-addressed artifact storage",
            "migration_ready": False, "required_gates": ["consistent copy", "dual reads", "row/hash reconciliation", "lost acknowledgement recovery", "RPO/RTO drill at production size", "single-writer cutover and rollback"],
            "limitations": ["This is a measured assessment of the selected ledger, not a production migration or a demonstrated five-minute RPO."]}


def recovery_drill(*, db_path=None, output_dir: str, actor: str, production_scope: bool = False) -> dict:
    from secopsai.research_assurance import person
    person(actor, role="operator", db_path=db_path)
    source = Path(db_path or soc_store.default_db_path()).resolve()
    requested = Path(text(output_dir, "recovery output directory")).expanduser()
    if requested.is_symlink():
        raise ValueError("recovery destination must not be a symlink")
    destination_dir = requested.resolve()
    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = destination_dir / ("recovery-" + secrets.token_hex(8) + ".db")
    if destination_dir.is_symlink() or destination == source:
        raise ValueError("recovery destination must be separate from the live ledger")
    start = time.monotonic()
    destination.touch(mode=0o600, exist_ok=False)
    with sqlite_writer_lock(str(source)), closing(soc_store.connect(str(source))) as live, closing(sqlite3.connect(destination)) as recovered:
        live.backup(recovered, pages=1024)
        tables = [r[0] for r in recovered.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        counts = {}
        for name in tables:
            if not name.replace("_", "").isalnum():
                raise ValueError("unexpected table identifier")
            before = live.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
            after = recovered.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
            if before != after:
                raise ValueError("recovered row counts do not reconcile")
            counts[name] = after
        if recovered.execute("PRAGMA quick_check").fetchone()[0] != "ok" or recovered.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("recovery integrity check failed")
        for content, sha256 in recovered.execute("SELECT content,sha256 FROM research_source_snapshots"):
            if hashlib.sha256(content).hexdigest() != sha256:
                raise ValueError("recovered source bytes failed provenance validation")
    os.chmod(destination, 0o600)
    elapsed = time.monotonic() - start
    result = {"status": "passed", "scope": "selected_production_ledger" if production_scope else "selected_ledger_only",
              "restored_bytes": destination.stat().st_size, "restore_seconds": round(elapsed, 3), "reconciled_tables": len(counts),
              "source_hashes_verified": True, "foreign_keys_verified": True, "rto_target_met_for_selected_ledger": elapsed <= 3600,
              "rpo_target_proven": False, "recovery_path": str(destination),
              "limitations": ["Network checkpoint age and reacquisition gaps were not measured. This drill cannot establish production RPO or production-size RTO for a different ledger."]}
    append("recovery_drill", {k: v for k, v in result.items() if k != "recovery_path"}, actor=actor, db_path=db_path)
    return result
