"""Bounded production delivery recovery; no registry scans, analysis or model jobs."""
from __future__ import annotations

import json
import os
import signal
import time
from datetime import datetime, timezone

import soc_store
from secopsai.core_edge_client import coordinator_client
from secopsai.research_operation_store import read_connection
from secopsai.worker_control import WorkerShutdown, check_shutdown, request_shutdown


def verify_delivery(*, db_path=None, client=None, seconds=840, retry_source_names=()):
    from secopsai.ontology import materialize_recent
    from secopsai.research_operation import hosted_projection
    from secopsai.research_primary_intel import collect_due

    if not 1 <= seconds <= 840:
        raise ValueError("delivery verification budget must be 1–840 seconds")
    deadline = time.monotonic() + seconds
    client = client or coordinator_client()
    if not client.enabled:
        raise ValueError("Core delivery is not configured")
    soc_store.init_db(db_path)
    source_results = []
    if retry_source_names:
        requested = {name.strip().casefold() for name in retry_source_names if name.strip()}
        with read_connection(db_path) as connection:
            rows = connection.execute("SELECT source_id,config_json,consecutive_failures FROM research_intel_sources").fetchall()
        selected = [(row, json.loads(row['config_json'])) for row in rows
                    if json.loads(row['config_json'])['name'].casefold() in requested]
        if {config['name'].casefold() for _, config in selected} != requested or any(not config['enabled'] for _, config in selected):
            raise ValueError("source recovery requires existing enabled source names")
        eligible = [row['source_id'] for row, _ in selected if row['consecutive_failures'] > 0]
        if len(eligible) > 10:
            raise ValueError("source recovery permits at most ten failed sources")
        if eligible:
            source_results = collect_due(db_path=db_path, force_source_ids=tuple(eligible), limit=len(eligible))['results']
    snapshot = materialize_recent(db_path=db_path, limit=100)['snapshot']
    queued = client.enqueue_ontology_snapshot(snapshot, db_path=db_path)
    if queued.get('status') != 'queued':
        raise ValueError("current ontology snapshot could not be durably queued")
    delivery = {'pending': None, 'failed': 0, 'flushed': 0}
    flushed_total = 0
    while time.monotonic() < deadline:
        check_shutdown()
        remaining = deadline - time.monotonic()
        delivery = client.flush_ontology_outbox(db_path=db_path, max_items=100, seconds=min(120, remaining))
        flushed_total += int(delivery.get('flushed', 0))
        print(json.dumps({'event': 'delivery_verification_batch', **{key: delivery.get(key) for key in
                         ('status', 'flushed', 'failed', 'pending', 'http_status', 'error')}}), flush=True)
        if delivery.get('pending') == 0:
            break
        if delivery.get('http_status') in {400, 401, 403}:
            break  # do not retry invalid envelopes or authorization failures
        if delivery.get('http_status') in {409, 422} and not delivery.get('flushed'):
            # A later entity batch may repair a missing endpoint for an older
            # relationship. Respect each rejected row's backoff while allowing
            # still-due, unattempted work through before declaring it invalid.
            with read_connection(db_path) as connection:
                due = connection.execute("SELECT count(*) FROM ontology_sync_outbox WHERE status='queued' AND next_attempt_at<=?", (soc_store.utc_now(),)).fetchone()[0]
            if not due:
                break
            continue
        if not delivery.get('flushed'):
            # Respect durable retry times instead of resubmitting hot loops.
            with read_connection(db_path) as connection:
                row = connection.execute("SELECT min(next_attempt_at) FROM ontology_sync_outbox WHERE status='queued'").fetchone()
            due = datetime.fromisoformat(row[0].replace('Z', '+00:00')) if row and row[0] else datetime.now(timezone.utc)
            wait = max(1, (due - datetime.now(timezone.utc)).total_seconds())
            if time.monotonic() + wait >= deadline:
                break
            time.sleep(min(wait, 30))
    projection = hosted_projection(db_path=db_path)
    stored = client.sync_research_operation(projection)
    accepted = delivery.get('pending') == 0 and stored.get('status') == 'stored'
    sources_ok = all(item.get('status') == 'acquired' for item in source_results)
    report = {'status': 'passed' if accepted and sources_ok else 'failed', 'flushed_total': flushed_total,
              'pending': delivery.get('pending'), 'projection_status': stored.get('status'),
              'health': projection.get('coverage', {}).get('health', {}),
              'sources_retried': len(source_results), 'source_failures': sum(item.get('status') != 'acquired' for item in source_results),
              'registry_scans_performed': False, 'analysis_performed': False, 'model_jobs_created': 0,
              'clef_enabled': projection.get('clef_enabled'), 'decision_mode': projection.get('decision_mode')}
    print(json.dumps({'event': 'delivery_verification_completed', **report}), flush=True)
    return report


def main():
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda _signum, _frame: request_shutdown())
    try:
        if os.environ.pop('SECOPSAI_RESTORED_LEDGER_RECOVERY', '0') == '1':
            from secopsai.daily_automation import recover_interrupted_runs
            recover_interrupted_runs(db_path=None, restored_snapshot=True)
        report = verify_delivery(retry_source_names=tuple(name.strip() for name in os.environ.get('SECOPSAI_VERIFY_RETRY_SOURCES', '').split(',') if name.strip()))
        return 0 if report['status'] == 'passed' else 1
    except (Exception, WorkerShutdown) as exc:
        print(json.dumps({'event': 'delivery_verification_failed', 'error_category': type(exc).__name__, 'http_status': getattr(exc, 'status', None)}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
