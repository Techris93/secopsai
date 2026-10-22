"""Bounded production recovery with no analysis or model jobs."""
from __future__ import annotations

import json
import os
import re
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

import soc_store
from secopsai.core_edge_client import coordinator_client
from secopsai.research_operation_store import read_connection
from secopsai.worker_control import WorkerShutdown, check_shutdown, request_shutdown


def _refresh_stale_enabled_sources(*, db_path, deadline, safety_margin_seconds=0):
    """Refresh stale or near-expiry enabled feeds before the shutdown checkpoint."""
    from secopsai.research_coverage import stale_enabled_sources

    stale = stale_enabled_sources(db_path=db_path, safety_margin_seconds=safety_margin_seconds)
    source_results = []
    collector_results = []
    primary = stale["intel_sources"]
    if primary:
        from secopsai.research_primary_intel import collect_due

        for offset in range(0, len(primary), 10):
            batch = primary[offset:offset + 10]
            if time.monotonic() >= deadline:
                source_results.extend({"source_id": item["source_id"], "status": "deferred_budget"}
                                      for item in primary[offset:])
                break
            outcome = collect_due(
                db_path=db_path,
                limit=len(batch),
                force_source_ids=tuple(item["source_id"] for item in batch),
            )
            completed = outcome.get("results", [])
            source_results.extend(completed)
            returned_ids = {item.get("source_id") for item in completed}
            source_results.extend({"source_id": item["source_id"], "status": "not_attempted"}
                                  for item in batch if item["source_id"] not in returned_ids)

    registry = stale["registry_collectors"]
    if registry:
        from secopsai.research_surveillance import run_registry_collector
        from secopsai.research_worker import MAX_PAGES_PER_CYCLE, collector_page_budget

        for index, item in enumerate(registry):
            if time.monotonic() >= deadline:
                collector_results.extend({"name": pending["name"], "ecosystem": pending["ecosystem"],
                                          "status": "deferred_budget", "coverage": None}
                                         for pending in registry[index:])
                break
            result = run_registry_collector(
                ecosystem=item["ecosystem"],
                max_pages=collector_page_budget(item["ecosystem"], MAX_PAGES_PER_CYCLE),
                db_path=db_path,
            )
            collector_results.append({
                "name": item["name"], "ecosystem": item["ecosystem"],
                "status": result.get("status"), "coverage": result.get("coverage"),
                "pages_selected": result.get("pages_selected", 0),
                "pages_processed": result.get("pages_processed", 0),
                "events_stored": result.get("events_stored", 0),
                "error_category": "collector_error" if result.get("error") else None,
            })
            print(json.dumps({"event": "stale_registry_collector_refresh", **collector_results[-1]}), flush=True)
    return source_results, collector_results


def verify_delivery(*, db_path=None, client=None, seconds=840, retry_source_names=(), retry_collector_names=(), require_zero=False,
                    refresh_stale_sources=False, refresh_seconds=840, freshness_safety_margin_seconds=300):
    from secopsai.ontology import materialize_recent
    from secopsai.research_operation import hosted_projection
    from secopsai.research_primary_intel import collect_due

    if not 1 <= seconds <= 2700:
        raise ValueError("delivery verification budget must be 1–2700 seconds")
    if refresh_stale_sources and not 1 <= refresh_seconds <= 2700:
        raise ValueError("stale-source refresh budget must be 1–2700 seconds")
    if (not isinstance(freshness_safety_margin_seconds, int)
            or not 0 <= freshness_safety_margin_seconds <= 3600):
        raise ValueError("freshness safety margin must be 0–3600 seconds")
    deadline = time.monotonic() + seconds
    client = client or coordinator_client()
    if not client.enabled:
        raise ValueError("Core delivery is not configured")
    soc_store.init_db(db_path)
    stale_source_results = []
    stale_collector_results = []
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
    collector_results = []
    if retry_collector_names:
        requested = {name.strip().casefold() for name in retry_collector_names if name.strip()}
        if not requested or len(requested) > 10:
            raise ValueError("registry collector recovery permits one to ten named collectors")
        from secopsai.research_surveillance import (
            MAX_REGISTRY_PAGES_PER_RUN,
            ensure_collectors,
            run_registry_collector,
        )
        from secopsai.research_worker import MAX_PAGES_PER_CYCLE, collector_page_budget

        collectors = ensure_collectors(db_path=db_path)
        selected = [collector for collector in collectors if collector['name'].strip().casefold() in requested]
        if {collector['name'].strip().casefold() for collector in selected} != requested:
            raise ValueError("registry collector recovery requires an existing collector name")
        if any(not bool(collector['enabled']) for collector in selected):
            raise ValueError("registry collector recovery requires an enabled collector")
        for collector in selected:
            if time.monotonic() >= deadline:
                raise TimeoutError("registry collector recovery exceeded the delivery verification budget")
            # An explicitly requested catch-up may drain a Crates.io backlog
            # beyond the routine worker's smaller per-cycle page budget.
            max_pages = (
                MAX_REGISTRY_PAGES_PER_RUN
                if collector['ecosystem'] == 'crates'
                else collector_page_budget(collector['ecosystem'], MAX_PAGES_PER_CYCLE)
            )
            result = run_registry_collector(
                ecosystem=collector['ecosystem'],
                max_pages=max_pages,
                db_path=db_path,
            )
            collector_results.append({
                'name': collector['name'],
                'ecosystem': collector['ecosystem'],
                'status': result.get('status'),
                'coverage': result.get('coverage'),
                'pages_selected': result.get('pages_selected', 0),
                'pages_processed': result.get('pages_processed', 0),
                'events_stored': result.get('events_stored', 0),
                'error_category': 'collector_error' if result.get('error') else None,
            })
            print(json.dumps({'event': 'registry_collector_recovery_result', **collector_results[-1]}), flush=True)
            if time.monotonic() >= deadline:
                raise TimeoutError("registry collector recovery exceeded the delivery verification budget")
    snapshot = materialize_recent(db_path=db_path, limit=100)['snapshot']
    queued = client.enqueue_ontology_snapshot(snapshot, db_path=db_path)
    if queued.get('status') != 'queued':
        raise ValueError("current ontology snapshot could not be durably queued")
    delivery = {'pending': None, 'failed': 0, 'flushed': 0}
    flushed_total = 0
    while time.monotonic() < deadline:
        check_shutdown()
        remaining = deadline - time.monotonic()
        if remaining < 15:
            # Leave enough time for one complete coordinator request. Passing
            # a tiny final slice to the client can manufacture a timeout and
            # put an otherwise healthy outbox row into exponential backoff.
            break
        delivery = client.flush_ontology_outbox(db_path=db_path, max_items=100, seconds=min(120, remaining))
        flushed_total += int(delivery.get('flushed', 0))
        print(json.dumps({'event': 'delivery_verification_batch', **{key: delivery.get(key) for key in
                         ('status', 'attempted', 'flushed', 'failed', 'pending', 'due_pending', 'deferred',
                          'oldest_pending_age_seconds', 'max_attempts', 'validation_failures',
                          'authorization_failures', 'http_status', 'error')}}), flush=True)
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
    # Refresh after the potentially long delivery drain, immediately before
    # the projection. The supervisor's shutdown checkpoint then persists any
    # newly acquired source state before the workflow publishes its final view.
    if refresh_stale_sources:
        stale_source_results, stale_collector_results = _refresh_stale_enabled_sources(
            db_path=db_path,
            deadline=deadline + refresh_seconds,
            safety_margin_seconds=freshness_safety_margin_seconds,
        )
    projection = hosted_projection(db_path=db_path)
    stored = client.sync_research_operation(projection)
    health = projection.get('coverage', {}).get('health', {})
    source_freshness_gaps = health.get('freshness_gaps') or []
    pending = delivery.get('pending')
    if pending is None:
        pending = health.get('ontology_pending')
    acknowledged = pending == 0 and stored.get('status') == 'stored'
    delivery_in_progress = False
    delivery_blockers = []
    if stored.get('status') != 'stored':
        delivery_blockers.append('hosted operation projection was not durably stored')
    if pending:
        oldest_age = health.get('ontology_oldest_age_seconds')
        last_ack = health.get('ontology_last_acknowledged_at')
        last_ack_age = None
        if last_ack:
            parsed_ack = datetime.fromisoformat(str(last_ack).replace('Z', '+00:00'))
            if parsed_ack.tzinfo:
                last_ack_age = max(0, (datetime.now(timezone.utc) - parsed_ack).total_seconds())
        if require_zero:
            delivery_blockers.append('strict delivery verification requires zero pending chunks')
        elif health.get('dead_letters'):
            delivery_blockers.append('dead-letter delivery work requires review')
        elif health.get('ontology_validation_failures') or health.get('ontology_authorization_failures'):
            delivery_blockers.append('delivery contains rejected or unauthorized work')
        elif oldest_age is None:
            delivery_blockers.append('pending delivery age is not measurable')
        elif oldest_age > 2 * 60 * 60:
            delivery_blockers.append('oldest delivery exceeds the two-hour service window')
        elif last_ack_age is not None and last_ack_age > 60 * 60:
            delivery_blockers.append('delivery has stopped acknowledging work for over one hour')
        elif stored.get('status') == 'stored':
            delivery_in_progress = True
    sources_ok = all(item.get('status') == 'acquired' for item in source_results)
    collectors_ok = all(
        item.get('status') == 'completed' and item.get('coverage') == 'complete'
        for item in [*collector_results, *stale_collector_results]
    )
    stale_sources_ok = all(item.get('status') == 'acquired' for item in stale_source_results)
    source_freshness_ok = not refresh_stale_sources or not source_freshness_gaps
    if refresh_stale_sources and source_freshness_gaps:
        delivery_blockers.append('enabled sources remain outside freshness targets: ' + ', '.join(source_freshness_gaps))
    if not stale_sources_ok:
        delivery_blockers.append('one or more stale primary sources could not be refreshed')
    if any(not (item.get('status') == 'completed' and item.get('coverage') == 'complete')
           for item in stale_collector_results):
        delivery_blockers.append('one or more stale registry collectors did not complete fully')
    report = {'status': ('passed' if acknowledged else 'in_progress' if delivery_in_progress else 'failed')
              if sources_ok and collectors_ok and stale_sources_ok and source_freshness_ok else 'failed', 'flushed_total': flushed_total,
              'pending': pending, 'delivery_blockers': delivery_blockers, 'projection_status': stored.get('status'),
              'health': health,
              'sources_retried': len(source_results), 'source_failures': sum(item.get('status') != 'acquired' for item in source_results),
              'stale_sources_refreshed': len(stale_source_results),
              'stale_source_refresh_failures': sum(item.get('status') != 'acquired' for item in stale_source_results),
              'stale_source_refresh_results': stale_source_results,
              'freshness_safety_margin_seconds': freshness_safety_margin_seconds if refresh_stale_sources else 0,
              'registry_collectors_retried': len(collector_results),
              'registry_collector_failures': sum(
                  not (item.get('status') == 'completed' and item.get('coverage') == 'complete')
                  for item in collector_results
              ),
              'registry_collectors_refreshed': len(stale_collector_results),
              'registry_collector_refresh_failures': sum(
                  not (item.get('status') == 'completed' and item.get('coverage') == 'complete')
                  for item in stale_collector_results
              ),
              'registry_collectors': [*collector_results, *stale_collector_results],
              'source_freshness_gaps': source_freshness_gaps,
              'registry_scans_performed': bool(collector_results or stale_collector_results), 'analysis_performed': False, 'model_jobs_created': 0,
              'clef_enabled': projection.get('clef_enabled'), 'decision_mode': projection.get('decision_mode')}
    print(json.dumps({'event': 'delivery_verification_completed', **report}), flush=True)
    return report


def main():
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda _signum, _frame: request_shutdown())
    try:
        if os.environ.pop('SECOPSAI_RESTORED_LEDGER_RECOVERY', '0') == '1':
            from secopsai.daily_automation import recover_interrupted_runs as recover_automation_runs
            from secopsai.research_surveillance import recover_interrupted_runs as recover_registry_runs
            automation_recovery = recover_automation_runs(db_path=None, restored_snapshot=True)
            registry_recovery = recover_registry_runs(db_path=None, restored_snapshot=True)
            print(json.dumps({
                'event': 'restored_snapshot_recovery',
                'automation_runs': automation_recovery,
                'registry_runs': registry_recovery,
            }), flush=True)
        seconds = int(os.environ.get('SECOPSAI_VERIFY_DELIVERY_SECONDS', '840'))
        report = verify_delivery(
            seconds=seconds,
            retry_source_names=tuple(name.strip() for name in os.environ.get('SECOPSAI_VERIFY_RETRY_SOURCES', '').split(',') if name.strip()),
            retry_collector_names=tuple(name.strip() for name in os.environ.get('SECOPSAI_VERIFY_RETRY_COLLECTORS', '').split(',') if name.strip()),
            require_zero=os.environ.get('SECOPSAI_VERIFY_REQUIRE_ZERO', '0') == '1',
            refresh_stale_sources=(os.environ.get('SECOPSAI_VERIFY_REFRESH_STALE_SOURCES', '0') == '1'
                                  and os.environ.get('SECOPSAI_VERIFY_DELIVERY_ONLY', '0') != '1'),
            refresh_seconds=int(os.environ.get('SECOPSAI_VERIFY_REFRESH_SECONDS', '840')),
            freshness_safety_margin_seconds=int(os.environ.get('SECOPSAI_VERIFY_FRESHNESS_MARGIN_SECONDS', '300')),
        )
        diagnostics = os.environ.get('SECOPSAI_WORKER_DIAGNOSTICS_DIR', '').strip()
        if diagnostics:
            path = Path(diagnostics) / 'delivery-drain.json'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps({'event': 'delivery_verification_completed', **report}), flush=True)
        return 0 if report['status'] in {'passed', 'in_progress'} else 1
    except (Exception, WorkerShutdown) as exc:
        error_code = getattr(exc, 'error_code', '')
        if not isinstance(error_code, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,99}', error_code):
            error_code = None
        print(json.dumps({'event': 'delivery_verification_failed', 'error_category': type(exc).__name__,
                          'http_status': getattr(exc, 'status', None), 'error_code': error_code}), flush=True)
        diagnostics = os.environ.get('SECOPSAI_WORKER_DIAGNOSTICS_DIR', '').strip()
        if diagnostics:
            path = Path(diagnostics) / 'delivery-drain.json'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'status': 'failed', 'error_category': type(exc).__name__,
                                        'http_status': getattr(exc, 'status', None), 'error_code': error_code}, indent=2), encoding='utf-8')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
