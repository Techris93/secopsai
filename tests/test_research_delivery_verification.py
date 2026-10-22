import json

import soc_store
import pytest
from secopsai.research_delivery_verification import verify_delivery


def test_delivery_verification_drains_exact_backlog_and_projects_without_reanalysis(tmp_path, monkeypatch):
    db = str(tmp_path / 'delivery.db')
    snapshot = {'entities': [{'entity_id': 'pkg:pypi:synthetic'}]}
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': snapshot})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {
        'coverage': {'health': {'ontology_pending': 0, 'artifact_backup_pending': 0}}, 'clef_enabled': False, 'decision_mode': 'observe'})
    class Client:
        enabled = True
        results = iter([{'status': 'degraded', 'flushed': 1, 'pending': 2}, {'status': 'accepted', 'flushed': 2, 'pending': 0}])
        def enqueue_ontology_snapshot(self, value, **kwargs):
            assert value == snapshot
            return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs):
            assert kwargs['seconds'] <= 120
            return next(self.results)
        def sync_research_operation(self, projection):
            return {'status': 'stored'}
    result = verify_delivery(db_path=db, client=Client(), seconds=2700)
    assert result['status'] == 'passed'
    assert result['flushed_total'] == 3 and result['pending'] == 0
    assert result['model_jobs_created'] == 0 and result['registry_scans_performed'] is False
    assert result['clef_enabled'] is False and result['decision_mode'] == 'observe'


def test_delivery_verification_preserves_rejected_backlog_and_fails(tmp_path, monkeypatch):
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {'coverage': {'health': {'ontology_pending': 1}}})
    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 1, 'flushed': 0, 'http_status': 422}
        def sync_research_operation(self, value): return {'status': 'stored'}
    result = verify_delivery(db_path=str(tmp_path/'rejected.db'), client=Client())
    assert result['status'] == 'failed' and result['pending'] == 1


def test_delivery_verification_does_not_start_a_partial_final_request(tmp_path, monkeypatch):
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {'coverage': {'health': {}}})
    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): raise AssertionError('short remaining budget must not flush')
        def sync_research_operation(self, value): return {'status': 'stored'}
    result = verify_delivery(db_path=str(tmp_path/'short-budget.db'), client=Client(), seconds=1)
    assert result['status'] == 'failed'


def test_routine_delivery_accepts_fresh_pending_work_but_explicit_drain_requires_zero(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {
        'coverage': {'health': {'ontology_pending': 37, 'ontology_oldest_age_seconds': 300,
                                'ontology_last_acknowledged_at': now, 'dead_letters': 0,
                                'ontology_validation_failures': 0, 'ontology_authorization_failures': 0}}})

    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): raise AssertionError('one-second budget does not start a partial request')
        def sync_research_operation(self, value): return {'status': 'stored'}

    routine = verify_delivery(db_path=str(tmp_path / 'routine.db'), client=Client(), seconds=1)
    assert routine['status'] == 'in_progress' and routine['pending'] == 37
    assert routine['delivery_blockers'] == []

    strict = verify_delivery(db_path=str(tmp_path / 'strict.db'), client=Client(), seconds=1, require_zero=True)
    assert strict['status'] == 'failed'
    assert strict['delivery_blockers'] == ['strict delivery verification requires zero pending chunks']


def test_delivery_verification_rejects_budgets_above_workflow_limit():
    with pytest.raises(ValueError, match='1–2700 seconds'):
        verify_delivery(client=object(), seconds=2701)


def test_delivery_entrypoint_recovers_registry_runs_from_restored_snapshot(monkeypatch):
    from secopsai import daily_automation, research_delivery_verification as delivery
    from secopsai import research_surveillance

    monkeypatch.setenv('SECOPSAI_RESTORED_LEDGER_RECOVERY', '1')
    calls = []
    monkeypatch.setattr(daily_automation, 'recover_interrupted_runs',
                        lambda **kwargs: calls.append(('automation', kwargs)) or 1)
    monkeypatch.setattr(research_surveillance, 'recover_interrupted_runs',
                        lambda **kwargs: calls.append(('registry', kwargs)) or {'interrupted': 1})
    monkeypatch.setattr(delivery, 'verify_delivery', lambda **kwargs: {'status': 'passed'})

    assert delivery.main() == 0
    assert calls == [
        ('automation', {'db_path': None, 'restored_snapshot': True}),
        ('registry', {'db_path': None, 'restored_snapshot': True}),
    ]


def test_delivery_entrypoint_logs_safe_hosted_error_code(monkeypatch, capsys):
    from secopsai import research_delivery_verification as delivery
    from secopsai.core_edge_client import CoreEdgeHTTPError

    def reject_projection(**kwargs):
        raise CoreEdgeHTTPError('hosted Core rejected projection', status=422, error_code='invalid_projection')

    monkeypatch.setenv('SECOPSAI_RESTORED_LEDGER_RECOVERY', '0')
    monkeypatch.setenv('SECOPSAI_VERIFY_DELIVERY_SECONDS', '840')
    monkeypatch.setenv('SECOPSAI_VERIFY_RETRY_SOURCES', '')
    monkeypatch.setenv('SECOPSAI_VERIFY_RETRY_COLLECTORS', '')
    monkeypatch.setattr(delivery, 'verify_delivery', reject_projection)
    assert delivery.main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report == {
        'event': 'delivery_verification_failed',
        'error_category': 'CoreEdgeHTTPError',
        'http_status': 422,
        'error_code': 'invalid_projection',
    }


def test_explicit_source_retry_only_attempts_selected_enabled_source(tmp_path, monkeypatch):
    from secopsai.research_primary_intel import collect_due, configure_source
    from secopsai.research_intake import SafeFetcher
    db = str(tmp_path/'sources.db')
    monkeypatch.setattr('secopsai.research_primary_intel.seed_sources', lambda **kwargs: {})
    for identity, enabled in [('selected', True), ('other', True), ('paused', False)]:
        configure_source({'source_id': identity, 'name': identity, 'url': 'https://example.test/'+identity,
                          'parser': 'normalized_json', 'source_class': 'vendor', 'enabled': enabled}, actor='synthetic', db_path=db)
    with soc_store.connect(db) as connection:
        connection.execute("UPDATE research_intel_sources SET last_attempt_at='2099-01-01T00:00:00Z' WHERE source_id IN ('selected','paused')")
        connection.commit()
    urls = []
    def fetch(url, max_bytes):
        urls.append(url)
        return 500, {}, b''
    collect_due(db_path=db, force_source_ids=('selected', 'paused'), fetcher=SafeFetcher(fetch=fetch))
    assert urls and set(urls) == {'https://example.test/selected'}


def test_selected_source_that_already_recovered_is_not_fetched_again(tmp_path, monkeypatch):
    from secopsai.research_primary_intel import configure_source
    db = str(tmp_path/'already-healthy.db')
    configure_source({'source_id': 'healthy', 'name': 'Already Healthy', 'url': 'https://example.test/healthy',
                      'parser': 'normalized_json', 'source_class': 'vendor', 'enabled': True}, actor='synthetic', db_path=db)
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {'coverage': {'health': {}}})
    def unexpected(**kwargs):
        raise AssertionError('a recovered source must not be fetched again')
    monkeypatch.setattr('secopsai.research_primary_intel.collect_due', unexpected)
    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 0, 'flushed': 0}
        def sync_research_operation(self, value): return {'status': 'stored'}
    result = verify_delivery(db_path=db, client=Client(), retry_source_names=('Already Healthy',))
    assert result['status'] == 'passed' and result['sources_retried'] == 0


def test_explicit_registry_collector_retry_runs_only_selected_enabled_collector(tmp_path, monkeypatch):
    db = str(tmp_path/'collector-retry.db')
    soc_store.init_db(db)
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {'coverage': {'health': {}}})
    calls = []

    def run_registry_collector(**kwargs):
        calls.append(kwargs)
        return {'status': 'completed', 'coverage': 'complete', 'pages_selected': 36,
                'pages_processed': 36, 'events_stored': 4}

    monkeypatch.setattr('secopsai.research_surveillance.run_registry_collector', run_registry_collector)

    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 0, 'flushed': 0}
        def sync_research_operation(self, value): return {'status': 'stored'}

    result = verify_delivery(db_path=db, client=Client(), retry_collector_names=('Open VSX search reconciliation',))
    assert len(calls) == 1
    assert calls[0]['ecosystem'] == 'open-vsx' and calls[0]['max_pages'] == 400
    assert result['status'] == 'passed'
    assert result['registry_collectors_retried'] == 1 and result['registry_collector_failures'] == 0
    assert result['registry_scans_performed'] is True and result['analysis_performed'] is False


def test_multiple_explicit_registry_collector_retries_cover_selected_sources(tmp_path, monkeypatch):
    db = str(tmp_path/'multiple-collector-retry.db')
    soc_store.init_db(db)
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {'coverage': {'health': {}}})
    calls = []

    def run_registry_collector(**kwargs):
        calls.append(kwargs)
        return {'status': 'completed', 'coverage': 'complete', 'pages_selected': 20,
                'pages_processed': 20, 'events_stored': 3}

    monkeypatch.setattr('secopsai.research_surveillance.run_registry_collector', run_registry_collector)

    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 0, 'flushed': 0}
        def sync_research_operation(self, value): return {'status': 'stored'}

    names = (
        'crates.io recently updated crates',
        'Go module index',
        'npm replicate changes',
        'NuGet V3 Catalog',
        'Packagist metadata changes',
    )
    result = verify_delivery(db_path=db, client=Client(), retry_collector_names=names)

    assert {call['ecosystem'] for call in calls} == {'crates', 'go', 'npm', 'nuget', 'packagist'}
    assert next(call['max_pages'] for call in calls if call['ecosystem'] == 'crates') == 500
    assert [item['name'] for item in result['registry_collectors']] == list(names)
    assert result['status'] == 'passed'
    assert result['registry_collectors_retried'] == len(names)
    assert result['registry_collector_failures'] == 0
    assert result['registry_scans_performed'] is True and result['analysis_performed'] is False


def test_stale_enabled_sources_uses_the_coverage_freshness_threshold(tmp_path):
    from datetime import datetime, timedelta, timezone
    from secopsai.research_coverage import coverage_report, stale_enabled_sources
    from secopsai.research_surveillance import ensure_collectors

    db = str(tmp_path / 'stale-sources.db')
    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    collectors = ensure_collectors(db_path=db)
    with soc_store.connect(db) as connection:
        for collector in collectors:
            completed = now - timedelta(seconds=1801 if collector['ecosystem'] == 'crates' else 60)
            connection.execute(
                """INSERT INTO registry_ingestion_runs
                   (run_id,collector_id,status,cursor_before,cursor_after,coverage_mode,started_at,completed_at)
                   VALUES (?,?, 'completed', '', '', ?, ?, ?)""",
                (f"run-{collector['ecosystem']}", collector['collector_id'], collector['mode'],
                 completed.isoformat().replace('+00:00', 'Z'), completed.isoformat().replace('+00:00', 'Z')),
            )
        connection.commit()

    stale = stale_enabled_sources(db_path=db, now=now)
    assert [(item['source_id'], item['delay_seconds']) for item in stale['registry_collectors']] == [
        ('COL-CRATES-RECENT', 1801.0),
    ]
    assert stale['intel_sources'] == []
    coverage_sources = {item['source_id']: item for item in coverage_report(db_path=db, now=now)['sources']}
    assert coverage_sources['COL-CRATES-RECENT']['fresh'] is False
    assert coverage_sources['COL-NUGET-CATALOG']['fresh'] is True


def test_routine_final_verification_refreshes_stale_sources_before_projection(tmp_path, monkeypatch):
    db = str(tmp_path / 'final-source-refresh.db')
    calls = []
    monkeypatch.setattr(
        'secopsai.research_coverage.stale_enabled_sources',
        lambda **kwargs: {'intel_sources': [], 'registry_collectors': [{
            'source_id': 'COL-NUGET-CATALOG',
            'name': 'NuGet V3 Catalog', 'ecosystem': 'nuget',
        }]},
    )
    monkeypatch.setattr('secopsai.research_surveillance.run_registry_collector', lambda **kwargs:
                        calls.append(kwargs) or {'status': 'completed', 'coverage': 'complete',
                                                 'pages_selected': 1, 'pages_processed': 1,
                                                 'events_stored': 2})
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {
        'coverage': {'health': {'freshness_gaps': [], 'ontology_pending': 0}},
    })

    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 0, 'flushed': 0}
        def sync_research_operation(self, value): return {'status': 'stored'}

    result = verify_delivery(db_path=db, client=Client(), refresh_stale_sources=True)
    assert [call['ecosystem'] for call in calls] == ['nuget']
    assert result['status'] == 'passed'
    assert result['registry_collectors_refreshed'] == 1
    assert result['registry_collector_refresh_failures'] == 0
    assert result['source_freshness_gaps'] == []


def test_final_source_refresh_fails_closed_when_freshness_gaps_remain(tmp_path, monkeypatch):
    db = str(tmp_path / 'remaining-source-gap.db')
    monkeypatch.setattr(
        'secopsai.research_coverage.stale_enabled_sources',
        lambda **kwargs: {'intel_sources': [], 'registry_collectors': [{
            'source_id': 'COL-NUGET-CATALOG',
            'name': 'NuGet V3 Catalog', 'ecosystem': 'nuget',
        }]},
    )
    monkeypatch.setattr('secopsai.research_surveillance.run_registry_collector', lambda **kwargs: {
        'status': 'completed', 'coverage': 'gap', 'pages_selected': 5,
        'pages_processed': 3, 'events_stored': 2,
    })
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {
        'coverage': {'health': {'freshness_gaps': ['NuGet V3 Catalog'], 'ontology_pending': 0}},
    })

    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 0, 'flushed': 0}
        def sync_research_operation(self, value): return {'status': 'stored'}

    result = verify_delivery(db_path=db, client=Client(), refresh_stale_sources=True)
    assert result['status'] == 'failed'
    assert result['source_freshness_gaps'] == ['NuGet V3 Catalog']
    assert result['registry_collector_refresh_failures'] == 1
    assert any('freshness targets' in item for item in result['delivery_blockers'])


def test_final_source_refresh_collects_stale_primary_intel_sources(tmp_path, monkeypatch):
    db = str(tmp_path / 'stale-primary-source.db')
    calls = []
    monkeypatch.setattr('secopsai.research_coverage.stale_enabled_sources', lambda **kwargs: {
        'intel_sources': [{'source_id': 'INTEL-SOURCE-1', 'name': 'Synthetic advisory feed'}],
        'registry_collectors': [],
    })
    monkeypatch.setattr('secopsai.research_primary_intel.collect_due', lambda **kwargs:
                        calls.append(kwargs) or {'results': [{'source_id': 'INTEL-SOURCE-1', 'status': 'acquired'}]})
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {
        'coverage': {'health': {'freshness_gaps': [], 'ontology_pending': 0}},
    })

    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 0, 'flushed': 0}
        def sync_research_operation(self, value): return {'status': 'stored'}

    result = verify_delivery(db_path=db, client=Client(), refresh_stale_sources=True)
    assert calls == [{
        'db_path': db, 'limit': 1, 'force_source_ids': ('INTEL-SOURCE-1',),
    }]
    assert result['status'] == 'passed'
    assert result['stale_sources_refreshed'] == 1
    assert result['stale_source_refresh_failures'] == 0


def test_incomplete_registry_collector_retry_keeps_delivery_verification_failed(tmp_path, monkeypatch):
    db = str(tmp_path/'collector-gap.db')
    soc_store.init_db(db)
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {'coverage': {'health': {}}})
    monkeypatch.setattr('secopsai.research_surveillance.run_registry_collector', lambda **kwargs: {
        'status': 'completed', 'coverage': 'gap', 'pages_selected': 400,
        'pages_processed': 400, 'events_stored': 4})

    class Client:
        enabled = True
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return {'pending': 0, 'flushed': 0}
        def sync_research_operation(self, value): return {'status': 'stored'}

    result = verify_delivery(db_path=db, client=Client(), retry_collector_names=('Open VSX search reconciliation',))
    assert result['status'] == 'failed' and result['registry_collector_failures'] == 1


def test_later_entity_delivery_can_repair_an_older_relationship(tmp_path, monkeypatch):
    db = str(tmp_path/'dependencies.db')
    soc_store.init_db(db)
    with soc_store.connect(db) as connection:
        connection.execute("INSERT INTO ontology_sync_outbox(idempotency_key,payload_json,next_attempt_at,created_at,updated_at) VALUES ('new-entity','{}','2020-01-01','2020-01-01','2020-01-01')")
        connection.commit()
    monkeypatch.setattr('secopsai.ontology.materialize_recent', lambda **kwargs: {'snapshot': {}})
    monkeypatch.setattr('secopsai.research_operation.hosted_projection', lambda **kwargs: {'coverage': {'health': {}}})
    class Client:
        enabled = True
        outcomes = iter([{'pending': 2, 'flushed': 0, 'http_status': 422},
                         {'pending': 0, 'flushed': 2, 'status': 'accepted'}])
        def enqueue_ontology_snapshot(self, *args, **kwargs): return {'status': 'queued'}
        def flush_ontology_outbox(self, **kwargs): return next(self.outcomes)
        def sync_research_operation(self, value): return {'status': 'stored'}
    result = verify_delivery(db_path=db, client=Client())
    assert result['status'] == 'passed' and result['flushed_total'] == 2
