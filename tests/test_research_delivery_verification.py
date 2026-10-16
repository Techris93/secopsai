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
