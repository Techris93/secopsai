import soc_store
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
    result = verify_delivery(db_path=db, client=Client())
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
