"""Exercise provider -> bridge -> durable job -> alert without live calls."""
import json
import pytest
import soc_store
from secopsai import research_ai_triage, typesafe_adapter
from secopsai.codex_bridge import BridgeSettings, _invoke_with_model_fallback, _safe_error_text
from secopsai.intelligence import prepare_bridge_request
from secopsai.intelligence_jobs import enqueue_job, claim_next_job, complete_job, get_job, fail_job, requeue_job, requeue_failed_jobs
from secopsai.decision_contracts import DecisionError


def test_artifact_true_positive_survives_all_boundaries(tmp_path, monkeypatch):
    db = str(tmp_path / 'core.db')
    monkeypatch.setenv('SECOPSAI_DECISION_MODE', 'observe')
    context = {'package': 'demo', 'version': '1', 'findings': [{'rule_id': 'R1', 'file_path': 'install.js', 'matched_strings': ['exfiltrate()']}],
               'install_time_files': [{'path': 'install.js', 'content': '\n'.join(['const x = 1;'] * 500) + '\nexfiltrate()'}]}
    key = research_ai_triage.record_hit(ecosystem='npm', package='demo', version='1', prescan={'score': 80, 'findings': context['findings']}, db_path=db)
    job = enqueue_job(action='triage_artifact', target_id=key, inputs={'selected_model': 'typesafe/jev-latest', 'artifact_triage': context}, db_path=db)
    claimed = claim_next_job(provider='typesafe', worker_id='test-worker', db_path=db)
    request = prepare_bridge_request('triage_artifact', {'artifact_id': key, 'artifact_triage': context}, db_path=db)
    assert request['context']['artifact_triage']['install_time_files'][0]['content'].endswith('exfiltrate()')
    def evaluate(state, questions, **kwargs):
        answers = {}
        for name, question in questions.items():
            kind = question['type']
            if kind == 'noul': answers[name] = {'type': kind, 'noul': .75}
            elif kind == 'score': answers[name] = {'type': kind, 'score': 3., 'confidence': .99, 'probabilities': {str(i): float(i == 3) for i in range(len(question['criteria']))}}
            else:
                options = question['criteria']
                choice = {'finding_verdict': 'true_positive', 'automation_recommendation': 'escalate', 'exposure_assessment': 'affected'}.get(name, next(k for k in options if k != 'none'))
                answers[name] = {'type': kind, 'choice': choice, 'confidence': .99, 'probabilities': {k: float(k == choice) for k in options}}
        return {'model': 'jev-fixed', 'answers': answers, 'usage': {}}
    monkeypatch.setattr(typesafe_adapter, 'evaluate_system_one', evaluate)
    raw, _ = _invoke_with_model_fallback(request, BridgeSettings(), None, ['typesafe/jev-latest'])
    lease = {k: claimed[k] for k in ('worker_id', 'lease_generation', 'lease_token')}
    malformed = {**raw, 'finding_confidence': None}
    with pytest.raises(DecisionError): complete_job(job['job_id'], result=malformed, actor='test-worker', db_path=db, **lease)
    assert get_job(job['job_id'], db_path=db)['status'] == 'running'
    done = complete_job(job['job_id'], result=raw, actor='test-worker', db_path=db, **lease)
    assert done['result']['finding_confidence'] == 99 and done['result']['malicious_probability'] == 75
    repeated = complete_job(job['job_id'], result=malformed, actor='test-worker', db_path=db, **lease)
    assert repeated['events'] == done['events'] and repeated['result'] == raw
    with soc_store.connect(db) as connection:
        connection.execute("UPDATE research_ai_triage SET job_id=? WHERE artifact_key=?", (job['job_id'], key))
        connection.execute("INSERT INTO research_alerts(alert_id,alert_type,severity,dedupe_key,reason,evidence_json,status,owner,created_at,updated_at) VALUES('A1','registry_release_anomaly','high','A1','test',?,'open','','t','t')", (json.dumps({'package': 'demo', 'version': '1'}),))
        item = {'artifact_id': key, 'job_id': job['job_id'], 'status': 'succeeded', 'result': raw}
        assert research_ai_triage._apply_result(connection, item, 't2') == 'escalated'
        assert research_ai_triage._apply_result(connection, item, 't3') is None
        row = connection.execute('SELECT verdict,confidence FROM research_ai_triage WHERE artifact_key=?', (key,)).fetchone()
        assert tuple(row) == ('suspicious', 99)
        assert connection.execute("SELECT status FROM research_alerts WHERE alert_id='A1'").fetchone()[0] == 'open'


def test_alert_boundary_revalidates_stored_clef_before_closure(tmp_path, monkeypatch):
    db = str(tmp_path / 'core.db')
    soc_store.init_db(db)
    key = research_ai_triage.record_hit(
        ecosystem='npm', package='demo', version='2',
        prescan={'score': 30, 'findings': [{'rule_id': 'R1', 'file_path': 'install.js', 'matched_strings': ['benign text']} ]},
        db_path=db,
    )
    with soc_store.connect(db) as connection:
        row = connection.execute('SELECT context_json, package, version FROM research_ai_triage WHERE artifact_key=?', (key,)).fetchone()
        context = json.loads(row['context_json'])
        context['clef'] = {'probability': 0, 'choice': 'benign'}  # Missing model, confidence and distribution.
        connection.execute('UPDATE research_ai_triage SET context_json=? WHERE artifact_key=?', (json.dumps(context), key))
        connection.execute("INSERT INTO research_alerts(alert_id,alert_type,severity,dedupe_key,reason,evidence_json,status,owner,created_at,updated_at) VALUES('A2','registry_release_anomaly','low','A2','test',?,'open','','t','t')", (json.dumps({'package': row['package'], 'version': row['version']}),))

        monkeypatch.setattr('secopsai.decision_policy.closure_decision', lambda *a, **kw: (True, 'synthetic-approved-policy'))
        primary = {
            'summary': 'Benign static match.', 'risk_assessment': 'Low.', 'evidence': ['R1'],
            'recommended_actions': ['Retain for audit.'], 'limitations': ['No runtime execution.'],
            'finding_verdict': 'benign_expected', 'finding_confidence': 99, 'malicious_probability': 2,
            'disposition_recommendation': 'expected_behavior', 'decision_evidence_refs': ['R1'],
            'assessment_version': 'decision-v2', 'provider': 'typesafe', 'model_version': 'jev-fixed',
            'automatic_closure_eligible': True, 'evidence_coverage': {'complete': True},
        }
        outcome = research_ai_triage._apply_result(
            connection,
            {'artifact_id': key, 'status': 'succeeded', 'job_id': 'AIJ-CLEF-REVALIDATE', 'result': primary},
            't2',
        )
        assert outcome == 'escalated'
        stored = connection.execute('SELECT verdict FROM research_ai_triage WHERE artifact_key=?', (key,)).fetchone()
        assert stored['verdict'] == 'inconclusive'
        alert = connection.execute("SELECT status, evidence_json FROM research_alerts WHERE alert_id='A2'").fetchone()
        assert alert['status'] == 'open'
        note = json.loads(alert['evidence_json'])['ai_triage']
        assert note['clef_present'] and not note['clef_validated']
        assert note['policy_reason'] == 'invalid_clef_decision'


@pytest.mark.parametrize('bulk', [False, True])
def test_requeue_preserves_captured_routing(tmp_path, bulk):
    db = str(tmp_path / 'core.db')
    captured = {'selected_model': 'typesafe/jev-latest', 'fallback_mode': 'quota_auth', 'fallback_models': ['cloudflare/clef']}
    job = enqueue_job(action='triage_artifact', target_id='demo', inputs=captured, db_path=db)
    claim_next_job(provider='typesafe', worker_id='test', db_path=db)
    fail_job(job['job_id'], error_code='authentication', error_message='synthetic', actor='test', db_path=db)
    if bulk: requeue_failed_jobs(db_path=db)
    else: requeue_job(job['job_id'], db_path=db)
    assert get_job(job['job_id'], db_path=db)['input'] == captured


def test_credential_diagnostics_redact_bearer_headers():
    assert 'synthetic-secret' not in _safe_error_text('Authorization: Bearer synthetic-secret; token=another')


@pytest.mark.parametrize('remote', [False, True])
def test_bridge_inline_artifact_completion_needs_no_local_artifact_record(tmp_path, monkeypatch, remote):
    from secopsai import codex_bridge, artifact_fleet
    db = str(tmp_path / 'core.db')
    context = {'findings': [{'rule_id': 'R1', 'safe_context': 'exfiltrate()'}]}
    model = 'typesafe/jev-latest'
    job = enqueue_job(action='triage_artifact', target_id='npm:inline@1', inputs={'selected_model': model, 'artifact_triage': context}, db_path=db)
    monkeypatch.setattr(codex_bridge, 'doctor', lambda *a, **kw: {'live_ready': True, 'models': {}, 'opencodex': {}})
    raw = {'summary': 'Suspicious installer', 'risk_assessment': 'Review payload', 'evidence': ['R1'], 'recommended_actions': ['Review'], 'limitations': [],
           'finding_verdict': 'true_positive', 'finding_confidence': 99, 'malicious_probability': 90, 'disposition_recommendation': 'true_positive', 'decision_evidence_refs': ['R1']}
    monkeypatch.setattr(codex_bridge, '_invoke_codex', lambda *a, **kw: raw)
    monkeypatch.setattr(artifact_fleet, 'record_model_result', lambda *a, **kw: pytest.fail('Inline research job attempted an unrelated local artifact write'))
    settings = BridgeSettings(model=model)
    if remote:
        settings = BridgeSettings(model=model, core_api_url='https://synthetic.invalid', bridge_token='synthetic')
        claimed = {**job, 'status': 'running'}
        request = prepare_bridge_request('triage_artifact', {'artifact_id': job['target_id'], 'artifact_triage': context}, db_path=db)
        monkeypatch.setattr(codex_bridge, '_remote_claim', lambda _: {'job': claimed, 'bridge_request': request})
        def finish(settings, job_id, outcome, payload):
            assert outcome == 'complete' and payload['result']['finding_confidence'] == 99
            return {'job': {**claimed, 'status': 'succeeded'}}
        monkeypatch.setattr(codex_bridge, '_remote_finish', finish)
    result = codex_bridge.run_once(settings=settings, db_path=db, require_ready_provider=False)
    assert result['status'] == 'succeeded' and result['job']['status'] == 'succeeded'
