from __future__ import annotations

import copy
import json

import pytest

import soc_store
from secopsai import research_assistant_team as team
from secopsai.codex_bridge import persist_model_routing
from secopsai.research_assurance import register_person
from secopsai.research_cases import add_evidence, create_case, get_case, update_case
from secopsai.research_operation import execute_hosted, hosted_projection
from secopsai.specialist_catalog import load_catalog, route_task, validate_catalog
from secopsai.specialist_orchestrator import get_run, record_primary_result, record_review_result, specialist_bridge_context


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.delenv('SECOPSAI_CORE_WORKER_ID', raising=False)
    for key in ('SECOPSAI_BRIDGE_MODEL', 'SECOPSAI_BRIDGE_FALLBACK_MODE', 'SECOPSAI_BRIDGE_FALLBACK_MODELS'):
        monkeypatch.delenv(key, raising=False)
    db = str(tmp_path / 'team.db')
    register_person({'person_id': 'operator.owner', 'display_name': 'Synthetic Owner', 'roles': ['operator', 'researcher'], 'qualification': 'Synthetic test fixture'}, actor='operator.owner', db_path=db)
    persist_model_routing(primary_model='opencodex/test-research', fallback_models=['opencodex/test-fallback'], fallback_mode='any_provider', db_path=db)
    case = create_case(title='DERIVED-CONCLUSION-MARKER', summary='DERIVED-CONCLUSION-MARKER', owner='operator.owner', db_path=db)
    case = add_evidence(case['case_id'], evidence_type='static_analysis', title='DERIVED-CONCLUSION-MARKER', sha256='a'*64,
                        provenance='Synthetic retained fixture', notes='DERIVED-CONCLUSION-MARKER', metadata={'file_contents': {'install.js': 'ORIGINAL-CODE-MARKER'}, 'model_score': 'DERIVED-CONCLUSION-MARKER'}, db_path=db)
    case = add_evidence(case['case_id'], evidence_type='analyst_note', title='DERIVED-CONCLUSION-MARKER', notes='DERIVED-CONCLUSION-MARKER', metadata={'file_contents': {'fake': 'DERIVED-CONCLUSION-MARKER'}}, db_path=db)
    return db, case['case_id']


def start(setup, request='one'):
    db, case_id = setup
    return team.start_team(case_id, {'request_id': request}, actor='operator.owner', db_path=db)


def output(db, case_id, summary='Bounded assessment', verdict='inconclusive'):
    return {'summary': summary, 'risk_assessment': 'Human review required', 'evidence': [get_case(case_id, db_path=db)['evidence'][0]['evidence_id']],
            'recommended_actions': ['Inspect exact evidence'], 'limitations': ['No experiment was performed'], 'research_verdict': verdict, 'research_confidence': 40}


def complete(run_id, db, case_id):
    record_primary_result(run_id, output(db, case_id), model='opencodex/test-research', db_path=db)
    record_review_result(run_id, output(db, case_id), model='opencodex/test-research', db_path=db)


def test_catalog_reuses_roles_and_records_per_source_commits():
    c = load_catalog()
    assert validate_catalog(c)['ok']
    assert len({p['id'] for p in c['profiles']}) == 20
    assert all(p['profile_id'] in {x['id'] for x in c['profiles']} for p in ({'profile_id': x[1]} for x in team.STAGES))
    new = next(p for p in c['profiles'] if p['id'] == 'research/research-synthesist')
    assert len(new['source_commit']) == 40
    invalid = copy.deepcopy(c)
    invalid['profiles'][-1]['source_commit'] = 'main'
    assert not validate_catalog(invalid)['ok']
    for title, expected in [('Review prior art', 'research/research-synthesist'), ('Perform skeptical review', 'testing/reality-checker'), ('Design Sigma rule', 'security/threat-detection-engineer')]:
        assert route_task({'title': title})['primary_profile']['id'] == expected


def test_all_six_stages_capture_model_and_end_at_human_review(setup):
    db, case_id = setup
    initial_case = get_case(case_id, db_path=db)
    current = start(setup)
    assert start(setup)['team_id'] == current['team_id']
    for stage, profile, _ in team.STAGES:
        current = team.advance_team(current['team_id'], db_path=db)
        run = get_run(current['runs'][stage], db_path=db)
        assert run['primary_profile_id'] == profile
        assert run['selected_model'] == 'opencodex/test-research'
        assert run['fallback_models'] == ['opencodex/test-fallback']
        if stage == 'challenge':
            context = specialist_bridge_context(run['run_id'], db_path=db)
            assert 'ORIGINAL-CODE-MARKER' in json.dumps(context)
            assert 'DERIVED-CONCLUSION-MARKER' not in json.dumps(context)
            assert context['blind_review']['previous_stage_outputs_included'] is False
        # Change live routing mid-team; later stages must retain captured routing.
        persist_model_routing(primary_model='typesafe/jev-latest', fallback_models=[], fallback_mode='disabled', db_path=db)
        complete(run['run_id'], db, case_id)
        current = team.advance_team(current['team_id'], db_path=db)
        assert stage in current['completed_stages']
    final = team.advance_team(current['team_id'], db_path=db)
    assert final['status'] == 'awaiting_human_review'
    assert final['publication_approved'] is False
    assert get_case(case_id, db_path=db)['evidence'] == initial_case['evidence']
    with soc_store.connect(db) as conn:
        assert conn.execute('SELECT count(*) FROM intelligence_jobs').fetchone()[0] == 12
        assert conn.execute("SELECT count(*) FROM research_operation_records WHERE kind='human_review'").fetchone()[0] == 0
    update_case(case_id, summary='Materially changed conclusion', db_path=db)
    assert team.get_team(final['team_id'], db_path=db)['status'] == 'stale'


def test_blind_stage_and_reviews_exclude_previous_writer_outputs(setup):
    db, case_id = setup
    current = start(setup)
    for stage, _, _ in team.STAGES:
        current = team.advance_team(current['team_id'], db_path=db)
        run_id = current['runs'][stage]
        record_primary_result(run_id, output(db, case_id, summary='EARLIER-ASSISTANT-MARKER'), model='opencodex/test-research', db_path=db)
        context = specialist_bridge_context(run_id, review=True, db_path=db)
        assert 'EARLIER-ASSISTANT-MARKER' not in json.dumps(context)
        assert 'DERIVED-CONCLUSION-MARKER' not in json.dumps(context)
        record_review_result(run_id, output(db, case_id), model='opencodex/test-research', db_path=db)
        current = team.advance_team(current['team_id'], db_path=db)


def test_lost_stage_receipt_recovers_without_duplicate_jobs(setup, monkeypatch):
    db, _ = setup
    current = start(setup)
    save = team._save
    monkeypatch.setattr(team, '_save', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('lost receipt')))
    with pytest.raises(RuntimeError):
        team.advance_team(current['team_id'], db_path=db)
    monkeypatch.setattr(team, '_save', save)
    recovered = team.advance_team(current['team_id'], db_path=db)
    assert recovered['runs']['synthesis']
    with soc_store.connect(db) as conn:
        assert conn.execute('SELECT count(*) FROM specialist_runs').fetchone()[0] == 1
        assert conn.execute('SELECT count(*) FROM intelligence_jobs').fetchone()[0] == 1


def test_conflicting_request_unsupported_model_and_evidence_changes(setup):
    db, case_id = setup
    current = start(setup)
    with pytest.raises(ValueError, match='conflicting'):
        team.start_team(case_id, {'request_id': 'one', 'extra': True}, actor='operator.owner', db_path=db)
    persist_model_routing(primary_model='typesafe/jev-latest', fallback_models=[], fallback_mode='disabled', db_path=db)
    with pytest.raises(ValueError, match='does not support'):
        start(setup, 'two')
    update_case(case_id, summary='Changed evidence context', db_path=db)
    assert team.advance_team(current['team_id'], db_path=db)['status'] == 'stale'
    with soc_store.connect(db) as conn:
        assert conn.execute('SELECT count(*) FROM specialist_runs').fetchone()[0] == 0


def test_disagreement_and_failed_provider_cannot_advance(setup):
    db, case_id = setup
    current = team.advance_team(start(setup)['team_id'], db_path=db)
    run_id = current['runs']['synthesis']
    record_primary_result(run_id, output(db, case_id, verdict='credible'), model='opencodex/test-research', db_path=db)
    record_review_result(run_id, output(db, case_id, verdict='not_substantiated'), model='opencodex/test-research', db_path=db)
    assert team.advance_team(current['team_id'], db_path=db)['status'] == 'needs_operator_review'
    assert team.advance_team(current['team_id'], db_path=db)['completed_stages'] == []
    other = team.advance_team(start(setup, 'failed')['team_id'], db_path=db)
    job_id = get_run(other['runs']['synthesis'], db_path=db)['intelligence_job_id']
    with soc_store.connect(db) as conn:
        conn.execute("UPDATE intelligence_jobs SET status='failed' WHERE job_id=?", (job_id,));conn.commit()
    assert team.advance_team(other['team_id'], db_path=db)['status'] == 'failed'


def test_cancel_stops_queued_jobs_and_hosted_start_is_idempotent(setup):
    db, case_id = setup
    command = {'action': 'assistant-team-start', 'case_id': case_id, 'actor': 'operator.owner', 'data': {'request_id': 'hosted'}}
    first = execute_hosted('hosted-one', command, db_path=db)
    assert execute_hosted('hosted-one', command, db_path=db) == first
    current = team.advance_team(first['team_id'], db_path=db)
    assert hosted_projection(db_path=db)['assistant_teams'][0]['team_id'] == current['team_id']
    team.cancel_team(current['team_id'], actor='operator.owner', db_path=db)
    final = team.advance_team(current['team_id'], db_path=db)
    assert final['status'] == 'canceled'
    assert get_run(current['runs']['synthesis'], db_path=db)['status'] == 'canceled'


def test_real_bridge_completion_advances_only_after_blind_review(setup, monkeypatch):
    from pathlib import Path
    import subprocess
    from secopsai.codex_bridge import BridgeSettings, run_once
    db, case_id = setup
    current = team.advance_team(start(setup)['team_id'], db_path=db)
    run_id = current['runs']['synthesis']
    monkeypatch.setattr('secopsai.codex_bridge.doctor', lambda *a, **k: {'status': 'ready', 'live_ready': True, 'provider': 'opencodex_proxy', 'opencodex': {'status': 'ready'}, 'models': {'default_model': 'opencodex/test-research', 'models': [{'id': 'opencodex/test-research'}]}})
    attempts = []
    def runner(command, stdin, environment, timeout):
        attempts.append(stdin)
        if len(attempts) == 2:
            assert 'DERIVED-CONCLUSION-MARKER' not in stdin
            assert 'ORIGINAL-CODE-MARKER' in stdin
        path = Path(command[command.index('--output-last-message') + 1])
        path.write_text(json.dumps(output(db, case_id)), encoding='utf-8')
        return subprocess.CompletedProcess(command, 0, '', '')
    settings = BridgeSettings(model='opencodex/test-research', worker_id='synthetic-team-bridge')
    first = run_once(db_path=db, settings=settings, runner=runner, require_ready_provider=False)
    assert first['status'] == 'succeeded', first
    assert team.advance_team(current['team_id'], db_path=db)['completed_stages'] == []
    second = run_once(db_path=db, settings=settings, runner=runner, require_ready_provider=False)
    assert second['status'] == 'succeeded', second
    assert get_run(run_id, db_path=db)['status'] == 'needs_review'
    assert team.advance_team(current['team_id'], db_path=db)['completed_stages'] == ['synthesis']


def test_empty_output_and_expired_team_never_advance(setup):
    db, case_id = setup
    current = team.advance_team(start(setup)['team_id'], db_path=db)
    run_id = current['runs']['synthesis']
    record_primary_result(run_id, {}, model='opencodex/test-research', db_path=db)
    record_review_result(run_id, {}, model='opencodex/test-research', db_path=db)
    assert team.advance_team(current['team_id'], db_path=db)['status'] == 'failed'
    other = start(setup, 'expired')
    with soc_store.connect(db) as conn:
        row = conn.execute("SELECT record_id,payload_json FROM research_operation_records WHERE kind='assistant_team_plan' AND json_extract(payload_json, '$.team_id')=?", (other['team_id'],)).fetchone()
        payload = json.loads(row[1]);payload['created_at'] = '2020-01-01T00:00:00Z'
        conn.execute('UPDATE research_operation_records SET payload_json=? WHERE record_id=?', (json.dumps(payload), row[0]));conn.commit()
    assert team.advance_team(other['team_id'], db_path=db)['status'] == 'failed'


def test_changed_case_can_still_cancel_queued_work(setup):
    db, case_id = setup
    current = team.advance_team(start(setup)['team_id'], db_path=db)
    update_case(case_id, summary='Changed evidence context', db_path=db)
    assert team.get_team(current['team_id'], db_path=db)['status'] == 'stale'
    assert team.cancel_team(current['team_id'], actor='operator.owner', db_path=db)['status'] == 'cancel_requested'
    assert team.advance_team(current['team_id'], db_path=db)['status'] == 'canceled'


class HostedFixture:
    enabled = True
    def __init__(self):
        self.jobs = {}
        self.lost = False
        self.cancelled = []
    def queue_assistant_job(self, payload):
        from secopsai.research_operation_store import canonical, digest
        key = payload['idempotency_key']
        if key in self.jobs:
            assert canonical(self.jobs[key]['payload']) == canonical(payload)
        else:
            self.jobs[key] = {'payload': copy.deepcopy(payload), 'job_id': 'AIJ-' + digest(key)[:16].upper(), 'status': 'queued'}
        if self.lost:
            self.lost = False
            raise RuntimeError('Synthetic lost queue acknowledgement')
        return {'job': {'job_id': self.jobs[key]['job_id']}}
    def assistant_results(self, job_ids):
        return {'results': [{'job_id': j['job_id'], 'target_id': j['payload']['target_id'], 'action': j['payload']['action'], 'status': j['status'],
                             'provider': 'synthetic-hosted', 'model': j.get('model', 'opencodex/test-research'), 'result': j.get('result', {})} for j in self.jobs.values() if j['job_id'] in job_ids]}
    def cancel_assistant_jobs(self, job_ids):
        self.cancelled.extend(job_ids)
        return {'canceled': job_ids}


def hosted(setup, monkeypatch):
    monkeypatch.setenv('SECOPSAI_CORE_WORKER_ID', 'github-actions-research-worker')
    return start(setup, 'hosted-transport')


def test_hosted_delivery_retries_same_evidence_and_reconciles_both_stages(setup, monkeypatch):
    from secopsai.research_assistant_transport import sync_hosted
    from secopsai.intelligence_jobs import get_job
    db, case_id = setup
    current = hosted(setup, monkeypatch)
    client = HostedFixture();client.lost = True
    with pytest.raises(RuntimeError):
        sync_hosted(client, db_path=db)
    assert len(client.jobs) == 1
    assert sync_hosted(client, db_path=db)['delivered'] == 1
    first = next(iter(client.jobs.values()))
    current = team.get_team(current['team_id'], db_path=db)
    run = get_run(current['runs']['synthesis'], db_path=db)
    assert get_job(run['intelligence_job_id'], db_path=db)['status'] == 'awaiting_provider'
    first.update(status='succeeded', result=output(db, case_id))
    assert sync_hosted(client, db_path=db)['applied'] == 1
    assert sync_hosted(client, db_path=db)['delivered'] == 1
    second = list(client.jobs.values())[1]
    request = second['payload']['inputs']['assistant_request']
    assert 'DERIVED-CONCLUSION-MARKER' not in json.dumps(request['context'])
    assert 'ORIGINAL-CODE-MARKER' in json.dumps(request['context'])
    second.update(status='succeeded', result=output(db, case_id))
    assert sync_hosted(client, db_path=db)['applied'] == 1
    sync_hosted(client, db_path=db)
    assert team.get_team(current['team_id'], db_path=db)['completed_stages'] == ['synthesis']
    assert team.get_team(current['team_id'], db_path=db)['publication_approved'] is False
    assert get_job(run['intelligence_job_id'], db_path=db)['status'] == 'succeeded'


def test_hosted_result_receipt_loss_and_cancel_are_idempotent(setup, monkeypatch):
    from secopsai import research_assistant_transport as transport
    db, case_id = setup
    current = hosted(setup, monkeypatch)
    client = HostedFixture()
    transport.sync_hosted(client, db_path=db)
    first = next(iter(client.jobs.values()));first.update(status='succeeded', result=output(db, case_id))
    terminal = transport._terminal
    monkeypatch.setattr(transport, '_terminal', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('lost result receipt')))
    with pytest.raises(RuntimeError):
        transport.sync_hosted(client, db_path=db)
    monkeypatch.setattr(transport, '_terminal', terminal)
    assert transport.sync_hosted(client, db_path=db)['applied'] == 1
    transport.sync_hosted(client, db_path=db)
    assert len(client.jobs) == 2
    team.cancel_team(current['team_id'], actor='operator.owner', db_path=db)
    assert transport.sync_hosted(client, db_path=db)['canceled'] == 1
    assert team.get_team(current['team_id'], db_path=db)['status'] == 'canceled'
    assert len(client.cancelled) == 1


def test_hosted_mismatched_model_and_changed_evidence_do_not_advance(setup, monkeypatch):
    from secopsai.research_assistant_transport import sync_hosted
    db, case_id = setup
    current = hosted(setup, monkeypatch)
    client = HostedFixture();sync_hosted(client, db_path=db)
    first = next(iter(client.jobs.values()));first.update(status='succeeded', result=output(db, case_id), model='unauthorized/model')
    assert sync_hosted(client, db_path=db)['rejected'] == 1
    sync_hosted(client, db_path=db)
    assert team.get_team(current['team_id'], db_path=db)['status'] == 'failed'
    other = start(setup, 'changed-hosted')
    sync_hosted(client, db_path=db)
    update_case(case_id, summary='Material change', db_path=db)
    assert sync_hosted(client, db_path=db)['canceled'] == 1
    assert team.get_team(other['team_id'], db_path=db)['completed_stages'] == []


def test_remote_bridge_uses_captured_request_without_local_run(setup, monkeypatch, tmp_path):
    from pathlib import Path
    import subprocess
    from secopsai.codex_bridge import BridgeSettings, run_once
    from secopsai.research_assistant_transport import sync_hosted
    db, case_id = setup
    hosted(setup, monkeypatch)
    client = HostedFixture();sync_hosted(client, db_path=db)
    first = next(iter(client.jobs.values()))
    payload = first['payload']
    claimed = {'job': {'job_id': first['job_id'], 'action': payload['action'], 'target_id': payload['target_id'], 'input': payload['inputs'], 'lease_generation': 1, 'lease_token': 'synthetic-lease'}, 'bridge_request': payload['inputs']['assistant_request']}
    monkeypatch.setattr('secopsai.codex_bridge._remote_claim', lambda *a, **k: claimed)
    monkeypatch.setattr('secopsai.codex_bridge._remote_finish', lambda *a, **k: {'job': {'job_id': first['job_id'], 'status': 'succeeded'}})
    monkeypatch.setattr('secopsai.codex_bridge._remote_post', lambda *a, **k: {'job': {'status': 'running'}})
    monkeypatch.setattr('secopsai.codex_bridge.doctor', lambda *a, **k: {'status': 'ready', 'live_ready': True, 'provider': 'opencodex_proxy', 'opencodex': {'status': 'ready'}, 'models': {'default_model': 'opencodex/test-research', 'models': [{'id': 'opencodex/test-research'}]}})
    def runner(command, stdin, environment, timeout):
        assert 'ORIGINAL-CODE-MARKER' in stdin
        Path(command[command.index('--output-last-message') + 1]).write_text(json.dumps(output(db, case_id)), encoding='utf-8')
        return subprocess.CompletedProcess(command, 0, '', '')
    result = run_once(db_path=str(tmp_path / 'independent-bridge.db'), settings=BridgeSettings(model='opencodex/test-research', core_api_url='https://synthetic.example', bridge_token='synthetic-bridge-token', worker_id='synthetic-remote-bridge'), runner=runner, require_ready_provider=False)
    assert result['status'] == 'succeeded', result
