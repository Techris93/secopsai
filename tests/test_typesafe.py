from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest

from secopsai.codex_bridge import BridgeSettings, _invoke_codex, _provider_for_model, list_models
from secopsai.intelligence import validate_bridge_result
from secopsai.decision_contracts import DecisionError
from secopsai import typesafe_adapter as adapter


@pytest.fixture(autouse=True)
def isolated_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv('TYPESAFE_API_KEY', raising=False)
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(adapter, '_credential_files', lambda: [tmp_path / '.env', tmp_path / '.secopsai/typesafe.key', tmp_path / '.secopsai/config.env'])
    monkeypatch.setattr('requests.post', lambda *a, **kw: pytest.fail('A unit test attempted a live provider request'))


def response(answers):
    resp = MagicMock(status_code=200)
    resp.json.return_value = {'model': 'jev-1.13.0', 'answers': answers, 'usage': {'input_tokens': 100, 'output_tokens': 0}}
    return resp


def service_answers(questions, *, verdict='true_positive', malicious=.99, confidence=.99):
    answers = {}
    chosen = {'finding_verdict': verdict, 'exposure_assessment': 'affected', 'automation_recommendation': 'escalate'}
    for key, question in questions.items():
        kind = question['type']
        if kind == 'noul':
            answers[key] = {'type': kind, 'noul': malicious if key == 'malicious' else .8}
        elif kind == 'score':
            probs = {str(i): float(i == 3) for i in range(len(question['criteria']))}
            answers[key] = {'type': kind, 'score': 3., 'probabilities': probs, 'confidence': confidence}
        else:
            options = question['criteria']
            choice = chosen.get(key, next((k for k in options if k != 'none'), 'none'))
            answers[key] = {'type': kind, 'choice': choice, 'probabilities': {k: float(k == choice) for k in options}, 'confidence': confidence}
    return answers


def mock_service(_url, **kwargs):
    return response(service_answers(kwargs['json']['questions']))


def test_availability_and_precedence(monkeypatch, tmp_path):
    assert not adapter.is_typesafe_available()
    path = adapter.set_typesafe_api_key('user-key')
    assert Path(path).stat().st_mode & 0o777 == 0o600
    assert adapter.get_typesafe_api_key() == 'user-key'
    adapter.set_typesafe_api_key('local-key', scope='local')
    assert adapter.get_typesafe_api_key() == 'local-key'
    monkeypatch.setenv('TYPESAFE_API_KEY', ' environment-key ')
    assert adapter.get_typesafe_api_key() == 'environment-key'


def test_env_file_updates_preserve_other_settings(tmp_path):
    (tmp_path / '.env').write_text('OTHER=value\nTYPESAFE_API_KEY="old"\n')
    adapter.set_typesafe_api_key('new', scope='local')
    assert (tmp_path / '.env').read_text() == 'OTHER=value\nTYPESAFE_API_KEY="new"\n'
    assert adapter.get_typesafe_api_key() == 'new'


def test_unconfigured_never_calls_network():
    assert adapter.probe_typesafe()['status'] == 'unconfigured'
    with pytest.raises(DecisionError, match='TYPESAFE_API_KEY is required'):
        adapter.evaluate_system_one('test', {})


def test_probe_validates_typed_answer(monkeypatch):
    monkeypatch.setenv('TYPESAFE_API_KEY', 'synthetic')
    with patch('requests.post', return_value=response({'probe': {'type': 'noul', 'noul': .5}})) as post:
        assert adapter.probe_typesafe()['ready'] is True
        assert post.call_args.kwargs['headers']['Authorization'] == 'Bearer synthetic'
    with patch('requests.post', return_value=response({})):
        assert adapter.probe_typesafe()['status'] == 'invalid_response'


def test_missing_probe_credentials_and_http_failure_do_not_leak_key(monkeypatch):
    monkeypatch.setenv('TYPESAFE_API_KEY', 'synthetic-sensitive-key')
    resp = response({})
    resp.status_code = 401
    resp.text = 'Invalid synthetic-sensitive-key'
    with patch('requests.post', return_value=resp) as post:
        result = adapter.probe_typesafe()
        assert result['status'] == 'unauthorized' and not result['ready']
        assert 'synthetic-sensitive-key' not in json.dumps(result)
        assert post.call_count == 1


@pytest.mark.parametrize('action', ['analyze_research_case', 'generate_analyst_brief', 'review_publication_safety', 'prioritize_findings', 'execute_specialist_work'])
def test_unsupported_actions_never_call_provider(action):
    with pytest.raises(DecisionError) as error:
        adapter.invoke_typesafe_action({'action': {'name': action}, 'context': {}})
    assert error.value.category == 'unsupported_action'


def test_triage_routes_and_does_not_assess_research_verdict(monkeypatch):
    monkeypatch.setenv('TYPESAFE_API_KEY', 'synthetic')
    with patch('requests.post', side_effect=mock_service):
        result = _invoke_codex({'action': {'name': 'triage_finding'}, 'context': {'finding_id': 'F-99'}}, BridgeSettings(), MagicMock(), model='typesafe/jev-latest')
    assert result['finding_verdict'] == 'true_positive'
    assert result['finding_confidence'] == 99
    assert result['verdict_recommendation'] == 'inconclusive' and result['verdict_confidence'] == 0
    assert result['model_version'] == 'jev-1.13.0'
    validate_bridge_result('triage_finding', result)


def test_artifact_has_independent_probability_identifiers_and_policy(monkeypatch):
    monkeypatch.setenv('TYPESAFE_API_KEY', 'synthetic')
    request = {'action': {'name': 'triage_artifact'}, 'instructions': 'supplied-action-policy',
               'context': {'artifact_triage': {'ecosystem': 'npm', 'package': 'test', 'version': '1',
                   'findings': [{'rule_id': 'R1', 'file_path': 'a.js', 'matched_strings': ['MATCHED_TEXT']}],
                   'flagged_files': [{'path': 'a.js', 'content': 'MATCHED_TEXT', 'complete': True}]}}}
    def service(_url, **kwargs):
        assert 'MATCHED_TEXT' in kwargs['json']['state']
        questions = kwargs['json']['questions']
        assert 'supplied-action-policy' in json.dumps(questions)
        assert 'needs_more_evidence' not in questions['finding_verdict']['criteria']
        return response(service_answers(questions, malicious=.75, confidence=.99))
    with patch('requests.post', side_effect=service):
        result = adapter.invoke_typesafe_action(request)
    assert result['finding_confidence'] == 99 and result['malicious_probability'] == 75
    assert result['decision_evidence_refs'] == ['R1']
    assert result['evidence_coverage']['complete']
    validate_bridge_result('triage_artifact', result)


def test_missing_confidence_is_rejected(monkeypatch):
    monkeypatch.setenv('TYPESAFE_API_KEY', 'synthetic')
    answers = service_answers(adapter.build_triage_questions())
    del answers['finding_verdict']['confidence']
    with patch('requests.post', return_value=response(answers)), pytest.raises(DecisionError, match='confidence'):
        adapter.invoke_typesafe_action({'action': {'name': 'triage_finding'}, 'context': {}})


@pytest.mark.parametrize('missing', ['credential_leakage', 'publication_risk'])
def test_supplementary_publication_checks_reject_missing_answers(missing):
    questions = adapter.build_publication_safety_questions()
    answers = service_answers(questions)
    del answers[missing]
    with pytest.raises(DecisionError):
        adapter._format_publication_safety_result(answers, {})


def test_supplementary_publication_checks_cannot_approve():
    answers = service_answers(adapter.build_publication_safety_questions())
    answers['safe_to_publish']['noul'] = .99
    answers['credential_leakage']['noul'] = .99
    result = adapter._format_publication_safety_result(answers, {})
    assert 'APPROVED' not in result['summary']
    assert result['publication_risks']
    assert result['verdict_recommendation'] == 'inconclusive'


def test_catalog_exposes_capabilities():
    models = {m['id']: m for m in list_models()['models']}
    assert models['typesafe/jev-latest']['supported_actions'] == ['triage_finding', 'triage_artifact']
    assert models['cloudflare/clef']['decision_only']
    assert _provider_for_model('typesafe/jev-latest', {}) == 'typesafe_ai:jev'
