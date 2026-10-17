from unittest.mock import MagicMock
import requests
import pytest
from secopsai.provider_http import post_json
from secopsai.decision_contracts import DecisionError
from secopsai.codex_bridge import _invoke_with_model_fallback, BridgeSettings


def reply(status, headers=None):
    response = MagicMock(status_code=status, headers=headers or {})
    response.json.return_value = {'model': 'synthetic'}
    response.text = 'synthetic-sensitive-key'
    return response


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr('secopsai.provider_http.time.sleep', lambda _: None)


@pytest.mark.parametrize('status,category,count', [(401, 'authentication', 1), (403, 'authentication', 1), (422, 'invalid_request', 1), (429, 'rate_limit', 3), (529, 'availability', 3)])
def test_http_errors_structured_and_redacted(status, category, count):
    session = MagicMock()
    session.post.return_value = reply(status)
    with pytest.raises(DecisionError) as error:
        post_json('https://synthetic.invalid', headers={}, payload={}, timeout=10, provider='test', session=session)
    assert error.value.category == category and error.value.http_status == status
    assert session.post.call_count == count
    assert 'synthetic-sensitive-key' not in str(error.value)


def test_retry_after_cannot_exceed_deadline():
    session = MagicMock()
    session.post.return_value = reply(429, {'Retry-After': '1000'})
    with pytest.raises(DecisionError): post_json('https://synthetic.invalid', headers={}, payload={}, timeout=1, provider='test', session=session)
    assert session.post.call_count == 1


def test_connection_recovery_and_invalid_json():
    session = MagicMock()
    session.post.side_effect = [requests.ConnectionError('sensitive-key'), reply(200)]
    assert post_json('https://synthetic.invalid', headers={}, payload={}, timeout=5, provider='test', session=session)['model'] == 'synthetic'
    session.post.side_effect = None
    session.post.return_value = reply(200)
    session.post.return_value.json.side_effect = ValueError('sensitive-key')
    with pytest.raises(DecisionError, match='not valid JSON'):
        post_json('https://synthetic.invalid', headers={}, payload={}, timeout=5, provider='test', session=session)


@pytest.mark.parametrize('category,mode,fallback', [('authentication', 'quota_auth', True), ('rate_limit', 'quota_auth', True), ('availability', 'any_provider', True), ('invalid_response', 'any_provider', False), ('safety', 'any_provider', False), ('unsupported_action', 'any_provider', False)])
def test_fallback_uses_categories(monkeypatch, category, mode, fallback):
    attempts = []
    result = {'summary': 'Triage', 'risk_assessment': 'Risk', 'evidence': [], 'recommended_actions': [], 'limitations': [], 'finding_verdict': 'true_positive', 'finding_confidence': 99, 'malicious_probability': 99, 'disposition_recommendation': 'true_positive', 'decision_evidence_refs': ['F1']}
    def invoke(request, settings, runner, *, model):
        attempts.append(model)
        if len(attempts) == 1: raise DecisionError('provider failed', category=category, http_status=401)
        return result
    monkeypatch.setattr('secopsai.codex_bridge._invoke_codex', invoke)
    call = lambda: _invoke_with_model_fallback({'action': {'name': 'triage_finding'}}, BridgeSettings(fallback_mode=mode), lambda _: None, ['typesafe/jev-latest', 'native'])
    if fallback:
        assert call()[1] == 'native' and len(attempts) == 2
    else:
        with pytest.raises(DecisionError): call()
        assert len(attempts) == 1


def test_capability_failure_never_silently_switches_provider(monkeypatch):
    monkeypatch.setattr('secopsai.codex_bridge._invoke_codex', lambda *a, **kw: pytest.fail('Unsupported action reached provider'))
    with pytest.raises(DecisionError) as error:
        _invoke_with_model_fallback({'action': {'name': 'analyze_research_case'}}, BridgeSettings(fallback_mode='any_provider'), None, ['typesafe/jev-latest', 'native'])
    assert error.value.category == 'unsupported_action'
