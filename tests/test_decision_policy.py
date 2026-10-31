import json
import pytest
from secopsai.decision_policy import closure_decision, policy_status
from secopsai.decision_evaluation import evaluate_records, evaluation_passes
from secopsai.research_ai_triage import clef_enabled


def decision(**updates):
    return {'finding_verdict': 'false_positive', 'finding_confidence': 99, 'malicious_probability': 4,
            'automatic_closure_eligible': True, 'evidence_coverage': {'complete': True}, 'assessment_version': 'decision-v2', 'provider': 'typesafe', 'model_version': 'jev-fixed', **updates}


def records():
    return [{'artifact_id': str(i), 'provider': 'typesafe', 'model_version': 'jev-fixed', 'label': 'malware' if i < 600 else 'benign', 'label_source': 'independent_review', 'partition': 'held_out', 'decision': 'escalate' if i < 600 else 'close', 'valid': True, 'evidence_complete': True} for i in range(800)]


@pytest.fixture(autouse=True)
def isolated_policy(monkeypatch):
    for key in ['SECOPSAI_DECISION_MODE', 'SECOPSAI_DECISION_POLICY_FILE', 'SECOPSAI_CLEF_PRESCREEN']:
        monkeypatch.delenv(key, raising=False)


def test_observation_and_clef_pause_are_defaults(monkeypatch):
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_ID', 'synthetic')
    monkeypatch.setenv('CLOUDFLARE_WORKERS_AI_TOKEN', 'synthetic')
    assert not clef_enabled() and not policy_status()['closure_enabled']
    assert closure_decision(decision()) == (False, 'observation_mode')
    monkeypatch.setenv('SECOPSAI_CLEF_PRESCREEN', '1')
    assert clef_enabled()


def test_enforcement_requires_reviewed_heldout_calibration(tmp_path, monkeypatch):
    report = {**evaluate_records(records(), held_out=True), 'ecosystems': {'npm': 400, 'pypi': 200}}
    assert evaluation_passes(report)
    manifest = tmp_path / 'policy.json'
    manifest.write_text(json.dumps({'approved': True, 'policy_version': 'decision-v2', 'evaluations': {'typesafe:jev-fixed': report}}))
    monkeypatch.setenv('SECOPSAI_DECISION_MODE', 'enforce')
    monkeypatch.setenv('SECOPSAI_DECISION_POLICY_FILE', str(manifest))
    assert closure_decision(decision(), ecosystem='npm') == (True, 'calibrated_benign')
    assert closure_decision(decision(), ecosystem='pypi') == (True, 'calibrated_benign')
    assert closure_decision(decision(), ecosystem='vscode') == (False, 'ecosystem_not_evaluated')
    assert closure_decision(decision()) == (False, 'ecosystem_not_evaluated')
    assert closure_decision(decision(), clef_probability=93) == (False, 'models_disagree')
    assert closure_decision(decision(), clef_probability=40, clef_choice='malicious') == (False, 'models_disagree')
    assert not closure_decision(decision(choice='needs_review'))[0]
    assert not closure_decision(decision(evidence_coverage={'complete': False}))[0]
    assert not closure_decision(decision(finding_verdict='needs_more_evidence'))[0]
    assert not closure_decision(decision(malicious_probability=True))[0]
    without_explicit_probability = decision(probability=1)
    without_explicit_probability.pop('malicious_probability')
    assert closure_decision(without_explicit_probability) == (False, 'invalid_decision')
    assert not closure_decision(decision(model_version='different-model'))[0]
    manifest.write_text('{}')
    assert not closure_decision(decision())[0]


def test_evaluation_rejects_false_closure_and_training_data():
    data = records()
    data[0]['decision'] = 'close'
    report = evaluate_records(data, held_out=True)
    assert not report['accepted'] and report['malware_closed'] == 1
    data[0]['partition'] = 'training'
    with pytest.raises(ValueError): evaluate_records(data, held_out=True)
    with pytest.raises(ValueError): evaluate_records([data[0], data[0]])
