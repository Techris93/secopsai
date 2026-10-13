import copy
import pytest
from secopsai.decision_contracts import DecisionError, validate_answers, validate_action_result

QUESTIONS = {'v': {'type': 'choice', 'criteria': {'bad': 'Malicious', 'good': 'Benign'}}, 'p': {'type': 'noul'}, 's': {'type': 'score', 'criteria': ['low', 'high']}}
GOOD = {'model': 'fixed-model', 'answers': {'v': {'type': 'choice', 'choice': 'bad', 'probabilities': {'bad': .9, 'good': .1}, 'confidence': .8}, 'p': {'type': 'noul', 'noul': .8}, 's': {'type': 'score', 'score': .6, 'probabilities': {'0': .4, '1': .6}, 'confidence': .7}}}


@pytest.mark.parametrize('value', [None, True, '0.5', float('nan'), float('inf'), -.1, 1.1])
def test_invalid_probabilities_rejected(value):
    data = copy.deepcopy(GOOD)
    data['answers']['p']['noul'] = value
    with pytest.raises(DecisionError):
        validate_answers(data, QUESTIONS, provider='test')


@pytest.mark.parametrize('mutation', ['missing', 'type', 'unknown', 'sum', 'inconsistent', 'confidence', 'score'])
def test_invalid_answers_rejected(mutation):
    data = copy.deepcopy(GOOD)
    if mutation == 'missing': del data['answers']['v']
    elif mutation == 'type': data['answers']['v']['type'] = 'noul'
    elif mutation == 'unknown': data['answers']['v']['choice'] = 'unknown'
    elif mutation == 'sum': data['answers']['v']['probabilities']['good'] = .5
    elif mutation == 'inconsistent': data['answers']['v']['choice'] = 'good'
    elif mutation == 'confidence': del data['answers']['v']['confidence']
    else: data['answers']['s']['score'] = .9
    with pytest.raises(DecisionError): validate_answers(data, QUESTIONS, provider='test')


def test_valid_distribution_and_missing_model():
    assert validate_answers(GOOD, QUESTIONS, provider='test') is GOOD
    with pytest.raises(DecisionError): validate_answers({'answers': GOOD['answers']}, QUESTIONS, provider='test')


def test_research_credibility_requires_evidence():
    base = {'summary': 'Research', 'risk_assessment': 'Risk', 'evidence': [], 'recommended_actions': [], 'limitations': [], 'verdict_recommendation': 'credible', 'verdict_confidence': 85}
    with pytest.raises(DecisionError): validate_action_result('analyze_research_case', base)
    assert validate_action_result('analyze_research_case', {**base, 'verdict_rationale': 'Supported by supplied evidence', 'verdict_evidence_refs': ['step-1']})


def test_other_actions_cannot_establish_research_credibility():
    base = {'summary': 'Finding', 'risk_assessment': 'Risk', 'evidence': [], 'recommended_actions': [], 'limitations': [], 'verdict_recommendation': 'credible', 'verdict_confidence': 85}
    with pytest.raises(DecisionError): validate_action_result('explain_finding', base)
