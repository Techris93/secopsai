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
    with pytest.raises(DecisionError): validate_answers({**GOOD, 'success': False}, QUESTIONS, provider='test')


def test_research_credibility_requires_evidence():
    base = {'summary': 'Research', 'risk_assessment': 'Risk', 'evidence': [], 'recommended_actions': [], 'limitations': [], 'verdict_recommendation': 'credible', 'verdict_confidence': 85}
    with pytest.raises(DecisionError): validate_action_result('analyze_research_case', base)
    assert validate_action_result('analyze_research_case', {**base, 'verdict_rationale': 'Supported by supplied evidence', 'verdict_evidence_refs': ['step-1']})
    disproved = {**base, 'verdict_recommendation': 'not_substantiated', 'verdict_confidence': 80,
                 'verdict_rationale': 'The primary artifact contradicts the claim.'}
    with pytest.raises(DecisionError): validate_action_result('analyze_research_case', {**disproved, 'verdict_evidence_refs': []})
    assert validate_action_result('analyze_research_case', {**disproved, 'verdict_evidence_refs': ['EVD-1']})


@pytest.mark.parametrize('verdict,confidence', [('credible', 85), ('inconclusive', 50)])
def test_other_actions_cannot_establish_research_credibility(verdict, confidence):
    base = {'summary': 'Finding', 'risk_assessment': 'Risk', 'evidence': [], 'recommended_actions': [], 'limitations': [], 'verdict_recommendation': verdict, 'verdict_confidence': confidence}
    with pytest.raises(DecisionError): validate_action_result('explain_finding', base)


def test_finding_triage_requires_separate_malicious_probability_and_evidence():
    base = {
        'summary': 'Finding review', 'risk_assessment': 'Review required', 'evidence': [],
        'recommended_actions': [], 'limitations': [], 'finding_verdict': 'true_positive',
        'disposition_recommendation': 'true_positive', 'finding_confidence': 99,
        'malicious_probability': 97, 'decision_evidence_refs': ['FND-1'],
    }
    assert validate_action_result('triage_finding', base, supplied_evidence_refs={'FND-1'}) is base
    for bad in ({k: v for k, v in base.items() if k != 'malicious_probability'},
                {**base, 'malicious_probability': float('nan')},
                {**base, 'decision_evidence_refs': ['INVENTED']}):
        with pytest.raises(DecisionError):
            validate_action_result('triage_finding', bad, supplied_evidence_refs={'FND-1'})


def test_artifact_abstention_can_only_name_a_supplied_missing_file():
    base = {
        'summary': 'Artifact review', 'risk_assessment': 'Review the omitted source file.', 'evidence': [],
        'recommended_actions': [], 'limitations': [], 'finding_verdict': 'needs_more_evidence',
        'disposition_recommendation': 'needs_review', 'finding_confidence': 60,
        'malicious_probability': 50, 'decision_evidence_refs': ['RULE-1'],
        'missing_evidence': ['package/payload.js'],
    }
    assert validate_action_result(
        'triage_artifact', base, supplied_evidence_refs={'RULE-1'},
        supplied_missing_files={'package/payload.js'},
    ) is base
    with pytest.raises(DecisionError, match='not identified as missing'):
        validate_action_result(
            'triage_artifact', {**base, 'missing_evidence': ['made-up.js']},
            supplied_evidence_refs={'RULE-1'}, supplied_missing_files={'package/payload.js'},
        )


def test_prioritization_requires_one_valid_result_per_supplied_finding():
    base = {'summary': 'Priorities', 'risk_assessment': 'Order by evidence and severity.', 'evidence': [],
            'recommended_actions': [], 'limitations': [], 'finding_priorities': [
                {'finding_id': 'FND-1', 'priority': 80, 'rationale': 'Strong corroborated signal.', 'evidence_refs': ['RULE-1']},
                {'finding_id': 'FND-2', 'priority': 20, 'rationale': 'Lower impact.', 'evidence_refs': ['RULE-2']},
            ]}
    assert validate_action_result('prioritize_findings', base, supplied_finding_ids={'FND-1', 'FND-2'},
                                  supplied_evidence_refs={'RULE-1', 'RULE-2'}) is base
    with pytest.raises(DecisionError):
        validate_action_result('prioritize_findings', {**base, 'finding_priorities': base['finding_priorities'][:1]},
                               supplied_finding_ids={'FND-1', 'FND-2'}, supplied_evidence_refs={'RULE-1', 'RULE-2'})
    fabricated = {**base, 'finding_priorities': [{**base['finding_priorities'][0], 'evidence_refs': ['UNKNOWN']}, base['finding_priorities'][1]]}
    with pytest.raises(DecisionError):
        validate_action_result('prioritize_findings', fabricated, supplied_finding_ids={'FND-1', 'FND-2'},
                               supplied_evidence_refs={'RULE-1', 'RULE-2'})


def test_publication_review_requires_complete_noncontradictory_checks():
    checks = {name: {'status': 'clear', 'finding': f'No {name} concern identified in the supplied case.'}
              for name in ('evidence', 'privacy', 'credential_leakage', 'operational_safety', 'legal_disclosure', 'reproducibility')}
    base = {'summary': 'Review complete.', 'risk_assessment': 'Human review remains mandatory.', 'evidence': [],
            'recommended_actions': [], 'limitations': ['This model assessment does not approve publication.'],
            'publication_risks': [], 'publication_checks': checks, 'disclosure_draft': 'Review-only disclosure draft.'}
    assert validate_action_result('review_publication_safety', base) is base
    incomplete = {**base, 'publication_checks': {key: value for key, value in checks.items() if key != 'privacy'}}
    with pytest.raises(DecisionError): validate_action_result('review_publication_safety', incomplete)
    contradiction = {**checks, 'privacy': {'status': 'concern', 'finding': 'Credential exposure is visible in the supplied draft.'}}
    with pytest.raises(DecisionError): validate_action_result('review_publication_safety', {**base, 'publication_checks': contradiction})
    with pytest.raises(DecisionError): validate_action_result('review_publication_safety', {**base, 'disclosure_draft': 'APPROVED. Proceed with publication.'})
    with pytest.raises(DecisionError): validate_action_result('review_publication_safety', {**base, 'recommended_actions': ['APPROVED. Proceed with publication.']})


@pytest.mark.parametrize('text,blocked', [
    ('REVIEW-ONLY DRAFT. NOT APPROVED. NOT FOR PUBLICATION.', False),
    ('This draft has not been approved and must not be sent.', False),
    ('Run it in an isolated, approved sandbox.', False),
    ('Notify the owner through approved channels.', False),
    ('Use an approved isolation plan.', False),
    ('APPROVED', True),
    ('Status: approved', True),
    ('Approved for publication.', True),
    ('The publication is approved.', True),
    ('This is an approved draft.', True),
    ('No concern found. Approved.', True),
    ('Proceed with publication.', True),
])
def test_publication_review_blocks_approval_claims_not_denials(text, blocked):
    checks = {name: {'status': 'clear', 'finding': f'No {name} concern identified.'}
              for name in ('evidence', 'privacy', 'credential_leakage', 'operational_safety', 'legal_disclosure', 'reproducibility')}
    result = {'summary': 'Review complete.', 'risk_assessment': 'Human review remains mandatory.', 'evidence': [],
              'recommended_actions': [], 'limitations': [], 'publication_risks': [], 'publication_checks': checks, 'disclosure_draft': text}
    if blocked:
        with pytest.raises(DecisionError, match='cannot approve release'):
            validate_action_result('review_publication_safety', result)
    else:
        assert validate_action_result('review_publication_safety', result) is result
