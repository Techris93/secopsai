// Mirrors the Python persistence contract; runs before a lease can complete.
export function requireModelAction(model, action) {
  if (/^(typesafe|typesafe-ai)\//.test(model) || /^cloudflare\/clef(?:-flash)?$/.test(model)) {
    if (!['triage_finding', 'triage_artifact'].includes(action)) throw new Error('unsupported_action');
  }
}

export function validateDecisionResult(action, result) {
  const fail = message => { throw new Error(message); };
  for (const key of ['summary', 'risk_assessment']) {
    if (typeof result?.[key] !== 'string' || !result[key].trim()) fail(`Invalid ${key}`);
  }
  for (const key of ['evidence', 'recommended_actions', 'limitations']) {
    if (!Array.isArray(result[key]) || result[key].some(item => typeof item !== 'string')) fail(`Invalid ${key}`);
  }
  if (action !== 'analyze_research_case' && ((result.verdict_recommendation ?? 'inconclusive') !== 'inconclusive' || (result.verdict_confidence ?? 0) !== 0)) fail('Research credibility was not assessed by this action');
  const integer = key => {
    if (!Number.isInteger(result[key]) || result[key] < 0 || result[key] > 100) fail(`Invalid ${key}`);
  };
  if (['triage_finding', 'triage_artifact'].includes(action)) {
    if (!['true_positive', 'false_positive', 'benign_expected', 'policy_noise', 'needs_more_evidence'].includes(result.finding_verdict)) fail('Invalid finding_verdict');
    if (!['true_positive', 'false_positive', 'expected_behavior', 'tune_policy', 'needs_review'].includes(result.disposition_recommendation)) fail('Invalid disposition_recommendation');
    if (action === 'triage_artifact' && result.finding_verdict === 'policy_noise') fail('Invalid artifact verdict');
    const expected = { true_positive: 'true_positive', false_positive: 'false_positive', benign_expected: 'expected_behavior', policy_noise: 'tune_policy', needs_more_evidence: 'needs_review' };
    if (result.disposition_recommendation !== expected[result.finding_verdict]) fail('Verdict contradicts disposition');
    integer('finding_confidence');
    if (action === 'triage_artifact') {
      integer('malicious_probability');
      if (result.finding_verdict === 'needs_more_evidence' && (!Array.isArray(result.missing_evidence) || !result.missing_evidence.length || result.missing_evidence.some(path => typeof path !== 'string' || !path.trim() || path.includes('\n')))) fail('Artifact abstention requires a named missing file');
    }
    if (!Array.isArray(result.decision_evidence_refs) || result.decision_evidence_refs.some(ref => typeof ref !== 'string' || !ref)) fail('Invalid decision_evidence_refs');
  }
  if (action === 'analyze_research_case') {
    if (!['credible', 'likely', 'inconclusive', 'not_substantiated', 'benign'].includes(result.verdict_recommendation)) fail('Invalid research verdict');
    integer('verdict_confidence');
    if (['credible', 'likely', 'benign'].includes(result.verdict_recommendation) && (!Array.isArray(result.verdict_evidence_refs) || !result.verdict_evidence_refs.length || result.verdict_evidence_refs.some(ref => typeof ref !== 'string' || !ref) || typeof result.verdict_rationale !== 'string' || !result.verdict_rationale.trim())) fail('Research verdict requires supporting evidence');
  }
  if (action === 'generate_analyst_brief' && (!Array.isArray(result.article_outline) || !result.article_outline.length || result.article_outline.some(item => typeof item !== 'string' || !item.trim()))) fail('Analyst brief requires an outline');
  if (action === 'review_publication_safety') {
    if (!Array.isArray(result.publication_risks) || result.publication_risks.some(item => typeof item !== 'string') || typeof result.disclosure_draft !== 'string' || !result.disclosure_draft.trim()) fail('Publication review requires risks and a review-only draft');
    if (result.publication_approved === true || result.approved === true) fail('Publication review cannot authorize release');
  }
}
