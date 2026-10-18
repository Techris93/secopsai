# Evidence-based research routing

SecOpsAI keeps **review priority** separate from **publication eligibility**.
Registry similarity, model confidence, severity, and alert counts do not by
themselves establish impact, novelty, or publication readiness.

Each case and discovery candidate exposes a read-only `routing` assessment:

| Route | Entry rule | Next action |
| --- | --- | --- |
| `urgent_review` | A current claim, assessed by a qualified technical reviewer, cites active evidence and an explicit urgent impact indicator. | Keep the case open, preserve cited evidence, and review exposure and disclosure promptly. An in-console alert is created immediately; notification is attempted only over separately configured urgent-review channels. |
| `validate` | Evidence or scope is incomplete, claims are absent or conflicting, or publication gates have not passed. | Collect the exact artifact and missing context, compare releases, check prior art, and ask for a human review only when structured behavior evidence makes impact plausible. |
| `publication_candidate` | Current claim assessments cite exact active evidence; scope and impact are explicit; a qualified technical reviewer passes claim, reproduction/corroboration, and materiality checks; prior-art and disclosure are current; publication and editorial gates pass. | Preserve the exact reviewed draft and complete the existing human release step. This route never publishes automatically. |
| `close_or_suppress` | A qualified reviewer records a positive benign explanation or exact duplicate relationship, cites evidence, and attests to a passing regression test and run. | Close the case with the disposition and test details in the audit history. |

The urgent impact indicators are explicit review annotations: `active_exploitation`,
`credential_theft`, `harmful_install_time_behavior`, and `victim_exposure`.
The claim action validates that each indicator cites the appropriate active
evidence type. Static credential access alone does not establish credential
theft; credential-theft escalation requires a primary source report or a
scoped experiment. A rule hit, package-name match, or model score cannot
create an urgent route by itself.

Immediate notifications are deliberately isolated from ordinary discovery and
collector channel selection. The hosted Research Worker explicitly routes
urgent review email to the already configured `research@secopsai.dev` inbox
through the existing SMTP delivery. Self-hosted deployments must configure
`SECOPSAI_RESEARCH_URGENT_ALERT_CHANNELS` with `email`, `webhook`, or both.
Email requires `SECOPSAI_RESEARCH_URGENT_REVIEWER_EMAIL`; signed webhooks require
`SECOPSAI_RESEARCH_URGENT_REVIEWER_WEBHOOK_URL` and
`SECOPSAI_RESEARCH_URGENT_REVIEWER_WEBHOOK_SECRET`. With no dedicated channel,
the urgent alert remains open and visible in Mission Control; it is never sent
to a general research inbox by fallback. Failed sends are audited and retried
with the worker's bounded backoff.

For a registry candidate, `research candidate list` includes the route,
whether a person needs to review it, publication blockers, evidence gaps, and
stable package/release/behavior grouping keys. A metadata-only candidate is a
validation lead. The daily worker promotes candidates that meet the configured
discovery policy and starts a bounded, non-executing artifact intake and static
analysis pipeline for their draft cases. Similarity may select safe evidence
collection; it does not set case confidence, establish impact, create an urgent
alert, or qualify a publication. The worker processes at most the lower of the
candidate-case and investigation limits each cycle. It does not infer a trusted
comparison package from a watchlist name. If no verified comparator is
supplied, the pipeline records that gap. Structured executable behavior or an
exact publisher mismatch can trigger routine technical review; cases without
such evidence remain in validation without generating a human review request.

For a case, `research case show <case-id>` includes `routing`. The dashboard
shows the same decision and reasons. Publication candidacy is independent of
the confidence field: there is no universal confidence cutoff in the routing
or publication-readiness gate.

For `universal-parcel-scraper@0.359.0-main.1977`, the supplied automated report
describes hard-coded tracking URLs but no observed behavior, a final verdict,
or confidence. The route is therefore **Validate**. The next work is to
acquire and hash the exact release, inspect the complete catalog and its use,
compare adjacent versions, consult authoritative carrier sources, and record
prior-art results. The URLs alone do not establish unexpected ownership,
network activity, data transfer, victim impact, or novelty, so the report is
neither urgent nor a publication candidate.

## Recording a close or suppress decision

Only a registered technical reviewer distinct from the case author can record
this decision. The exact cited text must resolve to active evidence. A benign
decision needs positive artifact, behavior, experiment, or primary-source
evidence; a duplicate decision must match an exact artifact hash or structured
subject identity. Both require a test node, reviewer-attested passed result,
CI run URL, commit, and timestamp. The test node must exist in the repository's
`tests/` tree. The system checks that the named test exists; it records the
reviewer's attestation and CI link rather than querying GitHub to verify the
run itself.

Example operation payload:

```json
{
  "decision": "benign",
  "explanation": "The complete release source shows these URLs are documented carrier tracking entries and no code sends package or user data to them.",
  "references": [
    {
      "evidence_id": "EVD-...",
      "selector": "metadata.file_contents.src/catalog.js",
      "start": 0,
      "end": 38,
      "excerpt": "const trackingEndpoints = [\"https://...\"]"
    }
  ],
  "regression_test": {
    "nodeid": "tests/test_research_routing.py::test_close_requires_audited_disposition",
    "result": "passed",
    "run_url": "https://github.com/Techris93/secopsai/actions/runs/123456789",
    "commit_sha": "0123456789abcdef0123456789abcdef01234567",
    "checked_at": "2026-10-18T12:00:00Z"
  }
}
```

Record it through the protected Research Operation action `case-disposition`
with the case ID and a registered technical reviewer identity. The action
closes the case and records the evidence references, rationale, test, CI run,
reviewer, and case fingerprint. New evidence invalidates the disposition for
routing purposes; the history is retained.

## Operational boundaries

- Automated validation collects registry metadata and exact artifacts where
  supported, hashes and inspects them without execution, and records evidence
  and limitations. Version comparison, prior-art searches, and additional
  context are automated only when their source or verified reference is
  available; otherwise they remain explicit case gaps.
- Automated research may draft hypotheses, prior-art search queries, and a
  report. These remain proposals until qualified review.
- Duplicate grouping uses exact package, release, behavior fingerprint, and
  recorded campaign identity. It does not infer shared attribution.
- A closed case without a current evidence-backed disposition and passing test
  is surfaced for validation rather than silently treated as benign.
- Review decisions, false alarms, missed issues, reproduction, and effort
  should be recorded in the research outcome ledger. Routing itself sets no
  global confidence threshold; tune policy only against independently labeled
  outcomes.
