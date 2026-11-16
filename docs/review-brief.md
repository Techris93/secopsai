# Review brief

Finished assistant teams wait for a person's technical review. The worker
prefills that review; the person records it at `#research/review` on the
dashboard (linked from the daily alert digest).

For each check the worker reports one of:

- **Verified**: the ledger proves it for the current case state (a current
  claim assessment for every claim, an execution experiment or sandbox
  result, a detection test, a verified patch). Shown ticked, with the proof.
- **Your judgement**: only a person can decide (materiality, competing
  explanations, affected versions, unverified mitigations, attribution words
  in the draft, completeness of limitations). Shown unticked, with a note.
- **Not established**: nothing supports it yet. Approval is impossible until
  it is. Shown unticked.

The suggested decision is *changes required* whenever any check is not
established or no current prior-art search exists; the rationale lists why.
The bulk button records exactly that on every not-ready case, and nothing else.
Approval always needs every check ticked by the person. Recording queues a
`case-review` operation; the worker validates and records it on its next run.

The draft is the case's claims word for word followed by the team's review
pack, so an approval passes the "each claim is in the draft" rule. Long text
is sent to Core in parts of under 4,000 characters and joined by the
dashboard, because Core cuts single strings at that length.

## Claims for cases that have none

A review needs at least one material claim. A case that skipped the pipeline
step that builds its evidence matrix has none, so when its team is awaiting
review the case sync builds that matrix first (actor
`automation:review-brief`, recorded on the case timeline). The claims are the
fixed evidence-derived ones every pipeline case gets: the subject, the
artifact hash and that SecOpsAI did not run it, the static observation count,
and a linked sandbox report if any. Claims whose evidence is missing are kept
in the ledger but left out of the draft. Model text from the team never
becomes a claim; it stays in the review pack. Every claim still needs a
person's claim assessment before an approval counts.
