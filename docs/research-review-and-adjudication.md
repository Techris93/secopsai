# Research Review And Adjudication

SecOpsAI uses two bounded reviews for publication-sensitive research. The
domain specialist checks the technical interpretation; a separate independent
reviewer checks the same evidence without seeing the primary review's verdict,
confidence, wording, or recommendation.

## Automatic routing

The Specialist Orchestrator selects a reviewed profile from
`secopsai/specialists/catalog.v1.json` and records the selected OpenCodex model
and fallback policy. Typical routes include:

- package or registry compromise: Threat Intelligence Analyst;
- incident or token breach: Incident Responder;
- CI or workflow change: DevOps Automator and Code Reviewer;
- application-security behavior: Application Security Engineer;
- publication claims: Threat Intelligence Analyst and Senior SecOps Engineer.

Automatic routing never exceeds read-only analysis. Worktree edits, PRs,
disclosure, sandbox submission, publication, deployment, and external
communication remain approval-gated.

## Review status

| Status | Meaning | Next step |
| --- | --- | --- |
| `not_started` | No specialist run exists | Queue the specialist |
| `awaiting_review` | Primary result is complete | Queue or await the blinded reviewer |
| `needs_review` | Both results are stored | Compare evidence and resolve disagreement if needed |
| `completed` | Review is complete and no unresolved disagreement remains | Continue audits and publication safety |

Material disagreement is persisted with the run and blocks publication. It is
not silently averaged away.

## Human adjudication

In the case workspace, open **Specialist and blind review**, read both
evidence-linked outputs, choose one decision, and enter a rationale that names
the supporting evidence. The decisions are:

- **Accept primary**: resolve in favor of the domain specialist.
- **Accept independent reviewer**: resolve in favor of the blind reviewer.
- **Request more evidence**: keep publication blocked and revise the evidence
  plan.

The dashboard requires at least 20 characters and confirms that recording the
decision does not publish or deploy. The CLI equivalent is:

```bash
secopsai research reliability adjudicate-review SOR-XXXXXXXXXXXXXXXX \
  --decision accept_primary \
  --rationale "The primary interpretation matches the verified artifact and registry evidence." \
  --json
```

The event, actor, timestamp, decision, and rationale are retained in the audit
trail. Resolving disagreement clears only that blocker; completeness,
originality, visual QA, claim support, disclosure, and human publication gates
still apply.

## Model failures

If the selected OpenCodex provider is unavailable and fallback is disabled,
the job remains queued with an explicit provider error. Do not change the
model merely to make a status green. Correct the provider or intentionally
change the persisted routing policy, then retry the captured job.
