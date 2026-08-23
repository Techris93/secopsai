---
title: Specialist Orchestrator
description: Deterministic specialist routing and approval-gated OpenCodex execution for SecOpsAI Mission Control work.
---

# Specialist Orchestrator

The Specialist Orchestrator turns a SecOpsAI Work item into a bounded,
auditable execution contract. It chooses one reviewed specialist profile,
captures the operator's persisted OpenCodex model and explicit fallback policy,
and applies an automation tier that cannot exceed the configured safety ceiling.

The specialist and the model are deliberately separate:

- The **specialist profile** defines domain guidance, expected deliverables,
  evidence needs, risk limits, and an independent reviewer.
- The **OpenCodex model** performs the bounded analysis or implementation. It is
  the primary model already selected under **Administration -> Automation ->
  Models**.
- The **execution policy** defines what the run may do. A profile never grants a
  tool, permission, filesystem path, network destination, or external action.

OpenClaw and Hermes remain optional telemetry and compatibility dispatch
runtimes. They are not model providers for Specialist Orchestrator runs.

## Architecture

```text
Work item
  -> bounded task normalization
  -> deterministic classifier
  -> reviewed specialist + independent reviewer
  -> persisted OpenCodex model/fallback snapshot
  -> execution-policy contract
  -> recommend | read-only | approved worktree | PR-ready worktree
  -> structured result + independent review + operator decision
```

Core owns routing, contracts, durable SQLite state, approvals, audit events,
recovery state, and OpenCodex job handoff. Mission Control uses typed helper
routes that build fixed CLI argument arrays. The browser cannot submit a shell
command, choose an arbitrary repository, or supply an unrestricted local path.

## Trusted specialist catalog

The versioned catalog is stored at
`secopsai/specialists/catalog.v1.json`. The initial profiles adapt a reviewed
subset of [Agency Agents](https://github.com/msitarzewski/agency-agents) at the
pinned commit recorded in the catalog. SecOpsAI retains the upstream repository,
commit, license, review date, source path, and source SHA-256 for every adapted
profile. The upstream MIT license is retained in
`secopsai/third_party/agency-agents-LICENSE.txt`.

SecOpsAI does **not** run an Agency Agents installer, load upstream prompt files
at runtime, or import executable examples. Catalog validation rejects malformed
profiles, unknown reviewers, duplicate IDs, and profile text that contains prompt
override, policy bypass, secret access, destructive command, publication,
deployment, or push instructions.

The reviewed roster covers:

- orchestration and cross-domain planning
- SecOps, incident response, threat intelligence, and application security
- backend, frontend/UI, DevOps/CI, database, and code review
- test automation and accessibility
- documentation, product, visual design, privacy, and compliance

## Deterministic routing

The classifier evaluates normalized title, description, domain, roles, risk
flags, and repository scope. It returns the primary and reviewer profiles,
confidence, score, risk, reasons, alternatives, evidence gaps, and a repository
alias. A manual override is accepted only when it names a profile already in the
reviewed catalog.

Example routes:

| Work | Primary specialist | Independent reviewer |
| --- | --- | --- |
| Investigate a breach or production incident | Incident Responder | Senior SecOps Engineer |
| Repair a GitHub Actions release gate | DevOps Automator | Code Reviewer |
| Audit a slow query or missing index | Database Optimizer | Backend Architect |
| Review authentication or reachable AppSec risk | Application Security Engineer | Senior SecOps Engineer |
| Correct a responsive Mission Control screen | Frontend Developer | UI Designer |
| Audit WCAG behavior | Accessibility Auditor | Frontend Developer |
| Prepare source-backed threat research | Threat Intelligence Analyst | Senior SecOps Engineer |
| Map SOC 2, ISO, HIPAA, NIST, CIS, or NIS2 evidence | Compliance Auditor | Privacy Engineer |

Ambiguous tasks route to the general orchestrator and retain an explicit
evidence gap rather than inventing scope.

## Automation tiers

| Tier | What it does | Approval and boundary |
| --- | --- | --- |
| Recommendation only | Saves the route and contract without model execution | No execution; safe default |
| Read-only analysis | Queues bounded analysis on the captured OpenCodex model | No repository edits; independent review is queued |
| Isolated worktree | Lets the model edit one allowlisted repository from the commit frozen in the reviewed contract | Explicit operator approval required before execution |
| PR-ready delivery | Produces a locally reviewable worktree and complete diff with verification evidence | Explicit approval; does not commit, push, or open a PR |

Automatic policy can never exceed read-only analysis. High- or critical-risk
work is reduced to recommendation when the deterministic guard requires human
alignment. The only exception is a trusted Core-created Research Case task
marked analysis-only: it may receive read-only specialist analysis and an
independent review, but it gains no state-changing authority. Worktree and
PR-ready tiers are never automatic.

The orchestrator never autonomously merges, pushes, opens or approves a pull
request, deploys, publishes, sends disclosure, submits external research,
mutates cloud or Kubernetes resources, changes billing or access control,
reads or rotates secrets, or deletes production data or evidence.

Worktree execution also enforces these controls in the runner:

- the reviewed base commit is captured before approval and used even if the
  source branch advances later;
- only one process can claim a ready run;
- sandbox command networking, web search, apps, MCP servers, plugins, hooks,
  skill installation, and multi-agent delegation are disabled;
- the inherited shell environment is reduced and default secret-name
  exclusions remain active;
- a model-created commit, a failed `git diff --check`, an unavailable base
  commit, or more than 40 changed files fails the run closed;
- the actual repository diff and file list, rather than the model's claimed
  file list, become the review evidence.

## Mission Control workflow

1. Open **Work** and check **Specialist Orchestrator**. Confirm the reviewed
   roster, selected OpenCodex model, fallback policy, automation policy, and
   active runs.
2. Open a work item and select **Open work brief**.
3. Review the recommended primary specialist, independent reviewer, routing
   reasons, evidence gaps, risk, permissions, runtime/file budget, reviewed
   repository commit, selected model, and fallback snapshot.
4. Keep **Automatic recommendation** unless evidence supports a specific
   reviewed specialist override.
5. Choose an automation tier. Use recommendation while scope is unclear; use
   read-only for diagnosis; use a worktree only for a bounded repository change.
6. Save or queue the run. Protected actions require the Automation action
   token. Route preview remains read-only.
7. For a worktree tier, approve the exact captured contract and base commit, then separately
   select **Run in worktree**. Inspect the resulting local diff and independent
   review before accepting anything.
8. Canceling a queued specialist run also cancels its linked queued model job.
   A running model job must first stop or be recovered by the bridge.
9. If the run stops, inspect its audit history and recovery state. A failed
   worktree is preserved rather than overwritten.

The **Route next priority item** control applies the persisted automatic policy
to the highest-priority open item in the current Work filter. In guarded mode it
may create a recommendation or read-only run only.

When editing the policy, background status refreshes preserve the unsaved form
values. **Save policy** verifies the value written to Core before reporting
success. The safe automatic setting is **Guarded automation** with a
**Read-only analysis** ceiling. If read-back does not match, the form remains
dirty and displays an error instead of silently returning to recommendation.

The complete daily workflow also routes Research Cases in `validation` or
`ready_to_publish` that contain a structured subject and active evidence. Core chooses the reviewed specialist,
captures the selected OpenCodex model and explicit fallback policy, queues the
independent reviewer, and attaches the completed summaries once as analyst-note
evidence. The result still requires operator acceptance and cannot approve or
publish the case.

## CLI workflow

Validate the catalog and inspect effective policy/model state:

```bash
secopsai specialists catalog --json
secopsai specialists status --json
secopsai specialists policy --json
```

Preview a route without writing state:

```bash
secopsai specialists route \
  --input-json '{"title":"Repair failing CI release gate","description":"Use the failed job evidence and preserve security gates.","repo_alias":"secopsai","evidence_refs":["run:473"]}' \
  --tier read_only --json
```

Create and queue a read-only run:

```bash
secopsai specialists create \
  --input-json '{"title":"Analyze slow finding query","repo_alias":"secopsai"}' \
  --tier read_only --enqueue --json
```

Create, approve, and execute an isolated worktree run:

```bash
secopsai specialists create \
  --input-json '{"title":"Add a regression test for the queue fix","repo_alias":"secopsai","evidence_refs":["issue:123"]}' \
  --tier worktree --json

secopsai specialists approve SOR-XXXXXXXXXXXXXXXX --json
secopsai specialists execute SOR-XXXXXXXXXXXXXXXX --json
secopsai specialists show SOR-XXXXXXXXXXXXXXXX --json
```

Configure guarded automatic read-only routing:

```bash
secopsai specialists policy \
  --mode guarded --maximum-automatic-tier read_only --json
```

Use `off` to disable automatic routing or `recommend` to permit recommendation
records only.

## Durable execution contract

Each run captures the facts needed to reproduce and audit its decision:

- normalized task, evidence references, task type, and allowlisted repo alias
- specialist catalog version/hash, primary profile, reviewer, and upstream pin
- selected OpenCodex primary model, ordered fallbacks, fallback mode, and source
- allowed and forbidden actions, runtime/retry/file budgets, and stop conditions
- approval state, run status, structured primary result, reviewer result, tests,
  artifacts, error state, timestamps, and append-only audit events
- local branch/worktree recovery information, withheld from dashboard responses

The captured model snapshot does not change when the operator later changes the
global model. With fallback disabled, provider failure leaves the run failed or
queued for that model. With an explicit fallback policy, only qualifying quota,
authentication, or provider-availability errors advance through the captured
ordered list. Schema, validation, safety, and task errors never trigger model
fallback.

## Profile update procedure

Treat every upstream profile update as prompt supply-chain review:

1. Clone or fetch Agency Agents into a disposable review directory. Do not run
   its installer or copy the complete profile collection into SecOpsAI.
2. Pin the exact reviewed commit and verify the upstream license.
3. Review only the source profiles required by the SecOpsAI roster. Reject tool
   grants, prompt overrides, secret access, destructive operations, autonomous
   external actions, or instructions that conflict with SecOpsAI policy.
4. Adapt minimal domain guidance and deliverables into the local data-only
   catalog. Do not embed executable commands as authority.
5. Record source path and SHA-256, increment the catalog version, update the
   review date/commit, and retain attribution.
6. Run catalog validation, routing and prompt-injection tests, the full Core
   suite, and dashboard contract tests. Review the catalog diff manually.

Optional source verification against a reviewed clone:

```bash
secopsai specialists catalog --source-root /path/to/reviewed/agency-agents --json
```

## Troubleshooting

### No OpenCodex model is selected

Open **Administration -> Automation -> Models**, select a primary, choose the
fallback policy, and save it. SecOpsAI will not silently select another model.

### The selected provider is unavailable

With primary-only mode, wait or fix that provider. If continuity is intended,
configure an ordered fallback list explicitly. Existing runs retain their own
captured routing snapshot.

### Hosted Mission Control says the orchestrator is unavailable

Specialist execution is local-helper-backed. Start the canonical local
Mission Control stack and open its local URL. Hosted mode fails safely when no
helper is configured; it does not call a retired helper tunnel or execute in the
browser.

### A worktree run is awaiting approval

This is expected. Review repository scope, evidence, selected model, fallback
policy, specialist, permissions, and stop conditions. Approval and execution are
separate protected actions.

### A worktree run failed

Open the run audit history. The worktree is preserved locally for recovery and
is not overwritten on retry. Resolve the recorded blocker deliberately; do not
create repeated speculative runs.

### A task routed to the wrong specialist

Improve the title, description, domain, evidence references, or repository
scope. If needed, choose a reviewed profile override and record why. Overrides
do not change permissions or the selected model.

## Current limitations

- The durable default is local SQLite; it is not a multi-tenant hosted job
  scheduler.
- PR-ready means a local, independently reviewed diff. It does not create or
  publish a pull request.
- Profile routing is deterministic rather than model-classified. This keeps it
  explainable but requires rule/catalog maintenance as domains evolve.
- The orchestrator does not replace issue ownership, code review, CI, release
  approval, or incident command.
