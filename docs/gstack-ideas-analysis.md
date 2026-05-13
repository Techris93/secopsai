# GStack Ideas Analysis for Techris93 Projects

Source studied: <https://github.com/garrytan/gstack>

Generated: 2026-05-14

## What GStack Does

GStack is an AI-assisted software factory pattern built around specialist
operator workflows rather than one generic coding loop. Its repo is organized
as reusable skill prompts and operating rules for planning, executive review,
engineering review, design review, devex review, QA, security review, shipping,
post-deploy canary checks, retrospectives, and investigations.

The most useful idea is not the exact prompt text. The useful idea is the
workflow system: user intent gets routed to the right role, each role has a
repeatable checklist, write actions stay gated, and shipping includes post-merge
verification instead of stopping when tests pass.

## Patterns Worth Copying

High-value patterns:

- Role-based workflows for common operator intents: plan, review, QA, security,
  ship, canary, retro, and investigation.
- No-fix-without-investigation discipline for broken CI, production incidents,
  suspicious findings, and stale telemetry.
- Production review beyond CI: inspect behavior, docs, deployment config,
  browser output, and operator experience.
- Post-deploy canary checks that use low-volume read-only health probes.
- Team-mode conventions that make workflows discoverable in shared repos.
- Browser QA and screenshots for public sites and dashboards.
- Devex review that measures time to first useful result.
- Retros that turn repeated manual recovery steps into automation.
- OpenClaw-style intent routing where a plain-language request maps to the
  safest workflow.

## What Not To Copy

- Do not vendor the gstack repo into Techris93 projects unless a specific
  workflow runner is later approved.
- Do not copy prompt text verbatim into public docs or products.
- Do not replace SecOpsAI's local-first execution model with remote session
  upload patterns.
- Do not add autonomous write/deploy behavior without approvals.
- Do not make security reports noisy by treating every theoretical risk as a
  confirmed vulnerability.
- Do not make financial or health-adjacent apps fully autonomous. They need
  stricter safety and human-review gates than generic software tooling.

## Foundation Implemented Now

SecOpsAI now has a first read-only workflow foundation inspired by GStack:

- `secopsai workflow list`
- `secopsai workflow show plan`
- `secopsai plan`
- `secopsai review`
- `secopsai qa`
- `secopsai cso`
- `secopsai ship`
- `secopsai canary`
- `secopsai retro`
- `secopsai investigate`

These commands do not run risky actions. They print role-specific phases,
suggested existing commands, and safety gates. This gives the CLI and dashboard
a stable shared workflow vocabulary without changing existing triage, blog,
supply-chain, OpenClaw, or reporting behavior.

## Repo-by-Repo Roadmap

### SecOpsAI

Priority: high.

Opportunities:

- Expand the new workflow catalog into executable but approval-gated workflow
  runners.
- Map `plan`, `review`, `qa`, `cso`, `ship`, `canary`, `retro`, and
  `investigate` to existing SecOpsAI checks.
- Add a no-fix-without-investigation command for CI failures and triage
  findings.
- Add release checklists that run docs verification, blog verification,
  advisory checks, OpenClaw freshness checks, and regression tests.
- Add structured workflow state to the agent runtime so dashboard and CLI can
  resume the same workflow.

Implementation phases:

- Phase 1: read-only workflow catalog and docs. Status: started.
- Phase 2: workflow run records, logs, and artifacts in the local run store.
- Phase 3: approval-gated execution for safe commands.
- Phase 4: dashboard and OpenClaw handoff IDs for the same workflow sessions.

Safety gates:

- Keep destructive/write actions behind explicit approval.
- Keep external-news publishing review-gated.
- Keep advisory-backed supply-chain findings actionable until explicitly
  triaged.

### secopsai-dashboard

Priority: high.

Local repo inspected:
`/Users/chrixchange/Documents/Codex/2026-04-20-fix-issues-techris-apr-19-2026/secopsai-dashboard-repo`

Opportunities:

- Add a Workflow Center that exposes the same workflow names as the CLI.
- Show workflow cards for Plan, Security Audit, QA, Release, Canary, Retro,
  Blog Ops, and Finding Investigation.
- Surface workflow state, GitHub Actions runs, approvals, logs, and next
  actions.
- Keep button-triggered actions protected by backend endpoints or GitHub
  workflow dispatch, never by direct browser shell execution.

Implementation phases:

- Phase 1: read-only workflow cards linked to existing SecOpsAI commands.
- Phase 2: protected action endpoints that dispatch GitHub Actions.
- Phase 3: resumable workflow sessions with status, logs, artifacts, and
  approvals.

### openclaw-secopsai-plugin

Priority: high.

Local repo inspected: `/Users/chrixchange/openclaw-secopsai-plugin`

Opportunities:

- Add intent routing patterns:
  - "Run security audit" to SecOpsAI CSO workflow.
  - "Investigate this finding" to source-backed investigation.
  - "Prepare release" to review, QA, ship, and canary workflow.
- Keep all close, apply, orchestrate, and deploy actions explicitly
  approval-gated.
- Return workflow handoff IDs so the same case can continue in CLI or
  dashboard.

Implementation phases:

- Phase 1: expose read-only workflow metadata tools.
- Phase 2: add handoff IDs for existing investigation and review flows.
- Phase 3: route natural-language intents to workflow-safe actions.

### secopsai.dev

Priority: medium.

Opportunities:

- Add public operator-workflow pages:
  - Investigate.
  - Review.
  - Publish advisory.
  - Ship release.
  - Canary monitor.
- Add a time-to-first-value checklist for new operators.
- Add a "how SecOpsAI works" workflow visual to explain local-first operation.

Implementation phases:

- Phase 1: workflow pages and navigation updates.
- Phase 2: interactive install and quickstart checklist.
- Phase 3: release/canary examples tied to dashboard screenshots.

### docs.secopsai.dev

Priority: high.

Opportunities:

- Document the workflow catalog and exact CLI commands.
- Add operator runbooks for no-fix-without-investigation, CI failure analysis,
  advisory publishing, and canary checks.
- Add devex review docs that measure fresh-machine setup and first useful scan.

Implementation phases:

- Phase 1: workflow command reference.
- Phase 2: runbooks linked from CLI help and dashboard.
- Phase 3: docs QA workflow that verifies examples against real CLI surfaces.

### blog.secopsai.dev

Priority: medium-high.

Opportunities:

- Use workflow language in editorial operations:
  - Plan article.
  - Security review.
  - Publish.
  - Canary.
  - Retro.
- Add post-publish canary checks for homepage, post page, RSS feed, JSON feed,
  and comments health.
- Add devex review for newsroom workflow: fetch, draft, approve, publish,
  deploy.

Implementation phases:

- Phase 1: docs and CLI workflow mapping.
- Phase 2: dashboard Blog Ops integration with workflow status.
- Phase 3: publishing analytics and weekly retro.

### onboard-ai

Priority: high.

Local repo inspected: `/Users/chrixchange/.openclaw/workspace/onboard-ai`

Opportunities:

- Add role workflows for business assistant quality:
  - CEO review for positioning and commercial fit.
  - QA for generated answers.
  - Devex review for onboarding setup.
  - Release workflow for config promotion.
- Require eval history and approval gates before changing production assistant
  config.
- Add category-specific reviewers for pricing, support, docs, and policy.

Implementation phases:

- Phase 1: workflow checklist docs and eval-gated config promotion.
- Phase 2: dashboard/API workflow state for experiments.
- Phase 3: role-specific subagents with bounded write scopes.

Safety gates:

- Do not promote config changes without evaluation output.
- Do not publish customer-specific data into eval fixtures.

### optifit

Priority: high, with stricter safety.

Local repo inspected: `/Users/chrixchange/optifit`

Opportunities:

- Add role workflows for plan review, safety review, QA, content review, and
  release canary.
- Add human-review gates for injury, rehab, medical-sensitive, and high-risk
  recommendations.
- Add feedback/canary monitoring for generated plans.
- Add devex review for onboarding gyms, coaches, equipment, and rules.

Implementation phases:

- Phase 1: safety workflow checklist and human-review gates.
- Phase 2: plan QA fixtures and feedback monitoring.
- Phase 3: bounded research against exercise catalogs and media.

Safety gates:

- Avoid fully autonomous health-adjacent advice.
- Store rationale, contraindication flags, fallback confidence, and reviewer
  history for promoted plan templates.

## Cross-Project Priorities

High priority:

- Shared workflow vocabulary across CLI, dashboard, plugin, and docs.
- No-fix-without-investigation debugging workflow.
- Release and canary checklists.
- Security audit workflow using safe OWASP and STRIDE prompts.
- Approval-gated write actions everywhere.

Medium priority:

- Browser QA screenshots for public sites and dashboards.
- Weekly retro and shipping analytics.
- Devex review and time-to-first-value checks.
- Docs pages that explain operator workflows.

Low priority:

- Full autonomous multi-role project manager loops.
- Remote session upload or hosted agent state by default.
- Broad prompt marketplaces or skill installers inside production repos.

## Risks and Safety Gates

- Workflow sprawl: too many commands can confuse operators. Keep the first
  surface small and role-oriented.
- False authority: a "CSO" workflow must still distinguish confirmed findings
  from possible risks.
- Approval bypass: dashboard buttons must never execute writes directly from
  the browser.
- Source quality: news and advisory publishing must cite sources and stay
  review-gated.
- Sensitive domains: optifit and gold/finance-like projects require stricter
  human review than SecOpsAI release automation.

## Next Implementation Steps

1. Add dashboard Workflow Center cards that read from the SecOpsAI workflow
   catalog or a matching static schema.
2. Add workflow run records to SecOpsAI's local artifact store.
3. Add a `secopsai workflow run <name>` command that executes only read-only
   checks by default.
4. Add approval-gated execution for publish, deploy, close, apply-action, and
   orchestrate actions.
5. Add docs pages for each workflow and verify the examples in CI.
