# Intelligence integrations

SecOpsAI supports two separate model-assisted operating modes. Both use the same versioned, read-only intelligence contract and both keep raw scanner output, packet data, package artifacts, credentials, and private keys outside model context.

## Choose the correct mode

| Mode | Where the model runs | Authentication | Best use |
|---|---|---|---|
| Local Codex bridge | Codex CLI on the operator's Mac or Linux sensor | Existing local ChatGPT sign-in | Private local analysis and Mission Control actions |
| ChatGPT app | ChatGPT calls the hosted SecOpsAI MCP server | SecOpsAI OAuth plus the user's ChatGPT account | Conversational access to authorized findings, assets, and research cases |

ChatGPT authentication pays for and identifies the model session. SecOpsAI OAuth separately decides which SecOpsAI data that person may read. One never replaces the other.

## Local OpenCodex / multi-model bridge

SecOpsAI can use your local OpenCodex proxy so research analysis is not locked to one ChatGPT account.

Research actions request evidence-led structured output rather than a chat-style paragraph. A completed case analysis includes an executive summary, confirmed facts, inferences, unsupported claims, contradictions, missing evidence, prioritized next steps, a confidence-scored verdict, evidence references, limitations, and publication risks. Mission Control presents these fields separately and retains the complete normalized result and job history.

## Autonomous finding and alert triage

Mission Control can use any model in the local OpenCodex catalog, including Kimi K3, Grok, Gemini, or an available Codex model, to review new canonical findings continuously. This includes host detections, Edge findings, supply-chain findings, and high-confidence research candidates produced by registry monitoring. Open **Administration → Automation**, select the model, then configure **Agent finding and alert review**.

Research candidate alerts are normalized into canonical findings with source `secopsai_research`. Package verification remains actionable even when the package is not present in the local repository. Missing local exposure affects the response scope only; it is never evidence that the external package is safe.

The reconciliation runs before every agent-triage cycle and is idempotent. It also backfills older open research alerts, so upgrading Core does not leave pre-existing alerts outside the model review queue.

Operational alerts such as registry timeouts and stale collector cursors are handled by deterministic health checks instead of model opinion. They resolve only after successful coverage recovery, remain visible while degraded, and never become package verdicts.

The modes are:

- `off`: no automatic model jobs are created.
- `advisory`: the model records a verdict, counterarguments, evidence references, and handling recommendation without changing the finding.
- `guarded`: Core may close a false positive or expected behavior only when deterministic SecOpsAI analysis independently supports the same disposition, the model meets the configured confidence and evidence thresholds, and no advisory-backed or strong threat evidence conflicts. The prior state is retained for one-click rollback.

Guarded mode may promote corroborated true positives to `in_review`. It never publishes, sends disclosure, submits an artifact, executes package code, performs destructive response, or treats missing local exposure as proof that a package is benign.

## Complete daily workflow

The daily coordinator links the operational steps that previously required
separate clicks or terminal commands. It runs only when its persisted schedule
is due and records one durable run with a result for every step:

1. Run due registry collectors, score new events, retry bounded failures, and
   recover interrupted collector work.
2. Apply the configured deterministic candidate-promotion policy. Promotion
   creates draft research cases only; it is not a maliciousness verdict.
3. Record every alert as feedback and queue eligible findings for the selected
   model. Unknown outcomes remain active-learning records and are never used as
   labels.
4. Collect exact package evidence and run bounded static investigations for
   eligible high-priority findings.
5. Run the guarded detection-learning replay, holdout, shadow, and canary
   checks. A failed quality gate produces a proposal or a blocked run; it does
   not silently change a detector.
6. Deliver configured operational health alerts with the existing retry and
   audit controls.

Configure or run the coordinator from **Administration → Automation → Daily
workflow automation**, or use the CLI:

```bash
cd /Users/chrixchange/secopsai
.venv/bin/python -m secopsai.cli intelligence autopilot daily status
.venv/bin/python -m secopsai.cli intelligence autopilot daily configure \
  --enabled on --interval-seconds 86400 \
  --max-alert-reviews 25 --max-investigations 5 \
  --max-candidate-cases 25 --auto-promote-candidates on --run-learning on
.venv/bin/python -m secopsai.cli intelligence autopilot daily run
```

The research worker checks the same schedule on every normal worker cycle, so
no second daemon is required. A stale or overlapping run is recovered and
marked in the run history rather than started twice. A failed step does not
cancel later steps; the cycle is marked `degraded` and the failed step remains
retryable on the next due cycle.

Agents may prepare evidence, triage recommendations, reversible finding
changes, draft cases, and learning proposals. Sandbox submission, disclosure
delivery, public publication, and unverified detector activation remain
explicit approval actions.

The model may propose rule or threshold tuning. Every proposal enters shadow mode. Only an ecosystem threshold that exactly matches a high-confidence deterministic historical replay, includes enough reviewed safe and risky findings, and introduces no known true-positive regression can activate automatically. Rule weights, conditions, and exceptions remain shadow-only.

## Closed-loop alert feedback

Every observed alert now contributes to a durable feedback ledger. This includes
verified true positives, false positives, expected behavior, unresolved alerts,
true-negative baseline observations, and later-discovered false negatives.
Unknown outcomes are retained for active learning, but they are not treated as
truth. Only evidence-backed or explicitly verified outcomes become training
examples.

The learning label is derived separately from the operational outcome:

| Outcome | Training class | Meaning |
|---|---|---|
| `true_positive` | positive | The alert correctly identified a threat. |
| `false_negative` | positive | A threat was missed; the missed evidence becomes a positive example. |
| `false_positive` | negative | The alert was not a threat. |
| `true_negative` | negative | A reviewed baseline stayed benign. |
| `unknown` | none | Not enough evidence yet; retained for future adjudication. |

The feedback ledger is append-only and records the subject, event, outcome,
evidence references, feature version, source, confidence, actor, and dedupe
key. The existing replay, holdout, shadow, canary, false-negative gate, and
rollback controls remain in force. This means every alert improves SecOpsAI's
context and active-learning queue immediately, while production detection rules
change only after deterministic validation.

Record a verified outcome explicitly when an investigation finishes:

```bash
cd /Users/chrixchange/secopsai
.venv/bin/python -m secopsai.cli intelligence autopilot learning feedback \
  --finding-id SCM-EXAMPLE \
  --feedback-outcome true_positive \
  --source operator_verified \
  --confidence 95 \
  --trust-score 95 \
  --evidence-ref EVD-EXAMPLE \
  --actor analyst
```

Record a missed detection or a reviewed benign baseline with a stable subject
key. These records do not require a finding ID:

```bash
.venv/bin/python -m secopsai.cli intelligence autopilot learning feedback \
  --subject-key missed-release-2026-01 \
  --feedback-outcome false_negative \
  --source operator_verified \
  --confidence 95 \
  --trust-score 95 \
  --evidence-ref EVD-EXAMPLE \
  --actor analyst

.venv/bin/python -m secopsai.cli intelligence autopilot learning feedback \
  --subject-key baseline-window-2026-01 \
  --feedback-outcome true_negative \
  --source rule_fixture \
  --confidence 100 \
  --trust-score 100 \
  --evidence-ref FIXTURE-EXAMPLE \
  --actor test-harness
```

Run the learning cycle from **Administration → Automation → Detection
Learning**. The page shows total feedback, trusted examples, unresolved
feedback, experiments, staged proposals, and rollbacks. A model recommendation
alone never becomes a label, and no learning cycle can publish, disclose,
execute packages, or perform destructive response.

CLI equivalents:

```bash
secopsai intelligence autopilot configure --mode guarded --model kimi/k3
secopsai intelligence autopilot run-now
secopsai intelligence autopilot status
secopsai intelligence autopilot runs
secopsai intelligence autopilot tuning
secopsai intelligence autopilot rollback ATR-XXXXXXXXXXXXXXXX
secopsai intelligence autopilot rollback-tuning DTP-XXXXXXXXXXXXXXXX
```

The background bridge checks for newly changed findings and normalized research-candidate alerts before each queue poll, so a continuously running service provides near-real-time review without adding a second daemon.

The bridge processes durable queued work before discovering another record, performs at most one new deterministic assessment per idle poll, and bypasses OpenCodex's redundant per-command `ensure` step after the provider health check succeeds. If the user-level bridge is stopped or reinstalled during a model run, interrupted local jobs are requeued immediately and keep their audit history.

Configured on this machine:

- `gpt-5.6-luna` (primary)
- `gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.4-mini` (same OpenAI/Codex fallback pool)
- `kimi/kimi-k2.7-code`
- `xai/grok-4.5`
- `google-antigravity/gemini-3.5-flash-low`
- plus the rest of your OpenCodex catalog

### Choose a model

List models:

```bash
cd /Users/chrixchange/secopsai
.venv/bin/python -m secopsai.cli intelligence bridge models
```

Run one job on a selected model:

```bash
.venv/bin/python -m secopsai.cli intelligence bridge run --once   --model kimi/kimi-k2.7-code   --db-path data/openclaw/findings/openclaw_soc.db
```

Set a default model for the bridge service:

```bash
export SECOPSAI_BRIDGE_MODEL=xai/grok-4.5
export SECOPSAI_BRIDGE_FALLBACK_MODELS=gpt-5.6-sol,gpt-5.6-terra,gpt-5.4-mini,google-antigravity/gemini-3.5-flash-low,kimi/kimi-k2.7-code,xai/grok-4.5
.venv/bin/python -m secopsai.cli intelligence bridge service stop
.venv/bin/python -m secopsai.cli intelligence bridge service start
```

The operator-selected model is persisted and used exclusively. Health probes and jobs do not walk the Codex fallback pool unless `SECOPSAI_BRIDGE_FALLBACK_MODELS` is set. If the selected model is at a usage limit, SecOpsAI reports that model as unavailable instead of spending other providers' quotas.

Mission Control model picker: the local bridge module in the dashboard lists the same catalog as a dropdown. Pick a model there and use **Process next job**; failed jobs can be requeued from the jobs table and retried on another model without recreating the pipeline.

Requeue a failed job after switching models:

```bash
.venv/bin/python -m secopsai.cli intelligence jobs requeue AIJ-...   --db-path data/openclaw/findings/openclaw_soc.db
```

OpenCodex must be healthy:

```bash
opencodex status
opencodex health --json
```

## Local Codex bridge

The bridge accepts only named SecOpsAI actions. It does not expose an arbitrary prompt or shell endpoint. Core builds a minimized context, the bridge runs Codex in an ephemeral read-only sandbox, and the structured result returns to the durable job record for human review.

Check the local installation and ChatGPT sign-in:

```bash
cd /Users/chrixchange/secopsai
.venv/bin/python -m secopsai.cli intelligence bridge doctor
```

List the approved actions:

```bash
.venv/bin/python -m secopsai.cli intelligence actions
```

Queue an explanation for one finding:

```bash
.venv/bin/python -m secopsai.cli intelligence enqueue \
  --action explain_finding \
  --target-id FND-EXAMPLE
```

Process one queued request:

```bash
.venv/bin/python -m secopsai.cli intelligence bridge run --once
```

Install the bridge as a user-level background service:

```bash
.venv/bin/python -m secopsai.cli intelligence bridge service install
.venv/bin/python -m secopsai.cli intelligence bridge service status
.venv/bin/python -m secopsai.cli intelligence bridge service logs
```

The installer creates `~/Library/LaunchAgents/ai.secopsai.codex-bridge.plist` on macOS or `~/.config/systemd/user/secopsai-codex-bridge.service` on Linux. It does not copy or persist a ChatGPT credential. Codex continues to own its local authentication state.

### Automated research investigations

Mission Control's **Run Investigation Pipeline** action uses the same durable bridge queue. Core first performs bounded package collection and deterministic static analysis, then creates three read-only jobs: case analysis, analyst brief, and publication-safety review. The bridge receives normalized case context, hashes, manifests, static indicators, and comparison results. It never receives the quarantined artifact, raw registry responses, local quarantine paths, secrets, or customer telemetry.

Bridge results return to Core as review proposals. They do not become evidence until an operator accepts them, and model-generated text is stored only as an analyst-reviewed case note. A bridge failure leaves the pipeline retryable; retries create a new revision and preserve the previous attempt for audit. Verdicts, sandbox submission, disclosure delivery, and publication remain independent human approvals.

## ChatGPT app MCP server

The app exposes nine read-only tools:

- workspace summary
- list and get findings
- list assets and recent asset changes
- list and get research cases
- build a non-persisting evidence matrix
- check publication readiness

The MCP server never runs Codex. ChatGPT provides the reasoning and calls the tools. The server verifies the SecOpsAI OAuth access token, checks issuer, audience, expiry, signature, and per-tool scope, then calls the Core intelligence API with a server-side read credential.

### Local protocol test

```bash
cd /Users/chrixchange/secopsai/apps/secopsai-chatgpt
npm ci --ignore-scripts
npm test
npm audit --audit-level=moderate
```

### Production OAuth requirements

Use an established OAuth 2.1 provider such as Auth0, Okta, Cognito, or Stytch. Configure authorization-code flow with PKCE `S256`, a token audience equal to `SECOPSAI_MCP_RESOURCE`, short-lived signed access tokens, the four SecOpsAI read scopes, and a JWKS endpoint. Do not build a custom password or token issuer inside the MCP server.

Required scopes:

- `secopsai.workspace.read`
- `secopsai.findings.read`
- `secopsai.assets.read`
- `secopsai.research.read`

The primary `render.yaml` deliberately does not provision this service. This keeps ordinary Core and research-worker Blueprint syncs independent from optional OAuth configuration and avoids an unused paid service. When the ChatGPT app is ready for a pilot, create one Render web service manually with:

- Repository: `Techris93/secopsai`
- Root directory: `apps/secopsai-chatgpt`
- Runtime: Node
- Build command: `npm ci --ignore-scripts`
- Start command: `npm start`
- Health path: `/readyz`
- Instance: Starter or higher for a reliable pilot; free is acceptable only for temporary development

Required service values:

| Variable | Purpose |
|---|---|
| `SECOPSAI_MCP_AUTHORIZATION_SERVER` | OAuth issuer base URL advertised to ChatGPT |
| `SECOPSAI_MCP_ISSUER` | Exact expected JWT `iss` value |
| `SECOPSAI_MCP_JWKS_URL` | Provider signing-key endpoint |
| `SECOPSAI_CORE_READ_TOKEN` | Same server-side read credential configured on Core |

Also set:

| Variable | Value |
|---|---|
| `SECOPSAI_MCP_ENVIRONMENT` | `production` |
| `SECOPSAI_MCP_RESOURCE` | Exact public service origin, without `/mcp` |
| `SECOPSAI_MCP_AUDIENCE` | Same exact public service origin |
| `SECOPSAI_MCP_ALLOWED_HOSTS` | Public service hostname only |
| `SECOPSAI_MCP_ALLOWED_ORIGINS` | `https://chatgpt.com` |
| `SECOPSAI_MCP_DOCUMENTATION_URL` | `https://docs.secopsai.dev/intelligence-integrations/` |
| `SECOPSAI_CORE_API_URL` | `https://secopsai-core-api.onrender.com` |

Set the production MCP resource and audience to the exact public Render origin. Change both together if a custom domain is introduced.

After the opt-in deployment, verify:

```bash
curl -sS https://secopsai-chatgpt-app.onrender.com/readyz
curl -sS https://secopsai-chatgpt-app.onrender.com/.well-known/oauth-protected-resource
```

Then enable ChatGPT developer mode, create a developer app using `https://secopsai-chatgpt-app.onrender.com/mcp`, complete the OAuth link, and test `secopsai_workspace_summary` before enabling any wider pilot group.

The current hosted Core is a single-tenant pilot deployment. Limit OAuth access to the same invited SecOpsAI organization. Do not use this deployment for multiple unrelated customers until Core enforces organization membership on every query.

## Security boundary

- Every MCP tool is read-only and declares its exact OAuth scope.
- Core read, ingest, and intelligence credentials are different.
- The local bridge runs only allowlisted actions and structured output.
- Raw telemetry and artifact contents are removed before context construction.
- Package metadata and finding text are treated as untrusted data, not model instructions.
- Model output is advisory. It cannot resolve a finding, approve disclosure, submit a sandbox artifact, or publish research.
