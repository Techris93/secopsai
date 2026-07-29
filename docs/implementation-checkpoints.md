# Implementation Checkpoints

## 111 Guarded Agent Resolution And Unified Alert Review

Status: implementation and local acceptance complete; repository release remains the final gate.

Added a guarded research-case resolution policy with deterministic evidence requirements, reversible case closure, rule retraction, operator accept/reopen review, durable decision records, and rollback snapshots. Agent closure is limited to evidence-complete `not_substantiated` and `benign` verdicts. `not_substantiated` means the evidence did not prove the allegation; `benign` additionally requires independently reviewed sandbox evidence. Likely or credible threats remain escalated, and publication, disclosure delivery, sandbox submission, destructive response, and unsupported rule activation remain human-controlled.

High-confidence registry research candidates now enter the canonical finding queue as `secopsai_research` supply-chain findings. The same model-assisted triage engine therefore covers host, Edge, supply-chain, and registry-research alerts. Missing local dependency exposure is explicitly recorded as response context and never treated as proof that an external package is safe. Resolving the notification alone leaves the canonical finding in a review-required state.

Before each model-triage cycle, Core idempotently reconciles both new and historical actionable research alerts, including watched-package version changes and imported non-operational research alerts. This makes restored databases and pre-release alerts eligible without a manual migration command. Collector degradation and retention alerts stay excluded from model verdicts and close only through deterministic coverage recovery.

Mission Control adds **Research → Resolved by agents** for policy configuration and reversible case review, plus a unified **Automation → Agent finding and alert review** table showing source, package context, model confidence, guardrail failures, tuning proposals, and rollback actions. Operational collector alerts remain in a separate deterministic lane and resolve only after coverage recovers.

Verification: 464 Core tests and 4 subtests passed; 17 focused Mission Control Python tests passed; browser contract tests and the production JavaScript check passed. Signed-in browser acceptance confirmed the guarded case policy and the live supply-chain decision queue. Browser console errors observed during acceptance originated only from installed wallet extensions, not SecOpsAI.

## 110 Authorized Artifact Evidence Workflow

Status: implementation complete locally; deployment and browser acceptance remain release gates.

Added hash-addressed local artifact quarantine, separate registry/artifact/validation subject states, bounded archive inspection, local comparison, deterministic IOC candidate extraction/review, durable local analysis jobs, partner acquisition records, typed Core CLI commands, and authenticated Mission Control helper endpoints. Raw package bytes remain local and are never sent to Supabase, Render, Cloudflare, or an AI provider. Arbitrary analyzer commands were removed; the optional deep NuGet provider is a pinned Docker image with no network, read-only access, dropped capabilities, and bounded resources.

Verification: `tests/test_research_artifacts.py` passed; existing research automation, analysis, and pipeline tests passed; Core CLI and dashboard server syntax checks passed; dashboard contract tests passed.

## 109 Full Intelligence Result Review

Status: implementation complete; Mission Control release and live browser acceptance are pending.

Expanded research prompts so frontier models produce comprehensive, evidence-led assessments rather than generic summaries. The bridge now requests investigation scope, method, 5-12 supported facts where available, explicit fact/inference/unsupported-claim separation, contradictions, missing proof, prioritized evidence-closing actions, verdict rationale, technical article structure, and publication/disclosure risk analysis. Schema-adjacent nested analyst briefs from Kimi, Grok, and Gemini are normalized into the canonical result instead of collapsing to placeholder text.

The safety boundary is unchanged: models receive normalized evidence, cannot browse or execute package code through this action, and cannot submit sandbox artifacts, send disclosure, change customer controls, or publish content.

## 108 Guarded Agent Research Completion

Status: complete in the local pilot and merged.

Added an optional `agent_review` mode for the Local Codex/OpenCodex bridge. When all bounded static-analysis jobs finish, Core accepts pipeline-scoped proposals, records an evidence-linked verdict, and reruns publication safety without requiring card-by-card operator acceptance. Verdict output is schema constrained and then independently guarded by Core: low-confidence work remains inconclusive, a credible verdict requires advisory-backed or sandbox evidence, unresolved contradictions and unsupported claims reduce certainty, and absence from a local repository can never establish package benignness or make ecosystem intelligence non-actionable.

The model receives normalized evidence only. Verdict evidence is limited to active records created by the same investigation pipeline. Every decision records the actor and pipeline revision, and repeated completion is idempotent. The automation cannot execute packages, submit artifacts to an external sandbox, send disclosure, change customer controls, approve publication, or publish content.

Operator surfaces:

- `secopsai research pipeline agent-complete RPL-...`
- `secopsai intelligence bridge service install --autonomy-mode agent_review`
- Mission Control **Complete Agent Review**

The remaining human gates are external sandbox submission, external disclosure delivery, and final publication approval.

Follow-up: bridge service installation now persists the selected OpenCodex provider/model identifier in the fixed service command. This prevents an autonomous background worker from silently reverting to a provider default after the browser closes or the workstation restarts. The service file still contains no provider credentials.

Live acceptance exposed a retracted-package recovery gap: an exact NuGet version previously collected and hashed had disappeared from the registry. Investigation pipelines now prefer a fresh official-registry collection but may reuse an exact prior quarantine artifact after independently verifying ecosystem, package, version, byte size, SHA-256, regular-file state, and configured size limit. Missing or altered cache entries still fail closed. The recorded step makes registry unavailability and quarantine reuse explicit, and no package code is executed.

Live acceptance: pipeline `RPL-37985992E2512C07` recovered `nuget:Braintree.Net@3.35.7` after the registry returned HTTP 404, reused the exact hash-verified quarantine artifact, freshly collected the legitimate reference package, and completed all three structured analyses through `google-antigravity/gemini-3.6-flash`. Guarded agent review accepted 18 revision-scoped proposals and recorded a `likely` verdict at 85% confidence. Publication preflight remained `needs_approval`; sandbox submission, disclosure delivery, and publication all remained false. The earlier Kimi/Grok provider-credit failures remain in the job audit history.

Release acceptance: Core PRs #92, #93, and #94 and Mission Control PRs #32 and #33 passed their Python-version matrix, MCP, security, dependency, Cloudflare, dashboard, and browser checks before merge. The local launchd bridge is running in `agent_review` mode with Gemini 3.6 persisted in its fixed command and no provider credentials in the service definition.

## 107 Hermes Agent v1.0.0 Integration

Status: complete in production.

Added a first-class Hermes Agent 0.18.2+ installation profile for macOS, Linux, and Windows through WSL2. The dedicated installer deploys SecOpsAI Core, enables the native read-only Hermes plugin, performs a bounded initial refresh, installs a five-minute user-level monitor, and provides focused health, status, log, recovery, update, and uninstall controls. Core now exposes `hermes doctor`, `hermes refresh`, and the complete `hermes service` lifecycle through the CLI.

The native Hermes plugin contains eight fixed, read-only tools for service health, normalized findings, triage summaries, sessions, and asset summaries. It invokes the Core virtual-environment CLI without a shell, enforces identifier validation, timeouts, output limits, a sanitized environment, and secret-key filtering, and cannot execute arbitrary commands, run scans, close findings, submit disclosure, or publish content. Hermes credentials, provider configuration, raw request headers, and raw request bodies remain excluded.

Aligned Core, package metadata, README, changelog, website, docs, and installer delivery on `v1.0.0`. Both tracked website copies now expose a responsive Hermes installation tab and remain byte-identical. The release workflow now listens for version tags, uses branch-independent `sha-<commit>` image tags, and allows the immutable tag to build its container and create the GitHub release.

Verification: the full Core suite passed with 419 tests, 16 existing warnings, and 4 subtests; focused Hermes tests passed; the wheel contains the Core runtime and plugin package data; docs command verification and strict MkDocs build passed; shell syntax, website parity, and repository diff checks passed. Live Hermes 0.18.2 validation normalized 16,296 local records without reading credential paths, installed and enabled the plugin, completed a background refresh, and reported a healthy launchd monitor. Desktop and mobile browser review confirmed the public command, copy action, responsive wrapping, and Hermes panel content.

Release acceptance: PRs #84 and #85 were merged after Python 3.10/3.11, MCP, SAST, secret, dependency, container, and Cloudflare checks passed. The immutable `v1.0.0` tag targets the verified release commit, the GitHub release and versioned container are published, and the public site and docs are live. `https://secopsai.dev/install.sh` returns the pinned standard installer and `https://secopsai.dev/install-hermes.sh` returns the Hermes 0.18.2+ installer. Cloudflare Pages now deploys the reviewed `website/` directory explicitly and rejects production deployments when either installer returns HTML or lacks its release marker.

Final production smoke: the plugin installed from `Techris93/secopsai/integrations/hermes`, reported enabled at version 1.0.0, and survived a Hermes gateway restart. Doctor reported Hermes 0.18.2, six readable telemetry sources, excluded `auth.json` and `.env`, a loaded launchd monitor, and a healthy refresh of 16,336 normalized records.

## 106 Mission Control Model Picker And Schema-Tolerant Bridge

Status: implementation complete; live pipeline verified end-to-end on Kimi.

Mission Control now exposes the OpenCodex model catalog as a dropdown in the local bridge module. Operators pick Kimi, Grok, Gemini, or any configured provider/model; the selection persists per browser tab and is passed to "Process next job" through the authenticated intelligence API. The bridge detail panel shows the selected model, catalog size, and fallback chain. Failed jobs gained a **Requeue** button, and the jobs table shows the executing provider.

Core fixes that made non-OpenAI models usable: the bridge output parser now strips markdown fences and unwraps adapter envelopes, and a normalizer maps schema-adjacent output (e.g. Kimi's confirmed_facts objects) into the canonical five-field bridge result with readable review-card text. The hosted Core API passes the worker-reported provider through validation and job completion.

Live verification: requeue and three run-once calls through Mission Control's API completed `analyze_research_case`, `generate_analyst_brief`, and `review_publication_safety` on `kimi/kimi-k2.7-code` for case RSC-42C6208F1F22; the pipeline reached awaiting_review with 19 grouped review items. xAI requires `ocx login xai` re-authentication before Grok runs.

Verification: Core suite 397 passed (one pre-existing agent_core failure unrelated), dashboard contract suites passed, server-side model validation rejects injection-shaped IDs, and the unauthenticated API path returns 401.

## 105 OpenCodex Multi-Model Bridge

Status: implementation complete; operator model-selection acceptance remains a release gate.

Extended the local intelligence bridge beyond a single ChatGPT-subscription path. SecOpsAI now discovers models from the local OpenCodex proxy/catalog, lets operators select models such as Kimi, Grok, and Gemini, and falls back automatically on usage/auth limits. Failed jobs can be requeued for another model without recreating the research pipeline.

Selection surfaces:

- `secopsai intelligence bridge models`
- `secopsai intelligence bridge run --model provider/model`
- `SECOPSAI_BRIDGE_MODEL`
- `SECOPSAI_BRIDGE_FALLBACK_MODELS`
- `secopsai intelligence jobs requeue <job_id>`

Safety boundary unchanged: only minimized SecOpsAI intelligence context is sent, package artifacts remain local, and model output stays advisory until human review.


## 104 Legacy Research Database Migration

Status: complete; CI and production merge are release gates.

Added an idempotent startup migration for research databases created before the active/retracted lifecycle was introduced. Existing `research_subjects`, `research_evidence`, and `research_iocs` tables receive a non-null `status` column with the default `active`, preserving all existing rows. This repairs the Mission Control Research Cases endpoint on long-lived SQLite deployments while leaving fresh databases unchanged.

Verification covers an exact legacy-schema fixture, repeated database initialization, the case-list query, and the live pilot database. The live endpoint now returns an empty valid case list instead of `no such column: s.status`.

Verification: the full Core suite passed with 394 tests, 14 existing warnings, and 4 subtests. MkDocs strict build and repository diff checks passed. All eight live scoped registry monitors then completed successfully with zero monitor failures.

## 103 Local Codex Research Investigation Pipeline

Status: implementation complete; local service activation and end-to-end operator acceptance are release verification gates.

Added a durable, revisioned investigation pipeline that starts from a Core Research Case, performs bounded static package intake, optionally compares a verified legitimate package, builds a preliminary claim matrix, and queues three structured Local Codex Bridge jobs without exports, uploads, copied prompts, API keys, or raw-artifact transfer. All deterministic evidence and model output first enter a human review queue. Accept and reject decisions are typed, audited, idempotent, and concurrency-safe.

The pipeline fails closed. It never executes package code, guesses a legitimate reference, records a maliciousness verdict, submits an artifact to a sandbox, sends disclosure, approves publication, or publishes content. Failed bridge work can be retried as a new revision; old proposals are retained but superseded. Core case responses now include pipeline, step, Intelligence-job, and review state for Mission Control.

Added CLI fallback commands under `secopsai research pipeline`, minimized bridge context, expanded structured research output fields, automatic Intelligence-job reconciliation, and recovery tests covering failed bridge jobs and stale-proposal isolation.

Real subscription-backed verification exposed and closed three integration defects: CLI dispatch for the nested pipeline command, Codex structured-output required-field compatibility, and excessive duplicate review proposals. Model lists are now action-scoped, bounded, deduplicated, and grouped. Browser case-detail responses contain bounded step summaries rather than quarantine locators or full analyzer/model payloads.

Verification: the full Core suite passed with 393 tests, 14 existing warnings, and 4 subtests. Focused research/intelligence/case suites passed. MkDocs strict build passed. A disposable live npm intake and ChatGPT-subscription Codex Bridge run reached `awaiting_review` with all three Intelligence steps complete, no package execution, no raw-artifact model transfer, and 19 grouped review cards from the real structured results.

## 102 Subscription Intelligence And ChatGPT App

Status: implementation complete; production OAuth provider configuration remains an external deployment gate.

Added the versioned `secopsai.intelligence.v1` read-only contract, minimized Core query actions, durable intelligence jobs and events, stale-worker recovery, a local Codex bridge that uses the operator's existing ChatGPT login, and user-level launchd/systemd service controls. The bridge accepts only named SecOpsAI actions, invokes Codex with an ephemeral read-only sandbox and fixed JSON output schema, sanitizes inherited environment variables, and never persists ChatGPT credentials.

Added an authenticated stateless MCP server for a SecOpsAI ChatGPT app. It exposes nine read-only tools for findings, assets, changes, research cases, evidence matrices, and publication readiness. It publishes OAuth protected-resource metadata, verifies JWT signature, issuer, audience, expiry, subject, and per-tool scopes, keeps the Core read token server-side, and returns reauthorization challenges for missing scopes. The primary Render Blueprint deliberately excludes this optional service so OAuth setup cannot block Core or research-worker deployment; production MCP startup intentionally fails closed until an established OAuth provider is configured.

Verification: the real local bridge completed a subscription-backed isolated smoke job; the Core full suite passed with 382 tests, 14 warnings, and 4 subtests; the final intelligence/API suite passed with 18 tests; strict docs build, MCP protocol tests, Node syntax checks, dashboard Python/JavaScript suites, desktop/mobile browser review, and dependency audit pass. The MCP dependency tree uses the current fixed MCP SDK with an explicit patched Hono adapter override; npm audit reports zero vulnerabilities.

## 101 Branded Research Email

Status: complete in production.

Added multipart branded email with the canonical SecOpsAI mark, plain-text fallback, HTML escaping, standards-compliant date and message identifiers, and role-specific sender names for research alerts and coordinated disclosures. The Render Blueprint owns only the public logo and product URLs; SMTP credentials remain server-side secrets. Inbox avatars remain a separate BIMI and DMARC-enforcement project rather than being misrepresented as an HTML-email feature.

Verification: focused delivery tests cover the HTML/plain alternatives, canonical logo URL, sender display names, required headers, and script-tag escaping. The full Core suite passed with 374 tests, 14 warnings, and 4 subtests; GitHub tests and security checks passed; Render deployed commit `bf8224f`; and production one-off job `job-d9g88trrjlhs73btljp0` successfully submitted the branded preview through the configured Resend SMTP channel.

## 100 Signed Research Alert Ingestion

Status: complete in production.

Added a bounded signed-webhook path from the managed research worker to the hosted Core API. The sender signs the exact JSON body and Unix timestamp with HMAC-SHA256. Core enforces a five-minute replay window, a 64 KB body limit, strict JSON parsing, an operational-alert type allowlist, evidence minimization, and a minimum 32-character shared secret.

The Render Blueprint now owns a shared `secopsai-research-alerts` environment group. Render generates the 256-bit webhook secret once and links the same value to Core and the worker without exposing it in Git or the browser. Automatic worker delivery is enabled only for operational coverage and retention alerts.

Core persists webhook deliveries idempotently with stable local IDs and retains existing operator status and ownership on repeat delivery. The canonical workspace response now includes reduced collector coverage and retention alerts. This closes the immediate visibility gap for operational worker health; registry events, candidates, artifacts, and full coverage history still remain on the separate worker disk.

Verification: focused Core API, delivery, worker, and observability suites passed with 22 tests; the full Core suite passed with 372 tests, 14 warnings, and 4 subtests. GitHub checks passed. Production Core health returned HTTP 200, unsigned webhook traffic failed closed with HTTP 401, and Render linked the generated shared secret to both services.

## 099 Managed Research Worker And Operational Alerting

Status: complete in production; signed webhook and authenticated Resend email delivery configured.

Provisioned `secopsai-research-worker` on Render Starter compute with a 1 GB persistent disk. The first production cycle completed all eight collectors and persisted registry observations on the worker disk. Added optional privacy-preserving Sentry initialization for the Core API and research worker, plus isolated-exception capture that never makes Sentry mandatory.

Collector failures, coverage gaps, and bounded incomplete windows now create high-severity `collector_degraded` alerts, deduplicated per ecosystem and UTC day. The worker can automatically deliver only operational collector alerts over configured email or signed webhook channels. Delivery is disabled by default, audited, bounded to five attempts, retried with exponential backoff, and cannot stop registry collection.

Deployment boundary: the Core API and worker have separate Render persistent disks. Worker surveillance data is therefore not yet a canonical hosted Core/dashboard data source. The next integration checkpoint must push reduced candidates, alerts, and coverage summaries through an authenticated Core ingestion contract or migrate both services to an appropriate shared database; Render disks must not be treated as shareable storage.

Verification: focused worker, delivery, and observability tests passed; the full Core suite passed with 369 tests, 14 warnings, and 4 subtests; MkDocs strict build and repository diff checks passed. GitHub checks passed, PR #72 was merged, and the managed worker is live. The production Resend DKIM, SPF, and return-path MX records resolve publicly; the Blueprint enables `email,webhook` only for operational coverage and retention alerts.

## 098 Public Documentation And Blog Asset Alignment

Status: source, generated output, and deployed blog archive reconciled for release.

Aligned the Docs product story with SecOpsAI Core, Edge, Research, findings, reporting, and local-first integrations. Reorganized the navigation by operator workflow, corrected page metadata, removed the failing GitHub release lookup, and extended the production CSP only for Cloudflare analytics.

Replaced the legacy dark social-card generator with the SecOpsAI technical-publication system. All 27 generated cards now use the paper palette, document identifier, semantic severity strip, ISO issue date, square rules, and bounded title layout. The rebuild path regenerates every archived card, including posts that currently use approved source media. Reconciled the 26-item deployed blog archive with Git so future deployment cannot roll back live content.

Verification: MkDocs strict build passed; docs command verification passed; blog verification passed; 27 blog tests and 4 subtests passed; full Core suite passed with 362 tests, 14 warnings, and 4 subtests; desktop/mobile visual checks covered Docs, Blog navigation, and info/high/critical social cards.

## 097 Research Provider Activation And Monitor Hardening

Status: local scheduler and eight watchlist-scoped registry baselines active; external credentials remain provider-controlled.

Corrected exact-package monitors so legitimate baselines do not become typosquat candidates, added deduplicated watched-version alerts, honored exact-name/exclusion suppression, and made stable releases the default when registries advertise prereleases as latest. Repaired the RubyGems v1 metadata endpoint and Packagist P2 list parsing, including current GitHub distribution hosts.

Configured and verified hourly baselines for npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go, and Open VSX. The first live run completed 8/8 with incomplete, watchlist-scoped coverage reported explicitly. Added a managed macOS launchd installer with a 15-minute due-run trigger and lifecycle/status/log commands. Built and smoke-tested the non-root, network-disabled NuGet metadata worker image after correcting its C# entry-point return path.

Outbound identities are separated: vulnerability disclosure defaults to `security@secopsai.dev` and research alerts default to `research@secopsai.dev`. Signed-webhook delivery is active. Resend SMTP is authenticated with a domain-scoped sending key stored only in Render, and `research@secopsai.dev` remains the alert sender and Cloudflare-routed recipient. Tria.ge API activation remains pending Researcher-license approval.

Verification: Core suite 280 passed with 14 warnings and 4 subtests; focused research suites 17 passed; NuGet analyzer container build and no-argument safety smoke test passed; launchd plist validation and due-run exit status passed.

## 090-096 Research Discovery Platform

Status: implemented on `codex/research-discovery-platform`; external provider configuration remains deployment-specific.

Added the Core-owned discovery foundation: versioned ecosystem capability records for npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go, and Open VSX; cross-ecosystem watchlists; durable monitor/cursor/candidate/alert tables; deterministic explainable similarity scoring; bounded package comparison; campaign-cluster persistence; approval-gated sandbox submission primitives; rule validation; disclosure and alert delivery attempt records; and an optional pinned Mono.Cecil metadata worker for NuGet.

The dashboard now exposes cross-ecosystem discovery, watchlist creation, monitor creation, due-run execution, candidate review, exact-package comparison, and campaign correlation through authenticated typed actions. Triage Ops remains the alert/remediation queue; Research remains the durable investigation and evidence ledger; Blog Ops remains publication review and deployment.

Important coverage boundary: the first monitor implementation is watchlist-scoped and reports incomplete coverage. It does not claim a complete global registry census. Registry-specific event/search adapters can feed the shared `ingest_registry_metadata` path as they are enabled.

Safety boundary: artifacts are bounded, hashed, quarantined, and statically inspected. Core never installs or executes package code. Tria.ge submission requires a server-side token, approved request, exact hash match, and explicit public-submission acknowledgement. Disclosure delivery is approval-gated and records success/failure attempts.

Verification for this checkpoint includes Core research discovery, analysis, rule, workflow, Python syntax, dashboard Python/JavaScript syntax, dashboard browser tests, and repository diff checks. Full suites and provider-backed smoke tests remain release gates.

## 083 Research job foundation

Status: complete locally.

Added durable `research_jobs` records, idempotency keys, lifecycle states, safe error fields, case timeline events, and CLI inspection. The local helper can invoke typed research actions; it does not expose arbitrary shell execution.

## 084 Safe package intake

Status: complete locally.

Added official-registry adapters for npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go, and Open VSX. Intake uses quarantine, hashes, bounded in-memory archive inspection, manifest/lifecycle detection, and static indicators. Preview jobs remain unattached until the operator explicitly attaches verified evidence.

## 085-088 Research gates

Status: complete locally.

Added evidence matrices, human verdicts, disclosure drafts/status, publication safety reviews, waivers, and publication approval records. Existing Blog Ops remains the final editing and publish surface.

## 089 Sandbox control plane

Status: complete as a safe control plane; provider activation remains external.

Added request, approval, status, and sanitized-result records. The default provider is manual result import. A dedicated isolated execution provider still requires separate infrastructure and credentials; Core will not execute investigated packages locally.

## Verification

- Core virtualenv suite: 280 passed, 14 warnings, 4 subtests passed.
- New intake/workflow suite: 7 passed.
- Dashboard research automation suite: 3 passed.
- Dashboard JavaScript and Worker syntax checks: passed.
- Dashboard repository has no `build` script; its supported deployment is static Pages/Worker serving and is validated with `npm run check` plus Cloudflare deployment checks.

## 098 Package Threat And Environment Exposure Separation

Status: complete.

Supply-chain triage now records package threat verdict, evidence confidence,
and environment exposure as independent assessments. Missing dependency
references produce `not_observed_in_scope` with explicit limitations; they do
not produce `expected_behavior`, false-positive classification, severity
downgrade, or automatic closure. Advisory-backed and denylisted packages remain
package-level true positives, while weak or incomplete evidence remains open
for review and safe Research Case validation.

The orchestrator no longer auto-closes supply-chain findings because a package
is absent locally. It queues a reviewed package-level decision and preserves
organization-wide exposure as a separate follow-up. Triage reports now render
dedicated threat and exposure sections.

Verification: 420 Core tests passed; focused triage/orchestrator tests passed;
MkDocs strict build and repository diff checks passed.

Historical reconciliation follows the same boundary. A previewable, idempotent
repair selects only malicious Core supply-chain findings closed as
`expected_behavior` with the former local-absence rationale. The next
orchestrator run applies the repair automatically, reopens those findings as
`unreviewed`, and records an audit note without touching unrelated analyst
closures.
# 110 Evidence-Gated Autonomous Finding Triage

Status: implementation complete; live model acceptance and hosted deployment verification pending.

Added continuous model review for canonical SecOpsAI findings using the selected OpenCodex model. Core now owns versioned triage settings, durable agent-triage runs, deterministic/model adjudication, reversible automatic dispositions, one-click rollback, and shadow-mode tuning proposals. Model-only suppression is blocked. Supply-chain findings cannot be downgraded because local exposure is absent, and advisory-backed, denylisted, or strong threat evidence prevents automatic closure.

Mission Control now exposes `off`, advisory, and guarded modes, confidence and evidence thresholds, model persistence, run-now, decision history, guardrail reasons, tuning proposal counts, and rollback. Historical replay can automatically activate only an exact high-confidence ecosystem-threshold recommendation; rule weight and condition changes remain shadow-only. Final publication, disclosure, external sandbox submission, package execution, and destructive response remain outside agent authority.

Verification: 450 Core tests, 4 subtests, strict MkDocs, 69 dashboard tests, 13 dashboard subtests, JavaScript syntax checks, hosted-worker contracts, desktop/mobile DOM review, model selection interaction, and console review pass. A live `kimi/k3` job reviewed SCM-FF3461F8E3215AF8, separated package verdict from local exposure, challenged report-text heuristic provenance, retained `needs_review`, and persisted three validated evidence references without auto-closing the finding. The live check also removed redundant `ocx ensure` latency, made the bridge claim queued jobs before discovering more work, and added immediate interrupted-job recovery on service restart.
