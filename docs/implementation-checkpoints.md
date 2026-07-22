# Implementation Checkpoints

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
