# Implementation Checkpoints

## 100 Signed Research Alert Ingestion

Status: implementation complete; Blueprint-managed production activation pending.

Added a bounded signed-webhook path from the managed research worker to the hosted Core API. The sender signs the exact JSON body and Unix timestamp with HMAC-SHA256. Core enforces a five-minute replay window, a 64 KB body limit, strict JSON parsing, an operational-alert type allowlist, evidence minimization, and a minimum 32-character shared secret.

The Render Blueprint now owns a shared `secopsai-research-alerts` environment group. Render generates the 256-bit webhook secret once and links the same value to Core and the worker without exposing it in Git or the browser. Automatic worker delivery is enabled only for operational coverage and retention alerts.

Core persists webhook deliveries idempotently with stable local IDs and retains existing operator status and ownership on repeat delivery. The canonical workspace response now includes reduced collector coverage and retention alerts. This closes the immediate visibility gap for operational worker health; registry events, candidates, artifacts, and full coverage history still remain on the separate worker disk.

Verification: focused Core API, delivery, worker, and observability suites passed with 22 tests; the full Core suite passed with 372 tests, 14 warnings, and 4 subtests. GitHub checks, production secret configuration, and an end-to-end signed delivery remain release gates.

## 099 Managed Research Worker And Operational Alerting

Status: complete in production; automatic external delivery remains disabled until provider credentials are configured.

Provisioned `secopsai-research-worker` on Render Starter compute with a 1 GB persistent disk. The first production cycle completed all eight collectors and persisted registry observations on the worker disk. Added optional privacy-preserving Sentry initialization for the Core API and research worker, plus isolated-exception capture that never makes Sentry mandatory.

Collector failures, coverage gaps, and bounded incomplete windows now create high-severity `collector_degraded` alerts, deduplicated per ecosystem and UTC day. The worker can automatically deliver only operational collector alerts over configured email or signed webhook channels. Delivery is disabled by default, audited, bounded to five attempts, retried with exponential backoff, and cannot stop registry collection.

Deployment boundary: the Core API and worker have separate Render persistent disks. Worker surveillance data is therefore not yet a canonical hosted Core/dashboard data source. The next integration checkpoint must push reduced candidates, alerts, and coverage summaries through an authenticated Core ingestion contract or migrate both services to an appropriate shared database; Render disks must not be treated as shareable storage.

Verification: focused worker, delivery, and observability tests passed; the full Core suite passed with 369 tests, 14 warnings, and 4 subtests; MkDocs strict build and repository diff checks passed. GitHub checks passed, PR #72 was merged, and Render deployed commit `9c629fd`. Live worker cycles now expose `operational_alert_ids` and the disabled-by-default `alert_delivery` state.

## 098 Public Documentation And Blog Asset Alignment

Status: source, generated output, and deployed blog archive reconciled for release.

Aligned the Docs product story with SecOpsAI Core, Edge, Research, findings, reporting, and local-first integrations. Reorganized the navigation by operator workflow, corrected page metadata, removed the failing GitHub release lookup, and extended the production CSP only for Cloudflare analytics.

Replaced the legacy dark social-card generator with the SecOpsAI technical-publication system. All 27 generated cards now use the paper palette, document identifier, semantic severity strip, ISO issue date, square rules, and bounded title layout. The rebuild path regenerates every archived card, including posts that currently use approved source media. Reconciled the 26-item deployed blog archive with Git so future deployment cannot roll back live content.

Verification: MkDocs strict build passed; docs command verification passed; blog verification passed; 27 blog tests and 4 subtests passed; full Core suite passed with 362 tests, 14 warnings, and 4 subtests; desktop/mobile visual checks covered Docs, Blog navigation, and info/high/critical social cards.

## 097 Research Provider Activation And Monitor Hardening

Status: local scheduler and eight watchlist-scoped registry baselines active; external credentials remain provider-controlled.

Corrected exact-package monitors so legitimate baselines do not become typosquat candidates, added deduplicated watched-version alerts, honored exact-name/exclusion suppression, and made stable releases the default when registries advertise prereleases as latest. Repaired the RubyGems v1 metadata endpoint and Packagist P2 list parsing, including current GitHub distribution hosts.

Configured and verified hourly baselines for npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go, and Open VSX. The first live run completed 8/8 with incomplete, watchlist-scoped coverage reported explicitly. Added a managed macOS launchd installer with a 15-minute due-run trigger and lifecycle/status/log commands. Built and smoke-tested the non-root, network-disabled NuGet metadata worker image after correcting its C# entry-point return path.

Outbound identities are separated: vulnerability disclosure defaults to `security@secopsai.dev` and research alerts default to `research@secopsai.dev`. SMTP/webhook sending remains disabled until authenticated provider credentials are supplied. Tria.ge API activation remains pending Researcher-license approval.

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
