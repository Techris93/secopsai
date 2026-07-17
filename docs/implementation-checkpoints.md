# Implementation Checkpoints

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

- Core virtualenv suite: 274 passed, 14 warnings, 4 subtests passed.
- New intake/workflow suite: 7 passed.
- Dashboard research automation suite: 3 passed.
- Dashboard JavaScript and Worker syntax checks: passed.
- Dashboard repository has no `build` script; its supported deployment is static Pages/Worker serving and is validated with `npm run check` plus Cloudflare deployment checks.
