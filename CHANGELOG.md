# Changelog

All notable SecOpsAI changes are tracked here. The format follows the spirit of
Keep a Changelog, with an `Unreleased` section for operator-visible work before
the next tagged release.

## Unreleased

### Added

- Added first-class Hermes Agent 0.18.2+ onboarding with an idempotent public installer, focused setup profile, native read-only Hermes plugin, bounded local telemetry refresh, and persistent launchd/systemd monitoring.
- Added `secopsai hermes doctor`, `secopsai hermes refresh`, and complete Hermes service lifecycle commands with owner-only state, overlap prevention, explicit degraded health, and retained logs/findings on uninstall.
- Added eight fixed-command Hermes tools for integration health, findings, sessions, triage summaries, and Edge asset context without arbitrary execution or credential exposure.
- Added a protected Core HTTP boundary for organization-scoped Edge bundle
  ingestion, minimized operator workspace reads, and import audit history.
- Added a one-command local Core API setup and a validated, persistent-disk
  Render Blueprint for controlled hosted pilots.
- Added the versioned SecOpsAI Edge graph/finding import path and made Edge a
  first-class pilot sensor module across Core docs and public product surfaces.
- Added first-pass multi-ecosystem supply-chain protection for crates.io,
  Chrome Web Store, Packagist, Go Modules, Hugging Face Hub, Maven Central,
  NuGet, Open VSX, RubyGems, PyPI, and npm.
- Added `secopsai supply-chain ecosystems` to report ecosystem capability
  levels and limitations.
- Added deterministic local-artifact rules for ecosystem manifests and source
  files, including Cargo `build.rs`, Chrome extension manifests, Composer
  lifecycle scripts, Go `init()` behavior, Hugging Face unsafe loading
  metadata, Maven build/plugin execution, NuGet install/build scripts, Open VSX
  activation behavior, and RubyGems install/source hooks.
- Added safe live registry metadata/artifact adapters for crates.io, Packagist,
  Go Modules, Hugging Face Hub, Maven Central, NuGet, Open VSX, and RubyGems,
  plus local CRX/ZIP artifact scanning for Chrome Web Store extensions.
- Added cross-ecosystem supply-chain campaign research with correlated package
  verdicts, environment-impact separation, SOC finding persistence, and
  review-only campaign blog drafts.
- Published GitHub Packages distribution as `@techris93/secopsai` while
  preserving the existing npm package release flow.
- Published the **SecOpsAI Supply-Chain Guard** GitHub Marketplace Action from
  `Techris93/secopsai-action`.
- Prepared the next unscoped npm wrapper release path as `secopsai@1.0.1`
  with a manual/tag-gated npm publish workflow.
- Added guarded PyPI and Docker Hub publish workflows plus a Homebrew tap
  reservation for SecOpsAI name ownership.
- Added a changelog entry helper at `scripts/changelog_entry.py`.

### Security

- Added separate Core ingest/read credentials, strict host and CORS policy,
  request size and graph limits, duplicate-key rejection, raw-telemetry field
  rejection, stable organization-scoped sync identity, and redacted workspace
  responses.
- Removed the default Telegram report recipient; report delivery now requires
  an explicit `--chat-id` or `TELEGRAM_CHAT_ID`.
- Made release tests and high/critical security scans block publish/deploy
  jobs instead of continuing after known failures.
- Hardened Security Scan workflow artifact handling so SARIF uploads are
  per-file guarded, dependency audits target project requirements, and
  high-severity Bandit findings remain blocking without legacy scan noise.
- Changed adaptive rule validation to stage improved generated rules for human
  review instead of committing generated code or leaving `detect.py` mutated.
- Preserved emergency supply-chain advisory/denylist matching for removed or
  yanked compromised artifacts.
- Preserved node-ipc, Mini Shai-Hulud, LiteLLM, mistralai, and guardrails-ai
  advisory-backed supply-chain behavior while expanding ecosystem coverage.
- Kept Chrome Web Store live CRX fetching disabled unless an operator supplies a
  local exported CRX/ZIP artifact, because stable unauthenticated CRX download
  is not reliable from registry metadata.
- Hardened supply-chain artifact handling with bounded downloads, safe archive
  extraction, traversal/symlink blocking, and no-execution analysis across the
  new live adapters.
- Added a `deadcode09284814` npm infostealer/botnet campaign advisory fixture
  with IOCs, behavioral indicators, and mitigation guidance for research and
  blog-drafting workflows.

### Docs

- Added the Hermes installation tab, one-command guide, plugin tool reference, service operations, data boundaries, recovery, and uninstall documentation.
- Documented Edge/Core ownership, privacy boundaries, one-step sync, graph
  inspection, and stable Edge-origin triage workflows.
- Documented the multi-ecosystem support matrix, per-ecosystem CLI examples,
  limitations, operator triage workflow, mitigation guidance, changelog
  workflow, public npm install path, GitHub Packages install path, and GitHub
  Marketplace Action usage.
- Documented SecOpsAI name reservation status across GitHub, Docker Hub, PyPI,
  Homebrew, npm, and GitHub Packages.

## 2026-05 SecOpsAI Operator Upgrades

### Added

- Added emergency advisory ingestion for compromised package versions so
  source-backed removed artifacts can still become high-confidence findings.
- Added SecOpsAI security blog automation, RSS/JSON feeds, approval-gated news
  drafting, Blog Ops, and moderated comments scaffolding.
- Added Triage Ops and Evidence-Based Verdict support for supply-chain alert
  investigation from the dashboard.
- Added OpenClaw replay freshness, source activity, and daily reporting
  improvements.
