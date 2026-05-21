# Changelog

All notable SecOpsAI changes are tracked here. The format follows the spirit of
Keep a Changelog, with an `Unreleased` section for operator-visible work before
the next tagged release.

## Unreleased

### Added

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
