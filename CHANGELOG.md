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
- Added a changelog entry helper at `scripts/changelog_entry.py`.

### Security

- Preserved emergency supply-chain advisory/denylist matching for removed or
  yanked compromised artifacts.
- Preserved node-ipc, Mini Shai-Hulud, LiteLLM, mistralai, and guardrails-ai
  advisory-backed supply-chain behavior while expanding ecosystem coverage.
- Kept non-npm/PyPI live artifact fetching disabled until safe deterministic
  registry adapters are implemented.

### Docs

- Documented the multi-ecosystem support matrix, per-ecosystem CLI examples,
  limitations, operator triage workflow, mitigation guidance, and changelog
  workflow.

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
