# OSS Artifact Fleet Gap Analysis

## Baseline before the fleet

SecOpsAI already had ecosystem-specific artifact analysis, crates `build.rs`
rules, package registry watchers, research cases, a bounded model bridge, and
review-only Blog Ops. It did not have one artifact-level queue joining those
capabilities, a central rule-pack contract, a staged triage record, or verified
high-volume throughput metrics.

## Implemented coverage

| Gap | Current state |
| --- | --- |
| Metadata-only stage | Cursor/index records and dedupe database exist; live collectors are bridged where available |
| Deterministic stage | Safe archive inspection, ecosystem rules, generic rule pack, IOC/hash evidence, and Rust/build-hook rules exist |
| Model stage | Minimized context builder and explicit triage record exist; no model call occurs for clean artifacts |
| Analyst stage | Suspicious/inconclusive statuses and analyst queue exist |
| Rust campaign | Safe `proc-macro1`, `proc-macro-en`, and legitimate `proc-macro2` fixtures and regression tests exist |
| Research handoff | Review-only artifact handoff and Blog Ops draft command exist |
| Dashboard | Artifact Fleet status, queue counts, and degraded/not-configured state are visible under Enterprise Security |

## Remaining limitations

- The current local implementation is not proof of a 114,000-artifact/day
  production fleet.
- Some ecosystems have global collectors through the existing research worker;
  others still require a dedicated metadata adapter or authorized marketplace
  integration.
- The generic YARA pack has structural validation when `yara-python` is absent;
  production deployments should enable native compilation and rule telemetry.
- Binary analysis is metadata and safe-string oriented; it is not a sandbox or
  full reverse-engineering system.
- Model calls require an available configured bridge/provider and remain
  approval-gated at the analyst and publication boundaries.
- Cost accounting becomes meaningful only after a worker records provider token
  usage and price configuration.

These limitations are surfaced as explicit status values rather than being
flattened into a clean result.
