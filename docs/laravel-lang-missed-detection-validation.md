# Laravel-Lang Missed Detection Validation

## Source Signals That Existed

The Laravel-Lang compromise pattern was detectable without waiting for a vendor
summary because the source systems exposed enough evidence:

- Packagist metadata for `laravel-lang/lang` and related packages.
- GitHub source repositories under `Laravel-Lang/*`.
- Historical tag/source reference changes across multiple repositories.
- Composer archives containing `composer.json` `autoload.files`.
- PHP helper code capable of payload retrieval, process execution, temp staging,
  disabled TLS verification, and credential discovery.
- Local `composer.lock` files that can show affected versions and source refs.

## Why SecOpsAI Missed It

SecOpsAI already supported Packagist package scans, but the old workflow was
reactive. It needed a package/version to scan and did not continuously compare
Packagist source references or GitHub tag state. That meant a tag-rewrite
campaign could be invisible until a write-up named the affected packages.

The old Composer static rules also flagged basic scripts and a small set of PHP
execution APIs, but they did not explicitly model Composer `autoload.files`,
disabled TLS verification, cloud metadata access, Kubernetes tokens,
`/proc/*/environ`, `.env`, SSH/Git/Docker/Vault/CI secret collection, temp
staging, or background PHP/VBS execution.

## What Changed

SecOpsAI now includes source-first Composer/Packagist checks:

- Packagist metadata rows include source URL/ref and dist ref.
- Packagist source snapshots can identify historical source/dist ref changes.
- Namespace watch supports `--namespace laravel-lang` style monitoring.
- GitHub tag provenance helpers detect rewritten tags, mass tag activity,
  unreachable commits, and unexpected fork origins.
- Composer static rules detect `autoload.files` backdoors and PHP
  credential-stealer behavior.
- A source-backed Packagist emergency advisory covers the Laravel-Lang validation
  package/version example.
- Local Composer exposure checks report affected `composer.lock` entries with
  source and dist references.

## Tests Proving Coverage

The deterministic test suite now covers:

- Packagist metadata parsing with source/dist refs.
- Mass Packagist version update detection.
- Historical source ref rewrite detection.
- GitHub tag rewrite and unreachable/fork provenance detection.
- Composer `autoload.files` helper detection.
- PHP credential-stealer strings including `flipboxstudio.info`, temp staging,
  cloud metadata, Kubernetes, `/proc`, and SSH secret access.
- `laravel-lang/lang@14.3.7` advisory matching.
- Local `composer.lock` exposure reporting.
- Laravel-Lang style campaign routing as supply-chain relevant.

## Operator Workflow Next Time

1. Run namespace or package monitoring against Packagist.

```bash
secopsai supply-chain watch-registry --ecosystem packagist --namespace laravel-lang --since 7d --dry-run --json
```

2. Check any high-risk package/version against emergency advisories.

```bash
secopsai supply-chain advisory check --ecosystem packagist --package laravel-lang/lang --version 14.3.7 --json
```

3. Review local Composer exposure.

Search `composer.lock` for affected packages and compare source/dist refs with
the source evidence.

4. If local exposure is present, remove affected vendor copies, rebuild from a
verified clean lockfile, and rotate credentials only after affected hosts are
contained.

## Remaining Limitations

- Live GitHub tag reachability and signature checks require API access or a
  scheduled integration that provides tag snapshots.
- Packagist package health flags are useful enrichment but not the primary
  signal.
- SecOpsAI does not execute PHP, Composer scripts, binaries, payloads, or
  package lifecycle hooks, so runtime-only behavior must be inferred from static
  evidence and local telemetry.
