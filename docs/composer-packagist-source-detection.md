# Composer/Packagist Source-First Detection

SecOpsAI monitors Composer packages from source-of-truth registry and repository
signals before relying on vendor write-ups. This closes the Laravel-Lang style
gap where malicious historical releases can be created by repointing Git tags
and letting Packagist serve compromised Composer archives.

## Why Laravel-Lang Was Missed

Before this change, Packagist support was mostly package-version scanning:

- Fetch Packagist metadata for one package.
- Download the dist archive for a selected version.
- Diff or statically inspect Composer/PHP files.
- Match local emergency advisories when present.

That path works when SecOpsAI already knows the package/version to scan. It did
not continuously compare Packagist source references or GitHub tag state, so a
short-window rewrite of many historical tags could be missed until a third-party
write-up named the affected packages.

## Source-First Pipeline

The Composer pipeline now checks these signals without executing package code:

- Packagist package metadata from `repo.packagist.org/p2/{vendor/package}.json`.
- Package namespace expansion through Packagist search, such as `laravel-lang/*`.
- Version timestamps, dist URLs, source URLs, dist references, and source refs.
- Previous safe metadata snapshots stored under `data/supply_chain/packagist_source`.
- GitHub tag snapshots supplied by API/fixture/workflow integration.
- Composer manifests and package archives inspected statically.
- Local `composer.lock` exposure checks.

## Detection Signals

Packagist metadata rules:

- `PACKAGIST-MASS-VERSION-UPDATE`: many versions change within a short window.
- `PACKAGIST-HISTORICAL-SOURCE-REF-CHANGED`: a previously observed version now
  points to a different source commit.
- `PACKAGIST-HISTORICAL-DIST-REF-CHANGED`: a previously observed version now
  points to a different dist ref.
- `PACKAGIST-SOURCE-REPO-MISMATCH`: source repository owner does not match the
  Packagist namespace.

GitHub tag provenance rules:

- `GITHUB-TAG-REWRITTEN`: a tag points to a new target SHA compared with a prior
  snapshot.
- `GITHUB-MASS-TAG-ACTIVITY`: many tags are created or updated inside a short
  window.
- `GITHUB-TAG-UNREACHABLE-COMMIT`: a tag points to a commit marked unreachable
  from expected lineage.
- `GITHUB-TAG-FORK-ORIGIN`: tag metadata references an unexpected source repo.

Composer/PHP artifact rules flag:

- `composer.json` `autoload.files`, especially helper/bootstrap paths.
- Composer lifecycle scripts that fetch or execute code.
- PHP dynamic execution, shell/process execution, network retrieval, disabled
  TLS verification, temp staging, PHP/VBS background execution, cloud metadata
  access, Kubernetes token reads, `/proc/*/environ`, `.env`, SSH, Git, Docker,
  Vault, and CI/CD credential discovery.

## Operator Commands

Watch one package:

```bash
secopsai supply-chain watch-registry \
  --ecosystem packagist \
  --package laravel-lang/lang \
  --since 7d \
  --dry-run \
  --json
```

Watch a namespace:

```bash
secopsai supply-chain watch-registry \
  --ecosystem packagist \
  --namespace laravel-lang \
  --since 7d \
  --dry-run \
  --json
```

Check emergency advisory coverage:

```bash
secopsai supply-chain advisory check \
  --ecosystem packagist \
  --package laravel-lang/lang \
  --version 14.3.7 \
  --json
```

## Local Exposure Review

For affected Composer packages, inspect `composer.lock` before deciding local
impact. SecOpsAI reports package name, installed version, lockfile path, source
URL, source reference, dist reference, and install timestamp when available.

Packages to review for the Laravel-Lang validation case:

- `laravel-lang/lang`
- `laravel-lang/http-statuses`
- `laravel-lang/attributes`
- `laravel-lang/actions`

## Safety Model

SecOpsAI never runs Composer scripts, package lifecycle hooks, PHP payloads,
binaries, extension activation code, or downloaded artifacts. All evidence is
metadata, tag provenance, archive file listings, static text analysis, local
lockfile review, or explicit operator-provided fixtures.
