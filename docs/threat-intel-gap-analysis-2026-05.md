# Threat Intelligence Gap Analysis - May 2026

This report documents why SecOpsAI missed recent supply-chain, developer-tooling,
GitHub-token, and VS Code extension compromise reporting, and what was changed to
reduce similar misses.

## Current Architecture

SecOpsAI has four relevant paths:

- `blog/data/news-sources.json` defines trusted security-news and advisory
  sources used by Blog Ops and campaign discovery.
- `secopsai.blog` fetches RSS/Atom/JSON/HTML sources, extracts deterministic
  security fields, creates review-only drafts, and blocks autopublishing.
- `secopsai.supply_chain` performs advisory matching, package/artifact static
  analysis, campaign intake, campaign discovery, autopilot dry runs, SOC finding
  persistence, and campaign blog draft handoff.
- Triage Ops displays persisted SCM/SOC findings and campaign-discovery output
  from protected helper endpoints.

The scanner already supported npm, PyPI, Open VSX, and other ecosystems, and it
already had campaign research and watchlist workflows. The main weakness was
not the artifact scanner. The miss happened earlier: source discovery and
normalization were biased toward package-name extraction and did not strongly
model GitHub-token incidents, repository download behavior, orphan commits, or
VS Code Marketplace extension compromise.

## Source Coverage Before Fix

Present sources included CISA, CERT/CC, MSRC, GitHub Security Lab, OpenSSF,
Google, Cloudflare, Microsoft, and Socket.

Missing or insufficient:

- JFrog Security Research was not in the default source registry, so the May 19
  Shai-Hulud wave could be discovered only indirectly.
- The Hacker News was not in the default source registry, so broad incident
  reporting about Grafana and Nx could be missed by the autonomous pipeline.
- GitHub Security Advisories were not explicitly configured as a campaign
  discovery source.
- Grafana security/vendor reporting was not represented as a vendor source.
- Open VSX / VS Code extension marketplace signals were not represented in the
  source registry.
- X/OSINT links remain configuration-gated because API credentials and source
  terms vary by operator environment.

## Detection Coverage Before Fix

Covered:

- npm lifecycle hooks, subprocesses, network egress, obfuscation, local file
  enumeration, environment credential harvesting, PyPI import/setup-time risks,
  static Open VSX extension checks, advisory matching, campaign correlation, and
  local dependency usage checks.

Gaps:

- GitHub token misuse and source-code download incidents were not first-class
  campaign records.
- Orphan/unreachable commit delivery was not a weighted rule.
- VS Code extension compromise signals were weaker than npm/PyPI package
  signals.
- GitHub repository enumeration/download activity was not normalized into SOC
  finding evidence.
- Source fetch failures were returned as generic errors but not as structured
  source status/freshness telemetry.

## Incident Root Cause

### Laravel-Lang Composer/Packagist Tag-Rewrite Campaign

Likely miss:

- Packagist support was package/version reactive and did not continuously
  compare source references or GitHub tag state.
- Campaign discovery could see a title about a Composer compromise but lacked a
  source-first path to prove affected package/version evidence from Packagist and
  GitHub.
- Composer static rules did not explicitly model `autoload.files` helper
  backdoors, disabled TLS verification, temp staging, cloud metadata,
  Kubernetes token reads, `/proc/*/environ`, or broad developer credential
  collection.

Fix:

- Added Packagist source/dist reference extraction, package namespace watch,
  source snapshot comparison, and historical metadata-change signals.
- Added deterministic GitHub tag provenance helpers for rewritten tags, mass tag
  activity, unreachable commits, and unexpected fork origins.
- Strengthened Composer/PHP static rules for autoload backdoors and credential
  stealer behavior.
- Added a source-backed Packagist emergency advisory and local `composer.lock`
  exposure checks for Laravel-Lang style validation.

### JFrog Shai-Hulud May 19 Wave

Likely miss:

- JFrog Research was not a default autonomous-discovery source.
- Detection logic could flag npm and PyPI artifacts if scanned, but campaign
  discovery did not reliably ingest the vendor report or promote affected
  package/version indicators into advisory-backed research.
- The optional GitHub dependency delivery path and PyPI import-time loader
  required explicit campaign/advisory coverage when artifacts were removed or
  unavailable.

Fix:

- Added JFrog Security Research as an hourly source.
- Added a source-backed advisory for `durabletask` 1.4.1-1.4.3 and
  `@cap-js/openapi` 1.4.1.
- Strengthened behavior keywords for GitHub dead-drop exfiltration, token abuse,
  import-time execution, and optional dependency delivery.

### Grafana GitHub Token Breach

Likely miss:

- This was not a classic package artifact event. It involved a missed workflow
  token and repository/source-code access after a supply-chain incident.
- The previous campaign model did not include GitHub repository incidents as
  first-class supply-chain research entities.

Fix:

- Added a `github` campaign ecosystem for source-backed repository/token
  incidents without cloning code.
- Added GitHub event fixture analysis for token exposure, repository download,
  Git Data API/orphan commit behavior, and CI/CD secret exposure.
- Added a source-backed Grafana GitHub token breach advisory using
  `github:grafana/grafana@2026-05` as a review artifact.

### Nx Console VS Code Extension 18.95.0

Likely miss:

- The previous Open VSX static checks existed, but source discovery did not
  reliably map "Nx Console 18.95.0" and VS Code Marketplace reporting into an
  extension package record.
- Orphan commit delivery and extension activation abuse were not high-weight
  discovery signals.

Fix:

- Added GitHub Security Advisories, The Hacker News, and Open VSX Registry as
  sources.
- Added a source-backed advisory for `open-vsx:nrwl.angular-console@18.95.0`
  with safe version `18.100.0`.
- Strengthened Open VSX rules for workspace activation, child process usage,
  credential harvesting, and GitHub/API/DNS exfiltration indicators.

## Freshness And Silent-Failure Coverage

`discover-campaigns` now returns `source_status` records for each polled source:

- `source`
- `url`
- `status`
- `fetched_at`
- `items`
- `newest_published_at`
- `sla_seconds`
- `error` when applicable

This makes source failures visible in CLI JSON and helper/dashboard responses.

## Remaining Limitations

- X/social monitoring remains placeholder/config-gated until credentials,
  source terms, and operator policy are configured.
- GitHub repository incident analysis is source-backed and event-fixture based;
  SecOpsAI does not clone private repositories or call GitHub APIs without an
  operator-provided integration.
- VS Code Marketplace live metadata is best-effort through source/advisory
  ingestion and Open VSX-compatible artifact/static analysis.
