# Missed Threat Validation Report - May 2026

This validation report maps each missed public incident to the SecOpsAI fix and
the deterministic test or fixture that proves the category is now detected.

## JFrog Shai-Hulud May 19 Campaign

Source:

- https://research.jfrog.com/post/shai-hulud-here-we-go-again-may19/

Why it was missed:

- JFrog Security Research was not in the default discovery source registry.
- The campaign included removed or hard-to-fetch artifacts, so advisory-backed
  detection was required when live artifact fetch could not prove the behavior.

Fix:

- Added JFrog Security Research to `blog/data/news-sources.json`.
- Added `data/advisories/jfrog-shai-hulud-may19-2026.json`.
- Added/weighted behavior coverage for GitHub token abuse, GitHub dead-drop
  exfiltration, lifecycle execution, PyPI import-time loaders, and persistence.

Validation:

- `tests/test_supply_chain.py::test_missed_threat_advisories_match_source_backed_versions`
  verifies `pypi:durabletask@1.4.2` matches the source-backed advisory.
- Existing npm/PyPI static tests continue to validate lifecycle, network,
  subprocess, and credential-harvesting behavior.

## Grafana GitHub Token Breach

Sources:

- https://thehackernews.com/2026/05/grafana-github-breach-exposes-source.html
- https://grafana.com/security/

Why it was missed:

- The incident class was GitHub workflow-token misuse and repository/source-code
  access rather than a package release diff.
- GitHub repository incidents were not first-class campaign entities.

Fix:

- Added the `github` campaign ecosystem for source-backed repository/token
  incidents without cloning or downloading repository contents.
- Added `data/advisories/grafana-github-token-breach-2026-05.json`.
- Added GitHub static event rules for token exposure, repository enumeration,
  code download, Git Data API abuse, orphan commits, and CI/CD secret exposure.

Validation:

- `tests/test_supply_chain.py::test_github_event_fixture_detects_token_and_mass_repo_download`
  verifies a harmless audit-event fixture raises GitHub token, repository
  enumeration/download, and orphan commit findings.
- `tests/test_supply_chain.py::test_missed_threat_advisories_match_source_backed_versions`
  verifies `github:grafana/grafana@2026-05` matches the source-backed advisory.

## Compromised Nx Console VS Code Extension 18.95.0

Sources:

- https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w
- https://thehackernews.com/2026/05/compromised-nx-console-18950-targeted.html

Why it was missed:

- Source discovery did not reliably normalize "Nx Console 18.95.0" into an
  Open VSX / VS Code extension record.
- VS Code extension activation and orphan commit delivery were not weighted as
  strongly as npm/PyPI package compromise signals.

Fix:

- Added GitHub Security Advisories, The Hacker News, and Open VSX Registry to
  the source registry.
- Added `data/advisories/nx-console-vscode-compromise-2026-05.json`.
- Strengthened Open VSX rules for workspace activation, child process execution,
  credential harvesting, and GitHub/API/DNS exfiltration.
- Added campaign intake extraction for Nx Console aliasing to
  `open-vsx:nrwl.angular-console`.

Validation:

- `tests/test_supply_chain.py::test_campaign_intake_extracts_vscode_extension_and_github_breach_signals`
  verifies source text becomes campaign records for
  `open-vsx:nrwl.angular-console@18.95.0` and `github:nrwl/nx-console`.
- `tests/test_supply_chain.py::test_open_vsx_fixture_detects_extension_activation_and_credential_theft`
  verifies a harmless VS Code extension fixture flags activation, credential,
  process, and exfiltration behavior.
- `tests/test_supply_chain.py::test_missed_threat_advisories_match_source_backed_versions`
  verifies the affected version `18.95.0` and safe version `18.100.0`.

## Source Freshness And Failure Visibility

Why it mattered:

- A feed failure or stale source could previously look like "no candidates",
  which makes missed intelligence hard to diagnose.

Fix:

- `discover-campaigns` now emits `source_status` telemetry per source, including
  success/error status, item counts, fetch time, newest published timestamp, and
  SLA seconds derived from polling hints.

Validation:

- `tests/test_supply_chain.py::test_discover_campaigns_scores_and_dedupes_feed_items`
  verifies successful source status records.
- `tests/test_supply_chain.py::test_discover_campaigns_reports_source_failures_structurally`
  verifies source failures are returned as structured errors.

## Operator Workflow

1. Run discovery:

   ```bash
   secopsai supply-chain discover-campaigns --since 24h --limit 25 --json
   ```

2. Review `source_status` first. Any `error` source needs feed/API attention
   before assuming there were no relevant incidents.

3. Promote a source-backed candidate:

   ```bash
   secopsai supply-chain campaign-candidates promote <candidate-id> --json
   ```

4. Run safe research without persistence:

   ```bash
   secopsai supply-chain research-campaign --input campaign.json --dry-run --no-fetch --json
   ```

5. Persist findings only after review:

   ```bash
   secopsai supply-chain research-campaign --input campaign.json --persist --search-root /path/to/repo --json
   ```

6. Create blog drafts only as review-only drafts:

   ```bash
   secopsai blog draft-campaign --campaign campaign.json
   ```

## Remaining Limitations

- X/social signals are not polled unless an operator configures approved API
  access and rate-limit policy.
- GitHub token/repository incidents are source-backed event analyses unless a
  real GitHub audit-log integration is configured.
- SecOpsAI still never executes packages, extension activation code, lifecycle
  hooks, payloads, or binaries; all validation is static and deterministic.
