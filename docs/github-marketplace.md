# GitHub Marketplace

SecOpsAI is published for GitHub Marketplace as **SecOpsAI Supply-Chain Guard**.
The listing is backed by the dedicated public action repository:

```text
https://github.com/Techris93/secopsai-action
```

Published release:

```text
https://github.com/Techris93/secopsai-action/releases/tag/v1.0.0
```

The main SecOpsAI repository contains workflows, docs, dashboard/blog assets,
and Python runtime code. GitHub Marketplace Action listings are cleaner from a
repository that packages one root action, so the Marketplace listing is served
from `Techris93/secopsai-action` while source copies stay here for review.

## Action Source Mirror

Source mirror files in this repo:

```text
marketplace/github-action/action.yml
marketplace/github-action/secopsai-action.sh
marketplace/github-action/README.md
```

The published action in `Techris93/secopsai-action` runs deterministic,
allowlisted SecOpsAI CLI modes:

- `supply-chain-scan`
- `advisory-check`
- `ai-dependency-guard`
- `discover-campaigns`
- `triage-summary`

It validates inputs, installs SecOpsAI from `Techris93/secopsai`, writes JSON
output to a file, and can fail the workflow on `high` or `critical` severity
when the caller opts in.

## Listing Metadata

Product name:

```text
SecOpsAI Supply-Chain Guard
```

Short description:

```text
Local-first supply-chain, AI dependency, advisory, campaign-discovery, and triage checks for GitHub Actions.
```

Primary category:

```text
Security
```

Secondary category:

```text
Continuous integration
```

Pricing:

```text
Free / open source
```

Support URL:

```text
https://github.com/Techris93/secopsai/issues
```

Privacy/data handling:

- The action runs inside the caller's GitHub Actions runner.
- No SecOpsAI service token is required.
- Inputs are passed to the local CLI.
- JSON output remains in the workflow workspace unless the caller uploads it.
- Package code is not executed by the wrapper.
- AI Dependency Guard uses registry metadata only and does not install
  dependencies suggested by AI output.

## Release And Maintenance Steps

1. Update `marketplace/github-action/*` in this repo.
2. Copy the changed files to the root of `Techris93/secopsai-action`.
3. Tag a new release, for example `v1.0.1`.
4. Keep Marketplace metadata aligned with this document.
5. Run a consumer workflow smoke test before announcing the new version.

## Suggested Screenshots

- A GitHub Actions run showing SecOpsAI completed.
- A JSON result artifact preview.
- A failed run caused by `fail-on-severity: critical`.
- A successful advisory-check run.

## Example Marketplace Usage

```yaml
name: SecOpsAI supply-chain guard

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  secopsai:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Techris93/secopsai-action@v1
        with:
          mode: advisory-check
          ecosystem: npm
          package: node-ipc
          version: 12.0.1
          fail-on-severity: critical
```

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: ai-dependency-guard
    scan-path: .
    fail-on-severity: high
```

## Why The Main Repo Is Not The Marketplace Repo

GitHub Marketplace Action requirements say the Marketplace repository should
contain one root action metadata file and should not contain workflow files.
This main SecOpsAI repo intentionally has multiple workflows for CI, security,
Blog Ops, benchmarking, and release automation. A dedicated action repository
keeps the Marketplace package clean while this repo remains the product source.
