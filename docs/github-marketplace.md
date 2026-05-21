# GitHub Marketplace Preparation

SecOpsAI should enter GitHub Marketplace as a GitHub Action, not as the main
multi-surface repository. The main repo contains workflows, docs, dashboard/blog
assets, and Python runtime code; GitHub Marketplace Action listings are intended
for a repository that packages one root action.

## Prepared Action

Prepared files:

```text
marketplace/github-action/action.yml
marketplace/github-action/secopsai-action.sh
marketplace/github-action/README.md
```

The action runs deterministic, allowlisted SecOpsAI CLI modes:

- `supply-chain-scan`
- `advisory-check`
- `discover-campaigns`
- `triage-summary`

It validates inputs, installs SecOpsAI from `Techris93/secopsai`, writes JSON
output to a file, and can fail the workflow on `high` or `critical` severity.

## Recommended Listing

Product name:

```text
SecOpsAI Supply-Chain Guard
```

Short description:

```text
Local-first supply-chain, advisory, campaign-discovery, and triage checks for GitHub Actions.
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

## Manual Submission Steps

1. Create a dedicated public repo, for example `Techris93/secopsai-action`.
2. Copy prepared action files to the root:
   - `action.yml`
   - `secopsai-action.sh`
   - `README.md`
3. Confirm the repository has no `.github/workflows/*` files when publishing
   the initial Marketplace listing.
4. Commit and push.
5. Open `action.yml` on GitHub and use the Marketplace banner to draft a
   release.
6. Accept the GitHub Marketplace Developer Agreement if GitHub prompts for it.
7. Select "Publish this Action to the GitHub Marketplace".
8. Choose the categories above.
9. Publish a semantic tag, for example `v1.0.0`.
10. After publishing, verify the listing install snippet and run a consumer
    smoke test.

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

## Why The Main Repo Is Not Submitted Directly

GitHub Marketplace Action requirements say the Marketplace repository should
contain one root action metadata file and should not contain workflow files.
This main SecOpsAI repo intentionally has multiple workflows for CI, security,
Blog Ops, benchmarking, and release automation. A dedicated action repository
keeps the Marketplace package clean while this repo remains the product source.
