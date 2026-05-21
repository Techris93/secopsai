# SecOpsAI Supply-Chain Guard Action

Run SecOpsAI supply-chain, advisory, campaign-discovery, and triage checks in
GitHub Actions.

This wrapper is deterministic and intentionally constrained. It does not accept
arbitrary shell command input, does not execute target package lifecycle scripts,
and writes JSON output for review or artifact upload.

## Usage

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
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secopsai-results
          path: secopsai-results.json
```

The GitHub Marketplace version is published from the dedicated public action
repository [`Techris93/secopsai-action`](https://github.com/Techris93/secopsai-action).
This directory is the source mirror kept with the main SecOpsAI product.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `mode` | `supply-chain-scan` | `supply-chain-scan`, `advisory-check`, `discover-campaigns`, or `triage-summary`. |
| `secopsai-ref` | `main` | Git ref to install from `Techris93/secopsai`. |
| `path` | `.` | Workspace path used by repository-aware modes. |
| `ecosystem` | empty | Ecosystem for package-specific checks. |
| `package` | empty | Package, module, extension, or artifact ID. |
| `version` | empty | Package version. |
| `previous-version` | empty | Optional previous version for `supply-chain-scan`. |
| `since` | `24h` | Discovery lookback window. |
| `limit` | `10` | Discovery candidate limit. |
| `output-format` | `json` | Only JSON is supported. |
| `output-file` | `secopsai-results.json` | Result file path. |
| `fail-on-severity` | `critical` | `none`, `high`, or `critical`. |

## Modes

### Advisory Check

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

### Supply-Chain Scan

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: supply-chain-scan
    ecosystem: pypi
    package: watchfiles
    version: 1.2.0
    fail-on-severity: high
```

### Campaign Discovery

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: discover-campaigns
    since: 24h
    limit: 10
    fail-on-severity: none
```

## Marketplace Notes

GitHub Marketplace Action listings should live in a repository with one root
`action.yml` and no product workflow noise. The published listing lives in
`Techris93/secopsai-action`; keep this source mirror aligned whenever the
wrapper changes.
