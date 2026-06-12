# Marketplace Listing

## Name

SecOpsAI Supply-Chain Guard

## Short Description

Local-first supply-chain, AI dependency, advisory, campaign-discovery, and
triage checks for GitHub Actions.

## Long Description

SecOpsAI Supply-Chain Guard brings SecOpsAI's local-first security checks into
GitHub Actions. It can run package-release scanning, AI Dependency Guard,
advisory checks, campaign-discovery review, and triage summaries from a
workflow without sending repository contents to a hosted SecOpsAI service.

The action is designed for security teams that want deterministic supply-chain
and developer-security checks in CI while preserving human review for risky
actions. It writes JSON output, supports severity-based failure, and uses
allowlisted SecOpsAI CLI modes rather than arbitrary shell command inputs.

## Categories

- Primary: Security
- Secondary: Continuous integration

## Pricing

Free / open source.

## Listing Assets

- Logo: square SecOpsAI shield or wordmark, preferably 512x512.
- Screenshot 1: successful `advisory-check` workflow run.
- Screenshot 2: failed `supply-chain-scan` run due to critical verdict.
- Screenshot 3: `ai-dependency-guard` report showing hallucinated dependency review.
- Screenshot 4: JSON result artifact.

## Installation

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: ai-dependency-guard
    scan-path: .
    fail-on-severity: high
```

## Published Links

- Action repository: `https://github.com/Techris93/secopsai-action`
- Release: `https://github.com/Techris93/secopsai-action/releases/tag/v1.0.0`
- Main SecOpsAI repository: `https://github.com/Techris93/secopsai`

## Support

- Issues: `https://github.com/Techris93/secopsai/issues`
- Documentation: `https://github.com/Techris93/secopsai`

## Security And Privacy

- Runs in the caller's GitHub Actions runner.
- Does not require a SecOpsAI cloud token.
- Does not publish or mutate findings by default.
- Does not execute target package lifecycle scripts.
- Does not install AI-suggested packages; AI Dependency Guard uses registry
  metadata only.
- Does not upload results unless the caller adds an upload-artifact step.

## Publication Checklist

- [x] Create dedicated public `Techris93/secopsai-action` repository.
- [x] Copy `marketplace/github-action/action.yml` to root `action.yml`.
- [x] Copy `marketplace/github-action/secopsai-action.sh` to root.
- [x] Copy `marketplace/github-action/README.md` to root.
- [x] Confirm there are no workflow files in the action repo.
- [x] Commit and push.
- [x] Accept the GitHub Marketplace Developer Agreement if prompted.
- [x] Draft a release from `action.yml`.
- [x] Select "Publish this Action to the GitHub Marketplace".
- [x] Choose Security and Continuous integration categories.
- [x] Publish tag `v1.0.0`.
- [ ] Run a consumer workflow smoke test after GitHub finishes Marketplace
  indexing and record the run URL in release notes.
