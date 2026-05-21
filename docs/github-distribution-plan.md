# GitHub Distribution

SecOpsAI is distributed through the existing npm package flow from
`supply-chain/package.json` and through GitHub-native distribution paths.

## Current Package State

- Repository: `https://github.com/Techris93/secopsai`
- Current npm package manifest: `supply-chain/package.json`
- Current npm package name: `secopsai`
- Current prepared npm wrapper version: `1.0.1`
- GitHub Packages package: `@techris93/secopsai`
- Marketplace Action repo: `https://github.com/Techris93/secopsai-action`
- Marketplace Action release: `https://github.com/Techris93/secopsai-action/releases/tag/v1.0.0`
- Python package metadata: `pyproject.toml` exposes the `secopsai` CLI.
- Existing GitHub workflows already build/test, scan, release containers, and
  run Blog Ops.

The root of this repository does not currently contain a Node `package.json`.
The npm-distributed CLI wrapper lives in `supply-chain/`.

## npm Registry Status

Registry checks on 2026-05-21 showed:

- `npm view secopsai --json` returns `secopsai@1.0.0`.
- The npm package is maintained by `techris`.
- `npm view @techris93/secopsai --json` returns `E404` from the public npm
  registry.

That means `secopsai` is not globally available for a new unrelated owner, but
it is already the public unscoped package name for this product line. This repo
is prepared for the next authorized unscoped npm release as `secopsai@1.0.1`.

Preferred public npm install:

```bash
npm install -g secopsai
```

The public npm publish workflow is:

```text
.github/workflows/publish-npm-package.yml
```

It validates `supply-chain/package.json`, runs `npm pack --dry-run`, and
publishes only when manually dispatched with `dry_run=false` or when an
`npm-v*` tag is pushed. It requires the repository secret `NPM_TOKEN` and does
not commit `.npmrc`.

## GitHub Packages Status

GitHub's npm registry requires package names and scopes to use lowercase
letters, and packages published by GitHub Actions can authenticate with the
repository `GITHUB_TOKEN`.

To preserve the existing npm package name, SecOpsAI does **not** change
`supply-chain/package.json` from `secopsai` to a scoped name in the repo.
Instead, `.github/workflows/publish-github-package.yml` creates a temporary
workflow-local manifest named:

```text
@techris93/secopsai
```

The workflow publishes that scoped package to:

```text
https://npm.pkg.github.com
```

This keeps the public npm install path stable while enabling GitHub Packages.

Published workflow runs:

- Dry run: `https://github.com/Techris93/secopsai/actions/runs/26197411144`
- Publish: `https://github.com/Techris93/secopsai/actions/runs/26197426834`

## Publishing Workflow

GitHub Packages workflow:

```text
.github/workflows/publish-github-package.yml
```

Triggers:

- `workflow_dispatch` with `dry_run=true` by default.
- `workflow_dispatch` with `dry_run=false` when an owner intentionally wants to
  publish.
- Tag pushes matching `v*`.

Permissions:

- `contents: read`
- `packages: write`

Token model:

- Uses `${{ secrets.GITHUB_TOKEN }}` as `NODE_AUTH_TOKEN`.
- No personal access token is committed or required for the normal repository
  workflow.

Safety:

- Runs `npm pack --dry-run` before publishing.
- Rewrites package name and `publishConfig` only inside the checked-out workflow
  workspace.
- Does not create or commit `.npmrc`.
- Generated `.tgz` files and `.npmrc` are ignored.

## Consumer Install Path

For public npm consumers:

```bash
npm install -g secopsai
```

For GitHub Packages consumers:

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

For private/package-authenticated installs, the user must authenticate to
GitHub Packages with a token that can read the package. Public visibility may
still need to be enabled after the first package publish because GitHub
Packages can default new packages to private.

## Marketplace Status

Official GitHub Marketplace Action requirements include:

- The action must be in a public repository.
- The repository must contain a single root `action.yml` or `action.yaml`.
- The repository must not contain workflow files.
- The action `name` must be unique.

This SecOpsAI repository already contains multiple GitHub workflows under
`.github/workflows/`, so it should **not** be submitted directly as the
Marketplace Action repository.

SecOpsAI is published from the dedicated action repository:

```text
https://github.com/Techris93/secopsai-action
```

Marketplace/release metadata:

```text
Name: SecOpsAI Supply-Chain Guard
Tag: v1.0.0
Category: Security
Secondary category: Continuous integration
```

The dedicated repo contains the root Marketplace action files:

```text
action.yml
secopsai-action.sh
README.md
```

Use the Marketplace Action in workflows:

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

The source wrapper remains mirrored under `marketplace/github-action/` in this
main repo so changes can be reviewed alongside SecOpsAI core code.

## Ongoing Owner Actions

1. For a public npm release, run `Publish npm Package` with `dry_run=true`.
2. After review, run it with `dry_run=false` or push an `npm-v*` tag to publish
   the prepared `secopsai` version.
3. After each SecOpsAI npm package release, run the GitHub Packages workflow
   with `dry_run=true`.
4. Run it with `dry_run=false` or push a `v*` tag to publish the matching
   `@techris93/secopsai` package version.
5. Keep `Techris93/secopsai-action` tagged releases in sync with wrapper
   changes.
6. If Marketplace metadata changes, update the release/listing from the
   `Techris93/secopsai-action` repository.

## Limitations

- The Marketplace action installs SecOpsAI from this GitHub repository and runs
  only allowlisted SecOpsAI CLI modes.
- The action does not run untrusted package lifecycle scripts; package checks
  use SecOpsAI's metadata/advisory-oriented CLI paths.
- GitHub Packages may require package visibility/access review after the first
  publish, depending on repository/account settings.
