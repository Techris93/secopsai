# GitHub Distribution Plan

SecOpsAI is already distributed through the existing npm package flow from
`supply-chain/package.json`. This plan adds GitHub-native distribution without
changing that npm install path.

## Current Package State

- Repository: `https://github.com/Techris93/secopsai`
- Current npm package manifest: `supply-chain/package.json`
- Current npm package name: `secopsai`
- Python package metadata: `pyproject.toml` exposes the `secopsai` CLI.
- Existing GitHub workflows already build/test, scan, release containers, and
  run Blog Ops.

The root of this repository does not currently contain a Node `package.json`.
The npm-distributed CLI wrapper lives in `supply-chain/`.

## GitHub Packages Strategy

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

The workflow then publishes that scoped package to:

```text
https://npm.pkg.github.com
```

This keeps the public npm install path stable while enabling GitHub Packages.

## Publishing Workflow

Workflow:

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

For GitHub Packages consumers:

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

For private/package-authenticated installs, the user must authenticate to
GitHub Packages with a token that can read the package. Public visibility may
still need to be enabled after the first package publish because GitHub
Packages can default new packages to private.

## Marketplace Eligibility Findings

Official GitHub Marketplace Action requirements include:

- The action must be in a public repository.
- The repository must contain a single root `action.yml` or `action.yaml`.
- The repository must not contain workflow files.
- The action `name` must be unique.

This SecOpsAI repository already contains multiple GitHub workflows under
`.github/workflows/`, so it should **not** be submitted directly as the
Marketplace Action repository.

## Recommended Marketplace Route

Use a dedicated Marketplace repository, for example:

```text
Techris93/secopsai-action
```

Copy these prepared files from this repository into that dedicated repo root:

```text
marketplace/github-action/action.yml -> action.yml
marketplace/github-action/secopsai-action.sh -> secopsai-action.sh
marketplace/github-action/README.md -> README.md
```

Then tag and publish the release through GitHub Marketplace.

The prepared action can also be used from this repo subdirectory before the
Marketplace repo is created:

```yaml
- uses: Techris93/secopsai/marketplace/github-action@main
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

Subdirectory usage is useful for testing, but GitHub will not automatically
list subdirectory action metadata in Marketplace.

## Required Owner Actions

1. Run the GitHub Packages workflow in dry-run mode.
2. Run it with `dry_run=false` or push a `v*` tag when ready to publish
   `@techris93/secopsai`.
3. After first publish, review GitHub package visibility and set it public if
   intended.
4. Create a dedicated public repository such as `Techris93/secopsai-action`.
5. Copy the prepared Marketplace Action files to the root of that repository.
6. Accept the GitHub Marketplace Developer Agreement if prompted.
7. Draft a release from the root `action.yml`, select "Publish this Action to
   the GitHub Marketplace", choose categories, and publish.

## Limitations

- This does not publish or submit anything automatically.
- The Marketplace action installs SecOpsAI from this GitHub repository and runs
  only allowlisted SecOpsAI CLI modes.
- The action does not run untrusted package lifecycle scripts; package checks
  use SecOpsAI's metadata/advisory-oriented CLI paths.
