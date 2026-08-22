# GitHub Distribution

SecOpsAI has four distinct distribution surfaces. They are related, but they
are not interchangeable.

## Verified Distribution Matrix

Verified on 2026-08-22:

| Surface | Published identity | Purpose | Install or use |
| --- | --- | --- | --- |
| Core platform | `Techris93/secopsai`, release `v1.0.0` | Complete Python CLI and local-first runtime | Official installer or source checkout |
| npm | `secopsai@1.0.0` | OpenClaw plugin package | `openclaw plugins install secopsai` |
| GitHub Packages | `@techris93/secopsai` | Scoped supply-chain wrapper published by the repository workflow | Authenticated npm install |
| GitHub Marketplace | `Techris93/secopsai-action@v1.0.0` | Constrained CI checks | GitHub Actions workflow |

The public npm metadata and dry-run tarball show an OpenClaw plugin with
`openclaw.plugin.json` and no global `secopsai` binary. Therefore
`npm install -g secopsai` is not documented as a Core CLI installation.

The local `supply-chain/package.json` currently describes a different,
unpublished `secopsai@1.0.1` supply-chain wrapper. Publishing that manifest
over the existing npm plugin would change the package's product type and must
not happen without an explicit migration decision.

## Core Platform

Recommended:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
cd ~/secopsai
source .venv/bin/activate
secopsai status
```

Manual:

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai
bash setup.sh --non-interactive --profile default
source .venv/bin/activate
```

## npm OpenClaw Plugin

```bash
openclaw plugins install secopsai
```

Core must still be installed on the machine the plugin is configured to use.
See [OpenClaw Plugin](OpenClaw-Plugin.md).

## GitHub Packages

The `Publish GitHub npm Package` workflow creates a temporary, workflow-local
manifest named `@techris93/secopsai` and publishes it to
`https://npm.pkg.github.com`.

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

The consumer may need a token with `read:packages`, depending on package
visibility and organization policy. Do not commit an authenticated `.npmrc`.

The publish workflow uses:

- `contents: read`
- `packages: write`
- the repository `GITHUB_TOKEN`
- a dry-run-first, manual/tag-gated release path

A successful publish run is recorded at
[GitHub Actions run 26197426834](https://github.com/Techris93/secopsai/actions/runs/26197426834).

## Marketplace Action

The dedicated Action repository is
[Techris93/secopsai-action](https://github.com/Techris93/secopsai-action).
The verified published tag is `v1.0.0`.

```yaml
- uses: Techris93/secopsai-action@v1.0.0
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
    fail-on-severity: critical
```

The published `v1.0.0` action metadata supports:

- `supply-chain-scan`
- `advisory-check`
- `discover-campaigns`
- `triage-summary`

AI Dependency Guard is a Core CLI capability. Do not document it as a
Marketplace Action mode until a new tagged Action release contains and
advertises the required inputs.

## Release Workflows

| Workflow | Registry | Guardrail |
| --- | --- | --- |
| `.github/workflows/publish-github-package.yml` | GitHub Packages | Scoped temporary manifest, dry-run first, `GITHUB_TOKEN` |
| `.github/workflows/publish-npm-package.yml` | Public npm | Must remain manual/tag-gated; requires `NPM_TOKEN` |
| Dedicated Action release | GitHub Marketplace | Publish a tested immutable tag before documenting new inputs |

The public npm workflow must not publish the prepared supply-chain wrapper until
the npm package-lineage decision in [npm Name Migration](npm-name-migration.md)
is resolved.

## Owner Checklist

1. Verify the artifact type, version, and file list before every registry publish.
2. Run the relevant workflow in dry-run mode.
3. Confirm no `.npmrc`, token, archive, cache, local data, or private telemetry is included.
4. Publish only from an reviewed commit and immutable release/tag.
5. Verify the exact consumer command against the published artifact.
6. Update documentation only after the tag/package exists.

## Limitations

- GitHub Packages API verification requires an authenticated token with `read:packages`; a package consumer may need the same scope.
- The Marketplace Action intentionally exposes only fixed modes and does not accept arbitrary shell commands.
- The Action does not run untrusted package lifecycle scripts.
- Public npm and GitHub Packages currently represent different package lineages; keep their install paths explicit.
