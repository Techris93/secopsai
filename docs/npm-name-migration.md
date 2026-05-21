# npm Name Migration

This note records the clean npm naming plan for SecOpsAI.

## Availability Result

Checked on 2026-05-21:

```bash
npm view secopsai --json
npm view @techris93/secopsai --json
```

Result:

- `secopsai` exists on the public npm registry as `secopsai@1.0.0`.
- The public npm package is maintained by `techris`.
- `@techris93/secopsai` returns `E404` from the public npm registry.
- GitHub Packages remains scoped as `@techris93/secopsai`.

Decision:

- Keep the public npm package name as `secopsai`.
- Prepare the next public npm wrapper release as `secopsai@1.0.1`.
- Preserve GitHub Packages as `@techris93/secopsai` through workflow-local
  manifest rewriting.
- Do not publish or deprecate anything without explicit maintainer approval.

## Install Paths

Preferred public npm install:

```bash
npm install -g secopsai
```

GitHub Packages install:

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

If a scoped public npm package is introduced later, document it separately and
keep it as a migration bridge rather than replacing the clean `secopsai` name.

## Release Preparation

Files prepared for public npm release:

- `supply-chain/package.json`: unscoped package name `secopsai`, version
  `1.0.1`, and `bin.secopsai`.
- `supply-chain/.npmignore`: excludes local auth files, logs, caches, tarballs,
  and generated outputs.
- `.github/workflows/publish-npm-package.yml`: manual/tag-gated public npm
  release workflow.
- `.github/workflows/publish-github-package.yml`: existing scoped GitHub
  Packages workflow remains unchanged.

Required repository secret:

```text
NPM_TOKEN
```

The token should be an npm automation token with publish access to `secopsai`.
Do not commit `.npmrc`, tokens, generated tarballs, or npm debug logs.

## Manual Publish Checklist

Only run this after explicit maintainer approval:

```bash
cd /Users/chrixchange/secopsai
git status --short
npm view secopsai --json

cd supply-chain
npm pack --dry-run
npm publish --access public
npm view secopsai --json
npm install -g secopsai
secopsai --help
```

GitHub Actions alternative:

1. Open the `Publish npm Package` workflow.
2. Run it with `dry_run=true`.
3. Review the package contents and version.
4. Run it with `dry_run=false` only after approval.
5. Verify `npm view secopsai --json`.

## Rollback Notes

Npm package versions cannot be overwritten after publication. If a bad release
is published:

- Publish a corrected higher version.
- Deprecate only the bad version, not the whole package.
- Update docs and Marketplace Action references if needed.

Example deprecation command, requiring explicit approval:

```bash
npm deprecate secopsai@1.0.1 "Superseded by a corrected SecOpsAI release. Please upgrade."
```

## Brand Reservation Checklist

Reserve or verify ownership for the surfaces tracked in
[Name Reservation](name-reservation.md):

- npm: `secopsai`
- GitHub: `Techris93/secopsai` and `Techris93/secopsai-action`
- Docker Hub: `secopsai`
- PyPI: `secopsai`
- Homebrew tap: `homebrew-secopsai` or `secopsai/tap`
- Domains: `secopsai.dev` and related product domains

If a registry name is unavailable, document ownership, contact path, and the
fallback name before publishing an alternate package.
