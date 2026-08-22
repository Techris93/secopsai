# npm Name And Package-Lineage Decision

This note replaces the earlier assumption that the public npm package and the
prepared supply-chain wrapper were already the same artifact.

## Verified State

Checked on 2026-08-22:

```bash
npm view secopsai --json
npm pack secopsai@1.0.0 --dry-run --json
npm view @techris93/secopsai --json
```

Results:

- `secopsai@1.0.0` exists on the public npm registry.
- Its published artifact is an OpenClaw plugin with
  `openclaw.plugin.json` and compiled plugin files.
- The public package metadata does not expose a global `secopsai` binary.
- `@techris93/secopsai` is not on the public npm registry; that identity is
  used by GitHub Packages.
- The local `supply-chain/package.json` prepares a different
  `secopsai@1.0.1` supply-chain CLI wrapper.

## Current Install Paths

Complete SecOpsAI Core:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

Published npm OpenClaw plugin:

```bash
openclaw plugins install secopsai
```

Authenticated GitHub Packages wrapper:

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

## Required Decision Before A Public npm Release

Do not publish the prepared `supply-chain/package.json` as
`secopsai@1.0.1` until the maintainer chooses one package lineage:

1. Keep `secopsai` as the OpenClaw plugin and publish the supply-chain wrapper under a different package name.
2. Convert `secopsai` into the broader wrapper through an explicit breaking migration with compatibility and release notes.
3. Build one package that intentionally supports both plugin and wrapper contracts, then test both install paths before release.

The safest current choice is option 1 or 3. Silently replacing a plugin package
with a different CLI would break existing consumers.

## Pre-Publish Checklist

- Confirm the chosen package identity and intended consumers.
- Confirm `name`, `version`, `bin`, entry points, and OpenClaw metadata.
- Run `npm pack --dry-run --json` and review every included file.
- Test in a clean temporary environment without lifecycle-script execution where possible.
- Verify the documented install command produces the intended executable or plugin.
- Use a manual/tag-gated workflow with `NPM_TOKEN`; never commit `.npmrc`.
- Publish an immutable higher version and verify registry metadata afterward.

## Rollback

npm versions cannot be overwritten. If a bad release is published, publish a
corrected higher version and deprecate only the affected version after explicit
maintainer approval.

## Brand Reservation

Registry and product-name ownership is tracked in
[Name Reservation](name-reservation.md). Package ownership does not remove the
need to preserve compatibility for existing consumers.
