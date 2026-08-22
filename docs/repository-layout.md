# Repository Layout

SecOpsAI keeps runtime code, compatibility entry points, operator data, public
sites, and distribution wrappers in one repository. Some similarly named files
serve different deployment targets; they are not interchangeable duplicates.

## Canonical Locations

| Path | Responsibility | Change guidance |
| --- | --- | --- |
| `secopsai/` | Packaged Python application and the canonical `secopsai` CLI | Add product runtime code here |
| `adapters/`, `openclaw_adapters/`, `integrations/` | Platform collectors and normalized integrations | Keep platform-specific code behind the shared event contracts |
| `rules/`, `schemas/`, `contracts/` | Detection content and stable data contracts | Preserve backward compatibility when changing identifiers or fields |
| `tests/`, `eval/` | Regression, workflow, and detection-quality validation | Keep deterministic fixtures free of credentials and live malware |
| `docs/` | Maintained operator and developer documentation | Put new long-form documentation here |
| `marketplace/`, `supply-chain/` | GitHub Action and npm/OpenClaw distribution wrappers | Do not treat these wrappers as replacements for the Python runtime |
| `website/` | Reviewed source deployed to `secopsai.dev` | Keep synchronized with the compatibility mirror required by CI |
| `www/` | Public-site compatibility mirror | CI verifies parity with `website/`; do not edit only one copy |
| `blog/` | Editorial state and generated security-research site | Preserve the complete published archive during rebuilds |
| `data/`, `reports/`, `results/` | Runtime inputs, local state, and generated evidence | Commit only explicit safe fixtures or reviewed public artifacts |
| `.github/` | CI, release, security, and deployment automation | Keep permissions least-privilege and actions pinned |

## Why Some Python Files Remain At The Root

Root modules such as `detect.py`, `correlation.py`, `findings.py`, and
`soc_store.py` are compatibility entry points used by tests, documented local
workflows, and the `pyproject.toml` package contract. Moving them into
`secopsai/` without a staged compatibility migration would break imports and
existing automation. New application code should use `secopsai/`; root wrappers
should remain small and should not grow a second implementation.

## Documentation At The Root

The root README, license, contribution guide, changelog, and security policy are
GitHub-facing project files. Older public guides such as `USER_WORKBOOK.md` and
`ADAPTIVE_INTELLIGENCE.md` remain at stable paths because existing links point
to them. New guides belong in `docs/`, and maintained documentation should be
linked from `mkdocs.yml`.

## Duplication Rules

Before deleting or consolidating a similarly named file:

1. Check `pyproject.toml`, workflows, tests, installers, and deployment config.
2. Confirm whether the files are separate source, wrapper, fixture, or deploy
   targets.
3. Update every documented and automated reference in the same change.
4. Preserve a compatibility shim when a public command or import path moves.
5. Verify packaging, documentation, tests, and deploy parity before removal.

The detailed module-level decisions are recorded in
[the module audit](module-audit-2026-05-31.md).
