# Name Reservation

This page tracks SecOpsAI name ownership across public package and distribution
surfaces. It is intentionally operational: do not publish packages, upload
images, or create paid resources unless an owner explicitly approves the action.

## Current Status

Checked on 2026-05-21:

| Surface | Desired name | Status | Next action |
| --- | --- | --- | --- |
| GitHub repository | `Techris93/secopsai` | Secured and public | Keep canonical repo protected. |
| GitHub user/org | `secopsai` | `secopsai` is already a GitHub user account; org lookup returns 404 | Cannot reserve exact org while username exists. Use `Techris93/secopsai` as canonical. |
| GitHub Marketplace Action | `Techris93/secopsai-action` | Secured and public | Keep releases aligned with Marketplace docs. |
| Homebrew tap | `Techris93/homebrew-secopsai` | Secured and public | Add a formula after a stable release tarball and SHA256 exist. |
| npm | `secopsai` | Secured as public npm package maintained by `techris` | Publish next approved npm wrapper version when ready. |
| GitHub Packages | `@techris93/secopsai` | Secured through GitHub Packages workflow | Keep scoped package workflow. |
| PyPI | `secopsai` | Available: PyPI JSON endpoint returned 404 | Publish an approved first package to reserve. |
| Docker Hub namespace/repo | `secopsai/secopsai` | Repository lookup returned 404; namespace reservation requires Docker Hub owner UI/account access | Create/claim Docker Hub organization or publish under approved owner namespace. |
| Docker Hub fallback repo | `techris93/secopsai` | Repository lookup returned 404 | Configure Docker Hub secrets and run the Docker Hub workflow after approval. |

## GitHub

Canonical project repository:

```text
https://github.com/Techris93/secopsai
```

The exact `secopsai` GitHub account name is unavailable because it resolves as
a user account. Keep the canonical project under `Techris93/secopsai` unless
the owner of `secopsai` transfers the account/name.

## Homebrew

Tap repository:

```text
https://github.com/Techris93/homebrew-secopsai
```

User-facing tap command:

```bash
brew tap Techris93/secopsai
```

Do not add `brew install secopsai` documentation until the tap contains a
working formula with a stable release URL and SHA256.

## PyPI

The `secopsai` PyPI name was available during checks. This repo now includes a
manual `Publish PyPI Package` workflow:

```text
.github/workflows/publish-pypi-package.yml
```

Required secret:

```text
PYPI_API_TOKEN
```

Safe reservation path:

1. Review `pyproject.toml`.
2. Run the workflow with `dry_run=true`.
3. Confirm `python -m twine check dist/*` passes.
4. Configure `PYPI_API_TOKEN`.
5. Run the workflow with `dry_run=false`.
6. Verify `https://pypi.org/project/secopsai/`.

Local dry-run commands:

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
```

## Docker Hub

This repo now includes a manual Docker Hub workflow:

```text
.github/workflows/publish-dockerhub-image.yml
```

Required secrets:

```text
DOCKERHUB_USERNAME
DOCKERHUB_TOKEN
```

Safe reservation path for the fallback owner namespace:

1. Confirm Docker Hub account ownership for `techris93`.
2. Run `Publish Docker Hub Image` with `dry_run=true` and namespace
   `techris93`.
3. Configure Docker Hub secrets.
4. Run with `dry_run=false`.
5. Verify `https://hub.docker.com/r/techris93/secopsai`.

To reserve the cleaner `secopsai/secopsai` path, create or claim the Docker Hub
`secopsai` organization in Docker Hub first. This cannot be safely completed
from the repository without account-owner access.

## No-Secret Rules

- Never commit `.npmrc`, `.pypirc`, Docker credentials, package tokens, or API
  keys.
- Use GitHub Actions secrets for publish tokens.
- Run dry-run workflows before any real publish.
- Record the publish URL and workflow run after each reservation.
