# Name Reservation

This page tracks exact `secopsai` name ownership across public package and
distribution surfaces. The primary target is the clean brand name `secopsai`,
not owner-scoped fallbacks such as `Techris93/secopsai`.

It is intentionally operational: do not publish packages, upload images, or
create paid resources unless an owner explicitly approves the action.

## Current Status

Checked on 2026-05-21:

| Surface | Desired name | Status | Next action |
| --- | --- | --- | --- |
| GitHub account/organization | `secopsai` | `secopsai` is already a GitHub user account; current CLI auth is `Techris93` | Log in as the `secopsai` account or obtain ownership/transfer before creating exact-name repos. |
| GitHub repository | `secopsai/secopsai` | Not created from this repo because current auth is not the `secopsai` account | Create under the `secopsai` account after account access is confirmed. |
| GitHub Marketplace Action | `secopsai/secopsai-action` | Not created from this repo because current auth is not the `secopsai` account | Create or transfer the action repo under `secopsai` before Marketplace submission. |
| Homebrew tap | `secopsai/homebrew-secopsai` or `secopsai/homebrew-tap` | Not created from this repo because current auth is not the `secopsai` account | Create the exact tap under the `secopsai` account after GitHub access is confirmed. |
| npm | `secopsai` | Secured as public npm package maintained by `techris` | Publish next approved npm wrapper version when ready. |
| GitHub Packages | `@secopsai/secopsai` | Requires GitHub `secopsai` account/org package namespace | Add a scoped package workflow after GitHub namespace access is available. |
| PyPI | `secopsai` | Available: PyPI JSON endpoint returned 404 | Publish an approved first package to reserve. |
| Docker Hub namespace/repo | `secopsai/secopsai` | Repository lookup returned 404; namespace repository listing returned 200 with no repos | Create/claim Docker Hub `secopsai` namespace, then run the Docker Hub workflow with namespace `secopsai`. |

## GitHub

Exact target repository:

```text
https://github.com/secopsai/secopsai
```

The exact `secopsai` GitHub name resolves as a user account, not an
organization. Current local GitHub CLI auth is `Techris93`, so this repository
cannot create or manage repos under `secopsai` until the owner logs in as that
account or transfers the namespace.

Owner action after logging in as `secopsai`:

```bash
gh auth login
gh repo create secopsai/secopsai --public --description "SecOpsAI security operations automation"
gh repo create secopsai/secopsai-action --public --description "GitHub Action for SecOpsAI"
gh repo create secopsai/homebrew-secopsai --public --description "Homebrew tap for SecOpsAI"
```

If the current `Techris93/secopsai` repository remains the development source,
transfer it to `secopsai/secopsai` instead of creating a second disconnected
repository.

## Homebrew

Exact target tap repository:

```text
https://github.com/secopsai/homebrew-secopsai
```

User-facing tap command:

```bash
brew tap secopsai/secopsai
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

Safe reservation path for the exact `secopsai` namespace:

1. Create or claim the Docker Hub `secopsai` namespace.
2. Run `Publish Docker Hub Image` with `dry_run=true` and namespace
   `secopsai`.
3. Configure Docker Hub secrets.
4. Run with `dry_run=false`.
5. Verify `https://hub.docker.com/r/secopsai/secopsai`.

This cannot be safely completed from the repository without Docker Hub
account-owner access.

## No-Secret Rules

- Never commit `.npmrc`, `.pypirc`, Docker credentials, package tokens, or API
  keys.
- Use GitHub Actions secrets for publish tokens.
- Run dry-run workflows before any real publish.
- Record the publish URL and workflow run after each reservation.
