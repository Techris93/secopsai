# Launch Checklist

Use this checklist when moving secopsai from repo state to a public release.

## Product

- Confirm benchmark evaluation is reproducible
- Confirm live OpenClaw pipeline produces findings
- Confirm setup script works on a clean machine

## Infrastructure

- Confirm Docker image builds from `Dockerfile`
- Confirm Render worker deploys from `main`
- Confirm GitHub Actions `Test & Build` passes
- Confirm `Security Scan` is reviewed for real findings

## Docs

- Confirm this MkDocs site builds successfully
- Confirm `docs.secopsai.dev` resolves to the live docs site
- Confirm all top-level docs pages are reachable

## Repository Guide

The full operational checklist remains in the repository root:

- [LAUNCH-CHECKLIST.md](https://github.com/Techris93/secops-autoresearch/blob/main/LAUNCH-CHECKLIST.md)
