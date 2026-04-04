# SCM-E4478B5EB136E2AE

- Title: Suspicious pypi package release: ty@0.0.28
- Severity: critical
- Status: open
- Disposition: unreviewed
- Platform: supply_chain
- Source: secopsai-supply-chain
- First Seen: 2026-04-02T21:37:08Z
- Last Seen: 2026-04-02T21:37:08Z

## Summary

Deterministic rules flagged: obfuscated eval, subprocess spawn, network egress, credential access, ast-aware semantic findings, manifest install-time build customization, wheel/sdist artifact divergence, suspicious code present only in one PyPI artifact

## Analysis

Deterministic rules flagged: obfuscated eval, subprocess spawn, network egress, credential access, ast-aware semantic findings, manifest install-time build customization, wheel/sdist artifact divergence, suspicious code present only in one PyPI artifact

## Supply Chain Context

- Ecosystem: pypi
- Package: ty
- Old Version: 0.0.27
- New Version: 0.0.28
- Report Path: /Users/chrixchange/secopsai/data/supply_chain/reports/pypi-ty-0.0.27-to-0.0.28.md

## Event IDs

- 50292d9199ea4c70f3dfef65b54d37b9

## Suggested Workflow

1. Inspect the finding with `secopsai show SCM-E4478B5EB136E2AE`.
2. Confirm impact, affected asset or package, and whether remediation is code, config, or triage.
3. If code changes are needed, implement and test them in a branch/worktree.
4. Update triage in SecOpsAI after remediation or false-positive review.
