# SecOpsAI Findings Triage & Investigation Guide

A step-by-step guide for reviewing, investigating, and dispositioning SecOpsAI alerts.

## Workflow

1. Refresh and inspect findings:

```bash
cd /path/to/secopsai
source .venv/bin/activate
secopsai refresh
secopsai triage list --status open --limit 20
```

2. Start analyst review:

```bash
secopsai triage start <FINDING_ID> --note "Initial analyst review started"
```

3. Gather evidence and generate case files:

```bash
secopsai triage investigate <FINDING_ID> --json
```

Generated artifacts:

- `reports/triage/<finding_id>.json`
- `reports/triage/<finding_id>.md`

4. Close with analyst-confirmed disposition:

```bash
secopsai triage close <FINDING_ID> --disposition needs_review --note "Escalated to senior analyst"
```

## Supported Dispositions

- `true_positive`
- `false_positive`
- `expected_behavior`
- `accepted_risk`
- `exception_granted`
- `needs_review`
- `tune_policy`
- `remediated`

## Supply-Chain Triage

`secopsai triage investigate SCM-XXXX` automatically gathers:

- finding summary and severity
- package policy matches (allowlist / denylist)
- local dependency references under the chosen search root
- stored verdict explanation and matched rules
- reputation signals from registry metadata when available
- suggested disposition and next actions

Use it to quickly decide whether a package is:

- `true_positive`
- `false_positive`
- `expected_behavior`
- `needs_review`

## Host-Based Triage

`secopsai triage investigate OCF-XXXX` currently supports:

- policy denial review
- exfiltration review
- generic host finding review with evidence summary and next actions

## Best Practices

- Always add a meaningful closure note.
- Use `triage start` before deep analysis so the SOC store reflects active analyst review.
- Treat `triage investigate` as evidence gathering, not auto-closure.
- Keep the generated case files for audit trail and rule tuning.
