# SecOpsAI Findings Triage & Investigation Guide

A step-by-step guide for reviewing, investigating, and dispositioning SecOpsAI alerts.

For day-to-day operations you now have two valid paths:

- manual analyst workflow with `triage start`, `triage investigate`, and `triage close`
- guarded automation with `triage orchestrate`, `triage queue`, and `triage apply-action`

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
secopsai triage investigate <FINDING_ID> --open-session --with-research --json
```

Generated artifacts:

- `reports/triage/<finding_id>.json`
- `reports/triage/<finding_id>.md`
- timestamped research reports under `reports/research/`
- investigation session artifacts under `data/sessions/`

4. Close with analyst-confirmed disposition:

```bash
secopsai triage close <FINDING_ID> --disposition needs_review --note "Escalated to senior analyst"
```

## Orchestrated Workflow

Use the native orchestrator when you want SecOpsAI to investigate open findings and auto-apply only the safest actions:

```bash
secopsai triage orchestrate --search-root ~/secopsai
secopsai triage queue
secopsai triage apply-action ACT-0001 --yes
secopsai triage summary
```

The orchestrator will:

- move findings into `in_review`
- write the same case files as manual investigation
- auto-close low-risk `expected_behavior` for eligible host/policy findings;
  supply-chain intelligence is excluded from this shortcut
- queue higher-risk actions such as allowlisting and tuning

## Supported Dispositions

- `true_positive`
- `false_positive`
- `expected_behavior`
- `accepted_risk`
- `exception_granted`
- `needs_review`
- `tune_policy`
- `remediated`

For supply-chain findings, do not use `expected_behavior`, `not_applicable`, or
`false_positive` solely because the package is absent from the current local
repository. Local absence changes the exposure assessment only. Keep credible
package intelligence open or in review, validate the artifact through the
Research workflow, and search organization-wide inventories separately.

## Supply-Chain Triage

`secopsai triage investigate SCM-XXXX` automatically gathers:

- finding summary and severity
- package policy matches (allowlist / denylist)
- local dependency references under the chosen search root
- stored verdict explanation and matched rules
- reputation signals from registry metadata when available
- optional source-backed research artifacts with `--with-research`
- suggested disposition and next actions

Use it to quickly decide whether a package is:

- `true_positive`
- `false_positive`
- `needs_review`

Record local deployment relevance in the separate exposure assessment rather
than using `expected_behavior` as a substitute for “not installed here.”

Preview and repair historical findings that were closed by the superseded
local-absence rule:

```bash
secopsai triage reconcile-exposure-closures --json
secopsai triage reconcile-exposure-closures --apply --json
```

The repair is intentionally narrow: it selects only closed
`secopsai-supply-chain` findings with a stored `malicious` verdict, an
`expected_behavior` disposition, and a legacy local-absence closure note. It
reopens them as `unreviewed` and adds an audit note. Ordinary analyst closures
are preserved. The orchestrator performs the same idempotent repair before its
next run so unattended installations converge automatically.

### False-Positive Relief

Immediate allowlist relief:

```bash
secopsai supply-chain allowlist add --ecosystem pypi --package textual
secopsai supply-chain explain-policy --ecosystem pypi --package textual
secopsai supply-chain reconcile-history --json
secopsai triage close SCM-XXXX --disposition false_positive --note "Verified legitimate package; added to allowlist."
```

Remove an allowlist entry:

```bash
secopsai supply-chain allowlist remove --ecosystem pypi --package textual
```

Tune a noisy rule instead of allowlisting a package:

```bash
secopsai supply-chain tune rule "wheel/sdist artifact divergence" --weight 1
secopsai supply-chain tune rule "manifest executable entrypoints" --disable
```

Tune thresholds:

```bash
secopsai supply-chain tune threshold --global-threshold --value 12
secopsai supply-chain tune threshold --ecosystem pypi --value 12
secopsai supply-chain tune threshold --package langchain --package-ecosystem pypi --value 14
```

Use allowlisting when one known-safe package keeps firing. Use rule or threshold tuning when the same heuristic is noisy across many legitimate packages.

## Host-Based Triage

`secopsai triage investigate OCF-XXXX` currently supports:

- policy denial review
- exfiltration review
- generic host finding review with evidence summary and next actions

## Best Practices

- Always add a meaningful closure note.
- Use `triage start` before deep analysis so the SOC store reflects active analyst review.
- Treat `triage investigate` as evidence gathering, not auto-closure.
- Prefer `--open-session --with-research` for higher-risk findings so the dashboard, CLI, and plugin all point to the same case trail.
- Keep the generated case files for audit trail and rule tuning.
- Run `secopsai research preflight` before large correlation or orchestrator runs when freshness is in doubt.
