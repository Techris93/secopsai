# Triage Orchestrator

SecOpsAI includes a native triage orchestrator that can investigate open findings, auto-apply low-risk dispositions, and queue higher-risk actions for analyst confirmation.

## What It Automates

The orchestrator can:

- fetch open findings from the local SOC store
- move findings to `in_review`
- run the native investigation workflow
- auto-close low-risk cases such as `expected_behavior`
- auto-close already-allowlisted false positives
- queue actions that require human approval
- embed Adaptive Response Layer context for response posture, priority roots, safe probes, and deception recommendations
- write JSON and Markdown run summaries

It does **not** silently change broad policy by default.

## Core Commands

Review a single run across open findings:

```bash
secopsai triage orchestrate --search-root ~/secopsai
```

Inspect queued actions:

```bash
secopsai triage queue
```

Apply a queued action after review:

```bash
secopsai triage apply-action ACT-0001 --yes
```

Generate a compact current-state summary:

```bash
secopsai triage summary
```

Run the adaptive response layer directly when you want the adaptive view without changing triage state:

```bash
secopsai adaptive-response --persist-memory
```

## Action Model

The orchestrator uses a guarded action model.

Auto-applied by default:

- move finding to `in_review`
- close as `expected_behavior`
- close as `false_positive` when the package is already allowlisted

Queued for analyst action:

- add a package to the allowlist
- tune rule weights
- disable or enable rules
- tune thresholds
- close as `needs_review`
- close as `tune_policy`

## Configuration

Default policy lives in:

- `config/triage_orchestrator.toml`

Current knobs:

- `safety.auto_close_expected_behavior`
- `safety.auto_close_allowlisted_false_positive`
- `safety.auto_start_in_review`
- `safety.reconcile_on_policy_change`
- `limits.max_findings_per_run`

## Scheduled Operation

Use the provided helpers for unattended runs:

```bash
bash scripts/run_triage_orchestrator.sh
bash scripts/install_triage_orchestrator_launchd.sh
bash scripts/run_triage_summary_notify.sh
bash scripts/install_triage_summary_launchd.sh
```

The runner executes the orchestrator, writes queue state, and emits reports under:

- `reports/triage/orchestrator/`

Each summary report now includes an **Adaptive Response** section with:

- response posture and sensitivity multiplier
- `observe -> detect_pattern -> adapt_response -> remember_outcome`
- priority roots for analyst attention
- safe active probes
- deception recommendations

The summary notifier runs `secopsai --json triage summary`, tracks only currently active `open` and `in_review` finding IDs, and sends Slack only when new active findings appear.

## Recommended Workflow

1. Run detection and correlation:

```bash
secopsai refresh
secopsai correlate
```

2. Let the orchestrator process the open queue:

```bash
secopsai triage orchestrate --search-root ~/secopsai
```

3. Review any queued actions:

```bash
secopsai triage queue
```

4. Apply the specific changes you approve:

```bash
secopsai triage apply-action ACT-0001 --yes
```
