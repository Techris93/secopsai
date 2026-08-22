# CLI Reference

This page documents the `secopsai` command-line interface.

## Global usage

```bash
secopsai [--json] <command> [options]
secopsai <command> [options] [--json]
```

`--json` is a global flag and is accepted either **before or after** the subcommand.

Examples:

```bash
secopsai --json list --severity high
secopsai list --severity high --json
```

## GitHub Actions Usage

For CI workflows, the published **SecOpsAI Supply-Chain Guard** GitHub
Marketplace Action wraps selected CLI modes with fixed, constrained execution:

```yaml
- uses: Techris93/secopsai-action@v1.0.0
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

AI Dependency Guard is currently invoked through the Core CLI. The published
`v1.0.0` Marketplace Action does not advertise that mode.

Distribution and Marketplace maintenance details live in
[GitHub Distribution](github-distribution-plan.md) and
[GitHub Marketplace](github-marketplace.md).

## Command overview

## Specialist Orchestrator commands

```bash
secopsai specialists status --json
secopsai specialists catalog --json
secopsai specialists route --input task.json --tier recommend --json
secopsai specialists create --input task.json --tier read_only --enqueue --json
secopsai specialists auto-route --input task.json --json
secopsai specialists runs --limit 25 --json
secopsai specialists show SOR-XXXXXXXXXXXXXXXX --json
secopsai specialists approve SOR-XXXXXXXXXXXXXXXX --json
secopsai specialists execute SOR-XXXXXXXXXXXXXXXX --json
secopsai specialists cancel SOR-XXXXXXXXXXXXXXXX --json
secopsai specialists policy --mode guarded --maximum-automatic-tier read_only --json
```

`route` is a read-only contract preview. `create` stores a durable run, and
`--enqueue` is accepted only for the `read_only` tier. `approve` and `execute`
are separate steps for `worktree` and `pr_ready` runs. Automatic policy can use
only `recommend` or `read_only`; it cannot edit repositories.

Task JSON accepts bounded fields such as `title`, `description`, `domain`,
`priority`, `status`, `owner_role`, `reviewer_role`, `repo_alias`,
`evidence_refs`, `external_facing`, and `requires_security_review`.
`repo_alias` is restricted to the repositories explicitly allowlisted by Core.

See [Specialist Orchestrator](specialist-orchestrator.md) for routing,
OpenCodex model snapshots, profile provenance, approval, and recovery behavior.

## Enterprise security commands

```bash
secopsai enterprise status --json
secopsai enterprise ingest --source aws.cloudtrail --input fixture.json --json
secopsai enterprise kubernetes-scan --path deployment.yaml --json
secopsai enterprise dast-validate --target-id web-1 --url https://app.example --owner security --authorized-by change-123 --json
secopsai enterprise prioritize-vulnerability --input vulnerability.json --json
```

Enterprise commands use bounded, redacted, organization-scoped records. Cloud
and active-scan actions are read-only or approval-gated by design.

## OSS artifact fleet commands

```bash
secopsai artifact-fleet index --since 24h --limit 1000 --json
secopsai artifact-fleet status --json
secopsai artifact-fleet source-health --json
secopsai artifact-fleet scan --since 24h --workers 8 --json
secopsai artifact-fleet triage --limit 500 --json
secopsai artifact-fleet triage --limit 500 --enqueue-model --model xai/grok-4.6 --json
secopsai artifact-fleet analyst-queue --limit 100 --json
secopsai artifact-fleet metrics --json
secopsai artifact-fleet benchmark --artifacts 1000 --workers 4 --fixture-mode --json
secopsai artifact-fleet cycle --since 24h --limit 1000 --workers 4 --json
```

The fleet indexes metadata first, scans only authorized artifacts, sends only
rule-hit context to model triage, and leaves suspicious or inconclusive work
for analyst review.

## Rust package research

```bash
secopsai research rust-package --package proc-macro1 --version 1.0.107 --dry-run --json
secopsai research rust-package --package proc-macro1 --version 1.0.107 --compare-package proc-macro2 --compare-version 1.0.107 --persist-findings --json
```

The Rust workflow verifies crates.io metadata and checksum, quarantines the
exact crate, performs static-only analysis, and optionally creates a Research
Case and review-only draft.

## Triage commands

### `secopsai triage list`

List findings from the SOC store by triage status.

```bash
secopsai triage list --status open --limit 20
secopsai triage list --status in_review --json
```

Options:

- `--status open|in_review|closed|triaged`
- `--limit <n>` — default `50`
- `--json`

### `secopsai triage start <finding_id>`

Mark a finding as actively under analyst review.

```bash
secopsai triage start SCM-XXXX --note "Initial analyst review started"
```

Options:

- `--note <text>` — analyst note stored with the finding
- `--json`

### `secopsai triage investigate <finding_id>`

Gather evidence, classify the finding type, and write case files.

```bash
secopsai triage investigate SCM-XXXX --search-root ~/secopsai --json
```

Options:

- `--search-root <path>` — where local dependency or repo references are checked
- `--json`

Writes:

- `reports/triage/<finding_id>.json`
- `reports/triage/<finding_id>.md`

### `secopsai triage close <finding_id>`

Close or disposition a finding with a required note.

```bash
secopsai triage close SCM-XXXX --disposition false_positive --note "Verified safe internal package."
```

Options:

- `--disposition true_positive|false_positive|expected_behavior|accepted_risk|exception_granted|needs_review|tune_policy|remediated`
- `--note <text>` — required analyst rationale
- `--json`

### `secopsai triage orchestrate`

Run the guarded triage orchestrator across open findings.

```bash
secopsai triage orchestrate --search-root ~/secopsai
secopsai triage orchestrate --limit 10 --json
```

Options:

- `--search-root <path>` — repository root for dependency presence checks
- `--limit <n>` — maximum findings to process
- `--queue-file <path>` — override queue path
- `--json`

Behavior:

- auto-starts findings into `in_review`
- auto-investigates findings
- auto-closes low-risk `expected_behavior` and allowlisted false positives
- queues higher-risk actions for analyst application

### `secopsai triage queue`

Show queued orchestrator actions awaiting analyst application.

```bash
secopsai triage queue
secopsai triage queue --json
```

Options:

- `--queue-file <path>` — override queue path
- `--json`

### `secopsai triage apply-action <action_id>`

Apply one queued action after analyst review.

```bash
secopsai triage apply-action ACT-0001 --yes
```

Options:

- `--queue-file <path>` — override queue path
- `--yes` — skip interactive confirmation
- `--json`

### `secopsai triage summary`

Generate a compact summary of current triage and queue state.

```bash
secopsai triage summary
secopsai triage summary --json
```

Options:

- `--limit <n>` — how many recent summary entries to include
- `--queue-file <path>` — override queue path
- `--json`

### `secopsai refresh`

Run the full OpenClaw live pipeline by default, or collect from selected platform adapters such as Hermes, macOS, Linux, and Windows.

```bash
secopsai refresh
secopsai refresh --json
secopsai refresh --skip-export
secopsai refresh --platform hermes
secopsai refresh --platform macos,openclaw,hermes
```

Options:

- `--skip-export` — reuse existing exported OpenClaw native telemetry
- `--openclaw-home <path>` — override `OPENCLAW_HOME`
- `--platform <list>` — comma-separated adapter list, for example `hermes`, `macos,openclaw`, or `macos,openclaw,hermes`
- `--verbose` — verbose refresh output
- `--json` — machine-friendly output

Returns:

- whether export ran
- output paths for audit/replay/findings
- total findings
- total detections

---

### `secopsai list`

List findings from the local SOC store.

```bash
secopsai list
secopsai list --severity high
secopsai list --limit 20 --json
```

Options:

- `--severity info|low|medium|high|critical`
- `--limit <n>` — default `50`
- `--no-refresh` — do not auto-refresh before listing
- `--cache-ttl <seconds>` — default `60`; minimum time between auto-refresh runs
- `--openclaw-home <path>`
- `--json`

Notes:

- By default, `list` may auto-refresh the pipeline first.
- Use `--no-refresh` to work only from what is already stored locally.

---

### `secopsai show <finding_id>`

Show one finding in detail.

```bash
secopsai show OCF-XXXX
secopsai show OCF-XXXX --json
```

Options:

- `--no-refresh`
- `--cache-ttl <seconds>`
- `--openclaw-home <path>`
- `--json`

---

### `secopsai mitigate <finding_id>`

Show recommended mitigation actions for a finding.

```bash
secopsai mitigate OCF-XXXX
secopsai mitigate OCF-XXXX --json
```

Options:

- `--no-refresh`
- `--cache-ttl <seconds>`
- `--openclaw-home <path>`
- `--json`

---

### `secopsai check --type malware|exfil|both`

Run a quick presence check against existing findings.

```bash
secopsai check --type malware
secopsai check --type exfil --severity medium --json
secopsai check --type both --no-refresh
```

Options:

- `--type malware|exfil|both` — required
- `--severity info|low|medium|high|critical` — default `low`
- `--no-refresh`
- `--cache-ttl <seconds>`
- `--openclaw-home <path>`
- `--json`

---

## Threat intelligence commands

### `secopsai intel refresh`

Download and normalize open-source IOC feeds into local storage.

```bash
secopsai intel refresh
secopsai intel refresh --json
secopsai intel refresh --enrich
```

Options:

- `--timeout <seconds>` — default `20`
- `--enrich` — perform lightweight local enrichment (DNS)
- `--json`

---

### `secopsai intel list`

List locally stored IOCs.

```bash
secopsai intel list
secopsai intel list --limit 20 --json
```

Options:

- `--limit <n>` — default `50`
- `--json`

---

### `secopsai intel match`

Match stored IOCs against the latest OpenClaw replay and persist matches as findings.

```bash
secopsai intel match
secopsai intel match --limit-iocs 500 --json
secopsai intel match --replay data/openclaw/replay/labeled/current.json
```

Options:

- `--limit-iocs <n>` — default `2000`
- `--replay <path>` — override replay file
- `--json`

---

## AI Dependency Guard

### `secopsai supply-chain ai-dependency-guard`

Scan AI-built code and optional AI-agent telemetry for hallucinated,
newly-registered, or lookalike dependencies.

```bash
secopsai supply-chain ai-dependency-guard --path . --json
secopsai supply-chain ai-dependency-guard --path . --include-agent-logs --agent-source auto --json
secopsai supply-chain ai-dependency-guard --path . --fail-on high --json
```

Options:

- `--path <path>` — repository or file to scan
- `--include-agent-logs` — include local OpenClaw/Hermes/session telemetry
- `--agent-source auto|openclaw|hermes|sessions`
- `--ecosystem <name>` — repeatable ecosystem filter
- `--fail-on high|critical` — opt-in CI failure threshold
- `--persist-findings` — persist high-confidence findings to the local SOC store
- `--report-path <path>` — write the full JSON report

The command reads registry metadata only and does not install, import, or
execute package code.

---

## Supply-chain policy commands

### `secopsai supply-chain allowlist add|remove`

Manage package allowlist entries in the active policy file.

```bash
secopsai supply-chain allowlist add --ecosystem pypi --package textual
secopsai supply-chain allowlist remove --ecosystem pypi --package textual
```

Options:

- `--ecosystem pypi|npm`
- `--package <name-or-wildcard>`

### `secopsai supply-chain tune rule`

Change a rule weight or enabled state.

```bash
secopsai supply-chain tune rule "wheel/sdist artifact divergence" --weight 1
secopsai supply-chain tune rule "manifest executable entrypoints" --disable
```

Options:

- `<rule_name>` — exact rule name
- `--weight <n>`
- `--disable`
- `--enable`

### `secopsai supply-chain tune threshold`

Set a global, ecosystem, or package threshold.

```bash
secopsai supply-chain tune threshold --global-threshold --value 12
secopsai supply-chain tune threshold --ecosystem pypi --value 12
secopsai supply-chain tune threshold --package textual --package-ecosystem pypi --value 14
```

Options:

- `--global-threshold`
- `--ecosystem pypi|npm`
- `--package <name>`
- `--package-ecosystem pypi|npm`
- `--value <n>`

---

## Auto-refresh behavior

These commands can auto-refresh the pipeline before reading findings:

- `list`
- `show`
- `mitigate`
- `check`

Behavior:

- If a recent refresh exists inside the TTL window, secopsai reuses cached results.
- Default TTL is `60` seconds.
- Use `--cache-ttl <seconds>` to change the window.
- Use `--no-refresh` to disable auto-refresh entirely.

Example:

```bash
secopsai list --severity high --cache-ttl 300
secopsai show OCF-XXXX --no-refresh
```

## Common command patterns

### Run the pipeline and inspect findings

```bash
secopsai refresh --json
secopsai list --severity high --json
```

### Reuse recent results for 5 minutes

```bash
secopsai list --severity high --cache-ttl 300
```

### Inspect and mitigate a finding

```bash
secopsai show OCF-XXXX --json
secopsai mitigate OCF-XXXX --json
```

### Threat intel workflow

```bash
secopsai intel refresh --json
secopsai intel match --limit-iocs 500 --json
secopsai list --severity medium --json --no-refresh
```

### Native triage workflow

```bash
secopsai triage list --status open
secopsai triage investigate SCM-XXXX --search-root ~/secopsai --json
secopsai triage orchestrate --search-root ~/secopsai
secopsai triage queue
secopsai triage apply-action ACT-0001 --yes
```

## Installer/runtime notes

- Recommended installation path:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

### `secopsai hermes`

Install the complete Hermes Agent integration with:

```bash
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

Inspect and refresh the integration:

```bash
secopsai hermes doctor
secopsai hermes refresh
secopsai hermes service status
secopsai hermes service run-now
secopsai hermes service logs
```

Service lifecycle actions are `install`, `start`, `stop`, `status`, `run-now`, `logs`, and `uninstall`. Installation accepts `--interval`, `--hermes-home`, `--db-path`, and `--no-start`. The minimum interval is 60 seconds and the default is 300 seconds.

- Public npm OpenClaw plugin:

```bash
openclaw plugins install secopsai
```

- The Core installer creates a virtualenv and installs the `secopsai` CLI into it.
- The packaged install includes the runtime helper modules required by the CLI entrypoint.

## Related docs

- [Getting Started](getting-started.md)
- [Threat Intel (IOCs)](threat-intel.md)
- [Findings Triage Guide](findings-triage-guide.md)
- [Triage Orchestrator](triage-orchestrator.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Hermes Agent Integration](Hermes-Integration.md)
- [Threat Model](threat-model.md)
