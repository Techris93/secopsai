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
- uses: Techris93/secopsai-action@v1
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

Distribution and Marketplace maintenance details live in
[GitHub Distribution](github-distribution-plan.md) and
[GitHub Marketplace](github-marketplace.md).

## Command overview

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

Run the full OpenClaw live pipeline and persist findings into the local SOC store.

```bash
secopsai refresh
secopsai refresh --json
secopsai refresh --skip-export
```

Options:

- `--skip-export` — reuse existing exported OpenClaw native telemetry
- `--openclaw-home <path>` — override `OPENCLAW_HOME`
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

- Public npm package:

```bash
npm install -g secopsai
```

- The installer creates a virtualenv and installs the `secopsai` CLI into it.
- The packaged install includes the runtime helper modules required by the CLI entrypoint.

## Related docs

- [Getting Started](getting-started.md)
- [Threat Intel (IOCs)](threat-intel.md)
- [Findings Triage Guide](findings-triage-guide.md)
- [Triage Orchestrator](triage-orchestrator.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Threat Model](threat-model.md)
