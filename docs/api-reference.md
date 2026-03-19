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

## Command overview

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

## Installer/runtime notes

- Recommended installation path:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

- The installer creates a virtualenv and installs the `secopsai` CLI into it.
- The packaged install includes the runtime helper modules required by the CLI entrypoint.

## Related docs

- [Getting Started](getting-started.md)
- [Threat Intel (IOCs)](threat-intel.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Threat Model](threat-model.md)
