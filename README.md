# SecOpsAI v2.0 - Local-First Security Operations

[![Version](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com/Techris93/secopsai)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **Local-first detection, investigation, and triage orchestration for OpenClaw, macOS, Linux, and Windows.**

SecOpsAI is a local-first security monitoring, investigation, and triage platform. It ingests OpenClaw audit telemetry and host OS security events, normalizes them into a unified schema, persists findings in a local SOC store, and now includes a native triage engine with queued analyst actions and supply-chain policy controls.

## What SecOpsAI does

- Collects telemetry from **OpenClaw**, **macOS**, **Linux**, and **Windows**
- Normalizes events into a **unified schema** for shared detection logic
- Detects suspicious behavior and stores findings in a local **SQLite SOC store**
- Correlates findings across platforms by **IP**, **user**, **time window**, and **file hash**
- Investigates and triages findings through a native **CLI workflow** and **triage orchestrator**
- Supports supply-chain policy management with **allowlists**, **rule tuning**, and **threshold tuning**
- Keeps data **local-first by default**

## Platform Support

| Platform | Source | Status | Notes |
|---|---|---:|---|
| OpenClaw | Audit logs | ✅ Production | Native telemetry source |
| macOS | Unified logging | ✅ Production | Auth, process, and host activity |
| Linux | journalctl / auditd | ✅ Beta | Ready for Linux deployment |
| Windows | Event Logs / Sysmon | ✅ Beta | Ready for Windows deployment |

## Cross-Platform Correlation

SecOpsAI can detect multi-system patterns that are hard to catch from a single log source alone:

- Same IP seen across multiple platforms → possible lateral movement
- Same user active across systems → possible credential abuse
- Time-clustered findings → coordinated attacker activity
- Same file hash across hosts → possible malware propagation

## Quick Start

### Install

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

Security note: only run a `curl | bash` installer if you trust the publisher and the source code. If you prefer a safer path, clone the repo and inspect `docs/install.sh` + `setup.sh` before running.

### Activate

```bash
cd ~/secopsai
source .venv/bin/activate
```

### Run detection

```bash
# OpenClaw-first refresh path
secopsai refresh

# Cross-platform adapter refresh
secopsai refresh --platform macos,openclaw

# Live streaming from a platform adapter
secopsai live --platform macos --duration 60

# Cross-platform correlation
secopsai correlate
```

### Review findings

```bash
secopsai list --severity high
secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
secopsai triage list --status open
secopsai triage investigate SCM-XXXX
secopsai triage close SCM-XXXX --disposition false_positive --note "Verified safe internal package"
secopsai triage orchestrate --search-root ~/secopsai
secopsai triage queue
```

## Operator Surfaces

### 1. CLI

The packaged `secopsai` CLI is now the single operator surface for both the OpenClaw pipeline and the cross-platform adapter workflow:

```bash
# OpenClaw and host pipeline
secopsai refresh
secopsai list --severity high
secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
secopsai triage investigate OCF-XXXX
secopsai triage close OCF-XXXX --disposition needs_review --note "Escalated to analyst"
secopsai triage orchestrate --search-root ~/secopsai
secopsai triage queue
secopsai triage apply-action ACT-0001 --yes
secopsai triage summary
secopsai intel refresh

# Cross-platform adapter workflow
secopsai refresh --platform macos
secopsai refresh --platform macos,openclaw
secopsai live --platform macos
secopsai correlate
```

For repo-local development you can still run the wrapper directly:

```bash
python3 cli.py refresh --platform macos,openclaw
python3 cli.py correlate
```

### 2. OpenClaw Native Plugin

Install SecOpsAI directly as an OpenClaw plugin for seamless integration:

```bash
openclaw plugins install secopsai
```

Available plugin tools:

| Tool | Description |
|------|-------------|
| `secopsai_list_findings` | List findings with optional severity filter |
| `secopsai_refresh` | Run the detection pipeline to refresh findings |
| `secopsai_show_finding` | Get detailed information about a specific finding |
| `secopsai_triage` | Set disposition, status, and add analyst notes |
| `secopsai_check_threats` | Check for malware or exfiltration indicators |
| `secopsai_mitigate` | Get recommended mitigation steps for a finding |
| `secopsai_search` | Search findings by keyword or pattern |
| `secopsai_stats` | Get statistics about the SOC database |

See [docs/OpenClaw-Integration.md](docs/OpenClaw-Integration.md) for detailed usage.

### 3. Optional Notification Workflows

When correlations or notable findings are detected, SecOpsAI can send notification workflows through the enabled local surfaces.

Current built-in operator flow is CLI-first. External chat or plugin surfaces remain optional.

## Architecture

```text
OpenClaw + Host Adapters -> Unified Schema -> Detection Engine -> Correlation Engine -> SQLite SOC Store
                                                           -> Native Triage Engine -> Action Queue / Policy Controls
                                                           -> CLI / Plugin / Notifications
```

Core layers:

- **Data adapters**: OpenClaw, macOS, Linux, Windows
- **Normalization**: unified event schema for shared logic
- **Detection**: rules and findings generation
- **Correlation**: IP/user/time/hash correlation across platforms
- **Triage**: investigation, case-file generation, dispositions, queueable actions
- **Operator surfaces**: CLI-first, plugin optional, notifications optional

## Threat Intelligence (IOC) pipeline

SecOpsAI also includes a local-first threat intel pipeline:

- Downloads open-source IOC feeds (URLhaus + ThreatFox)
- Normalizes + de-duplicates indicators
- Optional lightweight enrichment (DNS)
- Matches IOCs against replay events
- Persists matches into the local SOC store

Examples:

```bash
secopsai intel refresh --json
secopsai intel refresh --enrich
secopsai intel list --limit 20
secopsai intel match --limit-iocs 500 --json
```

## Supply Chain Monitoring

SecOpsAI includes a native supply-chain monitor for package-release review across
PyPI and npm. It polls the registries directly, diffs new releases against the
previous version, applies deterministic compromise rules, and can optionally use
an external `agent` model review as a second pass.

Slack configuration lives at `config/slack.json` by default.
Supply-chain policy overrides live at `config/supply_chain_policy.toml` by default.

Examples:

```bash
# Review one specific release
secopsai supply-chain scan --ecosystem pypi --package requests --version 2.32.0

# Review recent releases in the top watchlists
secopsai supply-chain once --top 1000 --lookback 600

# Continuous monitoring with Slack alerts
secopsai supply-chain monitor --slack --interval 300 --top 1000

# Show recent package scan history
secopsai supply-chain list --limit 20

# Explain policy and verdict details
secopsai supply-chain explain-policy --ecosystem pypi --package requests
secopsai supply-chain explain-verdict --ecosystem pypi --package requests --report /path/to/report.md

# Manage false-positive relief
secopsai supply-chain allowlist add --ecosystem pypi --package textual
secopsai supply-chain tune rule "wheel/sdist artifact divergence" --weight 1
secopsai supply-chain tune threshold --ecosystem pypi --value 12
```

OpenClaw/host monitoring can also send Slack alerts for new high-severity findings:

```bash
python run_openclaw_live.py --slack
bash scripts/install_openclaw_launchd.sh
```

You can tune supply-chain scoring and package exceptions by copying:

```bash
cp config/supply_chain_policy.example.toml config/supply_chain_policy.toml
```

The policy file supports:

- `thresholds.malicious_score`
- `ecosystem_thresholds.pypi` / `ecosystem_thresholds.npm`
- `package_thresholds."ecosystem:package"` or wildcard suffix entries
- `allow.packages`
- `deny.packages`
- `[rules]` toggles keyed by rule name
- `[rule_weights]` numeric overrides keyed by rule name

## Native Triage

SecOpsAI now includes a native analyst triage workflow that keeps findings,
investigation notes, and closure state inside the local SOC store.

Examples:

```bash
# Review open findings ready for triage
secopsai triage list --status open --limit 20

# Start a triage session on a finding
secopsai triage start SCM-XXXX --note "Initial analyst review started"

# Gather evidence and write triage case files
secopsai triage investigate SCM-XXXX --json

# Close a finding with a required analyst note
secopsai triage close SCM-XXXX --disposition false_positive --note "Verified safe internal package"

# Run the native orchestrator across open findings
secopsai triage orchestrate --search-root ~/secopsai

# Review queued analyst actions and apply one
secopsai triage queue
secopsai triage apply-action ACT-0001 --yes

# Generate a compact triage summary
secopsai triage summary
```

Each investigation writes:

- `reports/triage/<finding_id>.json`
- `reports/triage/<finding_id>.md`

The orchestrator only auto-applies low-risk actions by default:

- auto-start `in_review`
- auto-close `expected_behavior`
- auto-close already-allowlisted false positives

Higher-risk actions stay queued for analyst approval and application:

- allowlist changes
- rule tuning
- threshold tuning
- escalation closures such as `needs_review` or `tune_policy`

## Background Monitoring

Example operational model:

- scheduled refresh every 5 minutes
- local findings persistence
- cross-platform correlation pass
- optional notification workflows on notable findings
- optional scheduled triage orchestration via launchd/systemd helpers

On macOS, launchd-based execution is supported via helper scripts, including:

- `scripts/install_openclaw_launchd.sh`
- `scripts/install_supply_chain_launchd.sh`
- `scripts/install_triage_orchestrator_launchd.sh`

## Documentation

- [Docs site](https://docs.secopsai.dev)
- [Getting Started](docs/getting-started.md)
- [Universal Adapters](docs/universal-adapters.md)
- [Rules Registry](docs/rules-registry.md)
- [Deployment Guide](docs/deployment-guide.md)
- [API Reference](docs/api-reference.md)
- [Findings Triage Guide](docs/findings-triage-guide.md)
- [Triage Orchestrator](docs/triage-orchestrator.md)
- [Threat Intel](docs/threat-intel.md)
- [Threat Model](docs/threat-model.md)
- [Beginner Live Guide](docs/BEGINNER-LIVE-GUIDE.md)
- [OpenClaw Integration](docs/OpenClaw-Integration.md)

## Current state

What is implemented now:

- ✅ Base adapter abstraction and registry
- ✅ OpenClaw adapter
- ✅ macOS adapter
- ✅ Linux adapter
- ✅ Windows adapter
- ✅ Unified event schema
- ✅ CLI `--platform` support in universal adapter flow
- ✅ Cross-platform correlation engine
- ✅ Background monitoring / scheduled operation
- ✅ Native analyst triage workflow
- ✅ Supply-chain allowlist and tuning controls
- ✅ Native triage orchestrator with queued actions

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT (see [LICENSE](LICENSE)).
