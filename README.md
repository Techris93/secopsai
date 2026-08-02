# SecOpsAI v1.0.0 - Local-First Security Operations

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/Techris93/secopsai/releases/tag/v1.0.0)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **Local-first detection, investigation, network discovery, and triage orchestration for OpenClaw, Hermes Agent, macOS, Linux, Windows, and SecOpsAI Edge.**

SecOpsAI is a local-first security monitoring, investigation, and triage platform. It ingests OpenClaw audit telemetry, Hermes Agent telemetry, and host OS security events, normalizes them into a unified schema, persists findings in a local SOC store, and now includes a native triage engine with queued analyst actions and supply-chain policy controls.

## What SecOpsAI does

- Collects telemetry from **OpenClaw**, **Hermes Agent**, **macOS**, **Linux**, and **Windows**
- Imports normalized SecOpsAI Edge asset graphs and network-origin findings without importing raw scan logs
- Serves a protected Core ingestion/read API with separate Edge and operator credentials
- Normalizes events into a **unified schema** for shared detection logic
- Detects suspicious behavior and stores findings in a local **SQLite SOC store**
- Correlates findings across platforms by **IP**, **user**, **time window**, and **file hash**
- Investigates and triages findings through a native **CLI workflow** and **triage orchestrator**
- Adds an **Adaptive Response Layer** for threat memory, confidence scoring, weak-signal routing, time-aware anomaly detection, safe validation, and containment recommendations
- Provides a local **agent runtime** for tool routing, context compaction, loop detection, and isolated jobs
- Supports supply-chain policy management with **allowlists**, **rule tuning**, and **threshold tuning**
- Scans AI-built code and local agent telemetry for **slopsquatted / hallucinated dependencies**
- Keeps data **local-first by default**

## Platform Support

| Platform | Source              |        Status | Notes                            |
| -------- | ------------------- | ------------: | -------------------------------- |
| OpenClaw | Audit logs          | ✅ Production | Native telemetry source          |
| Hermes   | Agent/session/tool logs | ✅ Beta | Read-only Hermes Agent telemetry |
| macOS    | Unified logging     | ✅ Production | Auth, process, and host activity |
| Linux    | journalctl / auditd |       ✅ Beta | Ready for Linux deployment       |
| Windows  | Event Logs / Sysmon |       ✅ Beta | Ready for Windows deployment     |
| SecOpsAI Edge | LAN discovery / Wi-Fi inventory | ✅ Pilot | Separate sensor module with versioned Core sync |

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

For Hermes Agent 0.18.2 or later, install Core, the native read-only plugin, and the persistent monitor together:

```bash
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

Security note: only run a `curl | bash` installer if you trust the publisher and the source code. If you prefer a safer path, clone the repo and inspect `docs/install.sh` + `setup.sh` before running.

### GitHub Distribution

SecOpsAI's public npm package name is `secopsai`, so npm users can install the
CLI wrapper with the clean unscoped name:

```bash
npm install -g secopsai
```

The next prepared npm wrapper release is `secopsai@1.0.1`; publishing still
requires an authorized npm maintainer and must not be run from an untrusted
machine. See [docs/npm-name-migration.md](docs/npm-name-migration.md).

SecOpsAI is also published through GitHub Packages for GitHub-native installs,
where GitHub's npm registry keeps the package scoped:

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

The GitHub Packages workflow publishes the scoped package `@techris93/secopsai`
from the existing `supply-chain/` npm manifest without renaming the public npm
package. See
[docs/github-distribution-plan.md](docs/github-distribution-plan.md).

For GitHub Marketplace, SecOpsAI is published as **SecOpsAI Supply-Chain
Guard** from the dedicated public action repository
[`Techris93/secopsai-action`](https://github.com/Techris93/secopsai-action).
The action can run advisory checks, package scans, campaign discovery, and
triage summaries in GitHub Actions:

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

The source wrapper remains mirrored in [`marketplace/github-action`](marketplace/github-action).
See
[docs/github-marketplace.md](docs/github-marketplace.md).

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
secopsai refresh --platform macos,openclaw,hermes

# Live streaming from a platform adapter
secopsai live --platform hermes --duration 60

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
secopsai --json triage summary
```

### Adaptive Response Layer

Use the Adaptive Response Layer when you want stored findings to produce risk scoring, response guidance, and durable decision memory:

```bash
# Analyze stored findings and print response posture, top adaptive scores, and safe probes
secopsai adaptive-response

# Persist decaying threat memory and confidence trails for future runs
secopsai --json adaptive-response --persist-memory
```

What it implements:

- **Baseline detection**: severity, policy, and known-rule scoring
- **Adaptive memory**: decaying confidence trails for repeated finding traits
- **Signal routing**: weak-signal clustering across users, hosts, packages, rules, sessions, and sources
- **Triage coordination**: simple local rules that align analyst action
- **Adversarial simulation**: red-team/blue-team prompts for attacker adaptation
- **Layered defense**: blast containment, access tightening, logging escalation, and repair notes
- **Time-aware detection**: off-hours and weekend anomaly sensitivity
- **Priority routing**: attention allocation to the highest-risk shared roots
- **Validation probes**: safe active checks for suspicious entities
- **Deception controls**: honeypot, canary, and decoy recommendations

## Operator Surfaces

### 1. CLI

The packaged `secopsai` CLI is now the single operator surface for both the OpenClaw pipeline and the cross-platform adapter workflow:

```bash
# OpenClaw, Hermes, and host pipeline
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
secopsai adaptive-response --persist-memory
secopsai agent route --task "investigate this supply-chain finding with sources"
secopsai agent compact SES-1234567890ab --json
secopsai agent run-job --name docs-qa -- python scripts/docs_source_agent.py --build

# Cross-platform adapter workflow
secopsai refresh --platform macos
secopsai refresh --platform macos,openclaw,hermes
secopsai refresh --platform hermes
secopsai live --platform macos
secopsai correlate
```

For repo-local development you can still run the wrapper directly:

```bash
python3 cli.py refresh --platform macos,openclaw,hermes
python3 cli.py correlate
```

### 2. OpenClaw Native Plugin

Install SecOpsAI directly as an OpenClaw plugin for seamless integration:

```bash
openclaw plugins install secopsai
```

If your OpenClaw registry still requires the scoped alias during migration, use
`openclaw plugins install clawhub:@techris93/secopsai`.

Available plugin tools:

| Tool family | Examples |
| ----------- | -------- |
| Read-only research | `secopsai_investigate_finding`, `secopsai_investigate_with_sources`, `secopsai_research_finding`, `secopsai_review_release_with_sources` |
| Session state | `secopsai_session_list`, `secopsai_session_show` |
| Guarded writes | `secopsai_session_request_close_approval`, `secopsai_session_request_action_approval`, `secopsai_session_resolve_approval`, `secopsai_triage_apply_action`, `secopsai_close_finding` |

Use the plugin in the same order as the CLI:

1. investigate or research first
2. keep the evidence in a session
3. request approval for risky close or action changes
4. resolve and apply the approved change

See [docs/OpenClaw-Plugin.md](docs/OpenClaw-Plugin.md) for the current tool surface and [docs/OpenClaw-Integration.md](docs/OpenClaw-Integration.md) for the Python CLI workflow.

### 3. Hermes Agent Integration

Install the complete Hermes integration:

```bash
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

The installer verifies Hermes 0.18.2+, installs and enables the native plugin, performs one bounded read-only telemetry collection, and starts the five-minute user-level monitor.

```bash
secopsai hermes doctor
secopsai hermes service status
secopsai list --platform hermes --no-refresh
```

The plugin exposes read-only integration health, normalized findings, investigation sessions, triage counts, and Edge asset summaries. It cannot run arbitrary commands, refresh telemetry, scan networks, close findings, disclose research, or publish content.

See [docs/Hermes-Integration.md](docs/Hermes-Integration.md) for data boundaries, tools, service controls, recovery, and uninstall.

### 4. Optional Notification Workflows

When correlations or notable findings are detected, SecOpsAI can send notification workflows through the enabled local surfaces.

Current built-in operator flow is CLI-first. External chat or plugin surfaces remain optional.

## Architecture

```text
OpenClaw + Hermes + Host Adapters -> Unified Schema -> Detection Engine -> Correlation Engine -> SQLite SOC Store
                                                            -> Native Triage Engine -> Action Queue / Policy Controls
                                                            -> CLI / OpenClaw Plugin / Hermes Plugin / Notifications
```

Core layers:

- **Data adapters**: OpenClaw, Hermes Agent, macOS, Linux, Windows
- **Normalization**: unified event schema for shared logic
- **Detection**: rules and findings generation
- **Correlation**: IP/user/time/hash correlation across platforms
- **Adaptive response**: threat memory, confidence trails, weak-signal routing, timing-aware anomaly scoring, safe probes, and deception recommendations
- **Triage**: investigation, case-file generation, dispositions, queueable actions
- **Operator surfaces**: CLI-first, plugin optional, notifications optional

## Evaluation

SecOpsAI currently ships two evaluation paths with different purposes:

- `python evaluate.py` is the canonical detector benchmark used by regression tests, tuning work, and adaptive score tracking.
- `python -m eval.harness.runner` is the broader v2 evaluation harness for scenario-oriented gates and report generation.

Examples:

```bash
# Canonical detector benchmark
python evaluate.py
python evaluate.py --verbose

# Scenario/performance harness
./scripts/run_eval_harness.sh --full
./scripts/run_eval_harness.sh --category openclaw
```

Recommendation: use `evaluate.py` when modifying `detect.py` or tracking benchmark changes. Treat `eval.harness.runner` as a supplementary scenario/performance harness, not the primary tuning path.

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

# Scan AI-built code for hallucinated, newly registered, or lookalike dependencies
secopsai supply-chain ai-dependency-guard --path . --include-agent-logs --json

# Explain policy and verdict details
secopsai supply-chain explain-policy --ecosystem pypi --package requests
secopsai supply-chain explain-verdict --ecosystem pypi --package requests --report /path/to/report.md

# Manage false-positive relief
secopsai supply-chain allowlist add --ecosystem pypi --package textual
secopsai supply-chain tune rule "wheel/sdist artifact divergence" --weight 1
secopsai supply-chain tune threshold --ecosystem pypi --value 12
```

OpenClaw/Hermes/host monitoring can also send Slack alerts for new high-severity findings:

```bash
python run_openclaw_live.py --slack
bash scripts/install_openclaw_launchd.sh
bash scripts/install_triage_summary_launchd.sh
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

SecOpsAI can continuously review canonical host, Edge, supply-chain, and registry-research alerts with a selected local OpenCodex model. Mission Control supports `off`, advisory, and guarded automation modes. Guarded mode requires deterministic corroboration before reversible false-positive closure, records the complete model decision and evidence references, supports rollback, and places rule tuning in shadow replay before any activation. Operational collector failures use deterministic recovery checks rather than model verdicts. Final publication, external disclosure, sandbox submission, and destructive response remain separately controlled. See [Intelligence integrations](docs/intelligence-integrations.md#autonomous-finding-and-alert-triage).

SecOpsAI now includes a native analyst triage workflow that keeps findings,
investigation notes, and closure state inside the local SOC store.

The coordinated daily workflow can run the operational sequence without manual
terminal work: registry surveillance, deterministic candidate promotion,
alert-feedback capture, model-review queueing, evidence investigations,
guarded learning, and operational alert delivery. Configure it from Mission
Control under **Administration → Automation → Daily workflow automation**, or
use the Core CLI:

```bash
secopsai intelligence autopilot daily status
secopsai intelligence autopilot daily configure --enabled on --interval-seconds 86400
secopsai intelligence autopilot daily run
```

Each cycle records per-step results and continues after a recoverable failure.
Agents cannot submit sandbox artifacts, send disclosure, publish research, or
activate unverified detector changes.

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

## Guarded Research Autonomy

The Local Codex/OpenCodex bridge can complete repeatable research review work with the selected Kimi, Grok, Gemini, or Codex model. In `agent_review` mode it accepts bounded pipeline proposals, records an evidence-linked verdict, and reruns publication safety automatically:

```bash
secopsai intelligence bridge service install --autonomy-mode agent_review
```

Core guardrails prevent local dependency absence from becoming a benign verdict, constrain verdict evidence to the active pipeline, and reduce conclusions that lack sufficient confidence or proof. Package execution, external sandbox submission, disclosure delivery, customer-control changes, and final publication remain human-approved actions. See [Research Automation](docs/research-automation.md).

Research cases can also turn reviewed evidence into guarded detection proposals:

```bash
secopsai research rule propose RSC-...
secopsai research rule list RSC-...
```

Mission Control presents each structurally validated YARA, Sigma, or Semgrep
proposal with its evidence and limitations. Activation is a separate audited
decision; legitimate reference artifacts and low-confidence indicators are
never converted into detections automatically.

## Background Monitoring

Example operational model:

- scheduled refresh every 5 minutes
- local findings persistence
- cross-platform correlation pass
- optional notification workflows on notable findings
- optional scheduled triage orchestration via launchd/systemd helpers

On macOS, launchd-based execution is supported via helper scripts, including:

- `secopsai hermes service install`
- `scripts/install_openclaw_launchd.sh`
- `scripts/install_supply_chain_launchd.sh`
- `scripts/install_triage_orchestrator_launchd.sh`

The hosted registry-surveillance worker also enforces bounded storage
retention before each collection cycle. Inspect capacity or perform a guarded
recovery with:

```bash
secopsai research storage status --json
secopsai research storage maintain --aggressive --json
```

These commands preserve pending events, candidates, research cases, evidence,
IOCs, rules, and active alerts. See
[Research Discovery](docs/research-discovery.md#storage-capacity-and-recovery)
for the Render disk-pressure runbook and retention boundaries.

## Documentation

- [Docs site](https://docs.secopsai.dev)
- [Getting Started](docs/getting-started.md)
- [Core API and hosted Edge ingestion](docs/core-api.md)
- [Local Codex bridge and ChatGPT app](docs/intelligence-integrations.md)
- [Universal Adapters](docs/universal-adapters.md)
- [Rules Registry](docs/rules-registry.md)
- [Deployment Guide](docs/deployment-guide.md)

The hosted Core API has its own root Render Blueprint at
[`render.yaml`](render.yaml). It is intentionally separate from the existing
SecOpsAI worker service because the Core API owns the canonical Edge graph and
triage read boundary. Follow [`docs/core-api.md`](docs/core-api.md) to create
the Blueprint, configure its two unrelated secrets, and run the secret-safe
`./scripts/core-api hosted-check` before connecting the dashboard.
- [API Reference](docs/api-reference.md)
- [AI Dependency Guard](docs/ai-dependency-guard.md)
- [Findings Triage Guide](docs/findings-triage-guide.md)
- [Research Automation](docs/research-automation.md)
- [Triage Orchestrator](docs/triage-orchestrator.md)
- [Threat Intel](docs/threat-intel.md)
- [Threat Model](docs/threat-model.md)
- [Beginner Live Guide](docs/BEGINNER-LIVE-GUIDE.md)
- [OpenClaw Integration](docs/OpenClaw-Integration.md)
- [Hermes Integration](docs/Hermes-Integration.md)

## Current state

What is implemented now:

- ✅ Base adapter abstraction and registry
- ✅ OpenClaw adapter
- ✅ Hermes Agent adapter
- ✅ macOS adapter
- ✅ Linux adapter
- ✅ Windows adapter
- ✅ Unified event schema
- ✅ CLI `--platform` support in universal adapter flow
- ✅ Cross-platform correlation engine
- ✅ Adaptive Response Layer with response posture, confidence memory, safe probes, and deception recommendations
- ✅ Background monitoring / scheduled operation
- ✅ Native analyst triage workflow
- ✅ Supply-chain allowlist and tuning controls
- ✅ Native triage orchestrator with queued actions

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT (see [LICENSE](LICENSE)).
