# Getting Started with SecOpsAI

This guide takes you from install to your first triaged finding in about five minutes.

## What You'll Learn

- How to install SecOpsAI
- How to run your first detection
- How to read a finding
- How to investigate and triage findings
- Where to go next

## 30-Second Overview

SecOpsAI gives you security visibility for your network and your software supply chain, on your own hardware. It has four components:

| Component | What it does |
| --- | --- |
| **SecOpsAI Edge** | A sensor on your LAN that discovers devices and services and flags risky changes |
| **SecOpsAI Research** | Watches package registries for typosquats and suspicious releases |
| **Core** | The local store and `secopsai` CLI: findings, the asset graph, correlation, triage and reports |
| **Console** | A browser dashboard over the same findings |

Agent integrations bring OpenClaw and Hermes Agent telemetry into the same findings and triage workflow. All analysis runs on your machine: raw scans and package artifacts never leave it, and cloud reports carry minimized findings only.

This guide starts with Core, the CLI every other component reports into. For the network sensor, see [SecOpsAI Edge](edge-integration.md). For registry surveillance, see [Research Operations](research-operations.md).

## Install (2 minutes)

### Option 1: One-Command Setup (Recommended)

macOS/Linux:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

Security note: only run a `curl | bash` installer if you trust the publisher and the source code. If you prefer a safer path, clone the repo and inspect `docs/install.sh` + `setup.sh` before running.

This will:

- Clone `https://github.com/Techris93/secopsai.git` into `~/secopsai` (or `$SECOPSAI_HOME` if set)
- Create a virtualenv at `~/secopsai/.venv`
- Install Python dependencies and the `secopsai` CLI (editable install)
- Run basic validation + benchmark setup

Default behaviour (non-interactive):

- Optional native surfaces: **disabled**
- Benchmark generation: **enabled**
- Live export: **disabled**

Optional controls:

- `SECOPSAI_INSTALL_REF=<git ref or commit>` – pin to a specific version (by default, a fixed known-good commit is used)
- `SECOPSAI_HOME=/path/to/dir` – change the checkout location (default: `$HOME/secopsai`)

Example to explicitly track latest `main` instead of the pinned commit:

```bash
SECOPSAI_INSTALL_REF=main curl -fsSL https://secopsai.dev/install.sh | bash
```

After install, activate the environment:

```bash
cd ~/secopsai
source .venv/bin/activate
```

You now have the `secopsai` CLI available:

```bash
secopsai refresh                         # run the OpenClaw live pipeline
secopsai refresh --platform macos        # run adapter collection for a specific platform
secopsai refresh --platform hermes       # collect local Hermes Agent telemetry
secopsai live --platform macos           # stream adapter events live
secopsai correlate                       # run cross-platform correlation
secopsai list --severity high            # list high-severity findings
secopsai show OCF-XXXX                   # inspect a finding
secopsai triage orchestrate --search-root ~/secopsai  # investigate open findings

# Add --json to any command for machine-friendly output
# (either before or after the subcommand)
secopsai list --severity high --json
secopsai --json list --severity high
```

### Option 2: Manual Setup

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python prepare.py  # Generate data/events.json and data/events_unlabeled.json

python -m pytest tests/ -v  # Optional: verify installation
```

### Option 3: Hermes Agent

For Hermes Agent 0.18.2 or later, this installs Core, enables the read-only native plugin and starts the five-minute background monitor:

```bash
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

### GitHub-Native Install And CI

The published npm package is the OpenClaw plugin distribution, not the complete
Python CLI. Install it through OpenClaw after Core is available:

```bash
openclaw plugins install secopsai
```

The registry currently exposes `secopsai@1.0.0` as that plugin. Do not replace
it with the prepared supply-chain wrapper without an explicit package-lineage
and migration decision.

SecOpsAI is also published to GitHub Packages as `@techris93/secopsai` for
GitHub-native consumers:

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

GitHub Packages may require a token with package-read access depending on the
repository and package visibility. Do not commit `.npmrc` files that contain
tokens.

For GitHub Actions, use the published **SecOpsAI Supply-Chain Guard** action:

```yaml
name: SecOpsAI supply-chain guard

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  secopsai:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Techris93/secopsai-action@v1.0.0
        with:
          mode: advisory-check
          ecosystem: npm
          package: node-ipc
          version: 12.0.1
          fail-on-severity: critical
```

The published `v1.0.0` action can run advisory checks, supply-chain scans,
campaign discovery, and triage summaries without accepting arbitrary shell
commands. AI Dependency Guard is currently a Core CLI capability; do not use it
as a Marketplace Action mode until a tagged Action release advertises that
input contract.

Local equivalent:

```bash
secopsai supply-chain ai-dependency-guard --path . --include-agent-logs --json
```

See
[GitHub Distribution](github-distribution-plan.md) and
[GitHub Marketplace](github-marketplace.md) for release and maintenance notes.

## Run Your First Detection (1 minute)

The quickest end-to-end check is the bundled attack benchmark: it replays labeled agent telemetry through the detection rules and scores the result.

### Generate a Benchmark Corpus

Create a reproducible labeled attack dataset:

```bash
python generate_openclaw_attack_mix.py --stats
```

Output:

```
┌──────────────────────────────────────────┐
│ Attack-Mix Benchmark Generator           │
├──────────────────────────────────────────┤
│ Base benign events:    58                │
│ Simulated attacks:     22                │
│ Total events:          80                │
│ Timestamp range:       2 hours           │
└──────────────────────────────────────────┘

Attack Types:
  ✓ Dangerous Exec (2 events)
  ✓ Sensitive Config (1 event)
  ✓ Skill Source Drift (1 event)
  ✓ Policy Denial Churn (1 event)
  ✓ Tool Burst (2 events)
  ✓ Pairing Churn (1 event)
  ✓ Subagent Fanout (2 events)
  ✓ Restart Loop (2 events)
  ✓ Data Exfiltration (3 events)
  ✓ Malware Presence (2 events)

Files written:
  ✓ data/openclaw/replay/labeled/attack_mix.json
  ✓ data/openclaw/replay/unlabeled/attack_mix.json
```

### Evaluate Detection Accuracy

```bash
python evaluate_openclaw.py \
  --labeled data/openclaw/replay/labeled/attack_mix.json \
  --unlabeled data/openclaw/replay/unlabeled/attack_mix.json \
  --mode benchmark --verbose
```

Expected result:

```
┌─────────────────────────────────────────────┐
│ OpenClaw Attack Detection                   │
├─────────────────────────────────────────────┤
│ F1 Score:       1.000000  ✓                │
│ Precision:      1.000000  ✓                │
│ Recall:         1.000000  ✓                │
│ False Positive Rate:  0.000000             │
│                                             │
│ True Positives:       22  (attacks caught) │
│ False Positives:       0  (zero noise)     │
│ False Negatives:       0  (nothing missed) │
│ True Negatives:       58  (benign OK)      │
└─────────────────────────────────────────────┘
```

A score of 1.0 means every simulated attack was caught with no false positives, so the detection pipeline is working.

### Run on Live Telemetry (Optional)

If you have OpenClaw installed with audit logs in `~/.openclaw/`:

```bash
python detect.py
```

This will:

1. Export your local OpenClaw audit logs
2. Run detection rules
3. Output findings in `findings.json`

If you have Hermes Agent installed with local state in `~/.hermes/`, collect its
history, session, gateway, and tool-call telemetry without executing Hermes:

```bash
secopsai refresh --platform hermes
secopsai list --platform hermes
```

SecOpsAI does not read `~/.hermes/auth.json`, `.env`, or provider credential
files. See [Hermes Integration](Hermes-Integration.md) for the full source and
rule map.

## Start Network and Supply-Chain Monitoring

With an Edge sensor running, pull its asset graph and findings into Core, then check freshness. `edge sync` reads `SECOPSAI_EDGE_API_URL` and a workspace export token in `SECOPSAI_EDGE_ACCESS_TOKEN`:

```bash
secopsai edge sync      # import the Edge graph and findings into the local Core store
secopsai edge status    # source, bundle and sync timestamps, and the cursor
secopsai graph assets   # the discovered asset inventory
```

Run one research cycle to collect recent package releases and score them against your watchlists:

```bash
secopsai research worker run --once   # one bounded collection pass across due registries
secopsai research score run           # score collected events into candidates
```

See [SecOpsAI Edge](edge-integration.md) to set up a sensor, and [Research Discovery Platform](research-discovery.md) for watchlists, monitors and collector health.

## Run Your First Triage Pass

Once findings exist in the SOC store:

```bash
secopsai triage list --status open --limit 20
secopsai triage investigate SCM-XXXX --json
secopsai triage orchestrate --search-root ~/secopsai
secopsai triage queue
```

This gives you:

- evidence-gathering case files in `reports/triage/`
- low-risk auto-closure for clearly safe findings
- a queue for risky actions such as allowlisting or tuning

## Understand Your First Findings

The `findings.json` file contains detected attacks with context:

```json
{
  "total_findings": 22,
  "findings": [
    {
      "finding_id": "OCF-001",
      "title": "Dangerous Exec: curl | bash injection",
      "rule_id": "RULE-101",
      "attack_type": "T1059 - Command and Scripting Interpreter",
      "severity": "CRITICAL",
      "confidence": 1.0,
      "event_ids": ["evt-042"],
      "description": "Detected dangerous pipe execution pattern",
      "pattern": "curl ... | bash",
      "remediation": "Review command source; disable if unauthorized"
    },
    {
      "finding_id": "OCF-002",
      "title": "Data Exfiltration: curl -F upload",
      "rule_id": "RULE-109",
      "attack_type": "T1048 - Exfiltration Over Alternative Protocol",
      "severity": "HIGH",
      "timestamp": "2026-03-15T14:23:45Z",
      ...
    }
  ]
}
```

Each finding shows:

- **What was detected** — the attack pattern
- **Which rule caught it** — RULE-101, RULE-109, etc.
- **How severe** — CRITICAL, HIGH, MEDIUM, LOW
- **Confidence** — 0.0-1.0 likelihood of being a real attack
- **What action to take** — remediation guidance

## Next Steps

### Learn More About the Rules

Read [Rules Registry](rules-registry.md) to understand what each rule detects and how to tune it.

### Understand Performance Metrics

See [Rules Registry](rules-registry.md) for per-rule detection behavior and tuning guidance.

### Integrate Into Your Environment

Check [Deployment Guide](deployment-guide.md) for production deployment patterns.

### Learn the analyst workflow

Read [Findings Triage Guide](findings-triage-guide.md) for manual review and [Triage Orchestrator](triage-orchestrator.md) for the automated guarded workflow.

### Customize Detection Rules

Visit [API Reference](api-reference.md) to write custom rules or integrate with your tools.

## Troubleshooting

### "OpenClaw CLI not found"

Install OpenClaw from [docs.openclaw.ai/install](https://docs.openclaw.ai/install)

### "No findings detected in live telemetry"

This is expected! Live telemetry is usually benign. Try the benchmark instead:

```bash
python generate_openclaw_attack_mix.py --stats
python evaluate_openclaw.py --labeled data/openclaw/replay/labeled/attack_mix.json --unlabeled data/openclaw/replay/unlabeled/attack_mix.json --mode benchmark
```

### Tests fail

Ensure Python 3.10+ and run:

```bash
pip install --upgrade -r requirements.txt
python -m pytest tests/ -v
```

## Getting Help

- **Documentation:** [secopsai.dev](https://secopsai.dev)
- **GitHub Issues:** [Report a bug](https://github.com/Techris93/secopsai/issues)
- **Security reports:** see [security.txt](https://secopsai.dev/.well-known/security.txt)

---

**Ready for more?** → Read [Rules Registry](rules-registry.md) to understand each detection rule.
