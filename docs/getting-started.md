# Getting Started with secopsai

Welcome! This guide will get you from telemetry refresh to triage in under 5 minutes.

## What You'll Learn

- How to install secopsai
- How to run your first detection
- How to understand findings
- How to investigate and triage them
- Where to go next

## 30-Second Overview

**secopsai** is a local-first detection and triage platform for OpenClaw and host telemetry. It comes with:

- **Detection rules** for dangerous execution, policy abuse, data exfiltration, malware, and supply-chain release review
- **Reproducible benchmark corpus** for OpenClaw validation
- **Live telemetry support** for OpenClaw and host adapters
- **Native triage workflow** with investigation reports and queued analyst actions

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

### GitHub-Native Install And CI

For npm users, the clean public package name is `secopsai`:

```bash
npm install -g secopsai
```

The package name already exists on npm under the `techris` maintainer account,
and this repository is prepared for the next `secopsai@1.0.1` wrapper release.
Publishing still requires explicit maintainer approval and npm authentication.

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
      - uses: Techris93/secopsai-action@v1
        with:
          mode: advisory-check
          ecosystem: npm
          package: node-ipc
          version: 12.0.1
          fail-on-severity: critical
```

The action can run advisory checks, supply-chain scans, campaign discovery, and
triage summaries without accepting arbitrary shell commands. See
[GitHub Distribution](github-distribution-plan.md) and
[GitHub Marketplace](github-marketplace.md) for release and maintenance notes.

## Run Your First Detection (1 minute)

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

Perfect score! Your detection pipeline is ready.

### Run on Live Telemetry (Optional)

If you have OpenClaw installed with audit logs in `~/.openclaw/`:

```bash
python detect.py
```

This will:

1. Export your local OpenClaw audit logs
2. Run detection rules
3. Output findings in `findings.json`

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
- **Discussions:** [Ask a question](https://github.com/Techris93/secopsai/discussions)

---

**Ready for more?** → Read [Rules Registry](rules-registry.md) to understand each detection rule.
