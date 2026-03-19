# Getting Started with secopsai

Welcome! This guide will get you detecting security attacks in OpenClaw audit logs in under 5 minutes.

## What You'll Learn

- How to install secopsai
- How to run your first detection
- How to understand findings
- Where to go next

## 30-Second Overview

**secopsai** is a detection pipeline that identifies security attacks in [OpenClaw](https://docs.openclaw.ai) audit logs. It comes with:

- **12 battle-tested detection rules** covering dangerous execution, policy abuse, data exfiltration, and malware
- **Reproducible benchmark corpus** with 80 labeled events for validation
- **Live telemetry support** for detecting attacks in your OpenClaw workspace
- **Production-ready findings reports** with severity and incident deduplication

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
secopsai refresh                 # run the live pipeline
secopsai list --severity high    # list high-severity findings
secopsai show OCF-XXXX           # inspect a finding

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

### Option 2: Manual Setup

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python prepare.py  # Generate data/events.json and data/events_unlabeled.json

python -m pytest tests/ -v  # Verify installation
```

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
