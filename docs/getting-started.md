# Getting Started with secopsai

Welcome! This guide will get you up and running with SecOpsAI in under 5 minutes, whether you are starting with OpenClaw or expanding into macOS, Linux, and Windows workflows.

## What You'll Learn

- How to install secopsai
- How to run your first detection
- How to understand findings
- Where to go next

## 30-Second Overview

**secopsai** is a local-first security operations toolkit for [OpenClaw](https://docs.openclaw.ai), macOS, Linux, and Windows. It comes with:

- **A unified CLI** for collection, findings review, correlation, and threat intel
- **Multi-platform telemetry support** across OpenClaw and host adapters
- **Production-ready findings reports** with severity and incident deduplication
- **Cross-platform correlation** to connect related activity across sources
- **Threat-intel / IOC workflows** for local matching and enrichment

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

## Run Your First Workflow (1 minute)

Start with the unified CLI:

```bash
secopsai refresh
secopsai list
```

This is the simplest first run and the best default starting point.

To inspect a finding in detail:

```bash
secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
```

### Try platform-specific collection

You can collect from one or more platforms using `--platform`:

```bash
secopsai refresh --platform macos
secopsai refresh --platform linux
secopsai refresh --platform windows
secopsai refresh --platform openclaw
secopsai refresh --platform macos,openclaw
```

### Try correlation

```bash
secopsai correlate
```

### Try threat intel

```bash
secopsai intel refresh
secopsai intel list --limit 20
secopsai intel match --limit-iocs 500
```

### Optional: benchmark / OpenClaw-specific evaluation

If you want to validate the OpenClaw detection path with the benchmark corpus, you can still run the existing benchmark tools:

```bash
python generate_openclaw_attack_mix.py --stats
python evaluate_openclaw.py \
  --labeled data/openclaw/replay/labeled/attack_mix.json \
  --unlabeled data/openclaw/replay/unlabeled/attack_mix.json \
  --mode benchmark --verbose
```

## Understand Your First Findings

Your main review workflow is:

```bash
secopsai list
secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
```

In general, each finding gives you:

- **What was detected**
- **How severe it is**
- **Why it was flagged**
- **What evidence or context is attached**
- **What action to take next**

## Next Steps

### Beginner path

Read [Beginner Quickstart](quickstart-beginner.md) for the shortest path from install to findings.

### Platform-by-platform operations

Read [Operator Runbook](operator-runbook.md) for OpenClaw, macOS, Linux, and Windows workflows.

### Learn More About the Rules

Read [Rules Registry](rules-registry.md) to understand what each rule detects and how to tune it.

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
