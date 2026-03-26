# secopsai

Intelligent attack detection for OpenClaw audit logs.

## Why secopsai

secopsai turns OpenClaw audit activity into repeatable, explainable security findings.

- 12 detection rules for dangerous execution, policy abuse, exfiltration, and malware
- F1 1.0 on the labeled OpenClaw benchmark corpus
- Local-first pipeline with live telemetry support
- Docker, daemon, and CI/CD deployment paths

## Start Here

- [Getting Started](getting-started.md)
- [Rules Registry](rules-registry.md)
- [Deployment Guide](deployment-guide.md)
- [API Reference](api-reference.md)
- [Threat Intel (IOCs)](threat-intel.md)

## Quick Start

```bash
# 1) Install secopsai on the same host as your OpenClaw gateway
curl -fsSL https://secopsai.dev/install.sh | bash

# 2) Activate the virtualenv
cd secopsai
source .venv/bin/activate

# 3) Run the live OpenClaw pipeline via the CLI
secopsai refresh

# 4) Try the cross-platform adapter workflow
secopsai refresh --platform macos,openclaw
secopsai correlate

# 5) List high-severity findings
secopsai list --severity high
```

For benchmark-style evaluation instead of live telemetry:

```bash
python generate_openclaw_attack_mix.py --stats
python evaluate_openclaw.py \
  --labeled data/openclaw/replay/labeled/attack_mix.json \
  --unlabeled data/openclaw/replay/unlabeled/attack_mix.json \
  --mode benchmark
```

## What You Get

- Reproducible benchmark generation
- Rule-by-rule evaluation output
- Findings export with severity and incident grouping
- Containerized continuous polling workflow

## Operator Guides

- [Beginner Live Guide](BEGINNER-LIVE-GUIDE.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
