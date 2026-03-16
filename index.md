# secopsai

Intelligent attack detection for OpenClaw audit logs.

## Why secopsai

secopsai turns OpenClaw audit activity into repeatable, explainable security findings.

- 12 detection rules for dangerous execution, policy abuse, exfiltration, and malware
- F1 1.0 on the labeled OpenClaw benchmark corpus
- Local-first pipeline with live telemetry support
- Docker, daemon, and CI/CD deployment paths

## Start Here

- [Getting Started](docs/getting-started)
- [Rules Registry](docs/rules-registry)
- [Deployment Guide](docs/deployment-guide)
- [API Reference](docs/api-reference)

## Quick Start

```bash
curl -fsSL https://secopsai.dev/setup.sh | sh
python generate_openclaw_attack_mix.py --stats
python evaluate.py --labeled data/openclaw/replay/labeled/attack_mix.json --mode benchmark
```

## What You Get

- Reproducible benchmark generation
- Rule-by-rule evaluation output
- Findings export with severity and incident grouping
- Containerized continuous polling workflow

## Launch Docs

- [Quick Reference](QUICK-REFERENCE)
- [Launch Checklist](LAUNCH-CHECKLIST)
- [Launch Master Guide](LAUNCH-MASTER-GUIDE)