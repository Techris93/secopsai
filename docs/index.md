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

## Launch Guides

- [Quick Reference](quick-reference.md)
- [Launch Checklist](launch-checklist.md)
- [Launch Master Guide](launch-master-guide.md)
