# secopsai

Local-first cross-platform SecOps for OpenClaw, macOS, Linux, and Windows.

## Why secopsai

secopsai turns OpenClaw and host OS telemetry into repeatable, explainable security findings.

- Unified collection across **OpenClaw**, **macOS**, **Linux**, and **Windows**
- Local-first pipeline with SQLite-backed findings storage
- Cross-platform correlation by IP, user, time, and file hash
- Operator workflows through CLI, plugin, and WhatsApp surfaces
- Threat intel pipeline and deployment paths for ongoing monitoring

## Start Here

- [Getting Started](getting-started.md)
- [Universal Adapters](universal-adapters.md)
- [Correlation Engine](correlation-engine.md)
- [Rules Registry](rules-registry.md)
- [Deployment Guide](deployment-guide.md)
- [API Reference](api-reference.md)
- [Threat Intel (IOCs)](threat-intel.md)
- [OpenClaw Native Plugin](OpenClaw-Plugin.md)

## Quick Start

```bash
# 1) Install secopsai
curl -fsSL https://secopsai.dev/install.sh | bash

# 2) Activate the virtualenv
cd ~/secopsai
source .venv/bin/activate

# 3) Run the packaged OpenClaw pipeline
secopsai refresh

# 4) Try the universal adapter CLI flow locally
python3 cli.py refresh --platform macos,openclaw
python3 cli.py correlate

# 5) List high-severity findings
secopsai list --severity high
```

## Platform Support

| Platform | Source | Status | Notes |
|---|---|---:|---|
| OpenClaw | Audit logs | ✅ Production | Primary native telemetry integration |
| macOS | Unified logs | ✅ Production | Host telemetry collection |
| Linux | journalctl / auditd | ✅ Beta | Ready for Linux deployment |
| Windows | Event Logs / Sysmon | ✅ Beta | Ready for Windows deployment |

## What You Get

- Unified security event schema
- Local findings store with triage workflow
- Cross-platform correlation engine
- CLI and OpenClaw plugin workflows
- Optional WhatsApp alerting for notable correlations

## Operator Guides

- [Beginner Live Guide](BEGINNER-LIVE-GUIDE.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Universal Adapters](universal-adapters.md)
- [Correlation Engine](correlation-engine.md)
