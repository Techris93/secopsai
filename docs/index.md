# secopsai

Local-first security operations for OpenClaw, macOS, Linux, and Windows.

## Why secopsai

secopsai turns telemetry from OpenClaw and host platforms into repeatable, explainable security findings.

- Unified collection across **OpenClaw**, **macOS**, **Linux**, and **Windows**
- Local-first findings pipeline with SQLite-backed storage
- Cross-platform correlation by IP, user, time window, and artifacts
- Threat-intel / IOC workflows for local matching and enrichment
- Operator workflows through CLI, plugin, and related chat surfaces

## Start Here

- [Getting Started](getting-started.md)
- [Beginner Quickstart](quickstart-beginner.md)
- [Operator Runbook](operator-runbook.md)
- [Deployment Guide](deployment-guide.md)
- [Threat Intel (IOCs)](threat-intel.md)
- [API Reference](api-reference.md)
- [OpenClaw Native Plugin](OpenClaw-Plugin.md)

## Quick Start

```bash
# 1) Install secopsai
curl -fsSL https://secopsai.dev/install.sh | bash

# 2) Activate the virtualenv
cd ~/secopsai
source .venv/bin/activate

# 3) Run the default pipeline
secopsai refresh

# 4) Try cross-platform collection + correlation
secopsai refresh --platform macos,openclaw
secopsai correlate

# 5) Review findings
secopsai list --severity high
```

## What You Get

- Multi-platform telemetry collection
- Local findings storage and triage workflows
- Cross-platform correlation
- Threat-intel matching
- CLI and OpenClaw plugin workflows
- Deployment paths for ongoing monitoring

## Operator Guides

- [Beginner Quickstart](quickstart-beginner.md)
- [Operator Runbook](operator-runbook.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [OpenClaw Native Plugin](OpenClaw-Plugin.md)
