---
title: Home
template: home.html
hide:
  - navigation
  - toc
description: Local-first cross-platform SecOps docs for OpenClaw, macOS, Linux, and Windows.
---

# secopsai

Local-first cross-platform SecOps for OpenClaw, macOS, Linux, and Windows.

## Why secopsai

secopsai turns OpenClaw and host OS telemetry into repeatable, explainable security findings and now includes a native analyst workflow for investigation, disposition, and queued policy actions.

- Unified collection across **OpenClaw**, **macOS**, **Linux**, and **Windows**
- Local-first pipeline with SQLite-backed findings storage
- Cross-platform correlation by IP, user, time, and file hash
- Native CLI triage and orchestrated review workflow
- Threat intel pipeline and deployment paths for ongoing monitoring

## Start Here

- [Getting Started](getting-started.md)
- [Operator Runbook](operator-runbook.md)
- [Findings Triage Guide](findings-triage-guide.md)
- [Triage Orchestrator](triage-orchestrator.md)
- [Rules Registry](rules-registry.md)
- [Deployment Guide](deployment-guide.md)
- [API Reference](api-reference.md)
- [Threat Intel (IOCs)](threat-intel.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Supply Chain Security](supply-chain.md)
- [OpenClaw Plugin](OpenClaw-Plugin.md)

## Quick Start

```bash
# 1) Install secopsai
curl -fsSL https://secopsai.dev/install.sh | bash

# 2) Activate the virtualenv
cd ~/secopsai
source .venv/bin/activate

# 3) Run the packaged OpenClaw pipeline
secopsai refresh

# 4) Try the cross-platform adapter workflow
secopsai refresh --platform macos,openclaw
secopsai correlate

# 5) List high-severity findings
secopsai list --severity high

# 6) Run the native triage orchestrator
secopsai triage orchestrate --search-root ~/secopsai
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
- Native triage orchestrator with queued human-reviewed actions
- Cross-platform correlation engine
- CLI and OpenClaw plugin workflows
- Optional notification workflows for notable findings

## Operator Guides

- [Beginner Live Guide](BEGINNER-LIVE-GUIDE.md)
- [Operator Runbook](operator-runbook.md)
- [Findings Triage Guide](findings-triage-guide.md)
- [Triage Orchestrator](triage-orchestrator.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Supply Chain Security](supply-chain.md)
