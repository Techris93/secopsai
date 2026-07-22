---
title: Platform Overview
template: home.html
hide:
  - toc
description: Operator documentation for SecOpsAI network discovery, package-registry surveillance, findings triage, security research, reporting, and local-first integrations.
---

# SecOpsAI Documentation

Deploy SecOpsAI Edge sensors, monitor network and package-registry changes, investigate findings, manage research evidence, and produce reports without giving up control of raw telemetry.

## Why SecOpsAI

SecOpsAI connects network discovery, software supply-chain monitoring, host and agent telemetry, findings triage, research cases, and reporting in one local-first operating model.

- Unified collection across **OpenClaw**, **Hermes Agent**, **macOS**, **Linux**, and **Windows**
- SecOpsAI Edge asset discovery, service exposure, Wi-Fi inventory, and site sensor context
- Continuous package-registry monitoring and explainable candidate scoring across supported ecosystems
- Durable research cases for evidence, IOCs, disclosure, sandbox approval, and publication readiness
- Local-first pipeline with SQLite-backed findings storage
- Cross-platform correlation by IP, user, time, and file hash
- Native CLI triage and orchestrated review workflow
- AI Dependency Guard for hallucinated or slopsquatted packages in AI-built code
- Adaptive Response Layer with decaying threat memory, weak-signal routing, response posture, safe probes, and deception recommendations
- Threat intel pipeline and deployment paths for ongoing monitoring

## Start Here

- [Getting Started](getting-started.md)
- [SecOpsAI Edge](edge-integration.md)
- [Local Codex bridge and ChatGPT app](intelligence-integrations.md)
- [Operator Runbook](operator-runbook.md)
- [Findings Triage Guide](findings-triage-guide.md)
- [Research And Verification](research-and-verification.md)
- [Research Discovery Platform](research-discovery.md)
- [Triage Orchestrator](triage-orchestrator.md)
- [Adaptive Response Layer](adaptive-response.md)
- [Rules Registry](rules-registry.md)
- [Deployment Guide](deployment-guide.md)
- [API Reference](api-reference.md)
- [GitHub Distribution](github-distribution-plan.md)
- [GitHub Marketplace](github-marketplace.md)
- [Name Reservation](name-reservation.md)
- [Threat Intel (IOCs)](threat-intel.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Hermes Integration](Hermes-Integration.md)
- [Supply Chain Security](supply-chain.md)
- [AI Dependency Guard](ai-dependency-guard.md)
- [Emergency Supply Chain Advisories](supply-chain-advisories.md)
- [Security Blog Publishing](blog-publishing.md)
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
secopsai refresh --platform macos,openclaw,hermes
secopsai correlate

# 5) List high-severity findings
secopsai list --severity high

# 6) Run the native triage orchestrator
secopsai triage orchestrate --search-root ~/secopsai

# 7) Run adaptive response analysis
secopsai adaptive-response --persist-memory

# 8) Check AI-built dependency changes for slopsquatting risk
secopsai supply-chain ai-dependency-guard --path . --json
```

## GitHub Distribution

SecOpsAI is available through the original install flow, GitHub Packages, and
the published **SecOpsAI Supply-Chain Guard** GitHub Marketplace Action.

```bash
npm install -g secopsai
```

```bash
npm config set @techris93:registry https://npm.pkg.github.com
npm install @techris93/secopsai
```

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
```

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: ai-dependency-guard
    scan-path: .
    fail-on-severity: high
```

See [GitHub Distribution](github-distribution-plan.md) and
[npm Name Migration](npm-name-migration.md) for package release details, and
[GitHub Marketplace](github-marketplace.md) for action release maintenance.
Use [Name Reservation](name-reservation.md) to track GitHub, Docker Hub, PyPI,
Homebrew, npm, and package-registry ownership.

## Platform Support

| Platform | Source | Status | Notes |
|---|---|---:|---|
| OpenClaw | Audit logs | ✅ Production | Primary native telemetry integration |
| Hermes Agent | History, session, gateway, and tool logs | ✅ Beta | Read-only Hermes telemetry integration |
| macOS | Unified logs | ✅ Production | Host telemetry collection |
| Linux | journalctl / auditd | ✅ Beta | Ready for Linux deployment |
| Windows | Event Logs / Sysmon | ✅ Beta | Ready for Windows deployment |
| SecOpsAI Edge | LAN discovery and Wi-Fi inventory | ✅ Pilot | Separate local sensor module with normalized Core sync |

## What You Get

- Unified security event schema
- Edge asset graph and network-origin finding import
- Local findings store with triage workflow
- Native triage orchestrator with queued human-reviewed actions
- Adaptive Response Layer for threat memory, timing-aware anomalies, prioritization, safe probing, and deception
- Cross-platform correlation engine
- CLI, OpenClaw plugin, and Hermes adapter workflows
- Optional notification workflows for notable findings

## Operator Guides

- [Beginner Live Guide](BEGINNER-LIVE-GUIDE.md)
- [Operator Runbook](operator-runbook.md)
- [Findings Triage Guide](findings-triage-guide.md)
- [Research And Verification](research-and-verification.md)
- [Triage Orchestrator](triage-orchestrator.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [Hermes Integration](Hermes-Integration.md)
- [SecOpsAI Edge](edge-integration.md)
- [Supply Chain Security](supply-chain.md)
- [Emergency Supply Chain Advisories](supply-chain-advisories.md)
- [Security Blog Publishing](blog-publishing.md)
- [GitHub Distribution](github-distribution-plan.md)
- [GitHub Marketplace](github-marketplace.md)
