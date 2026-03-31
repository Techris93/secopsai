# secopsai

Local-first security operations for OpenClaw, macOS, Linux, and Windows.

## Why secopsai

secopsai turns telemetry from OpenClaw and host platforms into repeatable, explainable security findings.

- Unified collection across **OpenClaw**, **macOS**, **Linux**, and **Windows**
- **Supply Chain Security** — Detect malicious npm/PyPI packages and editor exploits
- Local-first findings pipeline with SQLite-backed storage
- Cross-platform correlation by IP, user, time window, and artifacts
- Threat-intel / IOC workflows for local matching and enrichment
- **Adaptive Intelligence** — Auto-generates detection rules from CVEs
- Operator workflows through CLI, plugin, and related chat surfaces

## Start Here

- [Getting Started](getting-started.md)
- [🛡️ Supply Chain Security](supply-chain.md) — **NEW!** Protect against npm, PyPI, and editor exploits
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

# 4) Check for supply chain attacks (NEW!)
secopsai-supply-chain check --project-path .

# 5) Try cross-platform collection + correlation
secopsai refresh --platform macos,openclaw
secopsai correlate

# 6) Review findings
secopsai list --severity high
```

## What You Get

- Multi-platform telemetry collection
- **Supply chain attack detection** (npm, PyPI, Vim, Emacs)
- **100+ detection rules** (auto-growing via adaptive intelligence)
- Local findings storage and triage workflows
- Cross-platform correlation
- Threat-intel matching
- CLI and OpenClaw plugin workflows
- Deployment paths for ongoing monitoring

## 🛡️ Supply Chain Security

Protect your dependencies from supply chain attacks:

```bash
# Check your project for malicious packages
secopsai-supply-chain check --project-path .

# Check a specific package
secopsai-supply-chain check --package axios --version 1.14.1

# Export results
secopsai-supply-chain check --output report.json
```

**Detects:**
- Malicious npm packages (axios@1.14.1, plain-crypto-js@4.2.1)
- PyPI backdoors (litellm@1.82.7)
- Editor exploits (Vim CVE-2025-27423, Emacs CVE-2025-1244)
- Runtime droppers and RATs
- Typosquatting attacks

[Learn more about Supply Chain Security →](supply-chain.md)

## Operator Guides

- [Beginner Quickstart](quickstart-beginner.md)
- [Operator Runbook](operator-runbook.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [OpenClaw Native Plugin](OpenClaw-Plugin.md)
- [Supply Chain Security](supply-chain.md)
