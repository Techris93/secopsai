# SecOpsAI Supply Chain Security Module

A security module for [SecOpsAI](https://secopsai.dev/) that detects and mitigates supply chain attacks on npm, PyPI, Vim, Emacs, and other developer tools.

## Prerequisites

**You must have SecOpsAI installed first:**

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

This installs SecOpsAI to `~/secopsai/` with the `secopsai` CLI.

## Installation

### Option 1: As SecOpsAI Module (Recommended)

```bash
# Clone this repository
git clone https://github.com/secopsai/supply-chain-module.git
cd supply-chain-module

# Install as SecOpsAI module
./install-secopsai-module.sh
```

### Option 2: Manual Integration

```bash
# Copy module to SecOpsAI
cp -r secopsai-toolkit ~/secopsai/modules/supply-chain

# Install dependencies
cd ~/secopsai
source .venv/bin/activate
pip install psutil requests pyyaml
```

## Quick Start

```bash
# Activate SecOpsAI
cd ~/secopsai
source .venv/bin/activate

# Run supply chain checks
secopsai-supply-chain check

# Check specific project
secopsai-supply-chain check --project-path /path/to/project

# Export findings
secopsai-supply-chain check -o supply_chain_findings.json
```

## Commands

| Command | Description |
|---------|-------------|
| `check` | Run supply chain detection on project |
| `status` | Check module installation status |

### Check Options

```bash
secopsai-supply-chain check [options]

Options:
  -p, --project-path PATH    Project directory to analyze (default: .)
  -o, --output FILE         Export findings to JSON file
  --fail-on-critical        Exit with error code on critical findings
```

## What It Detects

### Supply Chain Attacks
- **Malicious npm packages**: axios@1.14.1, plain-crypto-js@4.2.1
- **Malicious PyPI packages**: litellm@1.82.7
- **Runtime droppers**: RAT payloads from supply chain attacks

### Editor Exploits
- **Vim**: modeline vulnerabilities (CVE-2019-12735, CVE-2025-27423)
- **Emacs**: URI handler exploits (CVE-2025-1244)

### Python Backdoors
- **.pth file execution**: Malicious Python startup hooks

## SecOpsAI Integration

When integrated with SecOpsAI, findings appear in the SOC store:

```bash
# View all findings
secopsai list --severity high

# View supply chain specific findings
secopsai list --category supply_chain_npm

# View specific finding
secopsai show SCF-20260331123456-abc123

# Get mitigation guidance
secopsai mitigate SCF-20260331123456-abc123
```

Supply chain findings use the `SCF-` prefix (Supply Chain Finding) and are stored in the same SQLite database as native SecOpsAI findings (`OCF-` prefix).

## Architecture

This module integrates with SecOpsAI's existing infrastructure:

```
┌─────────────────────────────────────────────────────────┐
│                    SecOpsAI Platform                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │   secopsai  │  │   secopsai  │  │ secopsai-supply │ │
│  │   refresh   │  │    list     │  │     chain       │ │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ │
│         │                │                   │          │
│  ┌──────┴────────────────┴───────────────────┴──────┐  │
│  │               SecOpsAI SOC Store                 │  │
│  │         (SQLite: openclaw_soc.db)               │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Finding Categories

| Category | Description |
|----------|-------------|
| `supply_chain_npm` | npm package issues |
| `supply_chain_pypi` | PyPI package issues |
| `supply_chain_editor_vim` | Vim editor exploits |
| `supply_chain_editor_emacs` | Emacs editor exploits |
| `supply_chain_runtime` | Runtime dropper/RAT detection |

## Components

```
secopsai-toolkit/
├── supply_chain_module.py      # Main module (SecOpsAI compatible)
├── agents/                      # Detection agents
│   ├── npm_registry_monitor.py
│   ├── sbom_validator.py
│   ├── runtime_monitor.py
│   └── threat_intel.py
├── rules/                       # Detection rules
│   ├── sigma-supply-chain-rules.yml
│   └── yara-supply-chain-rules.yar
├── playbooks/                   # Incident response
│   └── incident_response.py
├── configs/                     # Security configurations
│   └── security-configs.conf
├── install-secopsai-module.sh  # SecOpsAI integration installer
└── research/                    # Research reports
    └── supply-chain-exploits-report.md
```

## Standalone Usage

You can also use components directly:

```bash
# npm Registry Monitor
python3 agents/npm_registry_monitor.py --package axios

# SBOM Validator
python3 agents/sbom_validator.py --generate ./my-project --policy strict

# Runtime Monitor
sudo python3 agents/runtime_monitor.py --monitor

# Threat Intelligence
python3 agents/threat_intel.py --check axios@1.14.1
```

## Research Foundation

This module is based on analysis of:

1. **Axios Supply Chain Attack (March 2026)** - npm credential compromise
2. **LiteLLM Attack (March 2026)** - PyPI .pth backdoor
3. **Vim tar.vim Exploit (CVE-2025-27423)** - Command injection
4. **Emacs URI Handler (CVE-2025-1244)** - Remote code execution

See [research/supply-chain-exploits-report.md](research/supply-chain-exploits-report.md) for full details.

## Documentation

- [SecOpsAI Integration Guide](SECOPSAI_INTEGRATION.md)
- [Research Report](research/supply-chain-exploits-report.md)
- [Build Summary](BUILD_SUMMARY.md)

## SecOpsAI Resources

- Website: https://secopsai.dev/
- Documentation: https://docs.secopsai.dev/
- GitHub: https://github.com/Techris93/secopsai

## License

MIT
