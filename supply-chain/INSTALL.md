# SecOpsAI - Unified Security Operations

## One-Command Installation

```bash
# Install SecOpsAI with all modules
curl -sSL https://secops.ai/install | bash

# Or manually
git clone https://github.com/secopsai/secopsai.git
cd secopsai
./install.sh
```

## Quick Start

```bash
# Check installation
secopsai status

# Scan for supply chain threats
secopsai supply-chain scan

# Monitor for runtime exploits
secopsai supply-chain monitor

# Check a specific package
secopsai supply-chain check axios
```

## Module System

SecOpsAI uses a modular architecture:

```
secopsai <module> <command> [args]
```

### Available Modules

| Module | Description | Commands |
|--------|-------------|----------|
| `supply-chain` | Supply chain attack detection | scan, monitor, check, validate, respond |

### Supply Chain Commands

```bash
# Scan current project
secopsai supply-chain scan

# Check specific package
secopsai supply-chain check axios@1.14.1

# Start runtime monitoring (requires sudo)
sudo secopsai supply-chain monitor

# Validate SBOM
secopsai supply-chain validate

# Run incident response playbook
secopsai supply-chain respond npm_supply_chain_compromise
```

## Installation Locations

- CLI: `~/.local/bin/secopsai`
- Modules: `~/.secopsai/modules/`
- Logs: `~/.secopsai/logs/`
- Config: `~/.secopsai/config.yaml`

## Update

```bash
secopsai update
```

## Uninstall

```bash
rm -rf ~/.secopsai ~/.local/bin/secopsai
```
