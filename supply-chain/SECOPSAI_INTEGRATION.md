# SecOpsAI Supply Chain Integration Guide

## Overview

This supply chain security module integrates **natively** with SecOpsAI's existing architecture:
- Uses SecOpsAI's SQLite SOC store for findings
- Compatible with `secopsai list`, `secopsai show`, `secopsai mitigate` commands
- Generates findings with `SCF-` prefix (Supply Chain Finding)

## SecOpsAI Command Alignment

| SecOpsAI Native | With Supply Chain Module |
|----------------|-------------------------|
| `secopsai refresh` | Runs detection + supply chain checks |
| `secopsai list --severity high` | Shows supply chain findings |
| `secopsai show OCF-XXXX` | Works with `SCF-XXXX` findings |
| `secopsai mitigate OCF-XXXX` | Provides supply chain mitigations |
| `secopsai check-supply-chain` | NEW: Dedicated supply chain scan |

## Installation

### Option 1: Install with SecOpsAI (Recommended)

```bash
# Install SecOpsAI first
curl -fsSL https://secopsai.dev/install.sh | bash

# Install supply chain module
cd ~/secopsai
source .venv/bin/activate

# Copy supply chain module to SecOpsAI
ln -s /path/to/secopsai-toolkit ~/secopsai/modules/supply-chain

# Install dependencies
pip install psutil requests

# Register module
echo 'supply-chain' >> ~/secopsai/config/modules.txt
```

### Option 2: Standalone with SecOpsAI Compatibility

```bash
cd secopsai-toolkit
./install.sh  # Installs as standalone but compatible format
```

## Usage

### Via SecOpsAI CLI (After Integration)

```bash
cd ~/secopsai
source .venv/bin/activate

# Full scan including supply chain
secopsai refresh

# View supply chain findings
secopsai list --severity high --category supply_chain_npm

# View specific finding
secopsai show SCF-20260331123456-abc123

# Get mitigation guidance
secopsai mitigate SCF-20260331123456-abc123
```

### Direct Module Usage

```bash
# Check current project
python3 supply_chain_module.py check --project-path .

# Export findings
python3 supply_chain_module.py check -p . -o supply_chain_findings.json

# Check with critical fail
python3 supply_chain_module.py check --fail-on-critical
```

## Finding ID Format

Supply chain findings use the prefix `SCF-`:
- `SCF-20260331123456-abc123`
- `SCF-{timestamp}-{hash}`

This distinguishes them from OpenClaw findings (`OCF-`) while maintaining compatibility.

## Finding Categories

| Category | Description |
|----------|-------------|
| `supply_chain_npm` | npm package issues |
| `supply_chain_pypi` | PyPI package issues |
| `supply_chain_editor_vim` | Vim editor exploits |
| `supply_chain_editor_emacs` | Emacs editor exploits |
| `supply_chain_runtime` | Runtime dropper/RAT detection |
| `supply_chain_sbom` | SBOM policy violations |

## Integration with SecOpsAI Adaptive Intelligence

The supply chain module feeds into SecOpsAI's adaptive intelligence:

1. **Daily at 11 PM UTC**: Adaptive pipeline fetches new supply chain CVEs
2. **Rule Generation**: Auto-generates detection rules from threat intel
3. **Validation**: Tests rules against evaluation dataset
4. **Deployment**: Validated rules auto-deploy

## Database Schema

Supply chain findings use the same schema as native SecOpsAI findings:

```sql
CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,  -- SCF-XXXXXX
    timestamp TEXT,
    severity TEXT,                -- critical, high, medium, low
    category TEXT,                -- supply_chain_*
    title TEXT,
    description TEXT,
    evidence TEXT,                -- JSON
    mitigation TEXT,
    status TEXT,                  -- open, closed
    disposition TEXT,             -- unreviewed, confirmed, false_positive
    source TEXT                   -- supply-chain-module
);
```

## Correlation

Supply chain findings participate in SecOpsAI's correlation engine:

```bash
# Cross-platform correlation
secopsai correlate

# This links:
# - Supply chain package compromise
# - Runtime process execution  
# - Network C2 connections
# - File system anomalies
```

## WhatsApp Integration

Via OpenClaw WhatsApp bridge:

```
User: check supply chain
Bot: Running supply chain scan...
     Found 2 findings:
     - SCF-XXX: Malicious npm package detected
     - SCF-YYY: Vim modeline vulnerability
```

## Configuration

Add to `~/secopsai/config/config.yaml`:

```yaml
modules:
  supply-chain:
    enabled: true
    npm:
      check_lockfile: true
      check_provenance: true
    editors:
      check_vim: true
      check_emacs: true
    runtime:
      monitor_processes: true
      check_suspicious_files: true
    sbom:
      policy: strict  # strict, moderate, permissive
```

## Directory Structure

```
~/secopsai/
├── secopsai                    # Main CLI
├── modules/
│   └── supply-chain/           # This module
│       ├── supply_chain_module.py
│       ├── agents/
│       ├── rules/
│       ├── playbooks/
│       └── configs/
├── data/
│   ├── openclaw/findings/      # Native findings
│   └── supply-chain/           # Module data
└── config/
    └── modules.txt             # Enabled modules
```

## Testing Integration

```bash
# 1. Verify module loads
secopsai status

# 2. Run supply chain detection
secopsai check-supply-chain

# 3. Check findings in SOC store
secopsai list --source supply-chain-module

# 4. Verify correlation works
secopsai correlate
```

## Troubleshooting

### Module not detected
```bash
# Check module link
ls -la ~/secopsai/modules/supply-chain

# Re-link if needed
ln -sf /path/to/secopsai-toolkit ~/secopsai/modules/supply-chain
```

### Findings not appearing
```bash
# Check SOC store path
ls ~/secopsai/data/openclaw/findings/openclaw_soc.db

# Verify table schema
sqlite3 ~/secopsai/data/openclaw/findings/openclaw_soc.db ".schema findings"
```

### Dependencies missing
```bash
cd ~/secopsai
source .venv/bin/activate
pip install psutil requests pyyaml
```

## Migration from Standalone

If you were using the standalone toolkit:

```bash
# Old way (still works)
python3 agents/npm_registry_monitor.py --package axios

# New way (integrated)
secopsai check-supply-chain

# Or direct module
python3 supply_chain_module.py check
```

## Contributing

To add new supply chain detection:

1. Add detection method to `SupplyChainDetector` class
2. Generate `SupplyChainFinding` with proper category
3. Update this documentation

## References

- SecOpsAI: https://secopsai.dev/
- Docs: https://docs.secopsai.dev/
- GitHub: https://github.com/Techris93/secopsai
