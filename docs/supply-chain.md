# Supply Chain Security

SecOpsAI includes a comprehensive **Supply Chain Security Module** that detects and mitigates attacks targeting software dependencies, package registries, and developer tools.

## Overview

Supply chain attacks have grown 742% since 2024. SecOpsAI adds a critical defense layer by detecting malicious packages at install time, before they can compromise your systems.

### What We Detect

| Attack Vector | Examples | Detection Method |
|--------------|----------|------------------|
| **npm packages** | axios@1.14.1, plain-crypto-js | Known malicious DB + heuristics |
| **PyPI packages** | litellm@1.82.7 | .pth file monitoring + imports |
| **Editor exploits** | Vim CVE-2025-27423, Emacs CVE-2025-1244 | Configuration analysis |
| **Runtime droppers** | Cross-platform RATs | File path + behavior detection |
| **Typosquatting** | lodash vs lodash-js | Levenshtein distance analysis |

## Quick Start

### Check Your Project

```bash
# Navigate to your project
cd /path/to/your/project

# Run supply chain check
secopsai-supply-chain check --project-path .

# Export results to JSON
secopsai-supply-chain check --output supply_chain_report.json
```

### Check a Specific Package

```bash
# Analyze a specific npm package
secopsai-supply-chain check --package axios --version 1.14.1

# Watch for new versions
secopsai-supply-chain check --package litellm --watch
```

## Known Malicious Packages

SecOpsAI maintains a database of known malicious packages:

| Package | Affected Versions | Attack Type | Date |
|---------|-------------------|-------------|------|
| axios | 1.14.1, 0.30.4 | Compromised npm credentials | Mar 2026 |
| plain-crypto-js | 4.2.1 | Supply chain RAT dropper | Mar 2026 |
| litellm | 1.82.7, 1.82.8 | PyPI .pth backdoor | Mar 2026 |

## Detection Capabilities

### 1. Static Analysis

- **Package metadata analysis**: Author reputation, download counts, publish dates
- **SBOM validation**: Compare against security policies
- **Typosquatting detection**: Identify lookalike packages
- **Known malicious detection**: Match against threat intel database

### 2. Runtime Monitoring

- **npm postinstall scripts**: Detect suspicious install-time behavior
- **Editor process anomalies**: Vim/Emacs spawning shells
- **Suspicious file drops**: RAT payloads in system directories
- **C2 beaconing**: Network connections to known malicious domains

### 3. Threat Intelligence

- **C2 domain blocklist**: sfrclak.com, models.litellm.cloud, etc.
- **Malicious package database**: Auto-updating list
- **CVE correlation**: Link findings to known vulnerabilities

## CLI Reference

### Commands

```bash
# Basic check
secopsai-supply-chain check

# Check specific project
secopsai-supply-chain check --project-path /path/to/project

# Check specific package
secopsai-supply-chain check --package <name> --version <version>

# Watch for changes
secopsai-supply-chain check --package <name> --watch

# Audit all versions
secopsai-supply-chain check --package <name> --audit

# Check lockfile
secopsai-supply-chain check --check-lockfile package-lock.json

# Export results
secopsai-supply-chain check --output report.json

# Fail on critical findings
secopsai-supply-chain check --fail-on-critical
```

### Options

| Option | Description |
|--------|-------------|
| `--project-path PATH` | Project directory to analyze |
| `--package NAME` | Package name to check |
| `--version VERSION` | Specific version to check |
| `--watch` | Watch for new versions/changes |
| `--audit` | Audit mode - check all versions |
| `--check-lockfile FILE` | Validate package-lock.json |
| `--output FILE` | Export results to JSON |
| `--fail-on-critical` | Exit with error on critical findings |

## Understanding Findings

Supply chain findings use the `SCF-` prefix (Supply Chain Finding):

```
SCF-20260401123456-abc123
```

### Severity Levels

| Level | Description | Example |
|-------|-------------|---------|
| **Critical** | Known malicious package confirmed | axios@1.14.1 detected |
| **High** | Suspicious behavior likely malicious | Unusual postinstall script |
| **Medium** | Potentially risky package | Low download count, new author |
| **Low** | Informational | Outdated dependency |

### Finding Categories

- `supply_chain_npm` - npm package issues
- `supply_chain_pypi` - PyPI package issues
- `supply_chain_editor_vim` - Vim editor exploits
- `supply_chain_editor_emacs` - Emacs editor exploits
- `supply_chain_runtime` - Runtime dropper detection

## Integration with Main SecOpsAI

Supply chain findings integrate seamlessly with the main SOC store:

```bash
# List supply chain findings
secopsai list --category supply_chain_npm

# View specific finding
secopsai show SCF-20260401123456-abc123

# Get mitigation guidance
secopsai mitigate SCF-20260401123456-abc123

# Correlate with other findings
secopsai correlate SCF-20260401123456-abc123
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  supply-chain-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install SecOpsAI
        run: curl -fsSL https://secopsai.dev/install.sh | bash
      
      - name: Run supply chain check
        run: |
          source ~/secopsai/.venv/bin/activate
          secopsai-supply-chain check --fail-on-critical
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

source ~/secopsai/.venv/bin/activate
secopsai-supply-chain check --fail-on-critical
```

## Best Practices

### Daily Workflow

```bash
# Morning security check (5 minutes)
source ~/secopsai/.venv/bin/activate
secopsai-supply-chain check --project-path .
secopsai list --severity critical
```

### Before Installing New Dependencies

```bash
# Always check before npm install
secopsai-supply-chain check --package <new-package>

# If clean, proceed with install
npm install <new-package>
```

### SBOM Validation

```bash
# Generate and validate SBOM
python3 ~/secopsai/supply-chain/agents/sbom_validator.py \
  --generate . \
  --package-manager npm \
  --policy strict
```

## Incident Response

If a malicious package is detected:

1. **Isolate**: Remove the package immediately
   ```bash
   npm uninstall <malicious-package>
   ```

2. **Investigate**: Check for signs of compromise
   ```bash
   secopsai show SCF-<FINDING_ID>
   ```

3. **Remediate**: Follow the mitigation guide
   ```bash
   secopsai mitigate SCF-<FINDING_ID>
   ```

4. **Verify**: Re-run the check
   ```bash
   secopsai-supply-chain check --project-path .
   ```

## Architecture

The Supply Chain Security Module consists of:

```
┌─────────────────────────────────────────────┐
│         Supply Chain Security Module        │
├─────────────────────────────────────────────┤
│  Agents          │  Rules                   │
│  • npm monitor   │  • Sigma rules (8)       │
│  • SBOM validator│  • YARA signatures (8)   │
│  • Runtime monitor│                         │
│  • Threat intel  │                          │
├─────────────────────────────────────────────┤
│  Detection Categories                        │
│  • npm packages                             │
│  • PyPI packages                            │
│  • Editor exploits (Vim/Emacs)              │
│  • Runtime droppers                         │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│           SecOpsAI SOC Store                │
│        (SQLite: openclaw_soc.db)           │
└─────────────────────────────────────────────┘
```

## Further Reading

- [User Workbook](../USER_WORKBOOK.md) - Complete user guide
- [Research Report](../research/supply-chain-exploits-report.md) - Technical details
- [SecOpsAI Integration](../SECOPSAI_INTEGRATION.md) - Integration guide

## References

- [Axios Supply Chain Attack (March 2026)](https://www.picussecurity.com/resource/blog/axios-npm-supply-chain-attack)
- [CVE-2025-27423](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27423) - Vim tar.vim exploit
- [CVE-2025-1244](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-1244) - Emacs URI handler
