# SecOpsAI User Workbook
## A Complete Guide for New Users

**Version:** 1.0  
**Last Updated:** 2026-04-01  
**Repository:** https://github.com/Techris93/secopsai

---

## 📚 Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Your First Scan](#your-first-scan)
4. [Understanding Findings](#understanding-findings)
5. [Supply Chain Security Module](#supply-chain-security-module)
6. [Daily Workflows](#daily-workflows)
7. [Incident Response](#incident-response)
8. [Troubleshooting](#troubleshooting)
9. [Quick Reference](#quick-reference)

---

## Getting Started

### What is SecOpsAI?

SecOpsAI is a **local-first, cross-platform security operations platform** that:
- 🔍 Detects threats across OpenClaw, macOS, Linux, and Windows
- 🛡️ Identifies supply chain attacks (npm, PyPI, editor exploits)
- 🧠 Uses adaptive intelligence to learn from new threats
- 📊 Correlates findings across multiple data sources

### Key Features

| Feature | Description |
|---------|-------------|
| **Supply Chain Security** | Detect malicious npm/PyPI packages, editor exploits |
| **Cross-Platform Detection** | Works on macOS, Linux, Windows, OpenClaw |
| **Adaptive Intelligence** | Auto-generates new detection rules from CVEs |
| **Local-First** | Your data stays on your infrastructure |
| **SOC Integration** | SQLite-based findings store with CLI tools |

---

## Installation

### Prerequisites

- Python 3.10 or 3.11
- pip3
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai
```

### Step 2: Run the Setup Script

```bash
chmod +x setup.sh
./setup.sh
```

This will:
- Create a Python virtual environment (`.venv`)
- Install all dependencies
- Set up the database directory structure
- Create necessary data directories

### Step 3: Activate the Environment

```bash
source .venv/bin/activate
```

### Step 4: Verify Installation

```bash
secopsai status
```

Expected output:
```
SecOpsAI Status
===============
Database: /home/user/secopsai/data/openclaw/findings/openclaw_soc.db
Rules: 100+ detection rules loaded
Supply Chain Module: Available
Status: Ready
```

---

## Your First Scan

### Basic Scan Command

```bash
secopsai refresh
```

This runs the complete detection pipeline and stores findings in the SOC database.

### View Your Findings

```bash
# List all findings
secopsai list

# List high severity findings only
secopsai list --severity high

# List findings from last 24 hours
secopsai list --since "24h"
```

### Example Output

```
ID                  Severity  Category              Title
─────────────────────────────────────────────────────────────────────
OCF-20260401001   medium    network_scan          Port scan detected
OCF-20260401002   high      auth_anomaly          Multiple failed logins
SCF-20260401001   critical  supply_chain_npm      Malicious package detected
```

### Get Details on a Finding

```bash
secopsai show OCF-20260401001
```

This displays:
- Full description
- Affected systems
- Recommended actions
- Related findings

---

## Understanding Findings

### Finding ID Format

| Prefix | Meaning | Example |
|--------|---------|---------|
| `OCF-` | OpenClaw Finding | `OCF-20260401123456` |
| `SCF-` | Supply Chain Finding | `SCF-20260401123456` |

### Severity Levels

| Level | Color | Meaning | Action Required |
|-------|-------|---------|-----------------|
| **Critical** | 🔴 | Immediate threat | Investigate NOW |
| **High** | 🟠 | Serious concern | Investigate today |
| **Medium** | 🟡 | Suspicious activity | Review this week |
| **Low** | 🟢 | Informational | Monitor |

### Categories

| Category | Description |
|----------|-------------|
| `supply_chain_npm` | Malicious npm packages |
| `supply_chain_pypi` | Malicious PyPI packages |
| `supply_chain_editor_vim` | Vim editor exploits |
| `supply_chain_editor_emacs` | Emacs editor exploits |
| `auth_anomaly` | Authentication issues |
| `network_scan` | Port/network scanning |
| `malware_detection` | Known malware signatures |

---

## Supply Chain Security Module

### What It Detects

The Supply Chain Security Module protects against:

| Attack Vector | Example | Detection Method |
|--------------|---------|------------------|
| **Compromised npm packages** | axios@1.14.1 | Known malicious package database |
| **PyPI backdoors** | litellm@1.82.7 | .pth file execution monitoring |
| **Editor exploits** | Vim tar.vim injection | Configuration analysis |
| **Runtime droppers** | Cross-platform RATs | Suspicious file detection |

### Running Supply Chain Checks

#### Check a Specific npm Package

```bash
secopsai-supply-chain check --package axios
```

#### Check Your Project

```bash
cd /path/to/your/project
secopsai-supply-chain check --project-path .
```

#### Export Results

```bash
secopsai-supply-chain check --output supply_chain_report.json
```

### Interpreting Supply Chain Findings

#### Example: Malicious Package Detected

```
🚨 MALICIOUS PACKAGE DETECTED
   ID: SCF-202604010042
   Package: axios@1.14.1
   Registry: npm
   Attack Type: compromised_credentials
   
   Description:
   This version of axios was published using compromised npm
   credentials. It contains a postinstall script that downloads
   and executes a remote access trojan (RAT).
   
   Affected Files:
   - node_modules/axios/package.json
   - node_modules/axios/lib/setup.js
   
   Recommended Actions:
   1. Immediately remove axios@1.14.1
   2. Run npm audit fix
   3. Check for signs of compromise
   4. Rotate any exposed credentials
```

### Supply Chain Playbooks

If a supply chain finding is detected, follow the automated playbook:

```bash
secopsai mitigate SCF-202604010042
```

This will guide you through:
1. Isolation steps
2. Evidence collection
3. Remediation actions
4. Verification

---

## Daily Workflows

### Morning Security Check (5 minutes)

```bash
# Activate environment
source ~/secopsai/.venv/bin/activate

# Run detection
secopsai refresh

# Check for critical findings
secopsai list --severity critical

# If any critical findings, investigate
secopsai show <FINDING_ID>
```

### Project Security Review

When starting work on a project:

```bash
cd /path/to/project

# Check for supply chain issues
secopsai-supply-chain check --project-path .

# Generate SBOM
python3 ~/secopsai/agents/sbom_validator.py \
  --generate . \
  --package-manager npm \
  --policy strict \
  --output sbom_report.json
```

### Weekly Deep Scan

```bash
# Full scan with all modules
secopsai refresh --full

# Review all high+ severity findings
secopsai list --severity high --since "7d"

# Check supply chain trends
secopsai list --category supply_chain_npm --since "7d"
```

### Before Deploying to Production

```bash
# Final security check
secopsai refresh

# Verify no critical findings
if secopsai list --severity critical | grep -q "CRITICAL"; then
  echo "❌ Critical findings detected! Review before deploying."
  exit 1
else
  echo "✅ No critical findings. Safe to deploy."
fi
```

---

## Incident Response

### Step 1: Identify the Finding

```bash
# Get finding details
secopsai show <FINDING_ID>

# See related findings
secopsai correlate <FINDING_ID>
```

### Step 2: Follow the Mitigation Guide

```bash
# Get step-by-step remediation
secopsai mitigate <FINDING_ID>
```

### Step 3: Execute Response Playbook

For supply chain incidents:

```bash
# Run automated response
python3 ~/secopsai/playbooks/incident_response.py \
  --finding-id <FINDING_ID> \
  --auto-remediate
```

### Step 4: Verify Resolution

```bash
# Re-run detection
secopsai refresh

# Confirm finding is resolved
secopsai show <FINDING_ID>
```

### Incident Response Workflow Diagram

```
┌─────────────────┐
│ Detection Alert │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ secopsai show   │
│ <FINDING_ID>    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ Critical?       │────▶│ Immediate Action│
└────────┬────────┘     └─────────────────┘
         │ No
         ▼
┌─────────────────┐
│ secopsai        │
│ mitigate        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Execute         │
│ Remediation     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Verify Fix      │
│ secopsai refresh│
└─────────────────┘
```

---

## Troubleshooting

### Common Issues

#### Issue: "secopsai: command not found"

**Cause:** Virtual environment not activated  
**Fix:**
```bash
source ~/secopsai/.venv/bin/activate
```

#### Issue: "Database not found"

**Cause:** Database directory not initialized  
**Fix:**
```bash
cd ~/secopsai
mkdir -p data/openclaw/findings
python3 -c "from soc_store import init_db; init_db()"
```

#### Issue: "No module named 'psutil'"

**Cause:** Dependencies not installed  
**Fix:**
```bash
cd ~/secopsai
source .venv/bin/activate
pip install -r requirements.txt
```

#### Issue: Supply chain check returns no results

**Cause:** Not in a project directory or no package files  
**Fix:**
```bash
# Navigate to project with package.json or requirements.txt
cd /path/to/your/project
secopsai-supply-chain check --project-path .
```

### Getting Help

1. **Check the documentation:**
   - README.md
   - SECOPSAI_INTEGRATION.md
   - ADAPTIVE_INTELLIGENCE.md

2. **Review GitHub issues:**
   - https://github.com/Techris93/secopsai/issues

3. **Check logs:**
   ```bash
   tail -f ~/secopsai/logs/secopsai.log
   ```

---

## Quick Reference

### Essential Commands

| Command | Purpose |
|---------|---------|
| `secopsai refresh` | Run full detection pipeline |
| `secopsai list` | List all findings |
| `secopsai list --severity high` | List high severity findings |
| `secopsai show <ID>` | Show finding details |
| `secopsai mitigate <ID>` | Get remediation steps |
| `secopsai correlate <ID>` | Find related findings |
| `secopsai-supply-chain check` | Check for supply chain issues |
| `secopsai status` | Check system status |

### Finding ID Patterns

| Pattern | Example | Description |
|---------|---------|-------------|
| `OCF-` | `OCF-20260401123456` | OpenClaw Finding |
| `SCF-` | `SCF-20260401123456` | Supply Chain Finding |

### Severity Filters

```bash
secopsai list --severity critical
secopsai list --severity high
secopsai list --severity medium
secopsai list --severity low
```

### Time-Based Filters

```bash
secopsai list --since "1h"    # Last hour
secopsai list --since "24h"   # Last 24 hours
secopsai list --since "7d"    # Last 7 days
secopsai list --since "30d"   # Last 30 days
```

### Category Filters

```bash
secopsai list --category supply_chain_npm
secopsai list --category supply_chain_pypi
secopsai list --category auth_anomaly
secopsai list --category network_scan
```

### Configuration Files

| File | Purpose |
|------|---------|
| `~/.secopsai/config.yml` | User configuration |
| `~/secopsai/data/openclaw/findings/openclaw_soc.db` | Findings database |
| `~/secopsai/rules/` | Detection rules |
| `~/secopsai/agents/` | Monitoring agents |

---

## Next Steps

### For Security Analysts

1. Review the [Adaptive Intelligence documentation](ADAPTIVE_INTELLIGENCE.md)
2. Learn how to [write custom detection rules](docs/custom-rules.md)
3. Set up [automated alerting](docs/alerting.md)

### For Developers

1. Integrate SecOpsAI into your CI/CD pipeline
2. Use the [pre-commit hook](docs/pre-commit.md) for supply chain checks
3. Review the [API documentation](docs/api.md)

### For System Administrators

1. Set up [log forwarding](docs/logging.md)
2. Configure [backup and recovery](docs/backup.md)
3. Review [security hardening](docs/hardening.md)

---

## Support

- 📖 **Documentation:** https://docs.secopsai.dev/
- 🐛 **Bug Reports:** https://github.com/Techris93/secopsai/issues
- 💬 **Discussions:** https://github.com/Techris93/secopsai/discussions
- 🌐 **Website:** https://secopsai.dev/

---

**Happy SecOps! 🛡️**

*Remember: Security is a process, not a product. Run SecOpsAI regularly and act on findings promptly.*
