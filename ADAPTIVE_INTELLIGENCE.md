# SecOpsAI Adaptive Intelligence System

## Overview

SecOpsAI now **actively learns** from threat intelligence sources and **automatically adapts** its detection rules to catch emerging attacks.

## How It Works

```
Daily at 11:00 PM UTC (2:00 AM Istanbul)
         |
         v
┌─────────────────────┐
│  Fetch Threat Intel │  ← CVEs, RSS feeds, GitHub PoCs
│  from 10+ sources   │
└──────────┬──────────┘
           |
           v
┌─────────────────────┐
│  Parse & Extract    │  ← IOCs, TTPs, MITRE techniques
│  Attack Patterns    │
└──────────┬──────────┘
           |
           v
┌─────────────────────┐
│  Generate Detection │  ← SQLi, RCE, Auth Bypass, etc.
│  Rules via LLM      │
└──────────┬──────────┘
           |
           v
┌─────────────────────┐
│  Test Against       │  ← Synthetic attack dataset
│  Evaluation Dataset │
└──────────┬──────────┘
           |
           v
┌─────────────────────┐
│  F1 Score           │
│  Improved?          │
└──────────┬──────────┘
           |
     ┌─────┴─────┐
     |           |
    YES          NO
     |           |
     v           v
┌────────┐  ┌────────┐
│DEPLOY  │  │DISCARD │
│Rules   │  │Rules   │
└────────┘  └────────┘
```

## Threat Intelligence Sources

| Source | Type | Frequency |
|--------|------|-----------|
| NVD (CVE Database) | Vulnerabilities | Daily |
| Bleeping Computer | News | Daily |
| Krebs on Security | Analysis | Daily |
| The Hacker News | News | Daily |
| Microsoft Security | Alerts | Daily |
| Google TAG | Reports | Daily |
| GitHub (PoCs) | Exploits | Daily |
| Ars Technica | News | Daily |
| Wired Security | News | Daily |
| Bruce Schneier | Analysis | Daily |

## Auto-Generated Detection Rules

The system generates rules for:

- **SQL Injection** (SQLi) - `T1190`
- **Remote Code Execution** (RCE) - `T1059, T1203`
- **Authentication Bypass** - `T1552, T1078`
- **Path Traversal** - `T1083`
- **Command Injection** - `T1059`
- **Cross-Site Scripting** (XSS) - `T1189`
- **Privilege Escalation** - `T1068, T1548`
- **IOC-based** (IPs, domains, hashes) - Various

## File Structure

```
secopsai/
├── threat_intel_ingestor.py      # Fetches threat data
├── adaptive_rule_generator.py    # Generates detection rules
├── adaptive_rule_validator.py    # Tests & validates rules
├── adaptive_intelligence_pipeline.py  # Master orchestrator
├── threat_intel/                 # Fetched indicators
│   ├── latest_indicators.json
│   └── indicators_YYYYMMDD_HHMMSS.json
├── auto_rules/                   # Generated rules (pending validation)
│   ├── auto_rule_auto_001.py
│   ├── auto_rule_auto_002.py
│   └── metadata.json
└── validated_rules/              # Rules that improved F1
    ├── auto_001.py
    └── auto_002.py

workspace/
├── adaptive-intel-daily.sh       # Shell script wrapper
└── com.openclaw.secopsai.adaptive-intel.plist  # launchd config
```

## Installation

### On MacBook

```bash
# 1. Copy plist to LaunchAgents
cp com.openclaw.secopsai.adaptive-intel.plist \
   ~/Library/LaunchAgents/

# 2. Load the service
launchctl load ~/Library/LaunchAgents/com.openclaw.secopsai.adaptive-intel.plist

# 3. Verify it's loaded
launchctl list | grep adaptive-intel
```

### Manual Run (Testing)

```bash
cd ~/workspace/secopsai
python3 adaptive_intelligence_pipeline.py
```

### Install Dependencies

```bash
pip3 install feedparser requests
```

## Notification

You'll receive Telegram notifications:

- **🧠 Started** - Pipeline begins
- **✅ Improved** - New rules deployed (F1 increased)
- **⚠️ No Change** - No improvement (rules discarded)
- **❌ Failed** - Error occurred

## Validation Criteria

Rules are **only deployed** if they:

1. Parse without syntax errors
2. Improve F1 score by at least 0.001 (0.1%)
3. Don't break existing rule evaluation

## Example Output

```
════════════════════════════════════════════════════════════
SecOpsAI Adaptive Intelligence Pipeline
Started: 2026-03-30T14:00:00Z
════════════════════════════════════════════════════════════

STEP 1: Ingesting Threat Intelligence
════════════════════════════════════════════════════════════
[CVE] Fetched 42 CVEs
[RSS] Fetched 18 articles
[GitHub] Fetched 12 PoCs
[SUMMARY] Total unique indicators: 67
  - Critical: 5
  - High: 23
  - Medium: 31
  - Low: 8

STEP 2: Generating Detection Rules
════════════════════════════════════════════════════════════
[GEN] Processing 67 indicators...
[GEN] Generated AUTO-001: SQL Injection: CVE-2026-1234...
[GEN] Generated AUTO-002: RCE Detection: CVE-2026-5678...
[GEN] Generated AUTO-003: Auth Bypass: CVE-2026-9012...
[GEN] Total rules generated: 8

STEP 3: Validating Rules
════════════════════════════════════════════════════════════
[BASELINE] F1 Score: 0.862651

STEP 4: Testing Rule Performance
════════════════════════════════════════════════════════════
[TEST] F1 Score with new rules: 0.871234

✅ SUCCESS] F1 improved by 0.008583
  Baseline: 0.862651
  New:      0.871234

[GIT] Committed validated rules
```

## Monitoring

Check logs:
```bash
# Latest run
tail -f ~/.openclaw/workspace/logs/adaptive-intel-out.log

# All results
cat ~/.openclaw/workspace/logs/adaptive_results.json

# Service status
launchctl print gui/$(id -u)/com.openclaw.secopsai.adaptive-intel
```

## Security Considerations

- Rules are generated from **public** threat intelligence only
- All rules are **tested** before deployment
- Only **improving** rules are kept
- Full audit trail in git commits
- No external APIs called with sensitive data

## Future Enhancements

- [ ] MISP integration for private threat feeds
- [ ] VT (VirusTotal) API for hash reputation
- [ ] AlienVault OTX pulses
- [ ] Twitter/X security researcher monitoring
- [ ] LLM-powered rule refinement
- [ ] Cross-correlation between new and existing rules

## Troubleshooting

### No indicators fetched
```bash
# Check network connectivity
curl -I https://services.nvd.nist.gov/rest/json/cves/2.0

# Check RSS feeds
python3 -c "import feedparser; print(feedparser.parse('https://...'))"
```

### Rules not generating
```bash
# Check Python dependencies
pip3 install feedparser requests

# Check threat intel file exists
ls -la ~/.openclaw/workspace/secopsai/threat_intel/
```

### F1 not improving
- Generated rules may not match your synthetic data patterns
- Consider expanding synthetic data generation
- Check if new attack types are represented in test data

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DATA SOURCES                              │
├─────────────────────────────────────────────────────────────┤
│  NVD CVE DB    RSS Feeds    GitHub PoCs    MISP (future)    │
└──────────────────┬──────────────────────────────────────────┘
                   │
           ┌───────▼────────┐
           │   Ingestor     │  threat_intel_ingestor.py
           └───────┬────────┘
                   │
           ┌───────▼────────┐
           │   Generator    │  adaptive_rule_generator.py
           └───────┬────────┘
                   │
           ┌───────▼────────┐
           │   Validator    │  adaptive_rule_validator.py
           └───────┬────────┘
                   │
           ┌───────▼────────┐
           │   Deployer     │  Git commit if F1 ↑
           └────────────────┘
```
