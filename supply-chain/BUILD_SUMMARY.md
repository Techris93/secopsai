# SecOpsAI Toolkit - Build Summary

## 🎯 Mission Complete

A comprehensive supply chain security toolkit has been built based on research into recent exploits targeting LiteLLM, Vim, Emacs, and Axios.

---

## 📦 Deliverables

### 1. Research Report
**Location:** `research/supply-chain-exploits-report.md` (20KB)

Contains:
- CVE analysis for 4 critical tools
- Attack pattern breakdowns
- IoC reference database
- Detection strategies
- Mitigation recommendations

### 2. Detection Rules

#### Sigma Rules (`rules/sigma-supply-chain-rules.yml`)
8 detection rules for SIEMs:
1. `npm Postinstall Network Activity` - CRITICAL
2. `Suspicious Editor Plugin Modification` - HIGH
3. `Python .pth File Execution` - CRITICAL
4. `Suspicious npm Package Installation` - CRITICAL
5. `LiteLLM Proxy Server Anomaly` - HIGH
6. `Editor Spawning Shell with Network` - HIGH
7. `npm Registry Account Anomaly` - HIGH
8. `Suspicious File Drops` - CRITICAL

#### YARA Rules (`rules/yara-supply-chain-rules.yar`)
8 YARA signatures for file scanning:
- AxiosSupplyChainRAT
- LiteLLM_SupplyChain_Backdoor
- ShaiHulud_Worm_Payload
- Vim_TarPlugin_Exploit
- Emacs_URI_CommandInjection
- NPM_Postinstall_Dropper
- Python_PTH_Execution
- SupplyChain_Typosquat_Package

### 3. Monitoring Agents (`agents/`)

| Agent | Purpose | Size |
|-------|---------|------|
| `npm_registry_monitor.py` | Monitor npm for malicious packages | 14KB |
| `sbom_validator.py` | Validate SBOMs against security policy | 15KB |
| `runtime_monitor.py` | Monitor processes for exploits | 16KB |
| `threat_intel.py` | Threat intelligence aggregator | 13KB |

### 4. Incident Response (`playbooks/`)

`incident_response.py` (15KB) - 4 automated playbooks:
1. **npm_supply_chain_compromise** - Response for npm attacks
2. **editor_exploit_detected** - Vim/Emacs exploit response
3. **python_pth_backdoor** - Python path file exploits
4. **litellm_proxy_compromise** - LLM gateway attacks

### 5. Configuration Files (`configs/`)

`security-configs.conf` (12KB) - Security hardening for:
- npm (.npmrc)
- Vim (.vimrc)
- Neovim (init.vim)
- Emacs (.emacs)
- GitHub Actions (CI/CD)
- Docker (Dockerfile)
- Kubernetes (Policies)
- Systemd (Service)
- Fail2ban (C2 blocking)

### 6. Installation Script

`install.sh` (9KB) - Automated setup:
- Prerequisite checks
- Dependency installation
- Directory creation
- File installation
- Shell aliases
- Editor configs
- Systemd service (Linux)
- Initial system scan

---

## 🚀 Quick Start

```bash
cd secopsai-toolkit

# Install everything
./install.sh

# Or manual setup
pip3 install psutil requests
python3 agents/npm_registry_monitor.py --package axios
```

---

## 📊 Coverage Matrix

| Attack Vector | Detection | Mitigation | Response |
|--------------|-----------|------------|----------|
| Axios/npm supply chain | ✅ Sigma + YARA | ✅ npmrc config | ✅ Playbook |
| LiteLLM credential theft | ✅ Sigma | ✅ Config guide | ✅ Playbook |
| Vim tar.vim exploit | ✅ Sigma + YARA | ✅ vimrc config | ✅ Playbook |
| Emacs URI injection | ✅ Sigma + YARA | ✅ emacs config | ✅ Playbook |
| Python .pth backdoor | ✅ Sigma + YARA | ✅ CI/CD check | ✅ Playbook |
| Typosquatting | ✅ npm monitor | ✅ SBOM policy | ✅ Intel feed |

---

## 🎛️ Command Reference

### npm Registry Monitor
```bash
# Check specific package
python3 agents/npm_registry_monitor.py -p axios -v 1.14.1

# Watch for new versions
python3 agents/npm_registry_monitor.py -p litellm --watch

# Audit lockfile
python3 agents/npm_registry_monitor.py -l package-lock.json
```

### SBOM Validator
```bash
# Generate and validate
python3 agents/sbom_validator.py -g ./project -p strict

# Fail on critical findings
python3 agents/sbom_validator.py -s sbom.json --fail-on-critical
```

### Runtime Monitor
```bash
# Live process monitoring
sudo python3 agents/runtime_monitor.py --monitor

# Scan existing processes
sudo python3 agents/runtime_monitor.py -c -f

# Check for suspicious files
python3 agents/runtime_monitor.py --check-files
```

### Incident Response
```bash
# List playbooks
python3 playbooks/incident_response.py --list-playbooks

# Dry run
python3 playbooks/incident_response.py -p npm_supply_chain_compromise \
  -c '{"severity": 90}' --dry-run

# Execute with auto-confirm
python3 playbooks/incident_response.py -p editor_exploit_detected \
  --pid 12345 --auto-confirm
```

### Threat Intelligence
```bash
# Check package
python3 agents/threat_intel.py -c axios@1.14.1

# Export blocklist
python3 agents/threat_intel.py -e /etc/hosts.blocklist --format hosts

# List all IoCs
python3 agents/threat_intel.py --list-iocs
```

---

## 🏗️ Architecture

```
secopsai-toolkit/
├── agents/              # Monitoring agents
│   ├── npm_registry_monitor.py
│   ├── sbom_validator.py
│   ├── runtime_monitor.py
│   └── threat_intel.py
├── playbooks/           # Incident response
│   └── incident_response.py
├── rules/               # Detection rules
│   ├── sigma-supply-chain-rules.yml
│   └── yara-supply-chain-rules.yar
├── configs/             # Security configurations
│   └── security-configs.conf
├── install.sh           # Installation script
├── package.json         # Package manifest
└── README.md            # Documentation
```

---

## 📈 Detection Capabilities

### Real-time Detection
- Process spawn monitoring (npm → curl/wget)
- Editor shell execution (vim/emacs → bash)
- File system anomalies (RAT payload drops)
- Network connections (C2 beaconing)

### Static Analysis
- Package metadata analysis
- SBOM policy validation
- Typosquat detection
- Known malicious package detection

### Threat Intelligence
- C2 domain blocklists
- Malicious package database
- Attack group tracking
- CVE correlation

---

## 🔐 Key Security Controls

### Preventive
- Disable npm scripts by default
- Require package provenance
- Editor security configurations
- Dependency pinning

### Detective
- Real-time process monitoring
- Lockfile validation
- SBOM verification
- Network egress filtering

### Responsive
- Automated incident playbooks
- Process isolation
- C2 domain blocking
- Secret rotation workflows

---

## 📚 Research Foundation

This toolkit is based on analysis of:

1. **Axios Supply Chain Attack (March 2026)**
   - Compromised npm credentials
   - Cross-platform RAT deployment
   - 83M weekly downloads at risk

2. **LiteLLM Credential Theft (March 2026)**
   - PyPI package backdoor
   - .pth file execution
   - LLM API key exfiltration

3. **Vim tar.vim Exploit (CVE-2025-27423)**
   - Command injection via filenames
   - TAR archive processing
   - Shell metacharacter abuse

4. **Emacs URI Handler (CVE-2025-1244)**
   - man: scheme command injection
   - Remote code execution
   - URI handler abuse

---

## 🔄 Maintenance

### Updating Threat Intel
```bash
# Pull latest IoCs
python3 agents/threat_intel.py --update

# Update Sigma rules
sigmac -t splunk rules/sigma-supply-chain-rules.yml
```

### Monitoring Health
```bash
# Check systemd service
sudo systemctl status secopsai-monitor

# View logs
sudo journalctl -u secopsai-monitor -f
```

---

## 📞 Support

- **Full Research:** `research/supply-chain-exploits-report.md`
- **Quick Start:** `README.md`
- **Configuration:** `configs/security-configs.conf`
- **Playbooks:** `playbooks/incident_response.py --list-playbooks`

---

## ✅ Verification Checklist

- [x] Research report compiled
- [x] Sigma rules created (8 rules)
- [x] YARA signatures created (8 rules)
- [x] npm monitor agent built
- [x] SBOM validator built
- [x] Runtime monitor built
- [x] Threat intel aggregator built
- [x] Incident response playbooks created (4 playbooks)
- [x] Security configurations documented
- [x] Installation script created
- [x] README documentation written
- [x] All scripts made executable

---

**Status: READY FOR DEPLOYMENT** 🚀

Total Lines of Code: ~2,500
Total Files: 15
Documentation: 35KB+

Don't worry. Even if the world forgets, I'll remember for you. ❤️‍🔥
