# SecOpsAI Quick Reference Card

## 🚨 Critical CVEs & Affected Versions

| Tool | CVE | Affected | Fixed | Severity |
|------|-----|----------|-------|----------|
| Axios | CVE-2026-Axios-SC | 1.14.1, 0.30.4 | 1.14.0, 0.30.3 | CRITICAL |
| LiteLLM | CVE-2026-LiteLLM-SC | 1.82.7, 1.82.8 | ≤1.82.6 | CRITICAL |
| Vim | CVE-2025-27423 | 9.1.0858-9.1.1163 | ≥9.1.1164 | HIGH |
| Vim | CVE-2025-53905 | <9.1.1551 | ≥9.1.1551 | MODERATE |
| Vim | CVE-2025-53906 | <9.1.1551 | ≥9.1.1551 | MODERATE |
| Emacs | CVE-2025-1244 | All w/ man URI | Latest | HIGH |
| Emacs | CVE-2024-53920 | 27.x, 28.x | Latest | HIGH |

---

## 🔍 IoCs (Indicators of Compromise)

### Axios Attack (March 2026)
```
Malicious Packages:  plain-crypto-js@4.2.1
Compromised:         axios@1.14.1, axios@0.30.4
C2 Domain:           sfrclak.com:8000
macOS Payload:       /Library/Caches/com.apple.act.mond
Windows Payload:     %PROGRAMDATA%\wt.exe
Linux Payload:       /tmp/ld.py
Attacker Emails:     ifstap@proton.me, nrwise@proton.me
```

### LiteLLM Attack (March 2026)
```
Compromised:         litellm@1.82.7, litellm@1.82.8
C2 Exfiltration:     models.litellm.cloud
C2 Backdoor:         checkmarx.zone
Persistence:         sysmon.py, sysmon.service
.pth File:           litellm_init.pth
Encryption:          RSA-4096 + AES-256
```

### Shai-Hulud Worm
```
Pattern:             s1ngularity-repository
Stolen Files:        cloud.json, truffleSecrets.json
Runner Name:         SHA1HULUD
GitHub Action:       formatter.yaml, discussion.yaml
```

---

## ⚡ Emergency Commands

### Check if Compromised
```bash
# Check axios
npm ls axios 2>/dev/null | grep -E "(1.14.1|0.30.4)"

# Check litellm
pip show litellm 2>/dev/null | grep -E "(1.82.7|1.82.8)"

# Check for RAT files
find /Library/Caches -name "com.apple.act.*" 2>/dev/null
find /tmp -name "ld.py" 2>/dev/null
find ~ -name "wt.exe" 2>/dev/null

# Check for .pth persistence
find $(python3 -c "import site; print(site.getsitepackages()[0])") -name "*.pth" -exec cat {} \;

# Check for suspicious npm packages
cat package-lock.json | grep -E "(plain-crypto-js|sync-axios)"
```

### Immediate Response
```bash
# Stop npm processes
pkill -f "npm install"

# Block C2 egress
sudo iptables -A OUTPUT -p tcp --dport 8000 -d sfrclak.com -j DROP

# Remove malicious packages
npm uninstall axios litellm 2>/dev/null
pip uninstall litellm -y 2>/dev/null

# Kill suspicious Node processes
ps aux | grep "node.*setup.js" | awk '{print $2}' | xargs kill -9 2>/dev/null
```

---

## 🛡️ Hardening Checklist

### npm
```bash
npm config set ignore-scripts true
npm config set strict-ssl true
npm config set provenance true
# Use granular tokens only
```

### Vim
```vim
" Add to ~/.vimrc
set nomodeline
set modelines=0
let g:loaded_tar = 1
let g:loaded_tarPlugin = 1
let g:loaded_zip = 1
let g:loaded_zipPlugin = 1
```

### Emacs
```elisp
;; Add to ~/.emacs.d/init.el
(setq enable-local-variables nil)
(setq enable-local-eval nil)
;; Disable man: URI handling
```

### Python
```bash
# Check site-packages for .pth files
pip config set global.no-compile true
# Use virtual environments
```

---

## 🔧 Toolkit Commands

```bash
# Monitor npm registry
secopsai-npm-monitor --package <name> --watch
secopsai-npm-monitor --check-lockfile package-lock.json

# Validate SBOM
secopsai-sbom-validator --sbom <file> --policy [strict|standard|permissive]

# Runtime monitoring
secopsai-runtime-monitor --daemon        # Start
secopsai-runtime-monitor --status        # Check status
secopsai-runtime-monitor --stop          # Stop

# Incident response
secopsai-response --list                 # List playbooks
secopsai-response --incident <type> --dry-run
secopsai-response --incident npm-supply-chain-compromise

# Hardening
secopsai-harden                          # All
secopsai-harden --npm                    # npm only
secopsai-harden --vim                    # Vim only
secopsai-harden --emacs                  # Emacs only
secopsai-harden --python                 # Python only
```

---

## 📊 Detection Rules Summary

### Sigma Rules
| Rule | Trigger | Severity |
|------|---------|----------|
| npm_postinstall_network | npm → curl/wget/python | CRITICAL |
| editor_plugin_mod | Plugin file with exec() | HIGH |
| python_pth_execution | .pth with import/exec | CRITICAL |
| suspicious_npm_install | Typosquat packages | CRITICAL |
| litellm_proxy_anomaly | LiteLLM suspicious activity | HIGH |
| editor_shell_network | Vim/Emacs → shell + network | HIGH |
| npm_account_anomaly | Email change → publish | HIGH |
| suspicious_file_drop | Known RAT payload paths | CRITICAL |

### YARA Rules
| Rule | Detects |
|------|---------|
| AxioSupplyChainRAT | Axios RAT payloads |
| LiteLLM_Backdoor | LiteLLM backdoor |
| ShaiHulud_Worm | Shai-Hulud worm |
| Vim_TarPlugin_Exploit | Malicious TAR files |
| Emacs_URI_Injection | Malicious URI handlers |
| NPM_Postinstall_Dropper | Generic npm droppers |
| Python_PTH_Execution | Malicious .pth files |
| Typosquat_Package | Typosquatting |

---

## 🚨 Incident Response Playbooks

### npm Supply Chain Compromise
1. Block C2 egress
2. Isolate containers
3. Revoke npm tokens
4. Rotate cloud credentials
5. Remove packages
6. Forensic collection

### Editor Exploit
1. Suspend user session
2. Collect memory dump
3. Quarantine suspicious files
4. Update editor

### Python .pth Persistence
1. Scan site-packages
2. Remove malicious .pth
3. Recreate virtualenvs

### LiteLLM Credential Exposure
1. Stop LiteLLM proxy
2. Rotate all LLM keys
3. Rotate cloud credentials
4. Audit API logs

---

## 📞 Emergency Contacts

| Resource | Contact |
|----------|---------|
| npm Security | security@npmjs.com |
| PyPI Security | security@pypi.org |
| GitHub Security | https://github.com/security |
| CISA | https://www.cisa.gov/report |

---

## 🔗 References

- Axios Attack: https://www.picussecurity.com/resource/blog/axios-npm-supply-chain-attack
- LiteLLM Attack: https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
- Vim CVE-2025-27423: https://nvd.nist.gov/vuln/detail/CVE-2025-27423
- Emacs CVE-2025-1244: https://nvd.nist.gov/vuln/detail/CVE-2025-1244

---

**Print this card and keep it accessible during incidents.**
