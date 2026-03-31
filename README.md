# SecOpsAI

Local-first security operations for OpenClaw, macOS, Linux, and Windows with **adaptive threat intelligence** and **continuous learning**.

SecOpsAI is a local-first security operations toolkit that collects telemetry, generates findings, correlates activity across platforms, and supports operator review and response workflows. It now **actively learns** from threat intelligence sources and **auto-generates detection rules** to catch emerging attacks.

## What's New

🛡️ **Supply Chain Security Module** — Detect and mitigate supply chain attacks on npm, PyPI, Vim, Emacs, and other developer tools. Includes detection rules for Axios, LiteLLM, and editor exploits.

🧠 **Adaptive Intelligence System** — Actively learns from CVEs, security news, and exploit repositories to generate new detection rules daily

🔄 **Continuous Learning** — Auto-validates new rules against F1 score; only deploys improving rules

🛡️ **Enhanced macOS Detection** — 15+ event sources including TCC, Gatekeeper, XProtect, launchd

📊 **Cross-Platform Correlation** — Links findings across OpenClaw, macOS, Linux, Windows

🧷 **Paperclip Integration** — Hierarchical org map for agent orchestration

---

## What it does

- Collects telemetry from OpenClaw, macOS, Linux, and Windows
- Normalizes events into a shared model for multi-platform analysis
- **Auto-generates detection rules** from daily threat intelligence
- Groups and deduplicates detections into incident findings
- Stores findings in local SQLite
- Can auto-sync persisted findings to a Supabase dashboard when credentials are configured
- Supports triage workflow: list, show, status, disposition, notes
- Provides mitigation guidance per finding
- Supports conversational workflows through plugin and WhatsApp bridge

## Why use it

- **Local-first**: no external APIs required
- **Self-improving**: learns from new threats automatically
- **Validated**: only keeps rules that improve detection accuracy
- **One command surface** for OpenClaw and host-platform workflows
- **Practical operator flow**: collect -> detect -> list -> investigate -> mitigate
- **Cross-platform correlation** and IOC matching built in
- **Automation-ready** and easy to extend

---

## 🧠 Adaptive Intelligence System

SecOpsAI now **actively learns** from security sources and adapts its detection rules:

### How It Works

```
Daily at 11:00 PM UTC
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
│  F1 Improved?       │  ← Only deploy if accuracy ↑
└──────────┬──────────┘
           |
     ┌─────┴─────┐
    YES          NO
     |           |
     v           v
┌────────┐  ┌────────┐
│DEPLOY  │  │DISCARD │
│Rules   │  │Rules   │
└────────┘  └────────┘
```

### Threat Intelligence Sources

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

### Auto-Generated Detection Rules

The system generates rules for:

- **SQL Injection** (SQLi) — `T1190`
- **Remote Code Execution** (RCE) — `T1059, T1203`
- **Authentication Bypass** — `T1552, T1078`
- **Path Traversal** — `T1083`
- **Command Injection** — `T1059`
- **Cross-Site Scripting** (XSS) — `T1189`
- **Privilege Escalation** — `T1068, T1548`
- **IOC-based** (IPs, domains, hashes)

### Running Adaptive Intelligence

```bash
# Manual run
python3 adaptive_intelligence_pipeline.py

# Or use launchd service
launchctl load ~/Library/LaunchAgents/com.openclaw.secopsai.adaptive-intel.plist

# Check status
launchctl list | grep adaptive-intel
```

See [ADAPTIVE_INTELLIGENCE.md](ADAPTIVE_INTELLIGENCE.md) for full documentation.

---

## 🛡️ Supply Chain Security Module

SecOpsAI now includes a dedicated module for detecting and mitigating supply chain attacks targeting developer tools and package ecosystems.

### What It Detects

| Attack Vector | CVE/Attack | Detection Method |
|--------------|------------|------------------|
| **npm packages** | Axios supply chain (March 2026) | Known malicious package detection |
| **PyPI packages** | LiteLLM backdoor (March 2026) | .pth file execution monitoring |
| **Vim exploits** | tar.vim injection (CVE-2025-27423) | Editor configuration analysis |
| **Emacs exploits** | URI handler injection (CVE-2025-1244) | Config file scanning |
| **Runtime droppers** | Cross-platform RATs | Suspicious file path detection |

### Known Malicious Packages

| Package | Affected Versions | Attack Type |
|---------|-------------------|-------------|
| `axios` | 1.14.1, 0.30.4 | Compromised npm credentials |
| `plain-crypto-js` | 4.2.1 | Supply chain RAT dropper |
| `litellm` | 1.82.7, 1.82.8 | PyPI .pth backdoor |

### Module Components

```
secopsai-toolkit/
├── supply_chain_module.py      # Main detection module
├── agents/
│   ├── npm_registry_monitor.py # npm package analysis
│   ├── sbom_validator.py       # SBOM policy validation
│   ├── runtime_monitor.py      # Process/file monitoring
│   └── threat_intel.py         # Threat intelligence aggregator
├── rules/
│   ├── sigma-supply-chain-rules.yml  # SIEM detection rules
│   └── yara-supply-chain-rules.yar   # File scanning signatures
├── playbooks/
│   └── incident_response.py    # Automated response playbooks
└── configs/
    └── security-configs.conf   # Hardening configurations
```

### Using the Supply Chain Module

```bash
# Run comprehensive supply chain check
secopsai-supply-chain check

# Check specific project
secopsai-supply-chain check --project-path /path/to/project

# Export findings to JSON
secopsai-supply-chain check --output supply_chain_findings.json

# Fail on critical findings (CI/CD integration)
secopsai-supply-chain check --fail-on-critical
```

### Findings Format

Supply chain findings use the `SCF-` prefix (Supply Chain Finding) and integrate with the main SecOpsAI SOC store:

```bash
# List supply chain findings
secopsai list --category supply_chain_npm
secopsai list --category supply_chain_editor_vim

# View specific finding
secopsai show SCF-20260401123456-abc123

# Get mitigation guidance
secopsai mitigate SCF-20260401123456-abc123
```

### Detection Capabilities

**Static Analysis:**
- npm package-lock.json analysis
- SBOM validation against security policies
- Typosquatting detection
- Known malicious package detection

**Runtime Monitoring:**
- npm postinstall script execution
- Editor process anomalies (vim/emacs spawning shells)
- Suspicious file drops (RAT payloads)
- C2 beaconing detection

**Threat Intelligence:**
- C2 domain blocklists (sfrclak.com, models.litellm.cloud)
- Malicious package database (auto-updating)
- CVE correlation

### Installation

The supply chain module is included in the main SecOpsAI installation. To use it:

```bash
cd ~/secopsai
source .venv/bin/activate

# Run supply chain checks
secopsai-supply-chain check
```

See [secopsai-toolkit/README.md](secopsai-toolkit/README.md) and [secopsai-toolkit/SECOPSAI_INTEGRATION.md](secopsai-toolkit/SECOPSAI_INTEGRATION.md) for detailed documentation.

---

## Quick Start

For a short first-run guide, see [docs/quickstart-beginner.md](docs/quickstart-beginner.md).
For a platform-by-platform operations guide, see [docs/operator-runbook.md](docs/operator-runbook.md).

### 1. Install

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

Security note: only run a `curl | bash` installer if you trust the publisher and the source code. If you prefer a safer path, clone the repo and inspect `docs/install.sh` + `setup.sh` before running.

When piped from `curl`, setup runs in non-interactive mode with safe defaults:

- optional native surfaces: disabled
- benchmark generation: enabled
- live export: disabled

Optional hardening controls for installer bootstrap:

- `SECOPSAI_INSTALL_REF=<git ref or commit>` to pin setup script source
- `SECOPSAI_INSTALL_SHA256=<sha256>` to enforce checksum verification

By default, `install.sh` uses a pinned immutable commit for secure installs.
If you explicitly want latest `main`, use:

```bash
SECOPSAI_INSTALL_REF=main curl -fsSL https://secopsai.dev/install.sh | bash
```

Optional runtime temp log directory:

- `SECOPSAI_TMP_DIR=/path` to override default temp log location (`$TMPDIR` or `/tmp`)

Fallback (manual setup):

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python prepare.py  # Generate data/events.json and data/events_unlabeled.json
python -m pytest tests/ -v  # Optional: verify installation
```

### 2. Activate environment

```bash
source .venv/bin/activate
```

### 3. Run your first workflow

```bash
# Default pipeline
secopsai refresh

# Cross-platform collection
secopsai refresh --platform macos,openclaw

# Live adapter streaming
secopsai live --platform macos --duration 60

# Correlation
secopsai correlate

# Run adaptive intelligence (generate rules from threat intel)
python3 adaptive_intelligence_pipeline.py
```

---

## 🛡️ Enhanced macOS Detection

SecOpsAI includes enhanced macOS telemetry with 15+ event sources:

| Source | Detection Focus |
|--------|-----------------|
| TCC (Transparency, Consent, Control) | Unauthorized access to camera, microphone, contacts |
| Gatekeeper | Unsigned/quarantined app execution |
| XProtect | Known malware detection |
| launchd | Persistent daemons, suspicious agents |
| System Extensions | Kernel extensions, driver loads |
| Network | C2 beacons, data exfiltration |
| Keychain | Credential access attempts |

### macOS Detection Rules

- **RULE-207**: TCC Privacy Violations
- **RULE-208**: Gatekeeper Bypass Attempts
- **RULE-209**: Process Anomalies
- **RULE-210**: Credential Access
- **RULE-211**: Network Anomalies
- **RULE-212**: Repeated Sudo Failures
- **RULE-213**: Unsigned Code Execution

See `adapters/macos/adapter.py` for implementation.

---

## 🔗 Cross-Platform Correlation

SecOpsAI correlates findings across platforms to detect multi-stage attacks:

### Correlation Patterns

| Pattern | Description | MITRE |
|---------|-------------|-------|
| `auth_compromise_then_abuse` | Auth failure → successful login from new IP | T1078, T1110 |
| `potential_exfiltration` | Large outbound transfer after sensitive access | T1041, T1048 |
| `persistence_then_config_change` | Persistence → config modification | T1543, T1098 |
| `defense_evasion` | Multiple evasion techniques in sequence | T1562, T1070 |
| `suspicious_execution_then_burst` | Unusual execution → rapid activity | T1204, T1496 |
| `credential_harvest_and_use` | Credential access → lateral movement | T1003, T1021 |

### Using Correlation

```bash
# Run correlation engine
python3 correlation.py

# Or via CLI
secopsai correlate
```

---

## OpenClaw Native Plugin

Install SecOpsAI directly as an OpenClaw plugin for seamless integration without manual virtualenv management:

```bash
openclaw plugins install secopsai
```

### Available Plugin Tools

| Tool | Description |
|------|-------------|
| `secopsai_list_findings` | List findings with optional severity filter |
| `secopsai_refresh` | Run the detection pipeline to refresh findings |
| `secopsai_show_finding` | Get detailed information about a specific finding |
| `secopsai_triage` | Set disposition, status, and add analyst notes |
| `secopsai_check_threats` | Check for malware or exfiltration indicators |
| `secopsai_mitigate` | Get recommended mitigation steps for a finding |
| `secopsai_search` | Search findings by keyword or pattern |
| `secopsai_stats` | Get statistics about the SOC database |

### Configuration

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "secopsai": {
        "enabled": true,
        "config": {
          "secopsaiPath": "~/secopsai",
          "socDbPath": "~/secopsai/data/openclaw/findings/openclaw_soc.db"
        }
      }
    }
  },
  "tools": {
    "allow": ["secopsai_triage"]
  }
}
```

See [docs/OpenClaw-Plugin.md](docs/OpenClaw-Plugin.md) for detailed usage.

---

## CLI: `secopsai`

This project exposes a first-class CLI, `secopsai`, for OpenClaw and host-platform workflows. It provides collection, findings review, correlation, threat-intel commands, and both pretty and JSON output. The CLI is installed into the project's virtualenv by `install.sh`.

Usage examples (after activating venv):

```bash
# 1) Run the default pipeline and persist findings
secopsai refresh
secopsai refresh --skip-export       # reuse existing native export
secopsai refresh --platform macos    # collect from a specific platform adapter

# 2) List and inspect findings (auto-refresh with cache)
secopsai list --severity high
secopsai list --severity high --json
secopsai list --severity high --cache-ttl 300   # reuse refresh from last 5 minutes

secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
secopsai check --type malware --severity high

# All subcommands accept --json for machine-friendly output
# (works either before or after the subcommand)
secopsai show OCF-XXXX --json
secopsai --json show OCF-XXXX
secopsai check --type malware --severity high --json
```

---

## 🧷 Dashboard Integration (Paperclip)

SecOpsAI Dashboard now includes Paperclip-style hierarchical organization:

- **Executive** (Agents Orchestrator) at top
- **Departments**: Platform, Security, Product, Revenue, Support
- **Visual connectors** between hierarchy levels
- **Role status indicators** (online/busy/offline)
- **Click for details** — stats and recent runs
- **Quick task creation** from any role

### Setup

```bash
cd secopsai-dashboard
./setup-paperclip.sh
python3 dashboard_server.py
```

---

## Sync findings to the dashboard

If you want to publish the local SecOpsAI findings store into the dashboard Supabase `findings` table:

```bash
secopsai sync-findings --dashboard-env ../secopsai-dashboard/.env
```

Direct script usage also works:

```bash
python3 scripts/sync_findings_to_supabase.py --dashboard-env ../secopsai-dashboard/.env
```

Notes:
- the sync prefers the local SQLite SOC store at `data/openclaw/findings/openclaw_soc.db`
- if the DB is missing or empty, it falls back to the latest `openclaw-findings-*.json` bundle
- schema mapping is validated against the dashboard findings migration by default
- use `--dry-run` to validate payload shape without writing
- upserts are idempotent via `external_finding_id`
- set `SUPABASE_SERVICE_ROLE_KEY` for write access; `SUPABASE_ANON_KEY` is accepted as fallback if your project permits inserts
- the script is safe to run when no local findings exist; it exits cleanly with `Nothing to sync`

---

## Security

This repo includes security guardrails and continuous scanning:

- Threat model: `docs/threat-model.md`
- CI security scans (on PRs): Semgrep (SAST), Trivy (dependency scan), and Gitleaks (secrets)

---

## Architecture

```text
                         ┌─────────────────────┐
                         │  Threat Intelligence │
                         │  (CVE, RSS, GitHub) │
                         └──────────┬──────────┘
                                    │
┌──────────────────┐                │        ┌──────────────────┐
│  OpenClaw        │                │        │  macOS Adapter   │
│  Telemetry       │                │        │  (15+ sources)   │
└────────┬─────────┘                │        └────────┬─────────┘
         │                          │                 │
         └────────────────────┬─────┴─────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Normalization     │
                    │  (Unified Schema)  │
                    └─────────┬──────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
┌────────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│ Detection Rules │  │ Correlation     │  │ Adaptive        │
│ (Static + Auto) │  │ Engine          │  │ Intelligence    │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  SQLite SOC Store  │
                    └─────────┬──────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
┌────────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│ CLI / Plugin    │  │ Dashboard       │  │ WhatsApp        │
└─────────────────┘  │ (Supabase)      │  │ Bridge          │
                     └─────────────────┘  └─────────────────┘
```

Core layers:

- **Data adapters**: OpenClaw, macOS, Linux, Windows
- **Supply Chain Security**: npm, PyPI, editor exploit detection
- **Normalization**: unified event schema for shared logic
- **Detection**: rules (static + auto-generated) and findings generation
- **Correlation**: IP/user/time/hash correlation across platforms
- **Adaptive Intelligence**: continuous learning from threat feeds
- **Operator surfaces**: CLI, plugin, WhatsApp, Dashboard

---

## Threat Intelligence (IOC) Pipeline

Security note: the intel pipeline downloads public IOC feeds and stores them locally under `data/intel/`. It does not call paid enrichment APIs by default.

secopsai includes a local-first threat intel pipeline:

- Downloads open-source IOC feeds (URLhaus + ThreatFox)
- Normalizes + de-duplicates indicators
- Optional lightweight enrichment (DNS resolution)
- Matches IOCs against your latest OpenClaw replay events
- Persists matches into the same local SOC store (so `secopsai list/show` can be used)

Examples:

```bash
# Download feeds and store them locally under data/intel/
secopsai intel refresh --json

# (Optional) add local enrichment
secopsai intel refresh --enrich

# List a few stored IOCs
secopsai intel list --limit 20

# Match IOCs against latest replay and persist matches as findings
secopsai intel match --limit-iocs 500 --json
```

---

## Daily Operation

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && python run_openclaw_live.py --skip-export && python soc_store.py list
```

macOS launchd helpers:

```bash
# Install OpenClaw daily collection
bash scripts/install_openclaw_launchd.sh

# Install adaptive intelligence
launchctl load ~/Library/LaunchAgents/com.openclaw.secopsai.adaptive-intel.plist

# Install autoresearch (threshold optimization)
launchctl load ~/Library/LaunchAgents/com.openclaw.secopsai.autoresearch.plist
```

---

## Conversational Commands

- check malware
- check exfil
- list high
- show OCF-...
- triage OCF-...
- mitigate OCF-...

Twilio bridge:

```bash
python twilio_whatsapp_webhook.py --host 127.0.0.1 --port 8091
```

---

## Minimal Files Required to Run

- setup.sh
- run_openclaw_live.py
- detect.py
- ingest_openclaw.py
- openclaw_prepare.py
- openclaw_findings.py
- soc_store.py
- openclaw_plugin.py
- scripts/openclaw_daily.sh
- scripts/install_openclaw_launchd.sh

**New (Adaptive Intelligence):**
- threat_intel_ingestor.py
- adaptive_rule_generator.py
- adaptive_rule_validator.py
- adaptive_intelligence_pipeline.py

**New (Cross-Platform):**
- correlation.py
- adapters/macos/adapter.py

**New (Supply Chain Security):**
- secopsai-toolkit/supply_chain_module.py
- secopsai-toolkit/agents/npm_registry_monitor.py
- secopsai-toolkit/agents/sbom_validator.py
- secopsai-toolkit/agents/runtime_monitor.py
- secopsai-toolkit/agents/threat_intel.py
- secopsai-toolkit/rules/sigma-supply-chain-rules.yml
- secopsai-toolkit/rules/yara-supply-chain-rules.yar
- secopsai-toolkit/playbooks/incident_response.py

Optional chat files:

- whatsapp_openclaw_router.py
- twilio_whatsapp_webhook.py
- scripts/run_twilio_whatsapp_bridge.sh

---

## Docs

- [secopsai-toolkit/README.md](secopsai-toolkit/README.md) — Supply chain security module
- [secopsai-toolkit/SECOPSAI_INTEGRATION.md](secopsai-toolkit/SECOPSAI_INTEGRATION.md) — Integration guide
- [ADAPTIVE_INTELLIGENCE.md](ADAPTIVE_INTELLIGENCE.md) — Continuous learning system
- docs/BEGINNER-LIVE-GUIDE.md
- docs/OpenClaw-Integration.md
- docs/deployment-guide.md
- docs/rules-registry.md
- docs/api-reference.md

---

## Contributing

See CONTRIBUTING.md.

---

## License

MIT (see LICENSE).
