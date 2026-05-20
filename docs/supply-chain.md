# Supply Chain Security

SecOpsAI includes a comprehensive **Supply Chain Security Module** that detects and mitigates attacks targeting software dependencies, package registries, and developer tools.

## Overview

Supply chain attacks have grown 742% since 2024. SecOpsAI adds a critical defense layer by detecting malicious packages at install time, before they can compromise your systems.

### What We Detect

| Attack Vector | Examples | Detection Method |
|--------------|----------|------------------|
| **npm packages** | axios@1.14.1, plain-crypto-js | Known malicious DB + heuristics |
| **PyPI packages** | litellm@1.82.7 | .pth file monitoring + imports |
| **crates.io** | Rust crates | Advisory matching + `build.rs`/proc-macro local rules |
| **Chrome Web Store** | Browser extensions | Advisory matching + manifest/permission/background-script rules |
| **Packagist** | Composer PHP packages | Advisory matching + Composer script/PHP source rules |
| **Go Modules** | Go module paths | Advisory matching + go.mod/init/process/network/env rules |
| **Hugging Face Hub** | Models and repos | Advisory matching + unsafe loading/custom-code metadata rules |
| **Maven Central** | Java artifacts | Advisory matching + POM/plugin/source behavior rules |
| **NuGet** | .NET packages | Advisory matching + nuspec/PowerShell/build-target rules |
| **Open VSX** | VS Code extensions | Advisory matching + activation/workspace/token rules |
| **RubyGems.org** | Ruby gems | Advisory matching + gemspec/extconf/Rake/Ruby source rules |
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

## Emergency Advisory Denylists

Some registry compromises are cleaned up quickly, which means the malicious artifact may be removed before SecOpsAI can fetch both versions and generate a diff. Emergency advisories close that gap by turning source-backed package/version intelligence into high-confidence findings.

```bash
# Check a removed/yanked compromised version without needing the artifact.
secopsai supply-chain advisory check --ecosystem npm --package @opensearch-project/opensearch --version 3.8.0

# Explain the verdict, including source URLs, IOCs, confidence, and mitigation.
secopsai supply-chain explain-verdict --ecosystem pypi --package guardrails-ai --version 0.10.1

# Upgrade historical "diff generation failed" rows when a new advisory matches.
secopsai supply-chain reconcile-history --include-advisories
```

See [Emergency Supply Chain Advisories](supply-chain-advisories.md) for the full operator workflow and JSON schema.

## Ecosystem Capability Matrix

```bash
secopsai supply-chain ecosystems
secopsai supply-chain ecosystems --ecosystem maven
```

npm and PyPI support full live metadata/artifact fetch, deterministic diff
analysis, advisory matching, SOC finding creation, and registry monitoring.
SecOpsAI also has live, no-execution adapters for crates.io, Packagist, Go
Modules, Hugging Face Hub, Maven Central, NuGet, Open VSX, and RubyGems.org.
Chrome Web Store scanning supports exported local CRX/ZIP artifacts because
stable unauthenticated CRX download is not reliable from server-side registry
metadata. Unsupported live monitoring returns a clear limitation instead of
failing obscurely.

Per-ecosystem operator examples:

```bash
secopsai supply-chain explain-verdict --ecosystem crates --package secopsai-fixture-crate --version 1.2.3
secopsai supply-chain explain-verdict --ecosystem chrome-web-store --package fixtureextensionid --version 4.5.6
secopsai supply-chain explain-verdict --ecosystem packagist --package vendor/fixture --version 1.0.0
secopsai supply-chain explain-verdict --ecosystem go --package github.com/example/fixture --version v1.2.3
secopsai supply-chain explain-verdict --ecosystem huggingface --package secopsai/fixture-model --version main
secopsai supply-chain explain-verdict --ecosystem maven --package com.example:fixture --version 2.0.0
secopsai supply-chain explain-verdict --ecosystem nuget --package fixture.package --version 3.0.0
secopsai supply-chain explain-verdict --ecosystem open-vsx --package secopsai.fixture --version 0.1.0
secopsai supply-chain explain-verdict --ecosystem rubygems --package fixture_gem --version 9.9.9
```

For non-npm/PyPI ecosystems, use these commands with advisory-backed versions
or live package identifiers. SecOpsAI fetches and unpacks artifacts into
temporary directories, blocks archive path traversal/symlinks, enforces
download/file-count limits, and never executes package, model, build, extension,
or install code.

Local artifact scanning is available when you have a CRX/ZIP/VSIX/JAR/NUPKG/GEM
or other supported archive:

```bash
secopsai supply-chain scan --ecosystem chrome-web-store --package <extension-id> --version <version> --artifact exported-extension.zip
secopsai supply-chain scan --ecosystem open-vsx --package namespace.extension --version 1.2.3 --artifact extension.vsix --previous-artifact previous.vsix
```

## Changelog Workflow

Record user-visible supply-chain changes in `CHANGELOG.md` before release.

```bash
python3 scripts/changelog_entry.py --section Security --message "Documented a new emergency advisory campaign."
```

Use:

- `Added` for new commands, adapters, workflows, or public features.
- `Changed` for behavior changes.
- `Fixed` for bug fixes.
- `Security` for detection, triage, hardening, advisory, or mitigation work.
- `Docs` for operator/documentation-only changes.
- `Internal` for test, refactor, or maintenance notes.

## Package-Scoped Registry Watch

Use the package-scoped registry watcher when a high-risk package publishes new
versions and you want fast deterministic analysis without executing package
code.

```bash
# Dry-run recent node-ipc publishes from npm registry metadata.
secopsai supply-chain watch-registry --ecosystem npm --package node-ipc --since 10m --dry-run --json

# Watch a package-scoped crates.io release feed.
secopsai supply-chain watch-registry --ecosystem crates --package serde --since 2h --dry-run --json

# Watch Packagist/Composer metadata.
secopsai supply-chain watch-registry --ecosystem packagist --package vendor/package --since 1d --dry-run --json

# Persist scan history and SOC findings only after you are ready to mutate local state.
secopsai supply-chain watch-registry --ecosystem npm --package node-ipc --since 2h --persist
```

The watcher reads package-scoped registry metadata, identifies versions inside
the requested lookback window where timestamps are available, compares each
version with the previous publish, and runs the same deterministic package-diff
rules used by `scan` and `explain-verdict`. NuGet has limited publish timestamp
data in the flat-container API, so SecOpsAI reports version-delta monitoring for
that ecosystem. It does not install or execute suspicious packages.

For node-ipc-style compromises, SecOpsAI looks for:

- Obfuscated appended JavaScript payloads in built bundles such as `node-ipc.cjs`.
- Import/module-load execution through IIFEs or self-executing CommonJS code.
- Host fingerprinting via OS APIs.
- Local file enumeration of `.ssh`, `.npmrc`, `.env`, lockfiles, and cloud config paths.
- `process.env` harvesting of GitHub, npm, cloud, SSH, or CI/CD credentials.
- Payload wrapping or exfiltration staging with network APIs.

Absence of local lockfile usage lowers environment impact, but it does not erase
package-level maliciousness when advisory or strong behavioral evidence exists.

## Cross-Ecosystem Campaign Research

Use campaign research when one actor, maintainer, namespace, C2 server, or
external report links multiple suspicious packages. This workflow works across
all ecosystems reported by `secopsai supply-chain ecosystems`; npm and PyPI can
use live artifacts, while every ecosystem can use advisory data and deterministic
fixture/local-artifact evidence without executing untrusted code.

```bash
secopsai supply-chain research-campaign \
  --input tests/fixtures/deadcode09284814-campaign.json \
  --dry-run \
  --json
```

You can also build a small campaign directly from flags:

```bash
secopsai supply-chain research-campaign \
  --campaign-id deadcode09284814-infostealer-botnet-campaign \
  --source-url https://thehackernews.com/2026/05/four-malicious-npm-packages-deliver.html \
  --actor deadcode09284814 \
  --package npm:chalk-tempalte:0.0.1 \
  --package npm:@deadcode09284814/axios-util:0.0.1 \
  --ioc 87e0bbc636999b.lhr.life \
  --behavior "credential theft" \
  --dry-run
```

Pass `--search-root /path/to/repo` when you want SecOpsAI to check local
manifests and lockfiles. Local usage changes the environment-impact field; it
does not erase package-level maliciousness when advisory or behavioral evidence
is strong.

Campaign JSON supports:

- `campaign_id`, `title`, `summary`, `severity`, `confidence`
- `source_urls` and `source_names`
- `actors`, `publishers`, `iocs`, and `behavioral_indicators`
- `packages`, where each package has `ecosystem`, `package`, `version`,
  optional `publisher`, optional `iocs`, optional `behavioral_indicators`, and
  optional deterministic `files` fixtures for static analysis

SecOpsAI correlates packages by same publisher, shared IOCs, shared source
reports, typosquatting signals, and deterministic behavior such as credential
harvesting, C2 communication, botnet/persistence behavior, install-time
execution, import/module-load execution, build hooks, unsafe model loading, and
extension permission abuse.

Persist findings only after reviewing the dry-run result:

```bash
secopsai supply-chain research-campaign --input campaign.json --persist --search-root /path/to/repo
```

Create a review-only blog draft from the campaign result or from an advisory:

```bash
secopsai blog draft-campaign --campaign tests/fixtures/deadcode09284814-campaign.json
secopsai blog draft-campaign --campaign deadcode09284814-infostealer-botnet-campaign
```

Campaign blog drafts remain private until review and approval. Do not publish
third-party screenshots or article text unless rights and attribution are clear;
use public source URLs as references and summarize findings in SecOpsAI's own
words.

## Autonomous Campaign Discovery

Autonomous discovery reduces manual campaign entry. SecOpsAI can poll the
trusted blog/news source registry, reuse the local news cache, extract
cross-ecosystem package names, IOCs, publishers, behavior signals, and source
links, then score campaign candidates before any SOC write happens.

Discovery is read-only by default:

```bash
secopsai supply-chain discover-campaigns --since 24h --limit 10 --json
secopsai supply-chain campaign-autopilot --since 24h --dry-run --json
```

Use watchlists to raise priority for packages, publishers, source URLs, or IOCs
you care about:

```bash
secopsai supply-chain campaign-watchlist add --package npm:node-ipc
secopsai supply-chain campaign-watchlist add --publisher deadcode09284814
secopsai supply-chain campaign-watchlist add --ioc 87e0bbc636999b.lhr.life
secopsai supply-chain campaign-watchlist list --json
```

Candidate intake can also convert one source report into campaign JSON:

```bash
secopsai supply-chain campaign-intake --url https://example.com/security-report --json
secopsai supply-chain campaign-intake --text report.txt --source-name "Trusted Research Team" --json
```

Promotion and persistence stay explicit:

```bash
secopsai supply-chain campaign-candidates list --json
secopsai supply-chain campaign-candidates promote <candidate-id> --json
secopsai supply-chain campaign-autopilot --since 24h --persist --search-root /path/to/repo --json
secopsai supply-chain campaign-autopilot --since 24h --persist --create-drafts --json
```

Safety model:

- Discovery and dry-run autopilot do not create SOC findings or blog drafts.
- `--persist` is required before campaign findings are written.
- `--create-drafts` only creates review-only drafts and never publishes.
- Only allowlisted sources from `blog/data/news-sources.json` are polled by
  default, and fetched text is sanitized/truncated for dashboard display.
- Discovery emits per-source `source_status` records so stale or failing feeds
  are visible instead of silently producing zero candidates.
- Package code is never executed; campaign research uses deterministic advisory,
  metadata, IOC, and static-behavior evidence.

Recent missed-threat hardening is documented in
`docs/threat-intel-gap-analysis-2026-05.md` and
`docs/missed-threat-validation-report-2026-05.md`. The current rules cover
source-backed GitHub token/repository incidents, orphan commits, VS Code/Open VSX
extension compromise, npm/PyPI lifecycle or import-time execution, and
credential-exfiltration behavior without running untrusted code.

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

- [User Workbook](https://github.com/Techris93/secopsai/blob/main/USER_WORKBOOK.md) - Complete user guide
- [Research Report](https://github.com/Techris93/secopsai/blob/main/research/supply-chain-exploits-report.md) - Technical details
- [SecOpsAI Integration](https://github.com/Techris93/secopsai/blob/main/supply-chain/SECOPSAI_INTEGRATION.md) - Integration guide

## References

- [Axios Supply Chain Attack (March 2026)](https://www.picussecurity.com/resource/blog/axios-npm-supply-chain-attack)
- [CVE-2025-27423](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27423) - Vim tar.vim exploit
- [CVE-2025-1244](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-1244) - Emacs URI handler
