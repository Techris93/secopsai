# Threat Model: SecOpsAI (OpenClaw sidecar)

This is a pragmatic threat model for the SecOpsAI product and its default deployment:

- Local-first secops pipeline (`secopsai` CLI)
- OpenClaw runtime delivery (e.g., WhatsApp)
- Local SOC store (SQLite)
- Threat intel IOC pipeline (URLhaus/ThreatFox)
- Optional scheduled automation (cron)

## System overview

### Components

- **User / Operator**: runs `secopsai` locally; may interact via WhatsApp.
- **OpenClaw**: runtime and conversational delivery layer.
- **SecOpsAI CLI**: local pipeline runner + findings UI.
- **Local storage**:
  - `data/openclaw/...` (replay bundles)
  - `data/openclaw/findings/openclaw_soc.db` (SOC store)
  - `data/intel/*` (IOC cache)
- **Installer**:
  - `https://secopsai.dev/install.sh` (bootstrap) → clones repo and runs `setup.sh`.
- **Feeds**:
  - URLhaus / ThreatFox (public IOC feeds).

### Trust boundaries

1) **Internet → local host**
   - Installer downloads
   - IOC feeds downloads
2) **Local host → OpenClaw runtime**
   - Agent executes commands and posts summaries
3) **User input → shell execution**
   - Chat prompts can cause command execution if not gated

## Data classification

- OpenClaw logs/audit: **sensitive** (may contain tokens, commands, internal hostnames)
- Findings DB: **sensitive** (security posture + evidence)
- IOC cache: **public data** but correlated matches are **sensitive**

## STRIDE analysis (summary)

| Threat | Component | Risk | Why it matters | Mitigations |
|---|---|---:|---|---|
| Spoofing | WhatsApp / OpenClaw chat | High | attacker impersonates operator → triggers actions | verify sender identity, require confirmation for write actions, limit command set |
| Tampering | SOC store (SQLite) | Med | malicious/accidental edits affect triage history | file permissions, backups, append-only audit log for triage changes |
| Repudiation | Triage actions | Med | no proof who changed status/disposition | log operator identity + timestamp, store immutable audit trail |
| Info disclosure | Logs / findings / reports | High | leaks internal commands, secrets, incident details | redact secrets, least-privilege log access, avoid sending raw logs over chat |
| Denial of service | IOC refresh / matching | Med | huge feeds / repeated runs consume CPU/disk | rate limit, size limits, caching TTL, run under controlled account |
| Elevation of privilege | Agent shell exec | Critical | agent can run arbitrary commands if misconfigured | restrict exec tool, require explicit confirmation, allowlist commands, run as non-admin user |

## Key risks + concrete mitigations

### 1) `curl | bash` installer provenance (supply chain)

**Risk:** executing remote code without verification.

**Mitigations:**
- Prefer a pinned git ref by default (already supported via `SECOPSAI_INSTALL_REF`).
- Recommend manual clone + inspect `docs/install.sh` + `setup.sh`.
- Consider signed releases or package manager distribution (brew/apt) for stronger provenance.

### 2) Agent can run shell commands

**Risk:** chat-driven automation can become remote code execution.

**Mitigations:**
- Default to read-only operations (`list/show/check`).
- Require explicit user confirmation before any write/triage action.
- Implement a strict allowlist (only `secopsai ...` commands) for agent execution.
- Run OpenClaw + secopsai under a dedicated low-privilege OS user.

### 3) Sensitive data in findings and WhatsApp summaries

**Risk:** leaking internal commands/tokens.

**Mitigations:**
- Redact obvious secrets from command strings before persisting or sending.
- Provide “short summary” messages by default.
- Keep detailed evidence local; send IDs + high-level titles over chat.

### 4) Threat intel ingestion abuse

**Risk:** malicious feed content, huge downloads, poisoned IOCs.

**Mitigations:**
- Enforce HTTPS-only, allowlist feed domains.
- Size limits + timeouts + caching.
- Treat IOC matches as *signals*; require human review for high-impact actions.

### 5) Scheduled jobs

**Risk:** unattended automation runs at bad times / wrong account.

**Mitigations:**
- Ensure cron runs under a controlled account.
- Back up `openclaw_soc.db` before enabling unattended automation.
- Emit “dry-run” summaries by default; require confirmation for writes.

## Verification checklist

- [ ] HSTS + CSP set for `secopsai.dev` and `docs.secopsai.dev`
- [ ] CI security scanning enabled (Semgrep/Trivy/Gitleaks)
- [ ] No secrets in repo history (gitleaks)
- [ ] Agent execution restricted (allowlist) + explicit confirmation for writes
- [ ] SOC DB backed up before automation
- [ ] Installer provenance documented (pinned ref + manual install path)
