# OpenClaw Integration (Conversational SecOps)

This guide shows how to wire **secopsai** into an existing **OpenClaw** deployment using the real Python CLIs:

- `run_openclaw_live.py` — live detection pipeline
- `soc_store.py` — findings store and triage
- `openclaw_plugin.py` — high-level malware/exfil/mitigation checks

---

## 1. Install secopsai

Run the one-line install on the **same machine** as your OpenClaw gateway:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

Fallback (manual clone + install.sh):

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai
curl -fsSL https://secopsai.dev/install.sh | bash
```

From now on, activate the virtualenv (created by `install.sh`) before running any commands:

```bash
cd secopsai
source .venv/bin/activate
```

---

## 2. Run the OpenClaw live pipeline (CLI-first)

Recommended entrypoint is the `secopsai` CLI, which runs the same five steps
in-process and writes structured metadata about the refresh.

```bash
# Full live run (export + ingest + prepare + detect + findings)
secopsai refresh

# If you have already exported from ~/.openclaw and just want to re-run
# ingest/prepare/detect/findings, skip the export step:
secopsai refresh --skip-export

# For automation/integrations, use JSON output:
secopsai refresh --json
```

Under the hood this runs the same sequence as before:

1. `export_real_openclaw_native.py` — pulls telemetry from `~/.openclaw`
2. `ingest_openclaw.py` — normalises into an audit stream
3. `openclaw_prepare.py` — builds replay bundles
4. `evaluate_openclaw.py` — runs detectors in live mode
5. `openclaw_findings.py` — writes findings (with mitigations) into the local SOC store

You can still call the script directly if needed:

```bash
python run_openclaw_live.py
python run_openclaw_live.py --skip-export
```

At the end, inspect the findings store:

```bash
secopsai list --severity high
# or, for raw store listing
python soc_store.py list
```

---

## 3. Inspect and triage findings (`soc_store` CLI)

Security note: triage operations modify the local SOC store (SQLite). If you are running secopsai via an agent, prefer read-only operations by default and require explicit user confirmation before any triage/write action.

**List all findings:**

```bash
python soc_store.py list
```

Example output:

```
OCF-62FA8D1D3578BF6E | HIGH     | status=open    | disposition=unreviewed   | OpenClaw Sensitive Config
OCF-C9D2523C770B6731 | HIGH     | status=open    | disposition=unreviewed   | OpenClaw Dangerous Exec / OpenClaw Tool Burst
OCF-478C69DCE3A33CC7 | INFO     | status=triaged | disposition=true_positive | OpenClaw Data Exfiltration
total_findings=14
```

**Show a single finding in full:**

```bash
python soc_store.py show OCF-62FA8D1D3578BF6E
```

**Triage:**

```bash
# Mark disposition
python soc_store.py set-disposition OCF-62FA8D1D3578BF6E true_positive

# Update status
python soc_store.py set-status OCF-62FA8D1D3578BF6E triaged

# Add analyst note
python soc_store.py add-note OCF-62FA8D1D3578BF6E analyst "validated via manual review"
```

---

## 4. High-level checks via the OpenClaw plugin facade

### Presence checks

```bash
# Malware only (high or above)
python openclaw_plugin.py check --type malware --severity high

# Exfil only (medium or above)
python openclaw_plugin.py check --type exfil --severity medium

# Both malware + exfil (any severity)
python openclaw_plugin.py check --type both

# List all HIGH+ findings
python openclaw_plugin.py list-high
```

**Output (JSON):**

```json
{
  "check_type": "malware",
  "findings_total": 14,
  "matched_count": 2,
  "high_or_above": 1,
  "top_matches": [
    {
      "finding_id": "OCF-C9D2523C770B6731",
      "severity": "HIGH",
      "status": "open",
      "disposition": "unreviewed",
      "title": "OpenClaw Dangerous Exec / OpenClaw Policy Denials",
      "first_seen": "...",
      "last_seen": "..."
    }
  ]
}
```

### Mitigation steps

```bash
python openclaw_plugin.py mitigate OCF-C9D2523C770B6731
```

**Output:**

```json
{
  "finding_id": "OCF-C9D2523C770B6731",
  "title": "OpenClaw Dangerous Exec / OpenClaw Tool Burst",
  "severity": "HIGH",
  "status": "open",
  "disposition": "unreviewed",
  "rule_id": "RULE-109",
  "recommended_actions": [
    "Identify which agent or skill issued the dangerous execs and confirm business justification.",
    "If unauthorized, disable or restrict that skill/tool configuration in OpenClaw.",
    "Rotate any secrets used in the commands (tokens, SSH keys, API keys).",
    "Add stricter policy/approval requirements for high-risk exec operations."
  ]
}
```

If no curated steps exist for the detected rule, the output will include generic fallback guidance.

---

## 5. Daily summary via OpenClaw cron

Security note: if you enable a scheduled job, ensure it runs under a controlled account and that automated writes/triage are intended. Backup your SOC store (`data/openclaw/findings/openclaw_soc.db`) before enabling unattended automation.

Configure an OpenClaw cron job to run the pipeline and post a summary every morning:

- **Schedule:** `30 7 * * *` (07:30 local)
- **Action (systemEvent text):**

```text
[SECOPSAI_DAILY_SUMMARY] Run:
  cd "$HOME/secopsai" && source .venv/bin/activate &&
  python run_openclaw_live.py --skip-export &&
  python soc_store.py list
Then summarise new/HIGH findings and send a message here.
```

When this fires, the agent should:

1. Execute the command via `exec`.
2. Parse `soc_store.py list` output.
3. Post a short summary:

> SecOpsAI: 14 findings total. New today: 2 (1 HIGH, 1 MEDIUM).
>
> - HIGH: OCF-C9D2523C770B6731 — OpenClaw Dangerous Exec / OpenClaw Tool Burst  
>   Reply `triage OCF-C9D2523C770B6731` to mark as true_positive+triaged.

---

## 6. For OpenClaw gateway operators

Running alongside an existing gateway:

- **Port separation:** secopsai uses no open ports by default; its Twilio bridge (if enabled) listens on a configurable local port (default `127.0.0.1:8091`) behind ngrok.
- **State directory:** `data/openclaw/` — keep it outside the gateway's writable path to avoid conflicts.
- **Recommended pattern:** one secopsai sidecar per gateway host. The sidecar reads from `~/.openclaw/logs/` and writes findings to its own SQLite store.
- **To confirm everything is wired up:**

```bash
python openclaw_plugin.py check --type both
# Should return a JSON object with findings_total > 0 after the first live run.
```
