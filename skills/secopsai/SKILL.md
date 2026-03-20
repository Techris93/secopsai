---
name: secopsai
description: "Conversational SecOps for OpenClaw audit logs. Run the live detection pipeline, inspect findings, triage incidents, and get mitigation guidance — all from chat."
---

# SecOpsAI Skill for OpenClaw

This skill lets an OpenClaw agent:

- Run the secopsai OpenClaw detection pipeline
- List and summarise findings from the local SOC store
- Triage findings by ID (disposition + status + note)
- Get structured mitigation steps for any finding
- Run a local-first threat intelligence (IOC) pipeline and match IOCs against OpenClaw replay

## Assumptions

- `secopsai` is installed at `~/secopsai`, preferably via a transparent repo checkout / manual setup flow such as:
  - `git clone https://github.com/Techris93/secopsai.git ~/secopsai`
  - `cd ~/secopsai && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- OpenClaw audit logs are present at `~/.openclaw/logs/` on the same host.
- The agent has access to an `exec` tool to run shell commands.
- The virtualenv at `~/secopsai/.venv` is used for all commands.

If installation guidance is needed, prefer pointing users to the GitHub repo/manual setup path first. Only mention the hosted installer as an optional shortcut, not the default recommendation.

---

## Safety defaults (read this)

This skill can run shell commands and can modify the local SOC store when performing triage.

- Prefer **read-only** operations by default (`list/show/check`).
- Before any write/triage action (`set-status`, `set-disposition`, `add-note`), require explicit user confirmation.
- If you enable scheduled jobs, ensure they run under a controlled account and that automated writes are intended.
- Backup the SOC DB (`data/openclaw/findings/openclaw_soc.db`) before enabling unattended automation.

## Command Mappings

### 1. Show findings

**User phrases:**

- "show findings"
- "show today's findings"
- "list findings"
- "what findings do we have"

**Exec command:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
  secopsai list --severity info --json --cache-ttl 60
```

(`--json` also works before the subcommand, e.g. `secopsai --json list ...`.)

**Agent behaviour:**

- Parse the JSON payload from `secopsai list` (field: `findings`).
- For each finding, extract: `finding_id`, `severity`, `status`, `disposition`, `title`.
- Reply with:
  - Total count
  - Count by severity (HIGH / MEDIUM / LOW / INFO)
  - List of HIGH (and MEDIUM) findings with ID and title

---

### 2. Run daily pipeline

**User phrases:**

- "run daily pipeline"
- "run secops scan"
- "refresh findings"
- "run live"

**Exec command:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
  secopsai refresh --json && \
  secopsai list --severity high --json --cache-ttl 300
```

**Agent behaviour:**

- Run the pipeline once (`refresh`) and then list current high-severity findings.
- From the `list` JSON output, highlight NEW or HIGH/CRITICAL findings (based on
  `first_seen`/`last_seen` fields when available).

Example reply:

> Daily SecOps summary: 3 high-severity findings.
>
> - HIGH: OCF-C9D2523C770B6731 — OpenClaw Dangerous Exec / Tool Burst (status=open)
> - HIGH: OCF-62FA8D1D3578BF6E — OpenClaw Sensitive Config (status=open)
>
> Reply `triage OCF-...` to mark as reviewed, or `mitigate OCF-...` for remediation steps.

---

### 3. Triage a finding (WRITE)

Important: this modifies the local SOC store. Confirm with the user before running.

**User phrases:**

- `triage OCF-<ID>`
- `triage OCF-<ID> note "your note here"`

**Exec command pattern:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
python soc_store.py set-disposition OCF-<ID> true_positive && \
python soc_store.py set-status OCF-<ID> triaged && \
python soc_store.py add-note OCF-<ID> analyst "<note text or 'validated via chat'>"
```

**Agent behaviour:**

Run all three commands in sequence. Confirm back:

> Triage complete: OCF-<ID> → disposition=true_positive, status=triaged.

---

### 4. Show a single finding in detail

**User phrases:**

- `show OCF-<ID>`
- `details OCF-<ID>`

**Exec command:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
  secopsai show OCF-<ID> --json
```

**Agent behaviour:**

Parse and summarise the JSON: title, severity, status, disposition, rule IDs,
number of events, first/last seen. Prefer the structured fields from
`secopsai show` and avoid re-parsing raw text.

---

### 5. Check for malware or exfil

**User phrases:**

- "check malware"
- "check exfil"
- "check both"
- "any malware findings?"

**Exec command pattern:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
  secopsai check --type <malware|exfil|both> --severity medium --json --cache-ttl 60
```

**Agent behaviour:**

Parse the JSON (`check` payload: `findings_total`, `matched_count`,
`high_or_above`, `top_matches`) and reply with a compact summary:

> Malware check: 2 matching findings (1 HIGH).
> Top: OCF-C9D2523C770B6731, HIGH — OpenClaw Dangerous Exec / Policy Denials.

---

### 6. Mitigate a finding (recommended actions)

**User phrases:**

- `mitigate OCF-<ID>`
- `show mitigation OCF-<ID>`
- `what should I do for OCF-<ID>`

**Exec command:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
  secopsai mitigate OCF-<ID> --json --cache-ttl 60
```

**Expected JSON fields:** `finding_id`, `title`, `severity`, `status`,
`disposition`, `rule_ids`, `recommended_actions` (list of strings).

**Agent behaviour:**

Reply with a numbered list of the `recommended_actions`. Example:

> Mitigation steps for **OCF-C9D2523C770B6731** (HIGH — OpenClaw Dangerous Exec / Tool Burst):
>
> 1. Identify which agent or skill issued the dangerous execs and confirm business justification.
> 2. If unauthorized, disable or restrict that skill/tool configuration in OpenClaw.
> 3. Rotate any secrets used in the commands (tokens, SSH keys, API keys).
> 4. Add stricter policy/approval requirements for high-risk exec operations.

If `recommended_actions` is empty or missing:

> No curated mitigation steps are available yet for this finding.
> Recommended next steps: review the associated events, confirm if the behaviour is expected, and restrict any over-permissive skills or credentials used.

---

## Threat Intel (IOCs)

### 7. Refresh IOC feeds

**User phrases:**

- "refresh intel"
- "update iocs"
- "pull threat intel"

**Exec command:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
  secopsai intel refresh --json
```

**Agent behaviour:**

- Parse JSON and report total IOCs and any feed errors.
- Do not call external paid enrichment APIs by default.

### 8. Match IOCs against OpenClaw replay

**User phrases:**

- "match intel"
- "check iocs"
- "any intel matches"

**Exec command:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && \
  secopsai intel match --limit-iocs 500 --json
```

**Agent behaviour:**

- Parse `matched_findings`.
- If matches exist, list the top 3 `TI-...` finding IDs and titles and offer `show TI-...`.

## Daily Summary (OpenClaw cron)

Configure an OpenClaw cron job to drive the `secopsai` CLI and produce a
concise chat summary.

- **Schedule:** `30 7 * * *` (07:30 local)
- **Action (systemEvent text):**

```text
[SECOPS_DAILY_SUMMARY_TRIGGER] Run the SecOpsAI pipeline and summarise new/high
findings for this chat.

Suggested steps for the agent:
1) cd "$HOME/secopsai" && source .venv/bin/activate
2) secopsai refresh --json
3) secopsai list --severity high --json --cache-ttl 300
4) Focus on high/critical findings first_seen in the last 24h.
5) Post a compact summary back into this conversation.
```

When this fires the agent should:

1. Execute the `secopsai` commands via `exec`.
2. Parse the JSON findings payload from `secopsai list --severity high --json`.
3. Post a summary: total count, HIGH/CRITICAL breakdown, and top finding IDs with
   titles and status.
4. Invite the user to `triage OCF-...` or `mitigate OCF-...` any flagged item.
