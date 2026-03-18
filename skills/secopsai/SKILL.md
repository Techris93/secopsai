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

## Assumptions

- `secopsai` is installed at `~/secopsai` (via `curl -fsSL https://secopsai.dev/setup.sh | sh`).
- OpenClaw audit logs are present at `~/.openclaw/logs/`.
- The agent has access to an `exec` tool to run shell commands.

---

## Command Mappings

### 1. Show findings

**User phrases:**

- "show findings"
- "show today's findings"
- "list findings"
- "what findings do we have"

**Exec command:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && python soc_store.py list
```

**Agent behaviour:**

Parse each `OCF-...` line into ID, severity, status, disposition, title. Reply with:

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
cd "$HOME/secopsai" && source .venv/bin/activate && python run_openclaw_live.py --skip-export && python soc_store.py list
```

**Agent behaviour:**

- Run pipeline, then re-list findings.
- Highlight new or HIGH findings.

Example reply:

> Daily SecOps summary: 3 findings (2 HIGH, 1 MEDIUM).
> - HIGH: OCF-C9D2523C770B6731 — OpenClaw Dangerous Exec / Tool Burst
> - HIGH: OCF-62FA8D1D3578BF6E — OpenClaw Sensitive Config
> Reply `triage OCF-...` to mark as reviewed, or `mitigate OCF-...` for remediation steps.

---

### 3. Triage a finding

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
cd "$HOME/secopsai" && source .venv/bin/activate && python openclaw_plugin.py show OCF-<ID>
```

**Agent behaviour:**

Parse and summarise the JSON: title, severity, status, disposition, rule IDs, event count, first/last seen.

---

### 5. Check for malware or exfil

**User phrases:**

- "check malware"
- "check exfil"
- "check both"
- "any malware findings?"

**Exec command pattern:**

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && python openclaw_plugin.py check --type <malware|exfil|both> --severity medium
```

**Agent behaviour:**

Parse the JSON (`matched_count`, `high_or_above`, `top_matches`) and reply with a compact summary:

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
cd "$HOME/secopsai" && source .venv/bin/activate && python openclaw_plugin.py mitigate OCF-<ID>
```

**Expected JSON fields:** `finding_id`, `title`, `severity`, `recommended_actions` (list of strings).

**Agent behaviour:**

Reply with a numbered list of the `recommended_actions`. Example:

> Mitigation steps for **OCF-C9D2523C770B6731** (HIGH — OpenClaw Dangerous Exec / Tool Burst):
> 1. Identify which agent or skill issued the dangerous execs and confirm business justification.
> 2. If unauthorized, disable or restrict that skill/tool configuration in OpenClaw.
> 3. Rotate any secrets used in the commands (tokens, SSH keys, API keys).
> 4. Add stricter policy/approval requirements for high-risk exec operations.

If `recommended_actions` is empty or missing:

> No curated mitigation steps are available yet for this finding.
> Recommended next steps: review the associated events, confirm if the behaviour is expected, and restrict any over-permissive skills or credentials used.

---

## Daily Summary (OpenClaw cron)

Configure an OpenClaw cron job:

- **Schedule:** `30 7 * * *` (07:30 local)
- **Action (systemEvent text):**

```text
[SECOPSAI_DAILY_SUMMARY] Run: cd "$HOME/secopsai" && source .venv/bin/activate && python run_openclaw_live.py --skip-export && python soc_store.py list. Then summarise new/HIGH findings and send here.
```

When this fires the agent should:

1. Execute the command via `exec`.
2. Parse `soc_store.py list` output.
3. Post a summary: total count, HIGH/MEDIUM breakdown, top finding IDs with titles.
4. Invite the user to `triage OCF-...` or `mitigate OCF-...` any flagged item.
