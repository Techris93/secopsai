# Operator Runbook

This runbook explains how to use **SecOpsAI** as an operator across **OpenClaw, Hermes Agent, macOS, Linux, and Windows**.

SecOpsAI is a local-first security operations toolkit that can:

- collect telemetry from multiple platforms
- normalize events into a shared model
- generate and store findings locally
- correlate activity across platforms
- ingest and match threat-intelligence indicators
- support review and response workflows through the CLI and related surfaces

---

## 1. Core workflow

Most day-to-day usage looks like this:

1. collect data with `refresh`
2. review findings with `list`
3. inspect details with `show`
4. get guidance with `mitigate`
5. correlate across sources with `correlate`
6. enrich detection with `intel`

---

## 2. Main command surface

### Refresh

Run collection and detection:

```bash
secopsai refresh
```

Collect from specific platforms:

```bash
secopsai refresh --platform macos
secopsai refresh --platform linux
secopsai refresh --platform windows
secopsai refresh --platform openclaw
secopsai refresh --platform hermes
secopsai refresh --platform macos,openclaw,hermes
```

### Live

Stream adapter activity in real time:

```bash
secopsai live --platform macos --duration 60
```

### Findings

```bash
secopsai list
secopsai list --severity high
secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
secopsai check --type malware
secopsai check --type exfil
```

### Correlation

```bash
secopsai correlate
secopsai correlate --window 60
```

### Threat intel

```bash
secopsai intel refresh
secopsai intel list --limit 20
secopsai intel match --limit-iocs 500
```

---

## 3. Platform workflows

## OpenClaw

Use this path when you want to monitor OpenClaw telemetry and findings first.

### Typical workflow

```bash
secopsai refresh
secopsai list
secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
```

### Best for

- agent and tool telemetry
- policy denials
- OpenClaw-native audit workflows
- local review and triage

---

## macOS

Use this when you want host telemetry from a Mac.

### Typical workflow

```bash
secopsai refresh --platform macos
secopsai live --platform macos --duration 60
secopsai list --platform macos
```

### Cross-platform example

```bash
secopsai refresh --platform macos,openclaw,hermes
secopsai correlate
```

### Best for

- host activity validation
- process and system event review
- comparing host events with OpenClaw telemetry

---

## Hermes Agent

Use this when monitoring Hermes Agent local telemetry and tool-call behavior.

### Typical workflow

```bash
secopsai refresh --platform hermes
secopsai list --platform hermes
secopsai show SCX-XXXX
```

### Cross-platform example

```bash
secopsai refresh --platform hermes,openclaw,macos
secopsai correlate
```

### Best for

- Hermes agent history and session review
- tool-call misuse detection
- credential discovery or exfiltration behavior
- comparing Hermes activity against OpenClaw or host telemetry

---

## Linux

Use this when monitoring Linux host telemetry.

### Typical workflow

```bash
secopsai refresh --platform linux
secopsai live --platform linux --duration 60
secopsai list --platform linux
```

### Cross-platform example

```bash
secopsai refresh --platform linux,openclaw
secopsai correlate
```

### Best for

- system/service/process activity
- server-side host review
- cross-host incident reconstruction

---

## Windows

Use this when monitoring Windows host telemetry.

### Typical workflow

```bash
secopsai refresh --platform windows
secopsai live --platform windows --duration 60
secopsai list --platform windows
```

### Cross-platform example

```bash
secopsai refresh --platform windows,openclaw
secopsai correlate
```

### Best for

- Windows event review
- host-level suspicious behavior
- comparing Windows activity against other sources

---

## 4. Multi-platform operations

This is the recommended path when you want the full value of SecOpsAI.

### Example

```bash
secopsai refresh --platform macos,linux,windows,openclaw,hermes
secopsai list
secopsai correlate
```

### Why use this

Multi-platform operation helps you spot:

- same user across different systems
- same IP across multiple telemetry sources
- clustered activity in a time window
- shared artifacts across hosts
- weak signals that become meaningful when combined

---

## 5. Investigation workflow

When a finding appears:

### Step 1: list findings

```bash
secopsai list
```

### Step 2: inspect a finding

```bash
secopsai show OCF-XXXX
```

### Step 3: get recommended actions

```bash
secopsai mitigate OCF-XXXX
```

### Step 4: check related detection categories

```bash
secopsai check --type malware
secopsai check --type exfil
```

### Step 5: correlate if needed

```bash
secopsai correlate
```

---

## 6. Threat-intel workflow

### Refresh feeds

```bash
secopsai intel refresh
```

### List stored indicators

```bash
secopsai intel list --limit 20
```

### Match against local data

```bash
secopsai intel match --limit-iocs 500
```

### Use when

- you want current public indicators
- you want local IOC matching
- you want extra context for investigations

---

## 7. Live validation workflow

Use `live` to verify collection and observe activity while testing.

Examples:

```bash
secopsai live --platform openclaw --duration 60
secopsai live --platform hermes --duration 60
secopsai live --platform macos --duration 60
secopsai live --platform linux --duration 60
secopsai live --platform windows --duration 60
```

Use this when:

- onboarding a new host
- validating permissions and visibility
- checking noise levels
- reproducing suspicious activity

---

## 8. Specialist Orchestrator workflow

Use Specialist Orchestrator when a Work item needs domain-specific analysis or
a bounded repository change through the selected OpenCodex model.

1. In Mission Control, open **Work** and confirm the selected model and fallback
   policy shown in **Specialist Orchestrator**.
2. Open a work item, select **Open work brief**, and review the recommended primary
   specialist, independent reviewer, routing reasons, evidence gaps, and risk.
3. Use **Recommendation only** while scope is incomplete. Use **Read-only
   analysis** for diagnosis that must not edit the repository.
4. Use **Isolated worktree** or **PR-ready delivery** only for bounded edits.
   Confirm the reviewed base commit and file limit, approve the captured
   contract, then start execution as a separate action.
5. Inspect tests, the local diff, audit history, and independent review. The
   orchestrator never commits, pushes, merges, deploys, publishes, discloses,
   accesses secrets, or mutates external infrastructure.
6. Cancel queued runs from the brief when they are no longer needed. SecOpsAI
   cancels the linked queued model job too; an active model job must stop or be
   recovered before cancellation can complete safely.

CLI preview:

```bash
secopsai specialists route \
  --input-json '{"title":"Review the failed CI gate","repo_alias":"secopsai","evidence_refs":["run:473"]}' \
  --tier read_only --json
```

Guarded automation may create recommendation or read-only runs only:

```bash
secopsai specialists policy \
  --mode guarded --maximum-automatic-tier read_only --json
```

See [Specialist Orchestrator](specialist-orchestrator.md) for profile
provenance, model routing, worktree approval, recovery, and troubleshooting.

---

## 9. Automation and JSON mode

For automation and integrations:

```bash
secopsai --json list
secopsai list --json
secopsai show OCF-XXXX --json
secopsai intel match --limit-iocs 500 --json
```

To keep the local refresh pipeline running on a Mac every 5 minutes with the repo virtual environment:

```bash
bash scripts/install_secopsai_agent_launchd.sh
```

Optional overrides:

```bash
SECOPSAI_REFRESH_PLATFORMS=macos,linux,openclaw,hermes \
SECOPSAI_REFRESH_INTERVAL_SECONDS=600 \
	bash scripts/install_secopsai_agent_launchd.sh
```

The installer writes `~/Library/LaunchAgents/com.secopsai.agent.plist`, reloads the job, and sends output to `logs/agent.log` and `logs/agent.error.log` inside the repo.

---

## 10. Repo-local development wrapper

For development from the repository:

```bash
python3 cli.py --help
python3 cli.py refresh --platform macos,openclaw,hermes
python3 cli.py correlate
```

For normal operator use, prefer:

```bash
secopsai ...
```

---

## 11. Recommended operating patterns

### Beginner operator

```bash
secopsai refresh
secopsai list
```

### OpenClaw-focused operator

```bash
secopsai refresh
secopsai list --severity high
secopsai show OCF-XXXX
```

### Cross-platform operator

```bash
secopsai refresh --platform macos,linux,windows,openclaw,hermes
secopsai correlate
secopsai list
```

### Threat-hunting operator

```bash
secopsai intel refresh
secopsai intel match --limit-iocs 500
secopsai correlate
```

### Validation / tuning operator

```bash
secopsai live --platform macos --duration 60
secopsai live --platform linux --duration 60
```

---

## 12. Practical guidance

- Start with one source before enabling everything.
- Use `refresh` and `list` as your default workflow.
- Use `live` for validation, not as your only review surface.
- Use `correlate` after you already have findings from more than one source.
- Use threat intel to enrich your investigations, not replace them.
- Reduce noisy detections before relying on dashboards or alert summaries.

---

## 13. Related documentation

- [Beginner Quickstart](quickstart-beginner.md)
- [Getting Started](getting-started.md)
- [Threat Intel](threat-intel.md)
- [Deployment Guide](deployment-guide.md)
- [OpenClaw Plugin](OpenClaw-Plugin.md)
- [Hermes Integration](Hermes-Integration.md)
- [Specialist Orchestrator](specialist-orchestrator.md)
