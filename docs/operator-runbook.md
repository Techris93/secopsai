# Operator Runbook

This runbook explains how to use **SecOpsAI** as an operator across **OpenClaw, macOS, Linux, and Windows**.

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
secopsai refresh --platform macos,openclaw
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
secopsai refresh --platform macos,openclaw
secopsai correlate
```

### Best for

- host activity validation
- process and system event review
- comparing host events with OpenClaw telemetry

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
secopsai refresh --platform macos,linux,windows,openclaw
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

## 8. Automation and JSON mode

For automation and integrations:

```bash
secopsai --json list
secopsai list --json
secopsai show OCF-XXXX --json
secopsai intel match --limit-iocs 500 --json
```

---

## 9. Repo-local development wrapper

For development from the repository:

```bash
python3 cli.py --help
python3 cli.py refresh --platform macos,openclaw
python3 cli.py correlate
```

For normal operator use, prefer:

```bash
secopsai ...
```

---

## 10. Recommended operating patterns

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
secopsai refresh --platform macos,linux,windows,openclaw
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

## 11. Practical guidance

- Start with one source before enabling everything.
- Use `refresh` and `list` as your default workflow.
- Use `live` for validation, not as your only review surface.
- Use `correlate` after you already have findings from more than one source.
- Use threat intel to enrich your investigations, not replace them.
- Reduce noisy detections before relying on dashboards or alert summaries.

---

## 12. Related documentation

- [Beginner Quickstart](quickstart-beginner.md)
- [Getting Started](getting-started.md)
- [Threat Intel](threat-intel.md)
- [Deployment Guide](deployment-guide.md)
- [OpenClaw Plugin](OpenClaw-Plugin.md)
