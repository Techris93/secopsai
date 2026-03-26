# Beginner Quickstart

This is the fastest way to get useful value from **SecOpsAI** without learning every feature up front.

SecOpsAI is a local-first security operations toolkit for **OpenClaw, macOS, Linux, and Windows**. It can collect telemetry, generate findings, correlate activity across platforms, and match local activity against threat-intel feeds.

## What this quickstart covers

In about 10 minutes, you will:

1. install SecOpsAI
2. run your first refresh
3. list and inspect findings
4. try cross-platform collection
5. run correlation
6. refresh threat intel and match IOCs

---

## 1. Install SecOpsAI

### Recommended install

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
cd ~/secopsai
source .venv/bin/activate
```

### Manual install

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Confirm the CLI is available:

```bash
secopsai --help
```

You should see commands such as:

- `refresh`
- `live`
- `list`
- `show`
- `mitigate`
- `check`
- `correlate`
- `intel`

---

## 2. Run your first refresh

Start with the default pipeline:

```bash
secopsai refresh
```

This is the easiest first run and is the best place to begin if you are primarily using SecOpsAI with OpenClaw.

---

## 3. Review findings

List findings:

```bash
secopsai list
```

Show only higher-priority findings:

```bash
secopsai list --severity high
```

Inspect one finding in detail:

```bash
secopsai show OCF-XXXX
```

Get mitigation guidance:

```bash
secopsai mitigate OCF-XXXX
```

---

## 4. Try platform-based collection

SecOpsAI can collect from one or more supported platforms using `--platform`.

Supported platform values:

- `openclaw`
- `macos`
- `linux`
- `windows`

Examples:

```bash
secopsai refresh --platform macos
secopsai refresh --platform linux
secopsai refresh --platform windows
secopsai refresh --platform openclaw
```

You can also combine platforms:

```bash
secopsai refresh --platform macos,openclaw
```

---

## 5. Run correlation

After collecting findings from more than one source, run correlation:

```bash
secopsai correlate
```

This helps connect related activity across users, hosts, IPs, time windows, or artifacts.

---

## 6. Refresh threat intel

Pull current IOC feeds:

```bash
secopsai intel refresh
```

List some locally stored indicators:

```bash
secopsai intel list --limit 20
```

Match IOCs against local data:

```bash
secopsai intel match --limit-iocs 500
```

---

## 7. Try live mode

Use live mode to validate collection or observe events in real time:

```bash
secopsai live --platform macos --duration 60
```

You can swap `macos` for any supported platform.

---

## 8. Useful JSON mode

For scripts and automation:

```bash
secopsai --json list
secopsai list --json
secopsai show OCF-XXXX --json
```

---

## 9. Best first walkthrough

If you want one short sequence to try everything important, run:

```bash
cd ~/secopsai
source .venv/bin/activate

secopsai --help
secopsai refresh
secopsai list
secopsai refresh --platform macos,openclaw
secopsai correlate
secopsai intel refresh
secopsai intel match --limit-iocs 500
```

---

## 10. Where to go next

- For full install and setup details: [Getting Started](getting-started.md)
- For platform-by-platform usage: [Operator Runbook](operator-runbook.md)
- For threat-intel details: [Threat Intel](threat-intel.md)
- For deployment patterns: [Deployment Guide](deployment-guide.md)
