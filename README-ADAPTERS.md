# SecOpsAI Universal Adapters

Multi-platform security monitoring with unified detection.

## Supported Platforms

| Platform | Source | Events |
|----------|--------|--------|
| OpenClaw | Audit logs | 4,402 |
| macOS | Unified logs | 400+ |
| Linux | journalctl/auditd | Available |
| Windows | Event Logs/Sysmon | Available |

## Quick Start

```bash
# Refresh all supported adapters
secopsai refresh --platform openclaw,macos,linux,windows

# Refresh specific platform
secopsai refresh --platform macos
secopsai refresh --platform openclaw
secopsai refresh --platform macos,openclaw

# Live streaming
secopsai live --platform macos

# List findings
secopsai list
secopsai list --platform macos

# Cross-platform correlation
secopsai correlate
```

For repo-local development, `python3 cli.py ...` calls the same unified `secopsai` command surface.
