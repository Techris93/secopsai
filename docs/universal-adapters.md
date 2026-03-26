# Universal Adapters

SecOpsAI includes a universal adapter architecture for collecting security-relevant telemetry from multiple platforms and normalizing it into a shared schema.

## Implemented Adapters

| Adapter | Source | Status | Notes |
|---|---|---:|---|
| `openclaw` | OpenClaw audit logs | ✅ Production | Native audit and session telemetry |
| `macos` | macOS unified logging | ✅ Production | Security, auth, and process events |
| `linux` | journalctl / auditd | ✅ Beta | Linux host telemetry |
| `windows` | Event Logs / Sysmon | ✅ Beta | Windows host telemetry |

## Core Design

The adapter system is built around a shared base class and registry pattern:

- `adapters/base.py` defines `BaseAdapter`
- `AdapterRegistry` provides dynamic adapter lookup and instantiation
- each adapter implements:
  - `collect()` for historical/batch collection
  - `stream()` for live event streaming where available
  - `normalize()` for conversion into the unified event schema

## Unified Event Schema

All adapters normalize events into `schemas/unified_event.schema.json`.

Common fields include:

- `timestamp`
- `event_type`
- `platform`
- `source`
- `host`
- `event_id`
- `actor`
- `target`
- `outcome`
- `severity`
- `metadata`

This allows shared detection and correlation logic across telemetry sources.

## CLI Usage

The packaged `secopsai` command is the canonical CLI for both the OpenClaw pipeline and the universal adapter workflow.

Examples:

```bash
# refresh specific platforms
secopsai refresh --platform macos
secopsai refresh --platform openclaw
secopsai refresh --platform macos,openclaw

# live stream from an adapter
secopsai live --platform macos --duration 60

# list findings
secopsai list
secopsai list --platform macos

# run cross-platform correlation
secopsai correlate
```

For repo-local development, `python3 cli.py ...` remains a thin wrapper around the same packaged command surface.

## Platform Notes

### OpenClaw

The OpenClaw adapter reads local audit logs and maps telemetry such as tool invocations, config changes, and sessions into the unified schema.

### macOS

The macOS adapter reads unified logging and can collect or stream host events relevant to authentication, privilege use, and security-relevant processes.

### Linux

The Linux adapter uses `journalctl` and `auditd`-style sources. It is designed for Linux deployment targets and correlates host activity with SecOpsAI findings.

### Windows

The Windows adapter is designed around Event Logs and Sysmon-style telemetry, enabling a Windows host to participate in the shared detection and correlation model.

## Why this matters

The universal adapter model shifts SecOpsAI from an OpenClaw-only detector into a broader local-first security monitoring platform.

That enables:

- host + OpenClaw visibility in one place
- shared detection logic across sources
- cross-platform correlation workflows
- a cleaner path toward future telemetry sources and optional SIEM export
