# Hermes Agent Integration

SecOpsAI supports Hermes Agent as a local-first telemetry source alongside
OpenClaw and host adapters for macOS, Linux, and Windows.

The Hermes adapter is read-only. It does not execute Hermes, run tools, install
packages, call model APIs, or modify Hermes configuration. It reads local
telemetry that Hermes already writes and converts it into SecOpsAI's shared
event schema for detection, triage, and correlation.

## What SecOpsAI Collects

By default, `secopsai refresh --platform hermes` reads:

| Source | Path | Purpose |
|---|---|---|
| Hermes command history | `~/.hermes/.hermes_history` | Operator prompts and command-like history entries |
| Agent logs | `~/.hermes/logs/agent.log` | Agent and tool execution status |
| Error logs | `~/.hermes/logs/errors.log` | Agent errors and failed tool calls |
| Gateway logs | `~/.hermes/logs/gateway.log` | Gateway/channel/session lifecycle events |
| Session state | `~/.hermes/sessions/sessions.json` | Session metadata, platform, and chat type |
| Request dumps | `~/.hermes/sessions/request_dump_*.json` | Redacted API failure metadata |
| Gateway state | `~/.hermes/gateway_state.json` | Local gateway state |

SecOpsAI intentionally does not read `~/.hermes/auth.json`, `~/.hermes/.env`, or
provider credential stores.

## Quick Start

```bash
cd ~/secopsai
source .venv/bin/activate

secopsai refresh --platform hermes
secopsai list --platform hermes
secopsai show SCX-XXXX
```

To combine Hermes with OpenClaw and host telemetry:

```bash
secopsai refresh --platform hermes,openclaw,macos
secopsai correlate
```

If Hermes is installed somewhere other than `~/.hermes`, set:

```bash
HERMES_HOME=/path/to/hermes-home secopsai refresh --platform hermes
```

## Detection Coverage

The first Hermes rules are intentionally high-signal:

| Rule | Detects |
|---|---|
| `RULE-120` Hermes Dangerous Tool Call | Pipe-to-shell, reverse-shell, destructive, or staged interpreter command patterns |
| `RULE-121` Hermes Credential Exfiltration | Credential-file discovery plus archive/upload, GitHub token handling, or outbound transfer behavior |
| `RULE-122` Hermes Request Dump Secret Leak | Token-like material that remains visible after SecOpsAI redaction |

Routine model errors, missing credits, gateway startup messages, and normal
Telegram/channel activity are collected for context but are not findings by
default.

## Redaction And Safety

The Hermes adapter redacts token-like values before normalized events are stored.
It also summarizes request dumps instead of preserving raw message bodies or
headers. Findings include safe command/evidence snippets, not raw credentials.

Keep these defaults:

- Do not sync raw Hermes logs to third-party systems without review.
- Use SecOpsAI findings and redacted evidence for triage.
- Rotate credentials if `RULE-121` or `RULE-122` fires.
- Treat channel/session identity as part of incident context.

## Operator Workflow

1. Run `secopsai refresh --platform hermes`.
2. Review Hermes findings with `secopsai list --platform hermes`.
3. Inspect evidence with `secopsai show <finding-id>`.
4. Correlate with OpenClaw or host telemetry if the same user, session, path, or
   time window appears elsewhere.
5. If credential access is suspected, rotate affected tokens and temporarily
   disable the relevant Hermes channel/toolset while investigating.

## Troubleshooting

If Hermes is not detected:

```bash
ls ~/.hermes
HERMES_HOME=~/.hermes secopsai refresh --platform hermes
```

If no findings appear, that can be healthy. SecOpsAI still collected context,
but only high-confidence Hermes abuse patterns are promoted to findings.
