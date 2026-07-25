# Hermes Agent Integration

SecOpsAI monitors local Hermes Agent activity and makes normalized security context available inside Hermes through a read-only plugin.

The integration has three parts:

1. SecOpsAI Core collects and detects against Hermes telemetry.
2. A background service refreshes that telemetry every five minutes.
3. The Hermes plugin reads normalized findings, sessions, triage counts, and Edge asset context from Core.

Package code, raw network scans, Hermes credentials, and arbitrary shell commands are not exposed to the plugin.

## Requirements

- Hermes Agent 0.18.2 or later
- macOS, Linux, or Windows with WSL2
- Python 3.10 or later
- Git, Bash, curl, and pip
- An initialized Hermes home directory, normally `~/.hermes`

Check Hermes before installation:

```bash
hermes --version
hermes status
```

## One-Command Installation

```bash
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

The installer:

- installs the immutable SecOpsAI v1.0.0 release under `~/secopsai`;
- creates the Python virtual environment;
- installs and enables the native read-only Hermes plugin;
- verifies Hermes telemetry access and version compatibility;
- performs one bounded initial refresh;
- installs a launchd service on macOS or a systemd user timer on Linux/WSL2;
- starts five-minute monitoring;
- prints status, findings, logs, update, and uninstall commands.

The command is idempotent. Re-running it updates the tagged Core installation, reinstalls the plugin, and replaces the service definition without deleting findings or logs.

## Verify The Installation

```bash
cd ~/secopsai
.venv/bin/python -m secopsai.cli hermes doctor
hermes plugins list
.venv/bin/python -m secopsai.cli hermes service status
```

A healthy doctor result confirms:

- Hermes 0.18.2 or later is available;
- `HERMES_HOME` exists;
- at least one supported telemetry source is readable;
- credential files remain excluded;
- the Hermes plugin is installed and enabled;
- the monitor service is installed;
- the latest refresh state is available.

## First Findings Workflow

Run a refresh immediately:

```bash
cd ~/secopsai
.venv/bin/python -m secopsai.cli hermes refresh
```

List Hermes findings without triggering another refresh:

```bash
.venv/bin/python -m secopsai.cli list --platform hermes --no-refresh
```

Inspect a finding:

```bash
.venv/bin/python -m secopsai.cli show <finding-id> --no-refresh
```

If no findings appear, the integration can still be healthy. SecOpsAI stores findings only when a high-signal Hermes rule matches. Routine logs remain local context and are not promoted automatically.

## Background Service

The default refresh interval is 300 seconds. Each run is bounded and protected by an owner-only lock, so overlapping runs are skipped.

```bash
cd ~/secopsai
.venv/bin/python -m secopsai.cli hermes service status
.venv/bin/python -m secopsai.cli hermes service run-now
.venv/bin/python -m secopsai.cli hermes service logs
.venv/bin/python -m secopsai.cli hermes service stop
.venv/bin/python -m secopsai.cli hermes service start
```

To install a different interval, use at least 60 seconds:

```bash
.venv/bin/python -m secopsai.cli hermes service install --interval 600
```

macOS uses `~/Library/LaunchAgents/ai.secopsai.hermes-monitor.plist`. Logs are stored under `~/Library/Logs/SecOpsAI/`.

Linux and WSL2 use:

- `~/.config/systemd/user/secopsai-hermes-monitor.service`
- `~/.config/systemd/user/secopsai-hermes-monitor.timer`
- `journalctl --user -u secopsai-hermes-monitor.service`

## Native Hermes Tools

The plugin exposes only fixed, read-only SecOpsAI commands:

| Tool | Purpose |
|---|---|
| `secopsai_hermes_status` | Show integration, plugin, service, and refresh health |
| `secopsai_hermes_findings` | List findings produced from Hermes telemetry |
| `secopsai_list_findings` | List minimized Core findings with bounded filters |
| `secopsai_show_finding` | Inspect one minimized finding |
| `secopsai_triage_summary` | Read finding, asset, research, and queue counts |
| `secopsai_session_list` | List investigation sessions |
| `secopsai_session_show` | Inspect one investigation session |
| `secopsai_asset_summary` | List minimized Edge assets from the Core graph |

Start Hermes and ask it to use the SecOpsAI toolset, for example:

```text
Check SecOpsAI Hermes integration health and show the latest Hermes findings.
```

The plugin cannot refresh telemetry, run a network scan, close a finding, send a disclosure, publish content, or execute an arbitrary command.

## Data Collected

The adapter reads existing local telemetry only:

| Source | Default path |
|---|---|
| Command history | `~/.hermes/.hermes_history` |
| Agent log | `~/.hermes/logs/agent.log` |
| Error log | `~/.hermes/logs/errors.log` |
| Gateway logs | `~/.hermes/logs/gateway.log` and related gateway logs |
| Session state | `~/.hermes/sessions/sessions.json` |
| Request failure metadata | `~/.hermes/sessions/request_dump_*.json` |
| Gateway state | `~/.hermes/gateway_state.json` |

SecOpsAI never collects:

- `~/.hermes/auth.json`;
- `~/.hermes/.env`;
- provider credential stores;
- raw authorization headers;
- raw request bodies;
- model credentials.

Request dumps are reduced to redacted failure metadata before persistence. Token-like values are removed before normalized events or findings are stored.

## Detection Coverage

| Rule | Detects |
|---|---|
| `RULE-120` Hermes Dangerous Tool Call | Pipe-to-shell, reverse-shell, destructive, or staged interpreter patterns |
| `RULE-121` Hermes Credential Exfiltration | Credential discovery followed by archive, upload, token handling, or outbound transfer behavior |
| `RULE-122` Hermes Request Dump Secret Leak | Token-like material that remains visible after redaction |

The rules are intentionally high-signal. Model errors, missing credits, normal gateway startup, and routine channel activity are not findings by default.

## Custom Installation Paths

Set custom paths before running the installer:

```bash
SECOPSAI_HOME=/opt/secopsai \
HERMES_HOME=/srv/hermes \
SECOPSAI_HERMES_REFRESH_SECONDS=600 \
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

When Hermes starts, `SECOPSAI_HOME` must point to the same Core installation if it is not `~/secopsai`.

## Updates

Re-run the installer to restore the tagged Core release, plugin, and service configuration:

```bash
curl -fsSL https://secopsai.dev/install-hermes.sh | bash
```

Update only the plugin:

```bash
hermes plugins update secopsai
```

## Recovery

If health is degraded:

```bash
cd ~/secopsai
.venv/bin/python -m secopsai.cli hermes doctor
.venv/bin/python -m secopsai.cli hermes service logs
hermes plugins list
hermes doctor
```

For a custom Hermes location:

```bash
HERMES_HOME=/path/to/hermes-home .venv/bin/python -m secopsai.cli hermes doctor
```

If the service definition is damaged, reinstall it without removing findings:

```bash
.venv/bin/python -m secopsai.cli hermes service install
```

## Uninstall

Remove the monitor and plugin while retaining Core findings and logs:

```bash
cd ~/secopsai
.venv/bin/python -m secopsai.cli hermes service uninstall
hermes plugins remove secopsai
```

The installer does not automatically delete `~/secopsai`, the SQLite SOC store, or service logs. Remove retained data only after reviewing your evidence and retention requirements.

## Platform Notes

- macOS requires a logged-in user session for the launchd user agent.
- Linux requires a working systemd user session.
- Windows uses the Linux installation inside WSL2. Native Windows service installation is not provided in v1.0.0.
- Hermes support remains Beta until it has broader external deployment evidence.
