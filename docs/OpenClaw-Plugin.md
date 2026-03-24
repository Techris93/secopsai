# OpenClaw Native Plugin

SecOpsAI is available as a first-class OpenClaw plugin, providing native TypeScript-based tools that integrate directly with OpenClaw's plugin system. This offers a more seamless experience than the Python CLI approach.

## Installation

Install from npm/ClawHub:

```bash
openclaw plugins install secopsai
```

Or install directly from npm:

```bash
npm install -g secopsai
openclaw plugins install -l /path/to/secopsai
```

## Configuration

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "secopsai": {
        "enabled": true,
        "config": {
          "secopsaiPath": "~/secopsai",
          "socDbPath": "~/secopsai/data/openclaw/findings/openclaw_soc.db"
        }
      }
    }
  },
  "tools": {
    "allow": ["secopsai_triage"]
  }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `secopsaiPath` | `~/secopsai` | Path to secopsai installation |
| `socDbPath` | `~/secopsai/data/openclaw/findings/openclaw_soc.db` | Path to SOC SQLite database |

**Note:** The `secopsai_triage` tool is marked as optional and requires explicit opt-in via `tools.allow` because it performs write operations on the SOC database.

## Available Tools

### secopsai_list_findings

List SecOps findings with optional severity filter.

**Parameters:**
- `severity` (optional): Filter by severity (`info`, `low`, `medium`, `high`, `critical`)
- `cacheTtl` (optional): Cache time-to-live in seconds (default: 60)

**Example:**
```
secopsai_list_findings severity=high
```

### secopsai_refresh

Run the SecOpsAI detection pipeline to refresh findings.

**Parameters:** None

**Example:**
```
secopsai_refresh
```

### secopsai_show_finding

Get detailed information about a specific finding.

**Parameters:**
- `findingId`: The finding ID (e.g., `OCF-A1B2C3D4`)

**Example:**
```
secopsai_show_finding findingId=OCF-A1B2C3D4
```

### secopsai_triage

Triage a finding by setting disposition, status, and adding notes.

**Parameters:**
- `findingId`: The finding ID (e.g., `OCF-A1B2C3D4`)
- `disposition`: Classification (`true_positive`, `false_positive`, `benign`)
- `status`: New status (`open`, `triaged`, `closed`)
- `note` (optional): Analyst note

**Example:**
```
secopsai_triage findingId=OCF-A1B2C3D4 disposition=false_positive status=closed note="Benign misconfiguration"
```

**Safety:** This tool requires explicit opt-in via `tools.allow` configuration.

### secopsai_check_threats

Check for malware or exfiltration indicators.

**Parameters:**
- `type`: Type of check (`malware`, `exfil`, `both`)
- `severity` (optional): Minimum severity threshold (`info`, `low`, `medium`, `high`)

**Example:**
```
secopsai_check_threats type=exfil severity=high
```

### secopsai_mitigate

Get recommended mitigation steps for a finding.

**Parameters:**
- `findingId`: The finding ID (e.g., `OCF-A1B2C3D4`)

**Example:**
```
secopsai_mitigate findingId=OCF-A1B2C3D4
```

### secopsai_search

Search findings by keyword or pattern.

**Parameters:**
- `query`: Search query string
- `severity` (optional): Filter by severity

**Example:**
```
secopsai_search query="unauthorized" severity=high
```

### secopsai_stats

Get statistics about the SOC database.

**Parameters:** None

**Example:**
```
secopsai_stats
```

## Prerequisites

The plugin requires a working secopsai installation:

1. Install secopsai first:
   ```bash
   curl -fsSL https://secopsai.dev/install.sh | bash
   ```

2. Ensure the virtual environment is set up at `~/secopsai/.venv/`

3. The plugin will automatically activate the virtualenv when running commands.

## Comparison: Plugin vs CLI

| Feature | Native Plugin | Python CLI |
|---------|--------------|------------|
| Installation | `openclaw plugins install` | `curl \| bash` + virtualenv |
| Tool discovery | Automatic | Manual wrapper scripts |
| Configuration | `openclaw.json` | Environment variables |
| Output format | Native OpenClaw format | Pretty + JSON |
| Write safety | Optional tool opt-in | Manual confirmation |
| Automation | Cron-friendly | Script-friendly |

## Troubleshooting

### "secopsai command not found"

Ensure secopsai is installed and the path in `openclaw.json` is correct:
```bash
ls -la ~/secopsai/.venv/bin/secopsai
```

### "Permission denied" on triage

Add `secopsai_triage` to `tools.allow` in `openclaw.json`.

### Database not found

Verify the `socDbPath` configuration matches your actual database location:
```bash
find ~/secopsai -name "*.db" 2>/dev/null
```

## See Also

- [OpenClaw Integration Guide](OpenClaw-Integration.md) — Python CLI approach
- [API Reference](api-reference.md) — Complete API documentation
- [Deployment Guide](deployment-guide.md) — Production deployment
