# Correlation Engine

SecOpsAI includes a cross-platform correlation engine that looks for higher-signal patterns across findings from multiple telemetry sources.

## What it correlates

The current correlation model focuses on patterns such as:

- same IP observed across multiple platforms
- same user active across multiple platforms
- clusters of findings in a shared time window
- shared file hashes across hosts or sources

These correlations help identify activity that may not appear suspicious when viewed from a single platform alone.

## Example use cases

### Lateral movement

A source IP observed in macOS, Linux, and Windows telemetry within a short time window may indicate lateral movement or coordinated access.

### Credential abuse

The same username appearing across multiple systems in unusual contexts may indicate compromised credentials.

### Coordinated attack execution

Multiple related events grouped in a tight time range can indicate a campaign or chained operator actions.

### Malware spread

A repeated file hash or related artifact across platforms may suggest malware propagation.

## CLI usage

```bash
python3 cli.py correlate
python3 cli.py correlate --window 60
```

## Alerting

When correlations are found, SecOpsAI can generate operator-facing notifications, including WhatsApp alerts, to surface high-value findings quickly.

## Operational guidance

Correlation quality improves as more findings accumulate over time. In a fresh deployment, you may see zero or few correlations initially because the engine needs multiple findings or platforms to identify shared patterns.
