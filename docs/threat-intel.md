# Threat Intelligence (IOC) Pipeline

secopsai includes a local-first threat intelligence pipeline that can:

1) Aggregate IOCs from open-source feeds
2) Normalize + de-duplicate + score them
3) Optionally enrich them with lightweight local OSINT (DNS resolution)
4) Match IOCs against your latest OpenClaw replay events
5) Persist any matches as findings in the local SOC store

## Security model (important)

- **Local-first**: IOC data is stored locally under `data/intel/`.
- **No paid enrichment APIs by default**: optional enrichment is DNS-only unless you add external integrations.
- **Be deliberate about automation**:
  - Matching results are written into the SOC store (SQLite).
  - If running via an agent, prefer read-only operations by default and require explicit confirmation for writes/triage.

## Quick start

After installation:

```bash
cd ~/secopsai
source .venv/bin/activate
```

### Refresh feeds

```bash
secopsai intel refresh
```

JSON output:

```bash
secopsai intel refresh --json
```

### Optional local enrichment (DNS)

```bash
secopsai intel refresh --enrich
```

### List a few IOCs

```bash
secopsai intel list --limit 20
```

### Match IOCs to your OpenClaw replay

```bash
secopsai intel match --limit-iocs 500
```

JSON output:

```bash
secopsai intel match --limit-iocs 500 --json
```

### Where matches land

Matches are persisted into the same SOC DB used by the rest of secopsai:

- `data/openclaw/findings/openclaw_soc.db`

You can review them using:

```bash
secopsai list --severity low --no-refresh
secopsai show TI-... --no-refresh
```
