# SecOpsAI Edge Integration

SecOpsAI Core can import Edge asset graphs and findings into the local SOC SQLite store.

## One-Step Sync From The Edge Repo

From the SecOpsAI Edge repo:

```bash
./scripts/edge core sync --cloud --core-root /Users/chrixchange/secopsai --output edge-bundle.json
```

This exports the normalized Edge bundle, saves it for audit/review, and imports it into this Core local SOC/graph store.

## Import A Bundle

```bash
secopsai edge import --bundle edge-bundle.json
```

Use a custom SOC/graph database:

```bash
secopsai edge import --bundle edge-bundle.json --db-path /path/to/openclaw_soc.db
```

## Sync From Edge API

```bash
SECOPSAI_EDGE_API_URL=https://secopsai-edge-api.onrender.com \
SECOPSAI_EDGE_ADMIN_TOKEN=<admin-token> \
secopsai edge sync
```

Or pass values directly:

```bash
secopsai edge sync \
  --edge-api-url https://secopsai-edge-api.onrender.com \
  --admin-token <admin-token>
```

## Inspect The Graph

```bash
secopsai graph assets
secopsai graph show 192.168.1.50
secopsai graph changes
```

## Review Edge Findings

```bash
secopsai triage list --source secopsai_edge
secopsai triage investigate EDGE-...
```

Core stores Edge findings with stable `EDGE-...` identifiers and preserves analyst triage state on re-sync.
