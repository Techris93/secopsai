# SecOpsAI Edge

SecOpsAI Edge is the network discovery and sensor module for the SecOpsAI platform. Edge owns authorized LAN discovery, Wi-Fi observations, worker heartbeat, and scan execution. Core owns the canonical asset graph, findings, long-term context, triage, research, and reporting workflows.

The repositories remain separate and do not share a database. They exchange a versioned `secopsai.edge.bundle.v1` contract containing normalized graph nodes, graph edges, and findings. Raw Nmap output, packet captures, and raw scan logs are excluded.

## One-Step Sync From The Edge Repo

From the SecOpsAI Edge repo:

```bash
./scripts/edge core sync --cloud --core-root "$HOME/secopsai" --output edge-bundle.json
```

This exports the normalized Edge bundle, saves it for audit/review, and imports it into this Core local SOC/graph store.

## Supervised Automatic Sync

From the Edge repo, install the platform service that repeats the same versioned export/import safely:

```bash
./scripts/edge core sync-service install --cloud --core-root "$HOME/secopsai" --interval 300
./scripts/edge core sync-service start
./scripts/edge core sync-service status
```

Use `logs`, `run-now`, `stop`, and `uninstall` for recovery. The service uses launchd on macOS and a systemd user timer on Linux. It has a separate lifecycle from the scanner worker and skips overlapping runs. A staged runner avoids macOS Documents-folder privacy failures; configuration and credentials are isolated in separate owner-only JSON files, and the token is never placed in launch arguments.

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
SECOPSAI_EDGE_ACCESS_TOKEN=<workspace-core-export-token> \
secopsai edge sync
```

Or pass values directly:

```bash
secopsai edge sync \
  --edge-api-url https://secopsai-edge-api.onrender.com \
  --access-token <workspace-core-export-token>
```

Create this expiring, revocable token from the Edge dashboard Settings page.
It grants only `core:export` for the selected workspace. The legacy admin-token
environment variable and CLI alias remain temporarily supported for existing
single-workspace installations, but new services should not use them.

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

## Ownership Boundary

| Surface | Owner |
|---|---|
| LAN and Wi-Fi collection | Edge sensor |
| Scan jobs, schedules, and worker health | Edge API |
| Raw scan minimization | Edge agent |
| Canonical findings and analyst disposition | Core |
| Asset graph and long-term change context | Core |
| Unified asset/finding operator workspace | SecOpsAI dashboard |
| Scan, schedule, and sensor administration | Edge dashboard |
| Local automation and approval-gated actions | OpenClaw plugin |

The canonical SecOpsAI dashboard now consumes Core graph assets, graph changes,
and Edge-origin findings, with optional server-side enrichment from the Edge
API for live sensor operations. The Edge dashboard remains the administration
surface for scans, schedules, and sensor recovery. Edge credentials are held by
the helper service and are never exposed to the browser.
