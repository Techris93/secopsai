# Ontology and research automation runbook

This runbook is for the SecOpsAI operator who owns the Core, Pages, and Render
accounts. It keeps the Python research ledger and the hosted operating picture
separate while making their health observable.

## Preflight and backup

1. Confirm the Render research worker is the only process that writes the live
   research database. Do not stop the active bridge or surveillance process
   merely to inspect the database.
2. Create an online SQLite backup with `Connection.backup()` (or the worker's
   existing backup command), outside the repository. Do not copy the live file
   while it is open.
3. Calculate SHA-256, open the backup read-only, and run `PRAGMA quick_check`.
4. Record the backup path, checksum, schema version, row counts, and time in the
   operator change log.

The September 2026 verified backup is kept under the owner-only directory
`/Users/chrixchange/.secopsai-backups/` with its checksum in the adjacent `.sha256`
file. The original ledger remains the canonical history; D1 is not a backup for
the roughly 10 GB SQLite store.

## Local ontology projection

Run the resumable projection in bounded batches:

```bash
cd /Users/chrixchange/secopsai
.venv/bin/python -m secopsai.cli --json ontology backfill \
  --db-path data/openclaw/findings/openclaw_soc.db --batch-limit 1000
```

Checkpoints are stored in `ontology_metadata`. A second run should report zero
new writes. Inspect `ontology quality` for canonical IDs, linked findings,
provenance, orphan records, stale records, and conflicts. Resolve identity
conflicts explicitly with `ontology resolve` and a reviewed `ontology merge`;
never merge solely because two display names look alike.

## Hosted rollout

Apply D1 migrations in a local database, run the Core Edge tests, then apply the
same migrations remotely. Deploy Core Edge and Pages before changing the Render
worker. Required server-side values are:

- Core Edge: `CORE_READ_TOKEN`, `CORE_INTELLIGENCE_TOKEN`,
  `CORE_BRIDGE_TOKEN`, `CORE_WORKSPACE_ID`, optional `CORE_ORGANIZATION_ID`,
  and `RESEARCH_WEBHOOK_SECRET`.
- Pages: `SECOPSAI_CORE_API_URL`, `SECOPSAI_CORE_READ_TOKEN`, and
  `SECOPSAI_CORE_INTELLIGENCE_TOKEN`.
- Runner: `SECOPSAI_CORE_COORDINATOR_URL` (or the Core API URL),
  `SECOPSAI_CORE_BRIDGE_TOKEN`, and a stable worker ID.

Keep tokens in provider secret stores. The browser receives only route
configuration; it never receives a Core credential.

Verify `/healthz`, `/readyz`, authenticated ontology search, entity detail,
bounded neighbors, lineage, quality, and the Mission Control Operating picture
page. Send one signed research-alert canary, repeat the exact request, and
expect the first response to create a record and the second to be idempotent.

## Runner health and degradation

After each collector cycle the runner should publish a heartbeat, queue age,
storage summary, collector status, and a redacted ontology snapshot. Snapshots
carry a stable idempotency key; failed deliveries stay in the bounded local
`ontology_sync_outbox` until Core Edge acknowledges them. A temporary Core or
network failure must leave local collection running and set hosted state to
`degraded`; the next cycle retries. Commands use leases and must end in one of
`succeeded`, `degraded`, `failed`, `canceled`, or `recovered`.

Monitor:

- heartbeat age and last completed collector cycle;
- queued command/job age and stale leases;
- Core Worker errors and D1 read/write counts;
- ontology orphan, stale, conflict, and provenance metrics;
- Render disk usage at 70% warning and 85% pressure;
- webhook HTTP 401/503 responses and signature age failures.

The fresh Render disk procedure is destructive to the rolling operational
buffer. Use it only after the verified backup and provider authorization. Keep
the retention and reserve settings, and prune before the disk reaches the
pressure threshold. Historical research remains in the local canonical backup.

## Recovery

If a hosted deployment fails, redeploy the previous Worker or Pages version and
leave additive ontology tables in place. If the fresh Render worker cannot
start, stop it, inspect logs, and restore the provider snapshot or verified
SQLite backup. Do not delete the only copy of the ledger. If Core is unavailable,
use the local dashboard at `http://127.0.0.1:45680` and continue collection
while the hosted status is degraded.
