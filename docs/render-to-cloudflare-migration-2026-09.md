# Render to Cloudflare migration, September 2026

## Scope and decisions

Only SecOpsAI resources were reviewed. Unrelated Render services were excluded.

| Render resource | Decision | Reason |
|---|---|---|
| `secopsai-core-api` | Migrate to Cloudflare Worker and D1 | Production traffic used a narrow signed webhook and read-only snapshot surface that fits Workers and D1. |
| `secopsai-research-worker` | Keep on Render | The continuous worker has a roughly 4.09 GB SQLite database, a 5 GB persistent disk, and long-running artifact work. Free D1 is too small and Workers Paid/Containers is not enabled. |
| `secopsai-edge-api` | Retire | The suspended FastAPI/PostgreSQL stack is not the active Mission Control data path. Rewriting more than 100 dormant routes into D1 would preserve duplicate architecture rather than reduce cost. |
| `secopsai-edge-scheduler` | Retire | It only called the suspended Edge API maintenance routes. |
| `secopsai-edge-postgres` | Retire after verified export | The dormant Edge database was the remaining cost behind the suspended stack. |
| Legacy `secopsai-chatgpt-app` | Retired | Replaced in source by the provider-neutral `secopsai-mcp-gateway`. Deploy the gateway only after OAuth issuer/JWKS, explicit clients, tenant binding, and Core credentials are configured. |
| legacy `secopsai` worker | Retire | It came from the obsolete `secops-autoresearch` repository and recent production logs repeatedly reported zero input records and zero detections. |

The retirement completed on 4 September 2026. Render now lists only
`secopsai-research-worker` among SecOpsAI services, and no SecOpsAI PostgreSQL
database or shared environment group remains.

## Core migration evidence

The replacement is `cloudflare/secopsai-core-edge` at
`https://core.secopsai.dev`, backed by D1 database
`a293a7e9-cc36-44e4-8bcd-2877337bf3dd`.

The Render Core snapshot was archived privately in the
`secopsai-migration-backups` R2 bucket. The archive SHA-256 is:

```text
1e925730b0f349044cdb027b05537c1fb8acb857e9a3e8dca6fdd19158cda351
```

The remote D1 import reconciled to:

- 118 workspace records: 4 assets, 110 findings, 1 site, 1 sensor, 1 service,
  and 1 sync-state record.
- 124 research alerts.
- 125 audit records.

Live validation confirmed public health and readiness, HTTP 401 for an
unauthenticated workspace read, HTTP 200 for authenticated workspace and audit
reads, and idempotent signed-alert delivery (`created=true`, then
`created=false`). The canary alert and its two audit records were removed after
the check, restoring the imported counts.

## Edge backup evidence

The Edge PostgreSQL export contains schema metadata and table CSVs for all 25
tables. Its private R2 archive SHA-256 is:

```text
345161e4a819d08adfa751093ef3acad17abdcee12a612c55492773771f979d5
```

The archive was downloaded from remote R2 and its checksum was recomputed
successfully. The temporary `/32` database access rule used for export was
removed; the database IP allowlist returned to empty.

The legacy worker and suspended ChatGPT deployment metadata/log archives were
also uploaded to private R2 and downloaded for checksum verification:

```text
legacy worker: b5e365fe9506a7987afa39ef395ef2039325439a1bfc381988263ed71da81b95
ChatGPT app:   82634b8707d0bdaae1b3e5f248e9d25739033a8937ef74041cb4b9cfa545a3b2
```

The preserved legacy log window contained 1,000 lines and repeatedly reported
zero records written, zero input events, and zero detections. The suspended
ChatGPT service had no log entries in the same window.

After cutover, a full research-worker cycle completed with Go, npm, and NuGet
collector coverage marked complete and storage pressure false. npm artifact
enrichment remained degraded because ten pre-existing analyses failed; that is
an application backlog issue, not a Core migration or delivery failure.

## Safety boundaries

- No package, artifact, extension, payload, or lifecycle script was executed.
- Secrets were transferred directly between owner-only files and provider
  secret stores; they were not printed or committed.
- The Core replacement accepts only the alert types already accepted by the
  Python Core API and enforces the same 64 KB body and five-minute replay limits.
- The research worker was not forced into an unsuitable serverless datastore.
- Cloudflare Containers were not enabled because they require Workers Paid and
  no billing change was authorized.

## Remaining migration work

Moving `secopsai-research-worker` requires one of these separately approved
paths:

1. Enable Workers Paid, benchmark Cloudflare Containers with a durable external
   database/object-store design, and migrate after parity and rollback tests.
2. Redesign the collector ledger into bounded, sharded D1 databases plus Queues,
   R2, and Workflows, then prove throughput and cost before cutover.

Until then, Render owns only the stateful research worker. Cloudflare owns the
public sites, dashboard, blog, Core Edge Worker, D1 Core store, and private
migration backups.
