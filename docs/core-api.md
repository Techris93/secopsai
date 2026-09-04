# SecOpsAI Core API

The Core API is the protected ingestion and read boundary for the unified
SecOpsAI operator experience. It imports the versioned, normalized Edge bundle
into Core's SQLite asset graph and findings store. It does not accept or expose
raw Nmap output, packet captures, or raw scan logs.

## Local setup

```bash
./scripts/core-api configure-local
./scripts/core-api run
```

In another terminal:

```bash
./scripts/core-api check
```

The generated `.core-api.env` is owner-only and ignored by Git. The service
binds to `127.0.0.1:8010` unless `HOST` or `PORT` is set. Do not bind the local
profile to a public interface.

## Authentication scopes

The API deliberately uses four unrelated bearer credentials:

- `SECOPSAI_CORE_INGEST_TOKEN` can submit normalized Edge bundles only.
- `SECOPSAI_CORE_READ_TOKEN` can read the minimized workspace and API audit log.
- `SECOPSAI_CORE_INTELLIGENCE_TOKEN` can queue, inspect, and cancel approved local intelligence jobs. It cannot read Edge bundles or operate sensors.
- `SECOPSAI_CORE_BRIDGE_TOKEN` can claim and complete queued intelligence jobs from the local Codex bridge. It cannot create jobs or query Core directly.

Neither token grants scanner control. Edge sensor and dashboard credentials
remain separate. Pilot and production startup rejects short or reused configured
credentials and wildcard host/origin settings. Intelligence job routes remain
unavailable until the third credential is configured.

`SECOPSAI_CORE_ORGANIZATION_ID` binds the Core deployment and ingest token to
one Edge workspace. A bundle for any other organization is rejected. This
single-organization boundary is intentional until canonical state moves to a
tenant-aware PostgreSQL design.

`SECOPSAI_CORE_WORKSPACE_ID` binds MCP activity and tool calls to one named
workspace inside that organization. Existing single-workspace deployments
default it to `SECOPSAI_CORE_ORGANIZATION_ID`; set it explicitly before adding
another workspace.

## Endpoints

| Endpoint | Authentication | Purpose |
|---|---|---|
| `GET /healthz` | Public | Process liveness and build version |
| `GET /readyz` | Public | SQLite readiness |
| `POST /api/v1/edge/bundles` | Ingest token | Idempotent normalized Edge import |
| `GET /api/v1/workspace` | Read token | Minimized Core/Edge operator context |
| `GET /api/v1/audit-logs` | Read token | Bundle import audit events |
| `GET /api/v1/intelligence/actions` | Read token | Approved read-only action catalog |
| `POST /api/v1/intelligence/query` | Read token | Deterministic minimized Core query |
| `POST /api/v1/intelligence/jobs` | Intelligence token | Queue an approved local Codex action |
| `GET /api/v1/intelligence/jobs` | Intelligence token | Inspect intelligence queue state |
| `GET /api/v1/intelligence/autopilot` | Intelligence token | Inspect continuous model-triage policy, runs, and tuning proposals |
| `POST /api/v1/intelligence/autopilot/configure` | Intelligence token | Configure off, advisory, or evidence-gated guarded automation |
| `POST /api/v1/intelligence/autopilot/run-now` | Intelligence token | Queue model review for eligible changed findings |
| `GET /api/v1/intelligence/daily` | Intelligence token | Inspect the coordinated daily workflow and step history |
| `POST /api/v1/intelligence/daily/configure` | Intelligence token | Configure the daily schedule and bounded step limits |
| `POST /api/v1/intelligence/daily/run` | Intelligence token | Run the complete coordinated workflow immediately |
| `POST /api/v1/intelligence/autopilot/runs/{run_id}/rollback` | Intelligence token | Restore the pre-decision finding state |
| `POST /api/v1/intelligence/autopilot/tuning/{proposal_id}/rollback` | Intelligence token | Restore the threshold baseline recorded before activation |
| `POST /api/v1/intelligence/jobs/{job_id}/cancel` | Intelligence token | Cancel a non-final job |
| `POST /api/v1/intelligence/bridge/claim` | Bridge token | Claim one queued job and receive minimized context |
| `POST /api/v1/intelligence/bridge/jobs/{job_id}/complete` | Bridge token | Return a schema-validated result |
| `POST /api/v1/intelligence/bridge/jobs/{job_id}/fail` | Bridge token | Record a bounded bridge failure |
| `GET /api/v1/enterprise/health` | Read token | Check enterprise data-plane readiness |
| `GET /api/v1/enterprise/metrics` | Read token | Read bounded metrics and Prometheus text |
| `GET /api/v1/enterprise/events` | Read token | Paginated normalized enterprise events |
| `POST /api/v1/enterprise/events` | Ingest token | Append a redacted idempotent event |
| `POST /api/v1/enterprise/vulnerabilities` | Intelligence token | Upsert prioritized vulnerability context |
| `POST /api/v1/enterprise/controls` | Intelligence token | Upsert a GRC control |
| `POST /api/v1/enterprise/evidence` | Intelligence token | Record hashed control evidence |
| `POST /api/v1/enterprise/actions` | Intelligence token | Propose an approval-gated action |
| `POST /api/v1/enterprise/workflows/{kind}` | Intelligence token | Record questionnaire, threat-model, or pen-test workflow |

The import endpoint requires UTF-8 `application/json`, rejects compressed
request bodies, enforces a 10 MiB default limit, rejects duplicate JSON keys,
and validates graph/finding count and type limits. API audit records contain
only import metadata and counts, never bearer credentials or bundle contents.

## Hosted deployment

The production-observed hosted Core boundary runs as the Cloudflare Worker in
`cloudflare/secopsai-core-edge`, backed by D1 and available at
`https://core.secopsai.dev`. It preserves the routes that were actually used by
the hosted research worker and operator read path:

- `GET /healthz`
- `GET /readyz`
- `POST /api/v1/research/alerts/webhook`
- `GET /api/v1/workspace`
- `GET /api/v1/audit-logs`
- `GET /api/v1/research/alerts`

The full FastAPI service and its intelligence, enterprise, and Edge-import
routes remain available for local deployments. Do not assume those routes are
implemented by the narrow Cloudflare service. Add a route only after its data
model, authentication scope, migration, and production caller are verified.

The Worker configuration binds the `secopsai-core-edge` D1 database and the
`core.secopsai.dev` custom domain. Configure its unrelated secrets with
Wrangler; never place them in `wrangler.jsonc`:

```bash
cd /Users/chrixchange/secopsai/cloudflare/secopsai-core-edge
wrangler secret put CORE_READ_TOKEN
wrangler secret put RESEARCH_WEBHOOK_SECRET
wrangler d1 migrations apply secopsai-core-edge --remote
npm test
wrangler deploy
```

The Render research worker uses the same webhook secret under the worker-side
name `SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET` and posts to:

```text
https://core.secopsai.dev/api/v1/research/alerts/webhook
```

The Worker rejects stale or invalid signatures, payloads larger than 64 KB,
unknown alert types, and unauthenticated reads. D1 imports are generated from a
reviewed, sanitized snapshot by `scripts/build_snapshot_import.py`; generated
SQL belongs in an owner-only backup directory, not the repository.

The stateful registry research worker remains on Render because its SQLite
database is larger than the free D1 per-database limit and its continuous
artifact workload requires a persistent filesystem. Moving that service
requires Cloudflare Workers Paid with Containers or a separately reviewed
sharded/serverless redesign. Do not delete it as part of the Core migration.

## Backup and recovery

Use D1 export and Time Travel for hosted Core recovery, and keep an encrypted or
access-controlled off-platform snapshot. Before deleting any former provider
service, verify the exported record counts, download the backup again, and
recompute its checksum. Local SQLite deployments still require the online
backup API or `.backup`; never copy a live database file without a
transaction-safe backup operation.

## Security boundary

- Edge owns scans and retains raw scanner telemetry.
- Core receives normalized graph nodes, graph edges, and findings only.
- Workspace responses omit MAC addresses, BSSIDs, and raw telemetry fields.
- CORS origins and trusted hosts are explicit in protected environments.
- Cloudflare terminates hosted TLS; the Worker returns restrictive response
  headers and D1 holds only normalized records.
- Every successful or rejected contract import is auditable without storing the
  submitted evidence body.
