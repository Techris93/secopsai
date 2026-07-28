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
| `POST /api/v1/intelligence/autopilot/runs/{run_id}/rollback` | Intelligence token | Restore the pre-decision finding state |
| `POST /api/v1/intelligence/autopilot/tuning/{proposal_id}/rollback` | Intelligence token | Restore the threshold baseline recorded before activation |
| `POST /api/v1/intelligence/jobs/{job_id}/cancel` | Intelligence token | Cancel a non-final job |
| `POST /api/v1/intelligence/bridge/claim` | Bridge token | Claim one queued job and receive minimized context |
| `POST /api/v1/intelligence/bridge/jobs/{job_id}/complete` | Bridge token | Return a schema-validated result |
| `POST /api/v1/intelligence/bridge/jobs/{job_id}/fail` | Bridge token | Record a bounded bridge failure |

The import endpoint requires UTF-8 `application/json`, rejects compressed
request bodies, enforces a 10 MiB default limit, rejects duplicate JSON keys,
and validates graph/finding count and type limits. API audit records contain
only import metadata and counts, never bearer credentials or bundle contents.

## Hosted deployment

`render.yaml` is the canonical root Render Blueprint for the Core API. Create a
new Blueprint from the `Techris93/secopsai` repository, select `main`, and use
the root Blueprint path. It creates one Starter instance and a 1 GB persistent
disk because SQLite data must survive deploys and Render disks cannot be
attached to a free service.

Before creating it:

1. Generate four unrelated secrets of at least 32 characters.
2. Set `SECOPSAI_CORE_INGEST_TOKEN`, `SECOPSAI_CORE_READ_TOKEN`, `SECOPSAI_CORE_INTELLIGENCE_TOKEN`, and `SECOPSAI_CORE_BRIDGE_TOKEN` when prompted.
3. Set `SECOPSAI_CORE_CORS_ORIGINS` to the exact operator dashboard origin.
4. Set `SECOPSAI_CORE_ORGANIZATION_ID` to the Edge workspace organization ID.
5. Confirm the expected hostname in `SECOPSAI_CORE_TRUSTED_HOSTS`.
6. Review current Render compute and disk pricing before applying the Blueprint.

The Blueprint intentionally uses one process and one persistent disk. Do not
increase the worker or instance count while Core uses SQLite. The later SaaS
architecture should move canonical Core state to managed PostgreSQL before
horizontal scaling or multi-tenant production.

After the service deploys, save its `onrender.com` origin and run the
secret-safe hosted preflight from the Core repository:

```bash
cd /Users/chrixchange/secopsai
SECOPSAI_CORE_API_URL='https://secopsai-core-api.onrender.com' \
SECOPSAI_CORE_READ_TOKEN='use-the-owner-only-render-secret' \
./scripts/core-api hosted-check
```

The command checks `/healthz`, `/readyz`, and the authenticated workspace
schema. It prints only status, version, schema, summary-key, and non-secret
error information. It never prints the bearer token or workspace response
body. Do not record the token in shell history; prefer an environment file with
mode `0600` or an approved secret manager.

The check must report `"ok": true` before configuring the canonical dashboard
Pages Worker with `SECOPSAI_CORE_API_URL` and `SECOPSAI_CORE_READ_TOKEN`. The
dashboard then calls Core server-side and keeps the read credential out of the
browser.

The current pilot service is deployed at
`https://secopsai-core-api.onrender.com`. The first hosted Edge bundle import
has been verified against the pilot workspace. Treat a transient `502` during
Render cold start as a retryable deployment event; repeated failures require
checking the service logs and readiness before sending customer data.

For the first Edge-to-hosted-Core import, use the separate ingest credential
with Core's existing Edge sync command:

```bash
SECOPSAI_EDGE_API_URL='https://secopsai-edge-api.onrender.com' \
SECOPSAI_EDGE_ACCESS_TOKEN='use-the-scoped-edge-export-token' \
SECOPSAI_CORE_API_URL='https://secopsai-core-api.onrender.com' \
SECOPSAI_CORE_INGEST_TOKEN='use-the-owner-only-core-ingest-secret' \
secopsai edge sync --remote-only
```

The read token used by the dashboard and the ingest token used by Edge are
unrelated. Rotate either independently. `--remote-only` avoids creating a
local SQLite mirror; omit it when the operator also wants local graph/triage
inspection. The hosted endpoint is idempotent for repeated bundle imports.
The Edge/Core client retries bounded transient `500`, `502`, `503`, `504`, and
network failures up to three times with short backoff; authentication and
validation errors are not retried.

## Backup and recovery

Render snapshots the attached disk, but SQLite still needs an application-level
backup drill. Use SQLite's online backup API or `.backup` command against a
separate destination, verify it with `PRAGMA integrity_check`, and restore only
into a separate test service during drills. Never copy a live database file
without a transaction-safe backup operation.

## Security boundary

- Edge owns scans and retains raw scanner telemetry.
- Core receives normalized graph nodes, graph edges, and findings only.
- Workspace responses omit MAC addresses, BSSIDs, and raw telemetry fields.
- CORS origins and trusted hosts are explicit in protected environments.
- Uvicorn runs behind Render TLS with bounded concurrency and request recycling.
- Every successful or rejected contract import is auditable without storing the
  submitted evidence body.
