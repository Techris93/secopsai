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

The API deliberately uses two unrelated bearer credentials:

- `SECOPSAI_CORE_INGEST_TOKEN` can submit normalized Edge bundles only.
- `SECOPSAI_CORE_READ_TOKEN` can read the minimized workspace and API audit log.

Neither token grants scanner control. Edge sensor and dashboard credentials
remain separate. Pilot and production startup rejects short, missing, reused,
or wildcard-host credentials.

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

1. Generate two unrelated secrets of at least 32 characters.
2. Set `SECOPSAI_CORE_INGEST_TOKEN` and `SECOPSAI_CORE_READ_TOKEN` when prompted.
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
