# SecOpsAI Core Edge Worker

This Cloudflare Worker is the narrow, production-observed replacement for the
Render Core API. It preserves the signed research-alert webhook and the
read-only workspace/audit contracts backed by D1. It does not execute package
research, model jobs, or local helper actions.

Secrets are configured with Wrangler and never committed:

- `CORE_READ_TOKEN`
- `RESEARCH_WEBHOOK_SECRET`
- `CORE_INTELLIGENCE_TOKEN`
- `CORE_BRIDGE_TOKEN`

Apply migrations, import a reviewed Core snapshot, deploy, and verify before
changing the research worker webhook URL. The canonical production origin is
`https://core.secopsai.dev`. Keep the former provider available until snapshot
counts, authenticated reads, and an idempotent signed canary all succeed.

The coordinator routes under `/api/v1/intelligence/*` use
`CORE_INTELLIGENCE_TOKEN` for Mission Control reads and mutations. The
Render runner and local Codex bridge use the separate `CORE_BRIDGE_TOKEN` for
heartbeats, command claims, and job completion. D1 stores only minimized
queue, automation, heartbeat, and audit metadata; the full research ledger
and package artifacts remain on the Python execution host.

## Ontology operating picture

Migrations `0003_ontology.sql` through `0009_runner_process_lease.sql` add
the bounded semantic projection used by Mission Control. The routes are:

- `GET /api/v1/ontology/search`
- `GET /api/v1/ontology/entities/{entity_id}`
- `GET /api/v1/ontology/entities/{entity_id}/neighbors`
- `GET /api/v1/ontology/entities/{entity_id}/timeline`
- `GET /api/v1/ontology/entities/{entity_id}/lineage`
- `GET /api/v1/ontology/entities/{entity_id}/risk`
- `GET /api/v1/ontology/quality`
- `POST /api/v1/ontology/sync`

Read routes use `CORE_READ_TOKEN`; the risk view uses
`CORE_INTELLIGENCE_TOKEN`; runner synchronization uses `CORE_BRIDGE_TOKEN`.
Sync requests are bounded, workspace-scoped, redacted, and idempotent with an
`Idempotency-Key`. D1 holds summaries and evidence references only. The Render
worker/local SQLite ledger remains the source of complete research history and
raw artifacts. Apply migrations before deploying a runner that calls
`/api/v1/ontology/sync`.
The search route also accepts the ontology base path (`/api/v1/ontology`) as a
backward-compatible alias, and all ontology read paths tolerate one or more
trailing slashes. This keeps the Pages proxy and older dashboard builds from
falling through to a static `404`; an unknown entity still returns the normal
authenticated `404` contract.
Ontology sync accepts at most 500 records of each kind and rejects a request
whose deterministic mutation plan would exceed 1,000 statements, including the
receipt. Preflight reads are capped at 50 D1 queries, matching the lowest D1
plan limit; an over-budget request returns `413` before the atomic batch starts.
The Python client chunks snapshots by the request byte bound and reports each
accepted or rejected chunk for resumable retries.
Migration `0006_ontology_evidence_scope.sql` adds workspace binding to evidence
references for existing D1 databases. The Python runner also keeps a bounded
`ontology_sync_outbox` in local SQLite: failed syncs are retried with the same
idempotency key after Core Edge recovers, while collection continues locally.
Migration `0007_ontology_entity_validity.sql` adds optional `valid_from` and
`valid_to` windows to entities so temporal identity remains explicit without
rewriting existing rows. Set `CORE_ORGANIZATION_ID` alongside
`CORE_WORKSPACE_ID` when tenant binding is required.

Migration `0008_lease_fencing.sql` rebuilds the ontology identity indexes and
adds lease generation/token columns used by bridge job and coordinator
claims. Run `npm run migrate:remote` against the intended D1 database before a
production deploy, or use `npm run deploy:remote` as the explicit migration
then deploy sequence. The migration command is idempotent under Wrangler's
tracked migration history; verify claim, heartbeat, completion, and failure
against the migrated database before connecting a runner.

Migration `0009_runner_process_lease.sql` adds process revision/start time,
generation, and lease token columns to runner heartbeats and coordinator
automation rows. Hosted runner heartbeats must present all four process lease
fields; a newer generation takes ownership, while an expired or older lease
receives `409`. Coordinator results are checked against that lease before
materialization, so a stale runner cannot overwrite the current schedule.
`CoreEdgeClient.sync_state` reports the process revision/start time and the
latest ontology status/counts. The revision is selected from
`SECOPSAI_BUILD_REVISION`, then `RENDER_GIT_COMMIT`, then `GIT_COMMIT`, with a
fresh process UUID as the local fallback. `sync_ontology` returns accepted and
rejected chunk IDs/counts so a partial sync can be resumed with stable
idempotency keys.

### Deployment verification

Deploy the migration and Worker together with `npm run deploy:remote`. Record
the resulting Worker version and confirm that the remote migration list reports
no pending migrations. Before connecting Pages or the runner, check the public
`/healthz` and `/readyz` endpoints, then make an authenticated request to
`/api/v1/ontology/search?q=&limit=1` with the read token. A `401` proves the
route is registered but unauthenticated; an authenticated `200` proves the
route, token binding, workspace scope, and D1 read path are live. If Pages
reports `core_ontology_route_unavailable`, compare the deployed Worker version
with the commit that contains the ontology routes and redeploy Core Edge before
redeploying Pages.
