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

Migrations `0003_ontology.sql` through `0007_ontology_entity_validity.sql` add
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
Migration `0006_ontology_evidence_scope.sql` adds workspace binding to evidence
references for existing D1 databases. The Python runner also keeps a bounded
`ontology_sync_outbox` in local SQLite: failed syncs are retried with the same
idempotency key after Core Edge recovers, while collection continues locally.
Migration `0007_ontology_entity_validity.sql` adds optional `valid_from` and
`valid_to` windows to entities so temporal identity remains explicit without
rewriting existing rows. Set `CORE_ORGANIZATION_ID` alongside
`CORE_WORKSPACE_ID` when tenant binding is required.
