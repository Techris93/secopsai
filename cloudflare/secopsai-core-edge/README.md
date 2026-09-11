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
