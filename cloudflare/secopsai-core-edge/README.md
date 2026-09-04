# SecOpsAI Core Edge Worker

This Cloudflare Worker is the narrow, production-observed replacement for the
Render Core API. It preserves the signed research-alert webhook and the
read-only workspace/audit contracts backed by D1. It does not execute package
research, model jobs, or local helper actions.

Secrets are configured with Wrangler and never committed:

- `CORE_READ_TOKEN`
- `RESEARCH_WEBHOOK_SECRET`

Apply migrations, import a reviewed Core snapshot, deploy, and verify before
changing the research worker webhook URL. The canonical production origin is
`https://core.secopsai.dev`. Keep the former provider available until snapshot
counts, authenticated reads, and an idempotent signed canary all succeed.
