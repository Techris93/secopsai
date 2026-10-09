# SecOpsAI Research Runner (Cloudflare)

> **Recommended free path:** `.github/workflows/research-worker.yml` runs the
> same supervisor on a GitHub Actions schedule (free for this public
> repository) and keeps the ledger in R2 through the free-plan
> `secopsai-ledger-store` Worker at `https://ledger.secopsai.dev`. The
> Container runner below is the always-on alternative (Workers Paid).
>
> Free-path cutover:
> 1. Set GitHub secrets `SECOPSAI_CORE_BRIDGE_TOKEN`,
>    `SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET`, `SECOPSAI_SMTP_PASSWORD`
>    (same values as on Render). `LEDGER_STORE_TOKEN` is already set.
> 2. Suspend the Render worker, then in a Render shell run
>    `LEDGER_STORE_URL=https://ledger.secopsai.dev LEDGER_STORE_TOKEN=<token>
>    SECOPS_FINDINGS_DIR=/var/data/secopsai-research python
>    cloudflare/secopsai-research-runner/container/supervisor.py --checkpoint-only`
>    to migrate the ledger (or start fresh with the `allow_empty_ledger`
>    workflow input).
> 3. Run **Research Worker** manually once, confirm a heartbeat for
>    `github-actions-research-worker` on Core Edge, then set the repository
>    variable `RESEARCH_WORKER_ENABLED=true`.

Replaces the Render background worker (`render.yaml`). A Cron Trigger asks a
single Durable Object to keep one Container running the unchanged Python
research worker (`secopsai.cli research worker run`). Core API, alerts,
heartbeats, and the ontology already run on Core Edge (Worker + D1).

## Why move

- The Render Starter worker (512 MB) was OOM-killed repeatedly (Sep 23,
  Oct 6). The runner uses a custom instance: 1 vCPU, 2 GiB RAM, 16 GB disk.
- One provider for Workers, D1, R2, Pages, and Containers; one deploy path.
- The ledger survives restarts through R2 checkpoints instead of a single
  attached disk.

## How state is kept

Container disk is ephemeral. `container/supervisor.py`:

1. restores `ledger/LATEST` from R2 when the disk is empty;
2. runs the worker;
3. every `SECOPSAI_LEDGER_CHECKPOINT_SECONDS` (default 1 h) takes a
   consistent SQLite online backup, gzips it, and uploads it in 32 MiB parts;
4. on SIGTERM writes a final checkpoint (Cloudflare allows 15 minutes).

The container reaches R2 only through `http://ledger.internal`, which the
Durable Object intercepts and routes to the `LedgerStore` entrypoint with a
per-start token. The container holds no R2 credentials. The last four
snapshots are kept.

## Cost (Workers Paid, Oct 2026 list prices)

Always-on 1 vCPU / 2 GiB / 16 GB: memory about $13, disk about $3, CPU
(about 20% active) about $10 per month, plus the $5 Workers Paid plan
shared with Core Edge. That is comparable to a Render Standard worker
(2 GB), which is what the current memory profile actually needs. R2
storage for four compressed snapshots is cents.

## Cutover

1. `npx wrangler r2 bucket create secopsai-research-ledger`
2. Set secrets: `RUNNER_ADMIN_TOKEN`, `SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET`,
   `SECOPSAI_CORE_BRIDGE_TOKEN`, `SECOPSAI_SMTP_PASSWORD`, and any model key.
3. Run the **Deploy Research Runner** workflow (needs Docker, so it runs in
   GitHub Actions). `RUNNER_ENABLED` is still `false`.
4. Suspend the Render worker. Copy its ledger once: on Render,
   `sqlite3 /var/data/secopsai-research/openclaw_soc.db ".backup /tmp/l.db"`,
   gzip it, and upload it as the first snapshot (or start empty).
5. Set `RUNNER_ENABLED` to `"true"`, deploy, then `POST /start` with the
   admin token. Confirm a heartbeat for `cloudflare-secopsai-research-runner`
   on `https://core.secopsai.dev` and `GET /status`.
6. After a week without incident, delete the Render service and `render.yaml`.

Never run Render and this runner at the same time: both would write alerts
and claim coordinator leases.
