# Research Discovery Platform

SecOpsAI Research Discovery turns supported registry observations into reviewable candidates. It is a lead-generation system, not an automatic maliciousness verdict.

## Coverage model

The capability registry is authoritative:

```bash
secopsai research ecosystems --json
```

The first implementation supports npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go modules, and Open VSX. Each ecosystem advertises metadata discovery, version history, artifact download, static inspection, deep-analysis availability, comparison, monitoring mode, limitations, and terms/rate-limit documentation.

The initial monitor mode is intentionally watchlist-scoped. A successful watchlist poll is not a clean registry result. Incomplete coverage, stale cursors, and adapter failures remain visible to operators.

An exact-package monitor creates a version baseline and records subsequent version changes as informational alerts. It does not classify the legitimate watched package as a typosquat. Lookalike candidates enter through registry event/search observations and are scored separately against watchlists. Exact approved names and explicit exclusions are suppressed unless an expected publisher is configured and the observed publisher differs.

## Global surveillance collectors

Beyond watchlist monitors, SecOpsAI runs registry-wide collectors that record every observable package event into an append-only ledger before scoring:

- **NuGet**: chronological V3 Catalog cursor ingestion (publish/delete events, optional leaf enrichment).
- **Packagist**: `metadata/changes.json` with the composite server cursor, bounded-retention safety alarms, and skew overlap.
- **PyPI**: simple-index reconciliation with serial headers; snapshots detect project additions and removals. Per-release detection still needs watchlist polling or backfill — the capability registry says so honestly.
- **RubyGems**: `timeframe_versions` sliding windows; the cursor advances only when a window fully drains, so bursts cannot be skipped.

```bash
secopsai research collect status                 # collector health, cursor lag, gaps
secopsai research collect run --ecosystem nuget  # one bounded ingestion pass
secopsai research collect pause --ecosystem pypi # pause without losing the cursor
secopsai research collect resume --ecosystem pypi
secopsai research collect retry-failures         # dead-letter retries with backoff
secopsai research collect coverage --days 7      # windows, gaps first
secopsai research collect events --limit 50      # the raw ledger
secopsai research score run                      # ledger -> watchlist candidates
```

A failed fetch never advances the cursor, so history cannot be skipped silently. A **coverage gap** is an operator-visible replay request, not a clean result.

## Continuous worker

`secopsai research worker run` executes due collectors on their own schedules (NuGet 15 min, Packagist 15 min, PyPI 1 hour, RubyGems 30 min), scores new events, retries dead letters, and recovers interrupted runs. One failing registry never stops the cycle.

```bash
secopsai research worker due           # which collectors are due and why
secopsai research worker run --once    # single cycle (cron-friendly)
secopsai research worker run           # loop mode with SIGTERM handling
```

On Render, the `secopsai-research-worker` background worker in `render.yaml` runs loop mode against a persistent disk (`SECOPS_FINDINGS_DIR=/var/data/secopsai-research`). The worker database is independent of the API database so collection can scale separately.

The worker creates a deduplicated high-severity `collector_degraded` alert when a registry run fails, leaves a coverage gap, or reaches a bounded collection limit. It creates at most one such alert per ecosystem per UTC day and continues collecting other registries. Delivery is disabled by default. To enable operational email alerts after configuring an authenticated SMTP provider, set:

```text
SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS=email
SECOPSAI_SMTP_HOST=<provider SMTP host>
SECOPSAI_SMTP_PORT=465
SECOPSAI_SMTP_USERNAME=<server-side username>
SECOPSAI_SMTP_PASSWORD=<server-side secret>
SECOPSAI_RESEARCH_ALERT_EMAIL=research@secopsai.dev
SECOPSAI_RESEARCH_FROM_EMAIL=research@secopsai.dev
```

Use `webhook` or `email,webhook` only after setting the corresponding signed-webhook URL and secret. Automatic delivery is intentionally restricted to collector coverage and retention alerts. Candidate, campaign, disclosure, sandbox, and publication actions remain operator-reviewed.

The hosted Core API exposes `POST /api/v1/research/alerts/webhook` for this operational path. The Render Blueprint creates the `secopsai-research-alerts` environment group, generates a 256-bit `SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET`, and links it to Core and the worker. The worker URL is `https://secopsai-core-api.onrender.com/api/v1/research/alerts/webhook`, and automatic webhook delivery is enabled in the Blueprint. The signature covers the exact request body and a Unix timestamp. Core rejects requests outside a five-minute replay window, payloads larger than 64 KB, non-operational alert types, invalid signatures, and duplicate JSON keys.

Webhook retries are idempotent. Core assigns a stable local alert ID from the worker alert ID and preserves the operator-owned status and owner fields when the same alert is delivered again. The Core workspace response includes normalized operational research alerts; raw package artifacts and scanner data are not accepted by this endpoint.

Rotate the webhook secret by temporarily disabling automatic webhook delivery, replacing the value once in the shared Render environment group, waiting for both linked services to redeploy, and then re-enabling the channel. A mismatched secret fails closed and produces an audited failed delivery on the worker.

Optional Sentry reporting is also disabled until `SECOPSAI_SENTRY_DSN` is present. When enabled, Core sends no default PII, excludes local variables, and records errors with traces and profiling disabled by default. Set a nonzero `SECOPSAI_SENTRY_TRACES_SAMPLE_RATE` only after reviewing the privacy and cost impact.

The repository includes the manual `Configure Resend DNS` GitHub workflow. It uses the existing server-side `CLOUDFLARE_API_TOKEN` Actions secret plus the public `RESEND_DKIM_PUBLIC_KEY` repository variable to locate `secopsai.dev` by exact zone name and idempotently configure the Resend DKIM record and the `send.secopsai.dev` SPF and return-path records. The token must have Zone read and DNS edit permission for `secopsai.dev`; a Pages-only token fails without changing DNS.

Important deployment boundary: Render persistent disks cannot be shared. The signed webhook synchronizes reduced operational alerts only. Registry events, candidates, artifacts, and full coverage history remain on the worker disk until their own authenticated ingestion contracts are implemented.

## Watchlist and monitor workflow

```bash
secopsai research watchlist add \
  --ecosystem nuget \
  --watch-type brand \
  --identifier braintree \
  --threshold 70 \
  --priority high

secopsai research watchlist list --ecosystem nuget
secopsai research monitor create --ecosystem nuget --watchlist-id WL-... --interval-seconds 900
secopsai research monitor list
secopsai research monitor run-due --limit 25
secopsai research candidate list
secopsai research campaign correlate
secopsai research campaign list
```

The dashboard provides the same actions under Research Discovery. Use **Add watchlist**, **Create monitor**, **Run due monitors**, **Compare exact packages**, and **Correlate campaigns**. Protected writes require the research action token.

On macOS, install the local due-monitor trigger as a background service:

```bash
bash scripts/install_research_monitor_launchd.sh install
bash scripts/install_research_monitor_launchd.sh status
bash scripts/install_research_monitor_launchd.sh run-now
bash scripts/install_research_monitor_launchd.sh logs
```

The trigger runs every 15 minutes by default and executes only monitors whose own schedule is due. Override the trigger at install time with `SECOPSAI_RESEARCH_MONITOR_TRIGGER_SECONDS`; values below five minutes are rejected. The service survives login/reboot and retains owner-only logs under `~/Library/Logs/SecOpsAI/`.

## Safe package intake and comparison

Intake resolves official metadata and artifact URLs through ecosystem-specific HTTPS allowlists, enforces response and archive limits, calculates SHA-256, stores the artifact in quarantine, and performs bounded static inspection. Package code is never installed, imported, decompiled by loading, or executed on Core, the dashboard host, or the MacBook helper.

From a case, use **Run Safe Package Intake**. For a side-by-side comparison, open **Compare packages** and enter exact package targets. The comparison records metadata, dependencies, file inventory, lifecycle scripts, indicators, hashes, and safety limitations.

NuGet analysis provides safe package inventory and byte-level API signal detection. For deep managed-metadata extraction, build `workers/nuget-analyzer` in a disposable network-disabled container and configure the server-side `SECOPSAI_NUGET_ANALYZER` command. Core accepts only JSON that explicitly reports `execution_performed: false`; it never loads customer or package assemblies into the Core process.

## Human gates

- A similarity score creates a candidate, not a verdict.
- **Request Sandbox Approval** creates a request only.
- **Approve public submission** requires an explicit acknowledgement before Tria.ge submission.
- Responsible disclosure must be approved before delivery.
- Publication safety checks, editorial review, and Blog Ops approval remain required before public release.

## Provider configuration

Keep `TRIAGE_API_TOKEN`, SMTP credentials, webhook secrets, and registry credentials server-side. Cloudflare Email Routing is inbound routing; outbound disclosure requires an SMTP or transactional provider with SPF, DKIM, and DMARC. Approved vulnerability disclosures default to `security@secopsai.dev`; research alerts default to `research@secopsai.dev`. Tria.ge is a public provider: do not submit confidential customer data, private credentials, or artifacts whose disclosure is not authorized.

## Recovery

Use `secopsai research monitor list` to find stale or failed monitors, rerun the affected monitor after the registry recovers, and inspect candidate provenance before promotion. Failed disclosure attempts are retained with a delivery ID and error summary. Sandbox results may be imported manually as sanitized JSON when the external connector is unavailable.
