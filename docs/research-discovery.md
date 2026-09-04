# Research Discovery Platform

SecOpsAI Research Discovery turns supported registry observations into reviewable candidates. It is a lead-generation system, not an automatic maliciousness verdict.

For the distinction between active coverage gaps, historical windows, stale
cursors, and bounded queue recovery, see
[Operational Queue Recovery](operational-queue-recovery.md). Historical gap
rows remain immutable audit evidence; only the current coverage state drives
operator alerts.

## Coverage model

The capability registry is authoritative:

```bash
secopsai research ecosystems --json
```

The first implementation supports npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go modules, and Open VSX. Each ecosystem advertises metadata discovery, version history, artifact download, static inspection, deep-analysis availability, comparison, monitoring mode, limitations, and terms/rate-limit documentation.

The initial registry monitor mode is intentionally honest about coverage. A
successful watchlist poll is not a clean registry result. Incomplete coverage,
stale cursors, and adapter failures remain visible to operators. In addition,
the worker can ingest an allowlisted, source-backed package advisory feed. A
source-backed lead is created even when no local dependency reference exists;
it remains `unverified` until the exact artifact is collected and analyzed.

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

`secopsai research worker run` executes the external advisory refresh and due
collectors on their own schedules (NuGet 15 min, Packagist 15 min, PyPI 1
hour, RubyGems 30 min, and the npm changes feed every 15 min), scores new
events, retries dead letters, and recovers interrupted runs. One failing
registry never stops the cycle.

Collector status separates an active coverage gap from an old cursor watermark. A successful run resolves open retention alerts for that collector automatically; an old alert record is historical evidence, not a current outage. When a feed is behind, let the worker process bounded catch-up cycles rather than starting overlapping collectors. A collector cursor advances only after its selected pages are persisted, so a restart is safe and idempotent.

```bash
secopsai research worker due           # which collectors are due and why
secopsai research worker run --once    # single cycle (cron-friendly)
secopsai research worker run           # loop mode with SIGTERM handling
secopsai research external-intel refresh --force --json  # refresh source-backed campaign leads now
```

On Render, the `secopsai-research-worker` background worker in `render.yaml` runs loop mode against a persistent disk (`SECOPS_FINDINGS_DIR=/var/data/secopsai-research`). The worker database is independent of the API database so collection can scale separately.

### Storage capacity and recovery

The worker runs bounded storage maintenance before every collection cycle. It preserves pending events, candidate-linked records, research cases, evidence, IOCs, active alerts, and the newest registry comparison snapshots. It removes only processed operational feed history after its configured retention period, old completed run history, resolved dead letters, expired delivery history, and superseded snapshots. Freed SQLite pages are reused by later collections.

The production Blueprint reserves 16 MB on the persistent disk. If free space drops below 128 MB or disk use reaches 85%, the worker releases that reserve before cleanup so SQLite can commit the recovery transaction. Storage pressure is reported separately from registry health; a full disk must not be presented as proof that a registry is unavailable.

Inspect and maintain storage with:

```bash
secopsai research storage status --json
secopsai research storage maintain --aggressive --json
secopsai research storage release-reserve --json
```

`maintain --aggressive` prunes all eligible batches and runs `VACUUM` only when enough free capacity exists to do so safely. It never deletes pending events, canonical candidates, cases, case evidence, IOCs, rules, unresolved alerts, or quarantined artifacts.

If Render reports `database or disk is full`, increase the worker disk from its **Disks** page before redeploying. Render supports increasing a persistent disk without downtime, but does not allow reducing it later. After capacity becomes available, deploy this release; the worker performs maintenance before it starts another collector. Then verify `storage status`, confirm `pressure=false`, and confirm a complete worker cycle in the logs.

The production Blueprint provisions 5 GB for continuous global-registry surveillance. Capacity must still be reviewed against measured ingestion rate: retain the automatic pressure guard and review the Disk Usage metric weekly. A bounded development deployment can use 1 GB, but a future multi-worker service must move this ledger to a managed datastore because Render persistent disks are single-service and cannot be shared.

Completed npm release analyses are retained for 30 days by default, while
candidate-linked evidence, failed/retryable analyses, exact events, and
quarantined artifacts are preserved by the storage guard. Override the
completed-analysis window with `SECOPSAI_RESEARCH_NPM_ANALYSIS_RETENTION_DAYS`
only after measuring the disk budget.

The worker creates a deduplicated high-severity `collector_degraded` alert when a registry run fails, leaves a coverage gap, or reaches a bounded collection limit. It creates at most one such alert per ecosystem per UTC day and continues collecting other registries. Delivery is disabled by default outside the production Blueprint. For a standalone deployment, configure:

```text
SECOPSAI_RESEARCH_AUTO_ALERT_CHANNELS=email,webhook
SECOPSAI_SMTP_HOST=smtp.resend.com
SECOPSAI_SMTP_PORT=465
SECOPSAI_SMTP_USERNAME=resend
SECOPSAI_SMTP_PASSWORD=<server-side secret>
SECOPSAI_RESEARCH_ALERT_EMAIL=research@secopsai.dev
SECOPSAI_RESEARCH_FROM_EMAIL=research@secopsai.dev
```

Use `webhook` or `email,webhook` only after setting the corresponding signed-webhook URL and secret. Automatic delivery is intentionally restricted to collector coverage and retention alerts. Candidate, campaign, disclosure, sandbox, and publication actions remain operator-reviewed.

The production Blueprint owns the non-secret Resend SMTP endpoint, port, username, sender, recipient, and `email,webhook` channel selection. The domain-scoped Resend sending key remains a manually managed `SECOPSAI_SMTP_PASSWORD` secret in Render and must never be committed to this repository. Healthy collection cycles send no email; delivery occurs only when a new eligible operational alert exists.

SMTP messages are multipart email with a plain-text fallback and an escaped HTML alternative. The HTML header uses the canonical SecOpsAI mark at `https://secopsai.dev/assets/favicon-512.png`; research mail uses the display name `SecOpsAI Research`, and approved disclosure mail uses `SecOpsAI Security`. Override `SECOPSAI_EMAIL_LOGO_URL` or `SECOPSAI_EMAIL_PRODUCT_URL` only with public HTTPS URLs controlled by SecOpsAI. Remote image loading remains an email-client decision, so the product name and message content never depend on the image rendering.

The HTML mark is different from the avatar that mailbox providers may show beside the sender. That inbox-level identity requires BIMI-capable DNS and mail authentication. Do not publish a BIMI record until SPF and DKIM are aligned, DMARC is monitored and moved to enforcement, the logo is converted to SVG Tiny PS, and the chosen mailbox-provider certificate requirements are satisfied.

The Cloudflare Core Edge Worker exposes `POST /api/v1/research/alerts/webhook`
for this operational path. Configure the same generated secret independently
as the Worker's `RESEARCH_WEBHOOK_SECRET` and the Render research worker's
`SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET`. The delivery URL is
`https://core.secopsai.dev/api/v1/research/alerts/webhook`, and automatic
webhook delivery is enabled in the Blueprint. The separate
`SECOPSAI_RESEARCH_EXTERNAL_ALERT_CHANNELS=webhook` setting sends
source-backed campaign leads only to Core. It never inherits the operational
email channel, because one campaign can contain hundreds of package versions.
The signature covers the exact request body and a Unix timestamp. Core rejects
requests outside a five-minute replay window, payloads larger than 64 KB,
unsupported alert types, invalid signatures, and duplicate JSON keys.

Webhook retries are idempotent. Core assigns a stable local alert ID from the worker alert ID and preserves the operator-owned status and owner fields when the same alert is delivered again. The Core workspace response includes normalized operational research alerts; raw package artifacts and scanner data are not accepted by this endpoint.

Rotate the webhook secret by temporarily disabling automatic webhook delivery,
setting the new value in Cloudflare and on the Render research worker, deploying
both services, verifying an idempotent signed canary, and only then re-enabling
the channel. A mismatched secret fails closed and produces an audited failed
delivery on the worker.

Optional Sentry reporting is also disabled until `SECOPSAI_SENTRY_DSN` is present. When enabled, Core sends no default PII, excludes local variables, and records errors with traces and profiling disabled by default. Set a nonzero `SECOPSAI_SENTRY_TRACES_SAMPLE_RATE` only after reviewing the privacy and cost impact.

The repository includes the manual `Configure Resend DNS` GitHub workflow. It uses the existing server-side `CLOUDFLARE_API_TOKEN` Actions secret plus the public `RESEND_DKIM_PUBLIC_KEY` repository variable to locate `secopsai.dev` by exact zone name and idempotently configure the Resend DKIM record and the `send.secopsai.dev` SPF and return-path records. The token must have Zone read and DNS edit permission for `secopsai.dev`; a Pages-only token fails without changing DNS.

Important deployment boundary: the Render research disk and Cloudflare D1 are
independent. The signed webhook synchronizes reduced operational and
source-backed alert context only. Registry events, candidates, artifacts, and
full coverage history remain on the worker disk until their own authenticated
ingestion contracts are implemented. Core still treats every external lead as
unverified until its evidence workflow completes.

### Proactive npm release enrichment

The npm changes feed identifies a package document, not the exact release that
changed. The worker therefore performs a second, bounded step before normal
watchlist scoring:

1. Resolve the package through the official `registry.npmjs.org` packument.
2. Compare the current release set with a compact package baseline. The
   append-only event ledger remains authoritative; the baseline is capped so a
   popular package cannot fill the worker disk.
3. Record an exact `version_observed` or `version_updated` event with the
   metadata URL, official tarball URL, integrity values, publisher summary,
   previous version, and packument hash.
4. Download a bounded number of exact artifacts into owner-only quarantine.
   Inspect the archive in memory for manifests, lifecycle hooks, process
   execution, credential/payment access, network endpoints, encoding, and
   persistence indicators. The package is never installed, imported, or run.
5. Create a source-backed proactive candidate only when explainable metadata or
   static indicators cross the conservative review threshold. The candidate is
   marked `static_confirmed` only when the exact artifact was collected
   successfully; it is never a maliciousness verdict.

The default safety budgets are 100 package documents and 10 artifact analyses
per worker cycle. They can be lowered or raised up to the hard safety caps with
`SECOPSAI_NPM_ENRICHMENT_EVENT_LIMIT` and
`SECOPSAI_NPM_STATIC_ANALYSIS_LIMIT`. Events that exceed the current budget
remain pending for the next cycle. Temporary registry or artifact failures are
retryable and create a separate `npm_enrichment_degraded` alert. That alert is
sent through the signed Core webhook when external alert delivery is enabled,
so a second-stage analysis failure cannot remain only on the worker disk.

Run the bounded step manually when validating a deployment:

```bash
secopsai research npm enrich --event-limit 100 --static-limit 10 --json
```

Inspect the exact release ledger and analysis status with:

```bash
secopsai research collect events --collector-id COL-NPM-CHANGES --limit 50
sqlite3 "${SECOPS_FINDINGS_DIR:-data/openclaw/findings}/openclaw_soc.db" \
  "select package,version,status,score,artifact_sha256,updated_at from research_npm_release_analyses order by updated_at desc limit 50;"
```

The first observation of a package establishes a baseline and checks its
current `latest` release. A package with no lifecycle or static indicator is
still recorded as analyzed; it is not silently treated as clean. A registry
that omits release timestamps, removes a packument, or was not monitored during
the publish window remains subject to the existing coverage and retry limits.
No monitor can prove that an entire registry is clean.

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
secopsai research candidate promotion-policy --ecosystem all
secopsai research candidate run-promotion-policy --ecosystem all
secopsai research campaign correlate
secopsai research campaign list
```

The dashboard provides the same actions under Research Discovery. Use **Add watchlist**, **Create monitor**, **Run due monitors**, **Compare exact packages**, and **Correlate campaigns**. Protected writes require the research action token.

Candidate promotion is disabled by default. Configure it with `research candidate promotion-policy --set`, then run `run-promotion-policy` without `--apply` to preview every decision. The policy evaluates a minimum score, evidence-reference count, optional publisher evidence, and ecosystem scope. Adding `--apply` may create draft Research Cases only; it never records a malicious verdict. Each promotion persists the candidate, exact policy, reasons, actor, resulting case ID, and event timestamp for audit and rollback review.

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

Keep `TRIAGE_API_TOKEN`, SMTP credentials, webhook secrets, and registry credentials server-side. For the local Mission Control helper, set `TRIAGE_API_TOKEN` in the owner-only `secopsai-dashboard/.env` file and restart the helper. The browser receives only a configured/not-configured provider state. Cloudflare Email Routing is inbound routing; outbound disclosure requires an SMTP or transactional provider with SPF, DKIM, and DMARC. Approved vulnerability disclosures default to `security@secopsai.dev`; research alerts default to `research@secopsai.dev`. Tria.ge is a public provider: do not submit confidential customer data, private credentials, or artifacts whose disclosure is not authorized.

## Recovery

Use `secopsai research monitor list` to find stale or failed monitors, rerun the affected monitor after the registry recovers, and inspect candidate provenance before promotion. Failed disclosure attempts are retained with a delivery ID and error summary. Sandbox results may be imported manually as sanitized JSON when the external connector is unavailable.
