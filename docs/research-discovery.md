# Research Discovery Platform

SecOpsAI Research Discovery turns supported registry observations into reviewable candidates. It is a lead-generation system, not an automatic maliciousness verdict.

## Coverage model

The capability registry is authoritative:

```bash
secopsai research ecosystems --json
```

The first implementation supports npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go modules, and Open VSX. Each ecosystem advertises metadata discovery, version history, artifact download, static inspection, deep-analysis availability, comparison, monitoring mode, limitations, and terms/rate-limit documentation.

The initial monitor mode is intentionally watchlist-scoped. A successful watchlist poll is not a clean registry result. Incomplete coverage, stale cursors, and adapter failures remain visible to operators.

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

Keep `TRIAGE_API_TOKEN`, SMTP credentials, webhook secrets, and registry credentials server-side. Cloudflare Email Routing is inbound routing; outbound disclosure requires an SMTP or transactional provider with SPF, DKIM, and DMARC. Tria.ge is a public provider: do not submit confidential customer data, private credentials, or artifacts whose disclosure is not authorized.

## Recovery

Use `secopsai research monitor list` to find stale or failed monitors, rerun the affected monitor after the registry recovers, and inspect candidate provenance before promotion. Failed disclosure attempts are retained with a delivery ID and error summary. Sandbox results may be imported manually as sanitized JSON when the external connector is unavailable.
