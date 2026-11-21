# SIEM And Observability

SecOpsAI exposes two kinds of output for monitoring and SIEM tools: operating
metrics about the pipeline, and normalized security events. Both are
minimized: raw scans and credential-shaped fields never leave the store.

## Core API endpoints

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/enterprise/health` | Store health, source cursors and dead letters (up to 100 each) |
| `GET /api/v1/enterprise/metrics` | The metrics below, as a snapshot and as Prometheus text |
| `GET /api/v1/enterprise/events?limit=&cursor=` | Normalized events, newest first, with `next_cursor` and `has_more` |
| `POST /api/v1/enterprise/events` | Ingest one normalized event; send an `Idempotency-Key` header to make retries safe |

Read endpoints need a read role; ingest needs the ingest role. From the CLI,
`secopsai enterprise status --json` returns store health, record counts and the
metrics snapshot.

## Metrics

Metrics are computed from the enterprise store, so the CLI, the API and any
scraper see the same values whichever process answers:

```bash
secopsai enterprise metrics --json
secopsai enterprise metrics --prometheus
```

| Metric | Type | Meaning |
| --- | --- | --- |
| `events_total`, `assets_total`, `vulnerabilities_total`, `open_vulnerabilities_total`, `controls_total`, `evidence_total`, `actions_total`, `dead_letters_total` | gauge | Record counts for the organization |
| `sources_total`, `sources_degraded` | gauge | Connectors, and how many are not healthy |
| `source_age_seconds_<source>` | gauge | Seconds since the source's last successful page |
| `source_latency_ms_<source>` | gauge | How long the last successful page took to fetch and store |
| `open_vulnerabilities_<severity>` | counter | Open vulnerabilities by severity |
| `vulnerabilities_overdue` | gauge | Open vulnerabilities past their SLA due date |
| `ingest_delay_seconds` | histogram | Delay between when an event happened and when it was stored, over the last 1,000 events |
| `pentest_items_open`, `pentest_items_awaiting_retest` | gauge | Penetration-test items not yet fixed, and fixed but not retested |

The Prometheus text prefixes every name with `secopsai_`, replaces other
characters with `_`, and reports histograms as `_count`, `_sum` and `_max`.

## Source health

Each connector records a source cursor with its status (`healthy` or
`degraded`), the time of its last success or error, and the error text. A
stalled or failing source is therefore visible instead of silent. See
[Cloud Connectors](cloud-connectors.md).

## Event export

Normalized events export as newline-delimited JSON, one event per line, with
keys sorted for stable diffs. Payloads are the redacted copies already in the
store.

Sending events to an HTTP collector is approval-gated:

- the endpoint must use HTTPS
- without approval, the export returns `status: proposed` with the event count
  and makes no network call
- only an approved export sends the NDJSON body
  (`Content-Type: application/x-ndjson`)

## Where to configure exporters

Splunk, Elastic, Chronicle, OpenTelemetry and Prometheus exports are configured
server-side. Normalized findings and report summaries can also go to Splunk
HEC; raw telemetry never leaves the local store. Optional Sentry error
reporting is privacy-preserving and disabled unless configured.

The dashboard shows `not_configured` for any exporter that is not enabled.
