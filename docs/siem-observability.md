# SIEM And Observability

SecOpsAI exposes two kinds of output for monitoring and SIEM tools: operating
metrics about the pipeline, and normalized security events. Both are
minimized: raw scans and credential-shaped fields never leave the store.

## Core API endpoints

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/enterprise/health` | Store health, source cursors and dead letters (up to 100 each) |
| `GET /api/v1/enterprise/metrics` | Metrics snapshot and the same data as Prometheus text |
| `GET /api/v1/enterprise/events?limit=&cursor=` | Normalized events, newest first, with `next_cursor` and `has_more` |
| `POST /api/v1/enterprise/events` | Ingest one normalized event; send an `Idempotency-Key` header to make retries safe |

Read endpoints need a read role; ingest needs the ingest role. From the CLI,
`secopsai enterprise status --json` returns store health, record counts and the
metrics snapshot.

## Metrics

`secopsai.siem.MetricsRegistry` holds bounded, thread-safe metrics:

| Type | Use |
| --- | --- |
| Counter | Totals that only grow, such as processing failures |
| Gauge | Current values, such as queue depth or source freshness |
| Histogram | Distributions such as ingestion latency, MTTD or remediation age; keeps the last 1,000 samples |

A snapshot reports each counter and gauge, and for each histogram its count,
sum and maximum. The Prometheus text prefixes every metric with `secopsai_`
and reports histograms as `_count`, `_sum` and `_max`.

The registry lives in one process. The CLI and the API endpoint above create a
fresh registry for each request, so they report empty metrics unless a
long-running hosted adapter records into a shared registry.

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
