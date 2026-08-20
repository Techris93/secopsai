# SIEM And Observability

`secopsai.siem.MetricsRegistry` provides bounded counters, gauges, and
histograms for ingestion latency, queue depth, source freshness, processing
failures, MTTD, false-positive rate, and remediation age. Prometheus text and
newline-delimited normalized-event export are available to a hosted adapter.

The enterprise store keeps source cursors, dead letters, audit records, and
organization-scoped events. Raw secrets and credential-shaped fields are
redacted before persistence. Optional Sentry remains privacy-preserving and
disabled unless configured.

Splunk, Elastic, Chronicle, OpenTelemetry, and Prometheus exports should be
configured server-side. The dashboard displays `not_configured` when no
exporter is enabled.
