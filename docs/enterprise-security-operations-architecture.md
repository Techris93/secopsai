# Enterprise Security Operations Architecture

## Purpose

SecOpsAI is currently a local-first security monitoring, investigation, and
triage platform. This document defines the target enterprise architecture for
cloud telemetry, SIEM-style observability, vulnerability management, DAST,
GRC evidence, customer questionnaires, threat modeling, penetration-test
coordination, and developer security awareness.

## Current architecture

The local path remains authoritative for workstation and sensor deployments:

- OpenClaw, Hermes, macOS, Linux, Windows, and SecOpsAI Edge adapters produce
  normalized events.
- `soc_store.py` persists findings, evidence, triage state, and audit history in
  SQLite.
- Supply-chain and research modules persist registry history, advisory data,
  artifacts, and cases in bounded local stores.
- The Core API exposes authenticated normalized ingest and read operations.
- The dashboard calls typed helper/API operations; it never executes arbitrary
  shell commands in the browser.
- The local Codex/OpenCodex bridge is optional, bounded, and approval-gated.

The active runtime is deliberately single-workspace and file-backed. SQLite
and local files must remain supported after the hosted data plane is added.

## Target architecture

```text
Cloud / Kubernetes / CI / host / agent sources
                |
       Connector and cursor layer
                |
   Normalization, redaction, dedupe, tenancy
                |
     Enterprise event and asset data plane
                |
 Detection-as-code + vulnerability + DAST + GRC
                |
 Findings, cases, tickets, controls, dashboards
                |
 Approval-gated response and audited exports
```

The target hosted data plane uses PostgreSQL with explicit transactions,
connection pooling, tenant isolation, bounded queries, and migration-managed
schemas. The local adapter uses the same repository contracts on SQLite.

## Ownership and trust boundaries

| Boundary | Owner | Default behavior |
| --- | --- | --- |
| Cloud, Kubernetes, CI, host, and agent collection | Connector layer | Read-only, cursor-based, rate-limited |
| Event normalization and redaction | Core | Remove credentials, raw bodies, and private payloads before persistence |
| Detection and scoring | Core rules | Deterministic evidence first; explainable output |
| Model assistance | Local/hosted bridge | Optional, minimized context, no provider fallback unless configured |
| Findings and case state | Data plane | Tenant-scoped, audited writes |
| Response and ticket creation | Action layer | Allowlisted, idempotent, approval-gated |
| Compliance evidence | GRC layer | Provenance, owner, expiry, reviewer, exportable |
| Customer answers | Questionnaire layer | Evidence-backed drafts; human approval before export/send |

## Deployment modes

### Local mode

Local helper mode continues to work with no PostgreSQL, cloud credentials, or
external scanner. It uses SQLite, local fixtures, and dry-run adapters. Missing
integrations render as `not_configured`; they must not be treated as healthy.

### Hosted mode

Hosted mode uses PostgreSQL, a pooled API connection, organization and role
claims, encrypted server-side connector configuration, and a worker for cursor
polling. The browser receives summaries and identifiers, never provider
credentials or raw cloud/agent telemetry.

## Feature flags

- `SECOPSAI_ENTERPRISE_DATA_STORE=sqlite|postgres`
- `SECOPSAI_ENTERPRISE_ORGANIZATION_ID`
- `SECOPSAI_ENTERPRISE_DATABASE_URL`
- `SECOPSAI_ENTERPRISE_CONNECTORS=aws,gcp,kubernetes,dast`
- `SECOPSAI_ENTERPRISE_METRICS=off|prometheus|otlp`
- `SECOPSAI_ENTERPRISE_ACTIVE_SCANS=off|approval_required`
- `SECOPSAI_ENTERPRISE_TICKETING=off|approval_required`
- `SECOPSAI_ENTERPRISE_GRC=off|local|hosted`

No flag enables destructive cloud, Kubernetes, DAST, disclosure, or ticketing
actions without an explicit approval record.

## Security and privacy requirements

- Credentials stay in environment/configuration stores and never in URLs,
  browser storage, command arguments, or logs.
- Raw cloud events, packet data, scanner output, package archives, and request
  bodies remain outside model context unless an approved minimized evidence
  path explicitly permits them.
- Every connector has bounded request size, timeout, retry, rate-limit, cursor,
  and dead-letter behavior.
- Every write has an actor, organization, request ID, idempotency key, and
  audit record.
- Evidence has a hash, source, collected time, owner, and expiry/review time.

## Remaining limitations

The first enterprise release does not claim SOC 2, ISO, HIPAA, or NIS2
certification. It provides control mappings and evidence workflows. Cloud
connectors remain read-only by default. Active DAST, IAM changes, firewall
changes, Kubernetes mutations, external disclosure, and publication remain
explicitly approved operations.
