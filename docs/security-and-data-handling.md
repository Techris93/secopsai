---
title: Security And Data Handling
description: SecOpsAI trust boundaries, local-first data handling, credentials, model context, and approval controls.
---

# Security And Data Handling

SecOpsAI is local-first by default. Operators decide which adapters,
integrations, model providers, hosted services, and protected actions to
configure. A capability being implemented does not mean it is configured,
active, or authorized.

## Data Locations

| Data | Default handling |
| --- | --- |
| Host and agent telemetry | Normalized and stored in the operator-controlled local data plane |
| Findings and triage records | Stored in local SQLite unless the optional hosted PostgreSQL adapter is configured |
| Package artifacts | Quarantined for bounded static inspection; not installed or executed |
| Dashboard data | Local helper and/or authenticated Supabase records, depending on deployment |
| Model requests | Minimized evidence sent only to the model/provider selected by the operator |
| Credentials | Local environment or server-side secrets; never intentionally rendered into browser configuration |
| Research and publication records | Local repository/data paths until an operator approves an external action |

Retention, backup, deletion, and access-control policy remain the operator's
responsibility for self-hosted deployments.

## Credentials

- Keep local secrets in owner-controlled environment files that are excluded from version control.
- Keep hosted credentials in the deployment platform's secret store.
- Never put passwords, access tokens, or private keys in URLs, public JavaScript, screenshots, logs, issues, or research drafts.
- Use separate credentials for operator authentication, Core reads, Edge reads, helper actions, model actions, Blog Ops, and deployment.
- Rotate any credential that may have been exposed.

## Artifact Safety

SecOpsAI inspects package metadata and archives without installing packages,
running lifecycle scripts, importing modules, activating extensions, executing
binaries, or launching downloaded payloads. Exact local artifact paths remain
CLI-controlled rather than browser-controlled.

Dynamic sandbox submission is a separate, approval-gated action. Operators must
confirm they are authorized to share an artifact with the selected provider.

## Model Safety

Deterministic evidence remains authoritative. Model review receives bounded,
minimized context and produces proposals or analyst briefs rather than
unreviewed security truth. The selected primary model persists. Any fallback
policy is explicit and visible; primary-only mode does not silently consume a
different provider.

Models cannot independently:

- Enable unverified detection rules.
- Submit artifacts to external sandboxes.
- Send vulnerability disclosures.
- Publish research.
- Deploy the blog.
- Apply cloud, Kubernetes, or active DAST changes.

## Browser And Helper Boundary

The dashboard calls typed, allowlisted helper routes. The browser cannot submit
arbitrary shell commands or choose unrestricted filesystem paths. Hosted mode
returns clear `not_configured` guidance when a local/helper-backed capability
is unavailable.

## External Services

Enabling Supabase, Cloudflare, Sentry, model providers, GitHub workflows,
webhooks, email, sandbox providers, or cloud connectors sends data to those
services according to the operator's configuration. Review the service's data
handling, region, retention, access, and cost controls before enabling it.

## Reporting

Report SecOpsAI vulnerabilities privately using the repository
[Security Policy](https://github.com/Techris93/secopsai/security/policy).
General research and operator contact routes are listed on the
[Contact](contact.md) page.
