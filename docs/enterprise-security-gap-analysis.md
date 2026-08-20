# Enterprise Security Gap Analysis

## Baseline

SecOpsAI already provides strong local detection engineering, supply-chain
analysis, cross-platform telemetry, triage orchestration, CI security gates,
research cases, and bounded model review. The remaining gaps are integration
and operating-model gaps rather than a replacement of those capabilities.

## Capability matrix

| Area | Existing state | Enterprise addition |
| --- | --- | --- |
| Detection and triage | Strong local SQLite workflow with evidence and approvals | Tenant-aware event/finding repositories and external alert routing |
| Vulnerability management | Strong package, artifact, advisory, and container coverage | Asset ownership, CVSS/exploitability context, SLAs, exceptions, tickets |
| Observability | Local logs, health, freshness, optional Sentry | Metrics, traces, dead-letter queues, SIEM exports, MTTD/MTTR measurements |
| AWS | Credential and behavior indicators only | CloudTrail, GuardDuty, Security Hub, IAM, VPC, and Secrets Manager adapters |
| GCP | Credential and metadata indicators only | Audit Logs, SCC, IAM, VPC, GKE, and Secret Manager adapters |
| Kubernetes | Static manifests, token indicators, and container scanning | Audit/API posture, RBAC, workload, admission, and runtime event ingestion |
| DAST | No first-class workflow | Authorized target registry, passive scan, approval-gated active scan, SARIF |
| GRC | Threat model and security documentation | Control catalog, evidence provenance, exceptions, expiry, auditor review |
| Questionnaires | No dedicated workflow | Versioned answer library, evidence links, review, import, and export |
| Threat modeling | Documentation and research-case evidence | Structured systems, trust boundaries, threats, mitigations, and reviews |
| Penetration testing | Artifact/evidence import | Engagement scope, authorization, partner deliverables, retest tracking |
| Awareness | Guides and security research | Finding-linked learning content and completion metrics |
| Data plane | SQLite/files, intentionally single-workspace | PostgreSQL, pooling, RBAC, tenant isolation, migrations, retention |

## Sequencing

1. Shared enterprise schemas, repositories, redaction, tenancy, and metrics.
2. AWS, GCP, Kubernetes, and SIEM export adapters.
3. Asset-centric vulnerability management and ticketing.
4. Authorized DAST and container/Kubernetes posture.
5. GRC evidence, questionnaires, threat modeling, and penetration-test cases.
6. Awareness content, dashboard surfaces, and hosted deployment hardening.

## Verification standard

Every addition requires deterministic fixtures, mocked external calls,
permission tests, redaction tests, pagination tests, failure/freshness tests,
and a documented not-configured state. No feature is considered complete merely
because its configuration or UI exists.
