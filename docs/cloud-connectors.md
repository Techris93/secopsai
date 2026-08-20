# Cloud Connectors

SecOpsAI provides read-only normalization contracts for AWS CloudTrail,
GuardDuty, Security Hub, GCP Audit Logs, Security Command Center, and
Kubernetes audit events.

The local fixture path is safe and does not contact a provider:

```bash
secopsai enterprise ingest --source aws.cloudtrail --input cloudtrail-fixture.json --json
secopsai enterprise ingest --source gcp.audit --input audit-fixture.json --json
secopsai enterprise ingest --source kubernetes.audit --input audit-fixture.json --json
```

Hosted adapters should use IAM role assumption, workload identity, or a
server-side secret manager. Credentials must not be passed in command
arguments, URLs, browser storage, or event payloads. Connector failures create
dead-letter records and degraded source-cursor state rather than an empty
healthy result.

Cloud changes, key revocation, firewall changes, and egress blocking remain
approval-gated actions.
