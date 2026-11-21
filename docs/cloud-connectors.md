# Cloud Connectors

SecOpsAI reads cloud and cluster security telemetry through read-only
connectors and normalizes it into one event format in the enterprise store.
Connectors never change cloud resources: there is no write path for IAM,
firewall, cluster or key changes.

## Supported sources

| Source ID | Provider data | Severity rule |
| --- | --- | --- |
| `aws.cloudtrail` | CloudTrail management events | `high` for `DeleteTrail`, `StopLogging`, `PutEventSelectors`, `CreateAccessKey`; otherwise `info` |
| `aws.guardduty` | GuardDuty findings | From the GuardDuty score: 8+ `critical`, 5+ `high`, 2+ `medium`, else `low` |
| `aws.securityhub` | Security Hub findings | The finding's severity label |
| `gcp.audit` | Cloud Audit Logs | `high` when the method sets IAM policy, creates a key, deletes or disables; otherwise `info` |
| `gcp.scc` | Security Command Center findings | The finding's severity |
| `kubernetes.audit` | Kubernetes audit events | `high` for create, delete, patch or update on cluster roles, role bindings, secrets, pods or deployments |

## Try it with a fixture

The fixture path reads a local JSON file and never contacts a provider. It is
the safe way to check normalization and storage:

```bash
secopsai enterprise ingest --source aws.cloudtrail --input cloudtrail-fixture.json --json
secopsai enterprise ingest --source gcp.audit --input audit-fixture.json --json
secopsai enterprise ingest --source kubernetes.audit --input audit-fixture.json --json
```

The input can be a single event, a list of events, or an object with an
`events`, `findings` or `items` list. A `next_cursor`, `nextToken` or
`nextPageToken` field is stored as the source cursor. `--limit` caps one page
at 1 to 500 records (default 100), and `--cursor` resumes from a stored cursor.

## What is stored

Each normalized event keeps:

- `event_id`, `source`, `event_type` (for example `aws.createaccesskey` or
  `kubernetes.delete.secrets`), `observed_at`, `severity` and `correlation_id`
- the actor (ARN and account for AWS, principal e-mail for GCP, user name and
  groups for Kubernetes) and, for Kubernetes, the object reference
- the original record with credential-shaped fields (`token`, `secret`,
  `password`, `api_key`, `authorization`, `cookie`, `private_key`) replaced by
  `[redacted]`

Events are written with an idempotency key built from the source and the
provider's event ID, so re-ingesting a page does not create duplicates. Each
event is limited to 256 KiB.

## Failure handling

A connector failure never looks like an empty, healthy result. The failed page
is recorded as a retryable dead letter, and the source cursor is marked
`degraded` with the error and time, while keeping the last good cursor. Run
`secopsai enterprise status --json` to see store health and recent counts,
including dead letters.

## Hosted adapters

Hosted collection uses the same normalizers through injected, read-only
clients (`boto3` for AWS). Supply credentials through IAM role assumption,
workload identity or a server-side secret manager. Never pass credentials in
command arguments, URLs, browser storage or event payloads.

Cloud changes, key revocation, firewall changes and egress blocking remain
approval-gated actions; see [Enterprise Deployment](enterprise-deployment.md)
for roles.
