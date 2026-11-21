# Enterprise Deployment

The enterprise features (connectors, vulnerability management, GRC and the
security workflows) share one data store. It runs on SQLite for a single
operator and on PostgreSQL for a hosted team deployment.

## Local mode (default)

No extra setup. Records go to `data/enterprise/enterprise.db` in the SecOpsAI
checkout; set `SECOPSAI_ENTERPRISE_DB_PATH` or pass `--db-path` to use another
file. Local mode needs no PostgreSQL and no cloud credentials, and every
enterprise CLI command works in it.

Check the store:

```bash
secopsai enterprise status --json
```

This reports the backend, the organization ID, record counts (events, assets,
vulnerabilities and open vulnerabilities, controls, evidence, questionnaires,
threat models, penetration tests, actions and dead letters) and recent items.

## Hosted mode (PostgreSQL)

```bash
pip install -r requirements-enterprise.txt   # psycopg with its connection pool
export SECOPSAI_ENTERPRISE_DATA_STORE=postgres
export SECOPSAI_ENTERPRISE_DATABASE_URL=postgresql://...
export SECOPSAI_ENTERPRISE_ORGANIZATION_ID=acme
```

The adapter keeps a pool of 1 to 10 connections and applies the schema in
`migrations/enterprise/` on start. Keep the database URL, cloud credentials and
connector settings in a server-side secret manager, not in shell history or
files in the repository.

## Organizations and roles

Every record carries an organization ID, and a store only reads and writes its
own organization's records. The ID must start with a letter or digit and may
contain `_ . : / -`, up to 120 characters.

CLI commands take `--organization-id`, `--actor` and `--role`. The hosted Core
API uses its configured organization ID and a fixed role per endpoint: reads
use `operator_read`, event ingestion `enterprise_ingest`, and writes
`intelligence_operator`. The caller's API credentials decide which endpoints
they may call.

| Role | Can do |
| --- | --- |
| `operator`, `security_engineer`, `administrator`, `intelligence_operator` | Create approval-gated action proposals and write governance records |
| `auditor`, `reviewer` | Write governance records (controls, evidence) |
| `analyst`, `operator_read` | Read |
| `service`, `enterprise_ingest` | Machine identities for ingestion |

Deleting events under a retention policy needs explicit approval and the
`administrator` or `security_engineer` role, and is recorded in the audit log.

## Data handling

- Credential-shaped fields (`token`, `secret`, `password`, `api_key`,
  `authorization`, `cookie`, `private_key`) are redacted before storage
- each stored record is limited to 256 KiB, and pages to 500 records
- the hosted Core API applies a fixed-window rate limit of 120 requests a
  minute

## Before exposing a hosted API

Configure exact CORS origins, trusted hosts, rate limits, retention, backups
and organization and role claims. The dashboard must show a clear
`not_configured` status for any enterprise connector that is unavailable.
