# Enterprise Deployment

Local installations use SQLite and the existing helper. Hosted installations
set `SECOPSAI_ENTERPRISE_DATA_STORE=postgres`,
`SECOPSAI_ENTERPRISE_DATABASE_URL`, and
`SECOPSAI_ENTERPRISE_ORGANIZATION_ID`, then install the optional enterprise
dependency:

```bash
pip install -r requirements-enterprise.txt
```

The PostgreSQL adapter uses a bounded connection pool. Cloud credentials and
connector configuration belong in a server-side secret manager. Configure
exact CORS origins, trusted hosts, rate limits, retention, backups, and
organization/RBAC claims before exposing hosted APIs.

Local helper mode remains valid with no PostgreSQL or cloud credentials. The
dashboard must show clear `not_configured` status for unavailable enterprise
connectors.
