# Enterprise migrations

`001_enterprise_security.sql` is the versioned schema for the enterprise
repository. The SQLite adapter applies it automatically. The PostgreSQL
adapter applies it when the optional enterprise dependency is installed and a
valid `SECOPSAI_ENTERPRISE_DATABASE_URL` is configured.

Run migrations only against the intended organization database. Back up the
database first and review the migration in change control.
