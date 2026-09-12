# SecOpsAI security ontology

SecOpsAI's ontology is an additive semantic layer over the existing research
ledger, findings tables, and Edge graph. It gives an analyst one stable way to
find an object, follow its relationships, inspect provenance, and decide what
can safely happen next. It does not replace the source records and it never
stores raw package content, credentials, scanner output, or private telemetry
in the hosted control plane.

## Contract

The current contract is `secopsai.ontology.v1`. Entity IDs are deterministic
and namespaced, for example `pkg:pypi:example`,
`pkgver:pypi:example@1.2.3`, `finding:secopsai:SCM-123`,
`asset:edge:asset-1`, and `case:secopsai:RSC-123`. Package names are
normalized per ecosystem (PyPI underscores become hyphens); vulnerability and
advisory identifiers are upper-cased; hash prefixes are removed from artifact
keys while the source value is retained as an alias.

Supported entities include packages and versions, artifacts, registries and
release events, advisories and vulnerabilities, repositories, manifests,
dependencies, builds, CI runs, deployments, assets, services, sensors,
networks, workspaces, owners, teams, findings, alerts, candidates, research
cases, investigations, evidence, IOCs, hypotheses, collectors, sources,
automation runs, intelligence jobs, tasks, commands, models, triage decisions,
remediation actions, approvals, and publications.

Relationships are typed. The principal paths are:

```text
package → package_version → release_event → advisory → artifact
artifact → finding → repository/manifest → build → deployment → asset
asset → owner/team → research_case → evidence → remediation_action
```

The API allowlist also includes `PACKAGE_HAS_VERSION`,
`VERSION_AFFECTED_BY_ADVISORY`, `VERSION_HAS_ARTIFACT`,
`REPOSITORY_DEPENDS_ON_VERSION`,
`MANIFEST_DECLARES_DEPENDENCY`, `BUILD_PRODUCES_ARTIFACT`,
`ARTIFACT_DEPLOYED_TO_ASSET`, `FINDING_ON_VERSION`, `FINDING_ON_ASSET`,
`ALERT_DERIVED_FROM_FINDING`, `CANDIDATE_PROMOTED_TO_CASE`,
`CASE_GROUPS_FINDING`, `CASE_GROUPS_ALERT`, `CASE_SUPPORTED_BY_EVIDENCE`,
`EVIDENCE_FROM_SOURCE`, `EVIDENCE_SUPPORTS_HYPOTHESIS`,
`ACTION_REMEDIATES_FINDING`, `RUN_PRODUCED_RESULT`,
`COMMAND_REQUESTS_RUN`, and `ACTOR_APPROVED_ACTION`, together with the
connector relationships used by Edge, collectors, investigations, and jobs.

Every entity and relationship carries source and source-record identity,
first/last seen, observed and validity times, confidence, freshness, workspace,
bounded properties, schema version, and audit history. Evidence is a reference
(`source`, locator, optional content hash, and a bounded summary), never the raw
artifact itself.

## Storage and backfill

Local SQLite remains authoritative for complete history and evidence. Its
ontology tables are created by `soc_store.init_db` and include entities, aliases,
relationships, evidence references, events, merge records, conflicts, change
history, metadata checkpoints, and ingest receipts. Core Edge's D1 migrations
`0003_ontology.sql`, `0004_control_plane_bounds.sql`,
`0005_ontology_ingest_receipts.sql`, and `0006_ontology_evidence_scope.sql`
provide the equivalent hosted projection; `0007_ontology_entity_validity.sql`
adds optional entity validity windows in already initialized D1 databases.
D1 stores bounded summaries, queue state, heartbeats, and references only.

Before a backfill, use SQLite's online backup API, calculate SHA-256, store the
backup outside the repository, and open it with `PRAGMA quick_check`. The
resumable CLI command is:

```bash
SECOPSAI_ROOT=/Users/chrixchange/secopsai
cd "$SECOPSAI_ROOT"
.venv/bin/python -m secopsai.cli --json ontology backfill \
  --db-path data/openclaw/findings/openclaw_soc.db --batch-limit 1000
```

The command checkpoints each source table in `ontology_metadata`, commits each
batch under the existing SQLite writer lock, and can be rerun safely. It
projects graph nodes, findings, research cases, alerts, candidates, and their
known relationships. Raw research artifacts and full evidence remain in their
original stores.

## APIs and authorization

The local Core API and the hosted Core Edge Worker expose the same read model:

```text
GET  /api/v1/ontology/search
GET  /api/v1/ontology/entities/{entity_id}
GET  /api/v1/ontology/entities/{entity_id}/neighbors
GET  /api/v1/ontology/entities/{entity_id}/timeline
GET  /api/v1/ontology/entities/{entity_id}/lineage
GET  /api/v1/ontology/entities/{entity_id}/risk
GET  /api/v1/ontology/quality
POST /api/v1/ontology/sync
```

Read routes require the read token. Risk explanations require the intelligence
token. Runner synchronization requires the separate bridge token. Sync batches
are bounded, validate entity and relationship allowlists, enforce configured
workspace scope, reject unnamespaced IDs and invalid package-version keys, and
accept an `Idempotency-Key` header. A repeated key returns the original receipt;
reusing it with a different payload is rejected. Protected reads and all writes
create audit records.

Traversal is depth-limited to four hops and each response has a bounded node,
relationship, and page limit. The service filters rows to the configured
workspace before returning neighbors, timelines, lineage, or risk context.

The risk endpoint is deterministic: severity, exploitability, asset criticality,
reachability, evidence references, and freshness are visible as separate
factors. A model can explain that context, but it cannot add an unsupported
relationship or claim that unavailable evidence exists. The returned action
contract is a reversible proposal and requires operator approval.

## Runner and Mission Control

After a collector cycle the Render research worker emits a heartbeat, publishes
a redacted coordinator snapshot, materializes a bounded ontology projection,
and sends it to Core Edge with a deterministic idempotency key. If the hosted
endpoint is unavailable, local collection continues, the cycle is marked
degraded, and the bounded SQLite outbox retries the same snapshot when the
endpoint returns.
Coordinator commands are claimed with a lease and reported as queued, running,
succeeded, degraded, failed, canceled, or recovered.

Mission Control's **Operating picture** page searches the same canonical IDs and
shows object detail, aliases, related records, lineage, event timeline,
freshness, provenance, contradictions, missing context, deterministic risk, and
a reversible next-action proposal. It keeps Findings, Assets, Work, Research,
Automation, and System as distinct operator surfaces while linking them through
the ontology. Hosted views show an explicit degraded or unavailable state when
Core cannot be reached; the local dashboard remains the full historical view.

## Data quality and governance

`/api/v1/ontology/quality` reports canonical-ID coverage, linked findings,
provenance coverage, evidence references, orphan entities and relationships,
stale entities, open conflicts, change history, and counts by entity type. Use
these metrics to alert on stale workers, rising orphans, queue age, missing
provenance, and storage pressure.

All model context is assembled from authorized ontology queries and bounded
evidence summaries. Source text and artifact metadata are treated as
untrusted input, secrets are redacted before model submission, and every result
records facts, inferences, contradictions, unsupported claims, missing
evidence, limitations, confidence, and evidence references. Publication,
disclosure, scanner changes, customer-control changes, artifact execution, and
other consequential actions remain approval-gated and rollback-aware.

## Verification walkthrough

The end-to-end fixture in `tests/test_ontology.py` creates a finding, asset,
team, evidence event, and bounded relationships, then verifies cycle-safe
neighbors, lineage, deterministic risk, alias resolution, conflict recording,
and an auditable merge. Core Edge tests cover token separation, workspace
filtering, malformed payloads, namespaced IDs, and ingest idempotency. The
dashboard contract test verifies the hosted proxy and all operating-picture
surfaces. Run the focused checks with:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/pytest -q \
  tests/test_ontology.py tests/test_ontology_migrations.py tests/test_core_api.py
cd cloudflare/secopsai-core-edge && npm test
cd /Users/chrixchange/secopsai-dashboard/secopsai-dashboard && npm test
```
