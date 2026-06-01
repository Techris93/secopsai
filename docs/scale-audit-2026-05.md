# SecOpsAI Scale Audit - May 31, 2026

This audit reviewed SecOpsAI and the canonical SecOpsAI dashboard for the five
common production data-access failures: N+1 reads, missing pagination, missing
indexes, unsafe connection/client reuse, and overbroad fetches.

## Architecture Summary

SecOpsAI is mostly file-backed with one local SQLite SOC store.

- SOC findings: `soc_store.py` stores findings, finding-event links, and notes in
  `data/openclaw/findings/openclaw_soc.db`.
- Supply-chain history: `secopsai/supply_chain.py` appends scan results to a
  JSONL history file and stores advisory JSON under the local advisory data
  directory.
- Triage state: `secopsai/triage/*` reads findings from the SOC store and writes
  report JSON/Markdown files.
- Blog Ops: `secopsai/blog.py` uses local JSON/Markdown files for drafts, posts,
  feeds, and source caches.
- Threat intelligence: `secopsai/intel.py` and related scripts read/write local
  JSON IOC and report files.
- Dashboard local helper: `dashboard_server.py` shells through allowlisted
  SecOpsAI CLI commands and reads local manifests/reports.
- Dashboard hosted worker: `_worker.js` uses GitHub API calls for Blog Ops and
  optionally proxies helper-backed SecOpsAI actions when configured.

No production Postgres/MySQL ORM path was found in the active app. Supabase SQL
migrations and sync scripts exist for optional/export workflows, but the default
runtime path remains SQLite plus local files.

## Findings

### 1. N+1 Reads

Found:

- `secopsai/triage/engine.py` listed findings through `soc_store.list_findings`,
  then loaded each finding again with `soc_store.get_finding` to infer category.
- `dashboard_server.py` reused the dependency path list, but reread every
  dependency manifest for every Triage Ops alert.
- `_worker.js` fetched draft metadata by listing GitHub contents and then
  fetching each draft JSON body individually. This is unavoidable with the
  current GitHub Contents API shape, but it was previously serial.

Fixed:

- Added filtered, payload-aware listing in `soc_store.list_findings`.
- Updated triage listing to filter in SQLite and parse payloads from the same
  query instead of per-row detail lookups.
- Added manifest text caching in `dashboard_server.py`, invalidated by file
  mtime/size.
- Added bounded batched draft loading in `_worker.js`.

### 2. Missing Pagination / Limits

Found:

- Most CLI commands already expose limits.
- `secopsai/supply_chain.py::load_recent_results(limit=...)` accepted a limit but
  read the full JSONL history into memory before slicing.
- Dashboard Blog Ops already capped drafts at 50, but the cap was implicit.

Fixed:

- `load_recent_results` now tails only the requested number of JSONL rows.
- Hosted Blog Ops draft listing now has explicit limit plumbing with a max of
  50.

### 3. Missing Indexes / Inefficient Lookups

Found:

- The SOC store had a primary key on `finding_id`, but no indexes for common
  dashboard/CLI access paths such as status, severity, source, or last seen.

Fixed:

- Added indexes:
  - `idx_findings_status_severity_first_seen`
  - `idx_findings_severity_score_first_seen`
  - `idx_findings_source`
  - `idx_findings_last_seen`
  - `idx_notes_finding_note`

### 4. Connection / Client Reuse

Found:

- SQLite connections are short-lived and scoped to operations. That is acceptable
  for local CLI/helper usage, but would need pooling if moved to a multi-user
  web service.
- HTTP access uses `requests.Session` in threat-intel and npm registry monitor
  components where repeated calls are expected.
- Hosted dashboard GitHub API calls use Cloudflare `fetch`; no raw token or
  arbitrary shell execution path was found.

Fixed:

- No connection-pool change was needed for the current local SQLite/CLI model.
- The worker now batches draft-content calls to reduce serial latency while
  keeping a hard cap.

### 5. Overbroad Fetches

Found:

- SOC list queries used explicit fields and did not use `SELECT *`.
- `get_finding` intentionally fetches `payload_json` only for detail views.
- The supply-chain recent-results list overfetched by reading the whole history.

Fixed:

- Kept SQL explicit-field style.
- Changed supply-chain history list to tail the requested number of rows.

## Tests Added

- `tests/test_triage.py::test_triage_list_uses_batched_store_rows_for_category_filtering`
  prevents the triage-list N+1 detail lookup from returning.
- `tests/test_supply_chain.py::test_load_recent_results_respects_zero_limit`
  verifies bounded history reads handle zero limits safely.
- Dashboard `tests/test_triage_ops_evidence.py::test_dependency_usage_reuses_manifest_text_cache`
  verifies manifest text caching.
- Dashboard `tests/blog-ops-worker.test.mjs::testDraftListHonorsLimitAndAvoidsUnboundedFetches`
  verifies hosted draft listing honors explicit limits.

## Remaining Risks

- The app is still primarily file-backed. That is fine for local SecOps/CLI use,
  but a shared multi-user deployment should move findings, drafts, source
  freshness, and action queues into a transactional database.
- GitHub Contents API draft summaries still require one content request per
  listed draft. The cap and batching keep this predictable, but a future
  production version should maintain a generated draft-summary index.
- JSON advisory/source stores are cached and indexed in memory, not a database.
  This is acceptable for current scale but should become table-backed if advisory
  volume grows substantially.

## Future Production DB Plan

If SecOpsAI is promoted to a persistent multi-user backend, migrate these stores
first:

- `findings`: index `status`, `severity_score`, `source`, `last_seen`,
  `ecosystem`, `package`, and `finding_id`.
- `blog_drafts`: index `review_status`, `updated_at`, `slug`, `source_name`.
- `supply_chain_results`: index `ecosystem`, `package`, `version`, `verdict`,
  `created_at`, and `finding_id`.
- `advisories`: index `ecosystem`, `package`, `status`, `advisory_id`,
  `campaign_id`.
- `triage_actions`: index `status`, `finding_id`, `created_at`, `action_id`.

Keep list endpoints summary-only by default and reserve full payload/report body
loads for detail endpoints.
