# Research-company operation

SecOpsAI's initial research programs are software supply chains and AI/agent
security. The daily product is a verified intelligence brief. Original
advisories and longer reports depend on evidence, independent reproduction and
disclosure readiness. Discovery volume is not a release quota.

## Release contract

1. Collection creates leads. Scores, hashes shared with an article, word
   overlap, and agreement between models do not substantiate a claim.
2. A qualified human reviewer, distinct from the author, records the exact
   statement, exact archived text span, origin/hash/acquisition time, versions,
   environment, sample set, observation period, alternatives and limitations.
3. Observation, source reporting, inference, disputed and unknown are separate
   assessments. Analytic confidence is an explicit reviewer judgment with a
   rationale. Likelihood is optional and separate; severity and exposure remain
   case fields. Reference count never increases confidence.
4. Execution claims require recorded execution output and a scoped laboratory
   experiment. Static source code can establish a file read in the code; it
   cannot establish execution, successful exfiltration or victim compromise.
5. Prior-art searches record the index, query, time, earlier reports and precise
   contribution. Text similarity remains an attribution check, not proof of
   novelty. Model specialists remain supplementary challenges.
6. A named qualified technical reviewer and editor review the same exact draft.
   All mandatory checks must pass. Changed facts, evidence, scopes, reviewers,
   sharing rights, or draft text invalidate the relevant approval.
7. The final blog publication boundary rechecks the current case and exact
   text. Original Research cannot bypass the case gate by removing its ID.
   Publication and deployment remain separate human decisions.

Confirmed requires a credible verdict **and** a current reviewed malicious
observation. ATT&CK mappings require a separately recorded, reviewed behavior
with precise references. Keyword matches only guide investigation.

## Setup with real people

Use `secopsai --json research operation ACTION --input record.json --actor ID`.
Inputs may also be supplied through standard input with `--input -`. The
dashboard's protected Research operation panel records claim assessments and
exact-draft approvals. Hosted writes are explicit operator commands processed
by the research worker; they are never model actions.

Register the operator first with `person-register`; the initial record must use
the same actor/person ID and include the operator role. Subsequent registration
requires a registered operator. Supply real names, roles and qualifications;
registration is the authorized operator's assertion, not government identity
verification. Existing administrator tokens remain the authentication boundary.
An author cannot self-review. Do not register a model or service as a human.

Useful actions:

| Work | Actions |
|---|---|
| Staff and duty coverage | `person-register`, `people`, `roster` |
| Claims and independent reviews | `claim-assess`, `case-review`, `audit` |
| Novelty and methods | `prior-art`, `compare-releases`, `experiment`, `behavior` |
| Primary intelligence | `source-configure`, `source-collect`, `events`, `event-verify` |
| Editorial operation | `board`, `brief-create`, `brief-edit`, `brief-approve`, `brief-publish`, `brief-correct`, `editions` |
| Partners and disclosure | `submission`, `disclosure-milestone`, `requirement` |
| Durability | `queue`, `queue-claim`, `queue-heartbeat`, `queue-complete`, `queue-fail`, `artifact-backup`, `artifact-restore`, `recovery-drill`, `storage-assessment` |
| Measured usefulness | `outcome`, `metrics`, `coverage`, `status` |

The seven-day roster uses weekday keys `0` through `6` (Monday through Sunday),
each containing `author_id`, `editor_id`, `backup_id`. All three must be distinct
registered people; the editor and backup must hold the editor role. A research
owner may have at most two active original investigations on the editorial board.

## Daily operation, Europe/Istanbul

| Time | Work and accountable owner |
|---|---|
| Continuous | Bounded collection, artifact comparison, queue and freshness checks |
| 09:00 | Duty operator reviews collection gaps and checkpoint health |
| 09:30 | Research owner selects leads and planned hypotheses |
| 10:00–15:00 | Protected planned research, alongside urgent verified incidents |
| 15:00 | Independent technical reviewer checks evidence; owner follows disclosure |
| 16:00 | Worker assembles a draft from verified public primary-source items |
| 17:00 | Duty editor reviews and explicitly approves release |
| 18:00 | Duty operator verifies public output and records unresolved handoff |

`SECOPSAI_PRIMARY_INTEL=1` enables bounded primary intake and draft assembly in
the existing single-writer Research Worker. It cannot approve or publish.
Assembly is idempotent for the edition date. A missing roster is an explicit
blocker. A quiet day is an honest coverage/update brief; nothing is fabricated.

Event verification records a checked summary, defensive action, limitations,
primary event and primary URL. Aggregators cannot corroborate themselves.
Source timestamps, acquisition time and first observation remain distinct.
Missing source publication time stays unknown. KEV/EPSS signals are not claims
of exploitation observed by SecOpsAI; EPSS is a predictive 30-day measure.

`brief-approve` requires every release checklist item, a rationale,
`expected_fingerprint`, and `reviewed_draft` equal to the complete current body.
The assigned editor or backup must be distinct from the author. Larger hosted
drafts that exceed the bounded projection remain in the ledger and cannot be
approved from a truncated view. `brief-publish` creates the reviewed public blog
files; use the existing controlled Blog Ops deployment process to release them.
Hosted commands exclude local sample paths, queue leases and publication from
an ephemeral worker. Corrections retain the original body and require a new
review of the corrected or retraction notice.

## Evidence and lab inputs

`claim-assess` requires `statement`, `assessment`, `confidence`, `references`,
`scope`, `rationale`, `quality`, `alternatives`, `contradictions`, `limitations`.
`scope` contains `versions`, `environment`, `sample_set`, `observation_period`.
`likelihood` is optional in [0,1]; it is not confidence. Contrary evidence
requires a resolution before a supported assessment can be recorded.

A reference selects an existing active evidence record, for example:

```json
{"evidence_id":"existing evidence ID","selector":"/metadata/file_contents/install.js","start":0,"end":42,"excerpt":"the exact 42-character archived passage"}
```

Selectors support JSON Pointer escaping (`~1` for slash, `~0` for tilde).
Offsets count Unicode characters and must match the excerpt exactly. Titles,
analyst notes, and repeated identifiers are not admissible proof spans. Accepted
categories are archived source excerpts, file contents, matched strings, trace
events and experiment output. Evidence also needs a hash, provenance and
acquisition time. Source excerpts establish source-reported facts, not direct
SecOpsAI observations.

`experiment` records artifact hash, affected versions, environment, trigger,
observed behavior, competing explanations, demonstrated impact, mitigation,
reproduction steps, authorization scope, limitations and exact output references.
Execution modes require disposable systems, synthetic credentials, controlled
networking and authorized targets. This record never executes a submitted
command. Existing approval-gated sandbox tooling performs authorized execution.
Detection and patch-verification outcomes require actual recorded experiments.

`compare-releases` takes two attributable, timestamped, hash-bound snapshots
for one package. It compares install hooks, dependency declarations, publisher
labels and permission declarations. AI/agent comparisons additionally require
complete paginated MCP catalogs; new/removed/changed tool schemas and annotations
are recorded as untrusted differences requiring reproduction. See the
[MCP tool specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
and [MCP security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).

## Durability and monitoring

Primary intake stores bounded archived bytes, provenance, normalized events,
queue items and the cursor in one SQLite transaction. Invalid or oversized
feeds and backpressure leave the cursor unchanged. The existing registry
collectors retain their own transactional cursor/event behavior.

Queue leases are fenced. Expired jobs re-enter retry or dead letter; stale
workers cannot complete them. A repeated identical completion with the same
lease returns the original outcome; conflicting delivery fails. Remote operator
mutations and their command receipt commit together, so lost acknowledgements
cannot duplicate an approval or correction. No availability fallback converts
invalid evidence into a favorable decision.

Coverage reports use a stated window. They distinguish metadata-only sources,
bounded artifact scans, unknown upstream denominators, skipped/error reasons,
queue age, missing evidence instrumentation and freshness. Historical rows are
not comprehensive surveillance. `null` is unknown, not zero. New scan stage
records identify the same release event through acquisition and analysis.

Primary-source collection visits at most ten due feeds per cycle, so initial
coverage does not wait for several registry cycles. Catalog feed repairs retain
the original source identity and archived events; explicit operator changes take
precedence. Google's feed uses its HTTPS FeedBurner endpoint. MSRC uses the
Security Update Guide advisory feed because its old blog feed now serves HTML.
RSS excerpts over 20,000 characters carry a truncation flag, original length,
hash and selected range; the full feed remains archived and coverage counts the
truncation. A shortened excerpt cannot establish claims about omitted text.
Publisher-provided HTTP citation links remain untrusted source identifiers;
collection and every redirect still require HTTPS. Citation normalization never
asserts that an HTTP link was fetched or silently substitutes a different URL.

The private artifact client and its production smoke use an explicit application
User-Agent. Authentication, checksum validation and redirect rejection remain
required; the edge receiving a request is not evidence of a successful backup.

Deploy the merged Core revision through **Deploy Core Edge** on `main`. This
protected production workflow validates the hosted contracts, applies additive
D1 migrations and checks authenticated assistant reads without creating jobs.
Use **Deploy Ledger Store** to update private immutable storage and verify it
with a bounded benign object. These workflows use configured repository secrets;
local access failures do not bypass production authentication. Keep the GitHub
research worker as the sole ledger writer during this rollout.

The deployed ledger-store protocol advertises safe completion retries. Do not
start the disabled container runner or another writer. Test the worker, storage
service and failure/lost-acknowledgement regressions before deployment. The
independent research-operation watchdog checks checkpoint/source freshness and
public availability; it cannot write the ledger or launch a replay.
It also acquires and parses the ten supported public feeds independently of the
worker, distinguishing HTTP transport denial from invalid feed contents. RSS
requests advertise RSS/Atom/XML media types. Failed acquisition never advances
the source cursor or records a successful collection. A source reachable from
a developer machine may still reject hosted runners; that remains a coverage
gap until the source permits access or an explicitly reviewed intake path is
available. An unrelated replacement feed cannot establish the missing coverage.

`recovery-drill` copies a selected ledger consistently into a separate owner-only
file, reconciles table counts, checks foreign keys and source hashes, and records
restore duration. A small fixture drill cannot prove recovery of a 10 GB
production ledger. RPO ≤5 minutes and RTO ≤1 hour are targets requiring a
production-size drill and checkpoint-age measurement. `storage-assessment`
reports actual table/storage sizes and the gates for a future metadata-store
migration. Keep the current ledger authoritative until dual reads, reconciliation,
rollback and cutover tests pass. The ledger checkpoint alone does not back up
quarantine files. `SECOPSAI_ARTIFACT_VAULT=1` backs up public registry artifacts
immediately when registered by the research pipeline, before that step can
succeed, and retries existing artifacts in bounded batches. It writes private,
immutable R2 objects before recording a completed manifest receipt in the
ledger. Each object and the complete restored artifact
must match their SHA-256 and size. No bytes are extracted or executed.

`artifact-backup` accepts `artifact_id`; restricted/local samples additionally
require a registered operator and the explicit Boolean
`cloud_storage_authorized: true`, supported by the applicable sharing agreement.
`artifact-restore` accepts `artifact_id` and requires a completed receipt. It
recovers verified bytes into owner-only local quarantine. These actions are
local operator commands, excluded from hosted/model interfaces. Failed or
missing bytes never create a completed backup receipt. Historical artifacts
whose ephemeral files were already lost require authorized reacquisition; a
catalog record alone cannot recover them. Restore before sandbox handoff.

Chunks are at most 32 MiB, artifacts at most 250 MiB; the worker attempts five
public artifacts per cycle with a shared 60-second deadline. Missing historical
files do not consume upload slots; their failures distinguish missing,
unreadable and non-regular local bytes from upload failure. Its result records
the pending backlog and explicit failures within the latest 1,000 catalog
entries, rather than claiming complete historical backup coverage. The
hosted coverage projection reports outstanding public backup receipts, and the
watchdog blocks operational readiness while enabled backups remain incomplete.
The
[R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)
validates streamed checksums and conditional immutable writes.

## Acceptance gates and real operational dependencies

The software verifies behavior using synthetic, isolated fixtures. That does
not establish model calibration, a legal authorization, a partnership, a real
human review, an original discovery, or fourteen days of daily operation.
`status` reports these requirements separately. Pending, revoked and expired
agreements cannot satisfy readiness.

Keep Clef paused, the replay stopped, and alert closure in observation mode.
No live evaluation was authorized by this program. A future held-out evaluation
must use independent labels, fixed corpus hashes, predeclared acceptance criteria
and uncertainty; record both models' decisions separately. Never average scores
as a substitute for calibrated policy.

Days 1–14 establish real reviewer ownership, deployment/recovery evidence,
coverage baseline and a reviewed pilot. Days 15–30 require fourteen consecutive
reviewed briefs and rejected unsupported claims. Days 31–60 require independently
reproduced cases and tested defenses. Days 61–90 require reviewed original reports,
disclosure follow-ups and an honest held-out quality/coverage report. Expanding
telemetry and ecosystems depends on consent, measured discovery value and review
capacity. These elapsed-time and staffing gates cannot be accelerated by software.

## Operational recovery rollout

The worker cooperatively stops at safe transport/stage boundaries. A forced
shutdown still writes a final checkpoint but now fails the run; preserving bytes
must not label an incomplete cycle healthy. Semantic chunks are persisted before
transport, retained until acknowledgement, retried with the same receipt, and
subject to backpressure instead of deleting pending work. Each delivery pass has
a shared deadline. The hosted readiness view reports the complete pending count.

All fifteen configured publisher/registry sources have reviewed intake paths.
Grafana uses its official RSS index, GitHub its public advisory API, Open VSX its
release API, and JFrog/Socket bounded same-origin publisher indexes. These indexes
are source-reported leads, not complete historical coverage or full article
acquisition. Missing dates stay unknown. Empty/challenged index pages fail closed.

If the original CISA feed returns 403, a token-authenticated fixed-source collector
on the Ledger Worker may acquire the same original URL. Only CISA News and the
separate advisory comparison are allowed. The private token is never forwarded
to a publisher. Hashes, original source identity and collection transport are
validated and retained. A failed relay remains a collection gap.

`SECOPSAI_PUBLIC_ARTIFACT_RECOVERY=1` permits bounded reacquisition of registered
public registry artifacts from their archived URL and the ecosystem adapter's
host allowlist. Both the original hash and size must match before catalog repair;
private durable backup must complete before a recovery receipt exists. This never
extracts or executes a sample and cannot recover changed or unavailable bytes.
Restricted submissions remain outside automatic recovery.

Incremental checkpoints use consistent SQLite backups. Version 3 pins a full
baseline in immutable, individually hashed gzip chunks. The opt-in version 4
format records only changed 4 KiB blocks relative to that baseline, plus the
complete baseline manifest. A delta never references another delta. This avoids
retransmitting a large gzip chunk when a small edit lands anywhere within it. The manifest is
committed only after all referenced objects exist, and older completion retries
cannot move the pointer backward. Restore verifies compressed chunks, bounded
decompression, raw chunks, full database hash and SQLite integrity before atomic
replacement. Sparse restoration also validates record ordering, offsets, block
lengths, frame checksums and the final full database hash. A corrupt local baseline
or a rewrite changing more than one quarter of its bytes triggers an explicitly
bounded full rebase. The combined baseline and patch references remain capped at
900 objects, below the storage service's internal request budget. Legacy checkpoints remain preserved; old clients cannot silently
restore a legacy ledger after the incremental pointer advances.

Deploy the additive Ledger protocol first. Then enable the repository variable
`RESEARCH_INCREMENTAL_CHECKPOINTS=true` only after checks and the active legacy
writer complete. The first full transfer has a separate bounded 600-second
bootstrap budget. Verified immutable chunk receipts survive an interrupted
manifest commit within a runner. After bootstrap or a verified incremental
restore, the workflow uses a 60-second interval and a 240-second total recurring
capture/upload budget. The interval is measured from capture start; saves never
overlap and a slow save does not add another idle interval. A compact hash index
verified against the immutable baseline avoids rereading that full file on every
sparse capture. These bounds are an implementation design;
production five-minute committed-loss guarantees require measured crash drills.
After deploying the additive version 4 server and passing its gates, enable
`RESEARCH_PAGE_DELTA_CHECKPOINTS=true`. The runner retains a private immutable
baseline copy; disk capacity must accommodate the live ledger, baseline and
consistent capture. Bootstrap and full rebases may exceed the recurring recovery
objective and must be reported separately rather than represented as a proven RPO.
Use the read-only **Research Recovery Drill** workflow to restore the exact
production checkpoint in disposable storage, check foreign keys, enumerate rows
and verify source archive hashes. It then writes synthetic committed markers to
the private copy, checkpoints them in the isolated `/recovery-drill` namespace,
interrupts the next checkpoint before manifest commit and kills only its own
synthetic writer. Restoring the previous isolated checkpoint measures committed
loss and confirms that a failed commit preserves the previous pointer. The
production pointer is never modified. The report checks the one-hour recovery
and five-minute loss targets for that scenario; continued production timing
monitoring is required before claiming a sustained guarantee.

No rollout changes Clef enablement, decision mode, replay status, publication
approval or existing single-writer ownership. Real reviewers, partner agreements,
consented telemetry and independently labeled evaluation evidence remain external
activation requirements.

The disposable parser laboratory (`python -m secopsai.research_parser_lab`)
performs deterministic mutation tests on fixed SecOpsAI-owned parser targets.
It creates a separate process with no inherited provider credentials, blocks
network sockets, bounds CPU/runtime/input count, and records the exact corpus
hash, seed and failure identities. It executes no package code. This makes
parser robustness experiments repeatable; it does not replace authorized
package execution, victim telemetry or independent human reproduction. A
synthetic laboratory pass cannot satisfy held-out model calibration or create a
publication approval.


Ontology receipt identity
------------------------

New `ontology-v2:` receipts hash normalized JSON with stable object-key order;
array order and factual values remain material. Legacy receipt hashes retain
their original backend contract. Only an explicit legacy `idempotency_conflict`
can create a durably recorded versioned retry. The original queued JSON and key
remain archived in `ontology_sync_receipt_migrations`; acknowledgement of the new
receipt is required before the old outbox row is removed. Lost acknowledgements
reuse the same recorded versioned request. Entity identity and scope conflicts
never trigger this migration.

Named validation failures remain queued for review and do not block later valid
chunks that can supply missing dependencies. Authorization or transport failures
stop the bounded batch. The dashboard and watchdog continue to report all pending
work; a rejected chunk is never counted as delivered. Hosted workers emit bounded
stage names through `SECOPSAI_WORKER_STAGE_LOGS=1` so an interrupted cycle identifies
its last stage without exposing case content. Recovery reports preserve SQLite
error codes and failure phases without recording endpoint bodies or credentials.


Source-to-lead delivery
-----------------------

Per-source, version and archived-source-hash delivery receipts track successful
advisory-to-lead materialization. The grouped package alert ID is captured rather
than guessed from a historical dedupe format. Unchanged facts are not repeatedly
upserted and cannot reopen an operator-resolved lead on every cycle. A changed
source hash or a missing referenced candidate/alert remains eligible for repair.
Receipts are written only after a durable alert exists; a crash before receipt
storage safely repeats the idempotent grouped upsert.

Hosted cycles prioritize historical private backup/recovery and primary-source
intake before external advisory materialization. The worker bounds that latter
batch to 100 records, so progress can resume from receipts rather than repeating
the same first thousand records and starving collection.


Existing ledgers migrate to schema version 14 before ontology receipt migration
or external advisory delivery. Both required delivery tables participate in the
initializer's fast-path check, including recovery from an incomplete upgrade.
A fresh supervisor restore fences running daily jobs from the serialized snapshot;
ordinary starts preserve live owners' leases. Cooperative shutdown releases only
the current run's exact owner and generation, retaining completed step evidence.
Daily automation invoked after the current worker's surveillance records that
step as already performed instead of recursively collecting the same sources.
Standalone daily automation still performs its own surveillance pass.

For delivery repair after collection/analysis already passed, the Research Worker
workflow's `delivery_only` input restores the canonical ledger, materializes a
bounded semantic snapshot, durably queues it, drains acknowledged delivery within
an 840-second budget and refreshes the hosted research-operation projection. It
uses the same single-writer lock and final checkpoint. It performs no registry
scans, package analysis or model jobs. Rejected or unacknowledged records remain
queued and fail verification. Optional `retry_sources` names select only enabled
primary sources still reporting failures; already recovered sources are skipped,
and disabled sources cannot be resumed by this path. A successful projection
write retries transient transport/server failures against one 45-second deadline;
authentication and contract failures are never retried as availability failures.
