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

`recovery-drill` copies a selected ledger consistently into a separate owner-only
file, reconciles table counts, checks foreign keys and source hashes, and records
restore duration. A small fixture drill cannot prove recovery of a 10 GB
production ledger. RPO ≤5 minutes and RTO ≤1 hour are targets requiring a
production-size drill and checkpoint-age measurement. `storage-assessment`
reports actual table/storage sizes and the gates for a future metadata-store
migration. Keep the current ledger authoritative until dual reads, reconciliation,
rollback and cutover tests pass. The ledger checkpoint alone does not back up
quarantine files. `SECOPSAI_ARTIFACT_VAULT=1` backs up public registry artifacts
in bounded batches to private, immutable R2 objects before recording a completed
manifest receipt in the ledger. Each object and the complete restored artifact
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
public artifacts per cycle with a shared 60-second deadline. Its result records
the pending backlog and explicit failures within the latest 1,000 catalog
entries, rather than claiming complete historical backup coverage. The
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
