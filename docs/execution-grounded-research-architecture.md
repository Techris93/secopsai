# Execution-Grounded Research Architecture

SecOpsAI adapts the reliability ideas in [Accelerating Scientific Research
with Gemini in the Real-World](https://arxiv.org/html/2608.26701v1) as an
independent defensive-security workflow. The paper is methodological
inspiration only; SecOpsAI does not copy its prompts, figures, code, weights,
or branding.

## Why this exists

Security research is easy to make persuasive and hard to make reproducible.
An incomplete registry fetch, a failed static scan, a model's unsupported
sentence, or a screenshot with unclear provenance can turn a useful lead into
an unsafe publication. The research reliability layer makes each transition
explicit and auditable:

```text
Discovery
  -> competing hypotheses
  -> safety and scope screen
  -> versioned evidence plan
  -> scaffold research
  -> transition audit
  -> full safe research
  -> immutable run bundle
  -> claim ledger and verification
  -> specialist review
  -> blinded independent review
  -> completeness/originality/visual audits
  -> publication safety
  -> human approval
```

The layer is additive. Existing Artifact Fleet, Source-First Artifact
Research, Research Cases, sandbox, Triage Ops, and Blog Ops records remain the
system of record for their respective domains.

## Current architecture

### Core services

- `secopsai/artifact_fleet.py` indexes registry metadata, scans quarantined
  archives without execution, deduplicates findings, and queues minimized
  model context.
- `secopsai/research_artifact_analysis.py` applies archive limits and static
  language/rule analysis. It never installs or executes a package.
- `secopsai/research_cases.py` stores subjects, evidence, IOCs, local usage,
  disclosure, publication readiness, and an explicit reconciliation operation.
- `secopsai/research_workflow.py` coordinates intake, evidence matrices,
  sandbox-result materialization, disclosure, and publication gates.
- `secopsai/research_reliability.py` owns the execution-grounded workflow,
  claim ledger, audits, immutable bundles, resource snapshots, and quality
  gate.
- `secopsai/specialist_orchestrator.py` selects a reviewed domain specialist,
  queues an independent reviewer, compares evidence-linked results, and
  records human adjudication for material disagreement.
- `secopsai/codex_bridge.py` and `secopsai/intelligence_jobs.py` persist the
  selected OpenCodex model and fallback policy, maintain a durable busy lease,
  and only probe the model captured by each job.
- `soc_store.py` applies schema migrations and stores hypotheses, plans,
  bundles, claims, revisions, audits, specialist runs, and audit events in
  SQLite (or the configured database adapter).

### Dashboard and typed boundary

Mission Control renders one Research Case reliability workspace in
`secopsai-dashboard/app.js`. It calls typed allowlisted actions in
`dashboard_server.py`; the browser cannot supply a shell command or an
unbounded path. The workspace exposes hypotheses, plans, run stages, claim
ledger, contradictions, specialist and blind review, adjudication, audits,
publication safety, and a next-action control.

The `research reliability` CLI is the reference interface. Dashboard routes
build the same fixed argument arrays and use the same Core functions, so a
button and a CLI invocation are auditable equivalents.

## Data contracts

### Hypothesis

Each substantial case receives a bounded pool of alternatives: malicious
compromise, benign or expected behavior, scanner false positive, unrelated
reporting, provenance anomaly, and insufficient evidence. A hypothesis stores
its statement, parents and lineage, predicted evidence, falsifiers, novelty,
plausibility, testability, impact, safety, estimated cost, confidence
distribution, status, and selection rationale. A model can propose a
comparison, but deterministic safety checks and evidence gates override it.

### Evidence plan

Plans are versioned. A plan records intended methods, required evidence,
expected outputs, limits, safety decisions, and completion criteria. A new
revision is required when a source disappears, a registry fails, an artifact
is unavailable, or the executed method differs from the intention. Reports
therefore cannot describe an unperformed method as completed.

### Run bundle

Every scaffold, transition, or full run stores a sanitized, chained SHA-256
bundle with:

- plan revision and normalized inputs;
- source URLs, registry snapshots, artifact identity, size, and SHA-256;
- tool and rule-pack versions/fingerprints;
- configuration, timestamps, attempts, failures, and bounded output summaries;
- selected OpenCodex model and explicit fallback policy;
- sandbox references when an approved result exists;
- CPU, memory, disk, queue depth, latency, retry, token, and cost estimates;
- completeness and tamper-evidence fields.

Secrets, credentials, private telemetry, and raw payload content are excluded.
The bundle is incomplete until required accounting is present; incomplete
runs cannot satisfy the publication gate.

### Claim ledger

The ledger extracts factual spans from analyst briefs and draft text. Each
claim records type, support status, confidence, evidence IDs, contradictions,
numeric values, package/version/hash/IOC identifiers, source provenance,
limitations, and reviewer decisions. Verification compares claims with
canonical case records and bundle evidence. Unsupported or contradicted claims
are removed or qualified with a persisted revision diff; no correction invents
support.

### Review and adjudication

The primary and independent reviewer receive the same evidence bundle and
claims, but the independent reviewer does not receive the primary verdict,
confidence, wording, or recommendation. Material disagreement sets a
publication blocker. An operator can record `accept_primary`,
`accept_reviewer`, or `request_more_evidence` with a rationale of at least 20
characters. A resolved acceptance clears only the disagreement blocker;
requesting more evidence keeps the case blocked.

### Visual evidence

Visual QA records desktop and mobile render checks, overflow, contrast,
missing alt text, and licensing/attribution. Screenshot evidence stores the
viewport (`desktop` or `mobile`), alt text, license or attribution, and the
source locator. Visual feedback is advisory; deterministic checks and human
publication approval remain authoritative.

## Safety boundaries

- No package, extension, build script, binary, container, or payload runs
  locally.
- Artifact collection is allowlisted, quarantined, hash-verified, and bounded
  by archive size, entry count, path, compression ratio, and expanded content.
- A sandbox request is a separate approval-gated public action. A completed
  sandbox result is materialized idempotently as linked evidence only after its
  report URL and artifact hash are validated.
- Model output is minimized review material, never a source of truth.
- Publication, deployment, disclosure, destructive response, cloud mutation,
  and external communication stay human-approved.
- The selected OpenCodex model is persisted with each job. Disabled fallback
  means the job remains queued rather than silently switching providers.
- Read-only case reads do not repair or reconcile state. The explicit
  `research case reconcile` operation is audited.

## Migration and compatibility

The schema migration is additive and idempotent. Existing cases continue to
render through legacy readiness labels while also exposing the structured
readiness object. Existing `research rust-package` and package intake commands
remain compatible; reliability controls are opt-in until a case enters the
execution-grounded workspace. Older specialist rows receive default
adjudication columns during startup migration.

No duplicate ecosystem-specific research panels are introduced. Rust, npm,
PyPI, Packagist, Go, Maven, NuGet, RubyGems, Open VSX, GitHub, Hugging Face,
containers, and approved archives use the existing adapter-driven intake; the
reliability layer adds common gates above those adapters.

## Methodology traceability

| Methodology | SecOpsAI implementation | Verification |
| --- | --- | --- |
| Competing alternatives | `generate_hypotheses`, persisted lineage and falsifiers | Hypothesis and ranking tests |
| Evidence-value selection | Pairwise ranking and bounded budgets | Ranking assertions and benchmark |
| Plan/reality reflection | Versioned evidence plans and executed-method fields | Plan revision tests |
| Scaffold/transition/full | Three explicit run stages | Transition and safety fixtures |
| Reproducible execution | Chained immutable run bundles and tool/resource snapshots | Bundle integrity tests |
| Claim-level grounding | Claim extraction, verification, and revision diff | Claim and clipping tests |
| Multi-objective quality | Completeness, originality, visual, cost, and safety scoring | Benchmark and audit tests |
| Layered safety | Directive screen plus compositional-risk checks | Unsafe composition fixture |
| Independent review | Specialist + blinded reviewer + adjudication | Disagreement/adjudication tests |
| Selective-reporting checks | Completeness and methodology audits | Adversarial fixtures |
| Originality controls | Similarity/attribution audit | Originality tests |
| Visual quality | Desktop/mobile render and evidence metadata | Dashboard runtime and visual tests |
| Resource-aware operation | CPU/RSS/disk/queue/model/latency/cost snapshots | Resource bundle assertions |

See [Research Reliability Operations](research-reliability.md),
[Claim Ledger](research-claim-ledger.md), and [Visual QA](research-visual-qa.md)
for operator procedures.
