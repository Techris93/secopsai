# OpenClaw Local-First SOC Implementation Roadmap

## Goal

Turn this repository into a local-first SOC backend for OpenClaw in small, low-risk increments while preserving the current detection lab workflow.

This roadmap is written to be implementable directly inside this repository.

## Guiding Constraints

- Keep user data local.
- Do not make Splunk or any external SIEM mandatory.
- Preserve current synthetic benchmark workflow.
- Add OpenClaw-specific capabilities in parallel, not by replacing existing ones.
- Build evaluation and regression checks before broad automation.
- Build on verified OpenClaw internals, not on an assumed upstream unified audit emitter.

Reference:

- `OPENCLAW_ACTUAL_INTERNALS_MAPPING.md`
- `OPENCLAW_INGESTION_ADAPTER_PLAN.md`

## Build Order

### Step 1. Freeze the OpenClaw raw audit schema

Create:

- `schemas/openclaw_audit.schema.json`
- `schemas/normalized_event.schema.json`

Purpose:

- define the adapter-facing raw event contract collected from verified OpenClaw native surfaces
- define the normalized event contract consumed by detections and evaluators

Acceptance checks:

- required fields documented
- example valid events included
- schema validator can reject malformed records

## Step 2. Add OpenClaw raw data folders

Create:

- `data/openclaw/raw/`
- `data/openclaw/replay/labeled/`
- `data/openclaw/replay/unlabeled/`
- `data/openclaw/findings/`

Purpose:

- keep product telemetry separate from synthetic and BOTSv3 datasets

Acceptance checks:

- repo structure is stable
- no current workflow is broken

## Step 3. Build the raw-to-normalized converter

Create:

- `openclaw_prepare.py`

Purpose:

- read adapter-produced OpenClaw JSONL events
- validate schema
- apply stable normalization into the internal event schema
- optionally generate labeled and unlabeled replay bundles

Suggested CLI:

- `python openclaw_prepare.py --input data/openclaw/raw/audit.jsonl --output data/openclaw/replay/labeled/sample.json`
- `python openclaw_prepare.py --stats`

Acceptance checks:

- malformed records handled clearly
- timestamps normalized
- stable event_id generated
- output is consumable by detector/evaluator
- every normalized record preserves provenance back to the adapter record

## Step 4. Add OpenClaw-specific evaluator

Create:

- `evaluate_openclaw.py`

Purpose:

- run detection on OpenClaw unlabeled replay data
- score against OpenClaw labeled replay data
- print per-rule metrics and missed attack types
- never overwrite baseline synthetic files

Acceptance checks:

- synthetic benchmark still works unchanged with `evaluate.py`
- OpenClaw benchmark runs independently
- results are reproducible

## Step 5. Add first OpenClaw rule pack

Edit:

- `detect.py`

Optional split later:

- `detect_openclaw.py`

First five rules to implement:

1. Dangerous exec command usage
2. Unapproved skill modification or source drift
3. Sensitive config change
4. Abnormal tool-call burst per actor/session
5. Repeated blocked policy decisions or bypass attempts

Input expectation:

- rules should key off normalized fields backed by actual OpenClaw surfaces such as tool lifecycle, config changed paths, subagent lifecycle, and approval state

Acceptance checks:

- no regression in synthetic benchmark
- OpenClaw evaluator shows expected hits on replay dataset
- rules are explainable and low-noise

## Step 6. Add local findings store

Create:

- `soc_store.py`

Purpose:

- persist findings, event references, analyst labels, and rule execution metadata

Recommended v1 storage:

- SQLite

Initial tables:

- `findings`
- `finding_events`
- `labels`
- `rule_runs`
- `notes`

Acceptance checks:

- findings can be inserted, queried, and updated locally
- schema migration path is documented

## Step 7. Add finding generation pipeline

Create:

- `openclaw_findings.py`

Purpose:

- convert rule hits into persisted local findings
- group related events into one finding
- assign default severity and status

Suggested outputs:

- SQLite records
- optional JSON summaries in `data/openclaw/findings/`

Acceptance checks:

- one detection run can produce grouped findings
- duplicate events are not creating noisy duplicate findings

## Step 8. Add local triage API

Create:

- `soc_api.py`

Purpose:

- expose local endpoints to review findings and labels

Suggested v1 endpoints:

- `GET /findings`
- `GET /findings/{id}`
- `POST /findings/{id}/label`
- `POST /findings/{id}/note`
- `GET /rules/stats`

Suggested tech:

- FastAPI

Acceptance checks:

- findings are queryable locally
- analyst can mark TP/FP
- no external dependency required

## Step 9. Add replay dataset tooling

Create:

- `openclaw_label.py`
- `data/openclaw/replay/README.md`

Purpose:

- create labeled replay sets from real OpenClaw usage
- define labeling conventions

Suggested labels:

- `malicious`
- `benign`
- `expected_admin`
- `misconfiguration`

Acceptance checks:

- small replay dataset can be created and re-used in CI
- labeling conventions are documented

## Step 10. Add dual-gate evaluation policy

Edit:

- `README.md`
- optionally create `evaluate_all.py`

Purpose:

- future rule changes should be measured against:
  - synthetic baseline
  - BOTSv3 benchmark
  - OpenClaw replay benchmark

Example policy:

- synthetic F1 must remain at or above target
- OpenClaw false positive rate must stay below threshold
- OpenClaw recall must improve over baseline or justify change

Acceptance checks:

- one command can show all benchmark outputs
- rule change acceptance becomes objective

## Recommended File Plan

### New files to add first

1. `schemas/openclaw_audit.schema.json`
2. `schemas/normalized_event.schema.json`
3. `openclaw_prepare.py`
4. `evaluate_openclaw.py`
5. `soc_store.py`
6. `openclaw_findings.py`
7. `soc_api.py`
8. `openclaw_label.py`

## Source-to-adapter priority

Implement adapters in this order:

1. Tool lifecycle
2. Session lifecycle
3. Subagent lifecycle
4. Config audit and restart sentinel
5. Skills mutation
6. Pairing events
7. Process registry
8. `OPENCLAW_IMPLEMENTATION_ROADMAP.md`

### Existing files to keep stable

- `prepare.py`
- `evaluate.py`
- `botsv3_convert.py`
- `evaluate_botsv3.py`

### Existing files likely to evolve

- `detect.py`
- `findings.py`
- `README.md`

## Suggested Development Sequence (Practical)

### Milestone A: Telemetry foundation

Build:

- schemas
- raw folder structure
- `openclaw_prepare.py`

Exit condition:

- OpenClaw raw events can be normalized into benchmark-ready JSON

### Milestone B: Evaluation foundation

Build:

- `evaluate_openclaw.py`
- first small labeled replay set

Exit condition:

- OpenClaw-specific score can be measured independently

### Milestone C: Detection MVP

Build:

- first five OpenClaw detections in `detect.py`
- finding grouping logic

Exit condition:

- meaningful local findings generated from replay or test data

### Milestone D: Local SOC operations

Build:

- `soc_store.py`
- `openclaw_findings.py`
- `soc_api.py`

Exit condition:

- analyst can review and label findings locally

### Milestone E: Continuous tuning

Build:

- replay labeling workflow
- dual-gate benchmark policy
- optional helper command to run all evaluations

Exit condition:

- this repo becomes a true local SOC tuning platform

## Suggested Acceptance Metrics

Use these metrics for early gating:

### Synthetic baseline

- F1 remains at current accepted level

### BOTSv3 benchmark

- no large precision collapse
- measurable incremental improvements only

### OpenClaw benchmark

- false positive rate under a defined threshold
- recall improves as replay coverage grows
- analyst-reviewed true positives increase over time

## What to Implement First in Code

If building immediately, do these in order:

1. `schemas/openclaw_audit.schema.json`
2. `schemas/normalized_event.schema.json`
3. `openclaw_prepare.py`
4. `evaluate_openclaw.py`
5. add 2 to 3 high-confidence OpenClaw rules in `detect.py`
6. `soc_store.py`
7. `openclaw_findings.py`
8. `soc_api.py`

## What Not to Build Yet

- full multi-tenant architecture
- auto-remediation engine
- external SIEM adapters as core feature
- complicated frontend before API and storage are stable
- probabilistic anomaly systems before deterministic rules and replay data are solid

## Immediate Next Recommended Action

Start with these three deliverables first:

1. audit schema JSON files
2. `openclaw_prepare.py`
3. `evaluate_openclaw.py`

That is the smallest useful foundation that keeps this aligned with secops-autoresearch rather than turning into an unfocused platform build.
