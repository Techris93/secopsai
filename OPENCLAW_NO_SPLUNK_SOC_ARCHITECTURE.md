# OpenClaw Local-First SOC Architecture (No Splunk)

## Goal

Build a local-first SOC capability around OpenClaw using the same detection and evaluation mindset as this repository, without making Splunk or any external SIEM a hard dependency.

This design keeps user data local, reuses the rule-based optimization model from this project, and leaves room for optional SIEM adapters later.

Status note:

- OpenClaw does not currently appear to expose one upstream-native SOC audit bus.
- This architecture should therefore be read as a collector-and-normalizer design built on verified native OpenClaw surfaces.
- See `OPENCLAW_ACTUAL_INTERNALS_MAPPING.md` for real vs proposed internals.

## Why This Fits SecOps Autoresearch

This repository already has the core pattern you need:

- normalized event data
- rule-based detection logic
- measurable scoring and regression testing
- findings generation and workflow safety

In other words:

- OpenClaw produces security telemetry
- this project becomes the detection research and scoring engine
- a small local SOC layer turns detections into incidents, triage, and analyst feedback

## High-Level Architecture

```text
OpenClaw Native Surfaces
  -> Local Collector / Adapter Layer
  -> Raw Event Store
  -> Normalizer / Validator
  -> Detection Engine
  -> Findings Store
  -> Triage API / Dashboard
  -> Analyst Feedback
  -> Evaluation + Rule Tuning Loop
```

## Core Components

### 1. OpenClaw Native Surface Collector

Purpose:

- collect structured events from verified OpenClaw native surfaces
- apply local privacy rules before persistence

Responsibilities:

- subscribe or ingest from tool events, hooks, config audit logs, restart sentinels, pairing state, and process/session registries
- write one adapter event object per line
- classify fields as keep/hash/redact/drop
- attach metadata like instance_id, request_id, session_id, actor_type, policy_decision
- never emit plaintext secrets

Recommended output path:

- `/var/log/openclaw/audit.log`
- for development: `data/openclaw/raw/audit.jsonl`

### 2. Raw Event Store

Purpose:

- keep immutable, local audit data for replay and forensics

Recommended v1 storage:

- JSONL files on disk, partitioned by day
- optional compression after rotation

Suggested layout:

```text
data/
  openclaw/
    raw/
      2026-03-15-audit.jsonl
      2026-03-16-audit.jsonl
    replay/
      labeled/
      unlabeled/
```

Retention guidance:

- raw logs: short retention, e.g. 7 to 30 days
- labeled replay bundles: retained for benchmarking

Raw adapter contract:

- `schemas/openclaw_audit.schema.json`

### 3. Normalizer / Validator

Purpose:

- convert raw OpenClaw audit events into the normalized schema consumed by detection rules

Responsibilities:

- validate required keys
- map event types into a stable internal schema
- normalize timestamps, actors, tool names, result fields, risk flags
- write both labeled and unlabeled benchmark sets for evaluation

Suggested files:

- `openclaw_prepare.py`
- `schemas/normalized_event.schema.json`

This would play the same role for OpenClaw that `prepare.py` plays for synthetic data.

### 4. Detection Engine

Purpose:

- run rule logic over normalized OpenClaw events

Current repo mapping:

- `detect.py`

Suggested evolution:

- keep `detect.py` as the shared rules module
- add event-family support for OpenClaw audit events
- separate generic rules from product-specific rules if needed

Example rule families for OpenClaw:

- dangerous exec command usage
- unusual burst of tool calls per actor
- skill installation from unknown source
- config changes affecting permissions or remotes
- repeated blocked policy decisions
- new channel pairing from unusual network context

### 5. Findings Store

Purpose:

- persist alerts, incidents, and analyst decisions

Recommended v1 storage:

- SQLite for single-instance MVP
- Postgres for multi-user or multi-instance setup

Suggested tables:

- `events_index`
- `findings`
- `finding_events`
- `labels`
- `rule_runs`
- `feedback`

Current repo mapping:

- `findings.py` can evolve from report publishing into local incident persistence and export.

### 6. Triage API / Dashboard

Purpose:

- give operators a minimal SOC console without a full SIEM

V1 features:

- list recent findings
- filter by severity, event_type, rule_id, actor, host, date
- open finding details and linked events
- mark true positive / false positive / expected admin activity
- add notes and resolution status

Technology options:

- simple FastAPI backend + SQLite/Postgres
- minimal frontend or server-rendered views
- CLI first if you want to stay lean

Suggested service:

- `soc_api.py`

### 7. Analyst Feedback Loop

Purpose:

- improve rules based on local reality

Feedback labels:

- `true_positive`
- `false_positive`
- `expected_admin`
- `needs_tuning`
- `benign_but_unusual`

Why this matters:

- this is how your local SOC becomes better than a static detection pack
- feedback turns real OpenClaw usage into tuning data

### 8. Evaluation and Rule Tuning Loop

Purpose:

- keep the autoresearch approach, but extend it to OpenClaw datasets

Current repo mapping:

- `evaluate.py` is the benchmark/scoring harness

Suggested evolution:

- keep synthetic dataset as regression baseline
- keep BOTSv3 as external realism benchmark
- add OpenClaw replay benchmark as product benchmark

Final scoring strategy:

- synthetic score protects against regressions
- BOTSv3 score tests general security realism
- OpenClaw replay score tests product-specific usefulness

## Folder and File Plan

Suggested additions to this repository:

```text
openclaw_prepare.py              # normalize adapter events into benchmark data
openclaw_detect.py               # optional product-specific rules if detect.py gets too broad
evaluate_openclaw.py             # safe evaluator for OpenClaw replay datasets
soc_api.py                       # local findings/triage API
soc_store.py                     # SQLite/Postgres persistence layer

schemas/
  openclaw_audit.schema.json     # adapter event schema grounded in real OpenClaw surfaces
  normalized_event.schema.json   # internal normalized schema

OPENCLAW_INGESTION_ADAPTER_PLAN.md

data/
  openclaw/
    raw/
    replay/
      labeled/
      unlabeled/
    findings/
```

## Event Flow

### Flow A: Live local detection

```text
Collector ingests native OpenClaw signal
  -> privacy transform
  -> append to local raw JSONL
  -> normalizer reads event
  -> detector runs matching rules
  -> finding created if rule triggers
  -> finding stored locally
  -> triage UI/API shows alert
```

### Flow B: Offline benchmark tuning

```text
Raw OpenClaw logs
  -> labeling / replay bundle creation
  -> normalized labeled dataset
  -> normalized unlabeled dataset
  -> evaluate_openclaw.py
  -> metrics by rule and overall
  -> tune detect.py
```

## MVP Build Plan

### Phase 1: Structured Telemetry

Deliverables:

- OpenClaw audit schema
- local JSONL emitter
- privacy transform middleware
- raw event rotation

Success criteria:

- audit events are structured, local, and privacy-safe

### Phase 2: Local Detection Pipeline

Deliverables:

- `openclaw_prepare.py`
- OpenClaw event normalization
- initial OpenClaw rule set in detection engine
- local finding persistence

Success criteria:

- findings generated locally from real OpenClaw activity

### Phase 3: Evaluation Harness

Deliverables:

- `evaluate_openclaw.py`
- labeled replay datasets
- per-rule scoring and regression checks

Success criteria:

- rule changes can be measured before deployment

### Phase 4: Triage Layer

Deliverables:

- local API or dashboard
- finding review workflow
- analyst feedback labels

Success criteria:

- operator can review and classify detections without external SIEM

### Phase 5: Optional Integrations

Deliverables:

- export adapters for Splunk, Elastic, or Wazuh
- optional downstream forwarding of findings only

Success criteria:

- integrations remain optional, not foundational

## How Existing Repo Files Evolve

### `detect.py`

Current role:

- synthetic and benchmark detection logic

Future role:

- shared core rule engine
- support both lab datasets and OpenClaw normalized events

Recommendation:

- keep shared detection functions here while product rules are still few
- split into `detect_core.py` and `detect_openclaw.py` only when complexity demands it

### `evaluate.py`

Current role:

- score against synthetic labeled/unlabeled data

Future role:

- remain the generic benchmark pattern
- OpenClaw gets a parallel evaluator rather than replacing the baseline

Recommendation:

- keep `evaluate.py` unchanged for default regression
- add `evaluate_openclaw.py` and keep dataset swapping safe

### `findings.py`

Current role:

- summarize and publish findings externally

Future role:

- become the finding serialization and export layer
- support local incident records first
- optional external publishing second

Recommendation:

- add local finding persistence before any new publishing integrations

### `prepare.py`

Current role:

- generate synthetic benchmark data

Future role:

- remain synthetic generator only

Recommendation:

- do not overload it with product telemetry prep
- create `openclaw_prepare.py` separately

## Detection Strategy Recommendation

Keep three rule categories:

### Category A: High-confidence security rules

Examples:

- suspicious exec patterns
- unapproved skill modification
- privileged config changes
- repeated blocked policy bypass attempts

Use:

- alert immediately

### Category B: Behavioral anomaly rules

Examples:

- unusual tool burst by actor
- unusual session duration or command density
- new tool/skill combination never seen before

Use:

- lower severity or require analyst review

### Category C: Policy drift / integrity rules

Examples:

- permissions widened unexpectedly
- remote endpoint changed
- plugin source changed from approved to unknown

Use:

- medium/high severity with high operational value

## Data Model Recommendation

Use two internal schemas:

### Raw audit schema

- mirrors emitted OpenClaw events closely
- privacy controls applied at emitter

### Normalized detection schema

- optimized for rule logic and scoring
- stable field names across datasets

Suggested normalized fields:

- `timestamp`
- `event_id`
- `event_type`
- `actor_id`
- `actor_type`
- `host`
- `tool_name`
- `action`
- `result_status`
- `duration_ms`
- `risk_score`
- `policy_decision`
- `label`
- `attack_type`
- `message`

## Recommended V1 Stack

If you want the simplest practical build:

- JSONL for raw event storage
- SQLite for findings and labels
- Python scripts for normalization and evaluation
- FastAPI for local triage API
- optional minimal frontend later

This is enough for a real MVP and preserves local-first privacy.

## What Not to Do in V1

- do not build a full SIEM clone
- do not add auto-remediation early
- do not mix raw privacy-sensitive content directly into findings
- do not make Splunk-specific field design decisions your core contract

## Best Next Build Sequence

1. Define and freeze OpenClaw raw audit schema.
2. Implement emitter-side privacy transform.
3. Add `openclaw_prepare.py` to normalize raw logs.
4. Create one small labeled OpenClaw replay dataset.
5. Add `evaluate_openclaw.py`.
6. Add first 5 local detections.
7. Add local finding store and simple triage view.

## Optional Future Adapters

Once the local-first architecture works, you can export:

- findings only to Splunk
- findings plus normalized events to Elastic
- selected metrics to Prometheus/Grafana

That keeps your own SOC logic primary and third-party systems secondary.
