# OpenClaw Ingestion Adapter Plan

This document turns the verified OpenClaw internals map into an implementation plan for a local SOC ingestion layer.

It assumes the conclusion in `OPENCLAW_ACTUAL_INTERNALS_MAPPING.md`:

- OpenClaw has the right native surfaces.
- OpenClaw does not expose one native SOC audit stream.
- this repository should build a collector and normalization layer over those native surfaces.

## Objective

Produce one local JSONL stream in `schemas/openclaw_audit.schema.json` from the smallest set of high-value OpenClaw sources.

Then transform that stream into `schemas/normalized_event.schema.json` for detection and evaluation.

## Target ingestion order

### Phase 1. Tool lifecycle adapter

Source of truth:

- agent event stream
- tool execution start/update/end flow
- after-tool-call hook context

Why first:

- highest detection value
- most stable identifiers
- directly supports exec, file mutation, gateway, cron, and session tool monitoring

Collector output examples:

- `surface=tool action=start`
- `surface=tool action=update`
- `surface=tool action=end`

Minimum extracted fields:

- `run_id`
- `session_key`
- `tool_name`
- `tool_call_id`
- sanitized args
- sanitized result
- duration

### Phase 2. Session lifecycle adapter

Source of truth:

- `session_start`
- `session_end`

Collector output examples:

- `surface=session action=start`
- `surface=session action=end`

Minimum extracted fields:

- `session_id`
- `session_key`
- `agent_id`
- `resumed_from`
- `message_count`

### Phase 3. Subagent lifecycle adapter

Source of truth:

- `subagent_spawning`
- `subagent_delivery_target`
- `subagent_spawned`
- `subagent_ended`

Collector output examples:

- `surface=subagent action=spawn`
- `surface=subagent action=end`

Minimum extracted fields:

- `child_session_key`
- `requester_session_key`
- `run_id`
- requester channel/account/to/thread
- mode
- outcome

### Phase 4. Config and restart adapter

Source of truth:

- gateway config RPC writes
- `config-audit.jsonl`
- restart sentinel payloads

Collector output examples:

- `surface=config action=patch`
- `surface=config action=apply`
- `surface=restart action=restart`

Minimum extracted fields:

- changed paths
- actor metadata if available
- note
- restart delay
- restart reason
- session key and delivery context

### Phase 5. Skills adapter

Source of truth:

- `skills.install`
- `skills.update`
- skills refresh/version bump notifications

Collector output examples:

- `surface=skills action=install`
- `surface=skills action=enable`
- `surface=skills action=disable`

Minimum extracted fields:

- `skill_key`
- enabled state
- install ID
- env/config mutation summary

### Phase 6. Pairing adapter

Source of truth:

- pairing request persistence
- pairing approval CLI/API path
- allowlist store mutation

Collector output examples:

- `surface=pairing action=start`
- `surface=pairing action=approve`
- `surface=pairing action=deny`

Minimum extracted fields:

- channel
- account ID
- normalized sender ID or hashed sender key

### Phase 7. Process registry adapter

Source of truth:

- exec details
- process session registry for background jobs

Collector output examples:

- `surface=exec action=start`
- `surface=exec action=end`
- `surface=exec action=status`

Minimum extracted fields:

- process session ID
- command
- cwd
- pid if present
- exit code
- output tail

## Adapter architecture

```text
OpenClaw Native Surfaces
  -> collector adapters
  -> adapter event JSONL (`openclaw_audit.schema.json`)
  -> normalizer (`openclaw_prepare.py`)
  -> normalized event JSON (`normalized_event.schema.json`)
  -> detector/evaluator
```

## File plan in this repository

### First implementation files

- `schemas/openclaw_audit.schema.json`
- `schemas/normalized_event.schema.json`
- `openclaw_prepare.py`
- `evaluate_openclaw.py`

### Likely helper modules

- `openclaw_adapters/tool_events.py`
- `openclaw_adapters/session_hooks.py`
- `openclaw_adapters/subagent_hooks.py`
- `openclaw_adapters/config_events.py`
- `openclaw_adapters/skills_events.py`
- `openclaw_adapters/pairing_events.py`

## Detection-oriented feature extraction

The normalizer should populate these feature families first:

- mutation flag per tool
- duration and exit-code features
- changed-path count and sensitive-path indicators
- per-session tool burst counters
- repeated deny/block counters
- subagent fan-out counters
- skill enable/install drift flags

## Guardrails

- never assume a native upstream field exists if it was only inferred in design docs
- favor append-only local JSONL over hidden stateful transforms
- treat privacy classification as part of collection, not a later optional step
- preserve raw source provenance so every normalized event can be traced back

## Success criteria

Phase 1 is successful when this repository can ingest OpenClaw tool lifecycle activity into `openclaw_audit.schema.json` records and deterministically normalize those into detector-ready events without inventing missing upstream structure.
