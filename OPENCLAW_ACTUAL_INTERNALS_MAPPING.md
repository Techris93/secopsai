# OpenClaw Actual Internals Mapping

This document maps the earlier proposed OpenClaw audit and SOC schema against the real internals in the upstream OpenClaw repository at `openclaw/openclaw`.

The goal is to separate:

- real data/control surfaces that already exist in OpenClaw
- nearby surfaces that can be reused for telemetry
- fields that are still proposed and would require a new emitter or normalizer

## Bottom line

OpenClaw already has real primitives for:

- run-scoped agent events
- tool execution lifecycle events
- session lifecycle hooks
- subagent lifecycle hooks
- session keys and session IDs
- channel pairing state and approval flow
- config mutation RPCs with restart sentinels
- config write audit JSONL
- background exec session state
- skills status, install, update, and refresh flows

OpenClaw does not appear to have one built-in, unified SOC audit bus that emits a single normalized JSON event stream for all of those domains. That part of the previous design remains proposed.

## Verified surfaces

### 1. Run and tool lifecycle

These are real.

- `src/infra/agent-events.ts` defines `AgentEventPayload` with `runId`, `seq`, `stream`, `ts`, `data`, and optional `sessionKey`.
- `src/agents/pi-embedded-subscribe.handlers.ts` subscribes to embedded agent events including `tool_execution_start`, `tool_execution_update`, `tool_execution_end`, `agent_start`, and `agent_end`.
- `src/agents/pi-embedded-subscribe.handlers.tools.ts` translates tool execution lifecycle into emitted agent events and hook invocations.
- `src/plugins/hooks.ts` exposes `before_tool_call` and `after_tool_call` hook execution paths.

What this means:

- `run_id` is real.
- `session_key` is real.
- `tool_name`, `tool_call_id`, tool args, sanitized tool result, and duration are real.
- a normalized `event_type` field is still proposed; OpenClaw currently spreads this across `stream` plus `data.phase` plus hook name.

### 2. Session lifecycle and identity

These are real.

- `src/auto-reply/reply/session.ts` initializes session state and fires `session_start` and `session_end` hooks.
- `src/auto-reply/reply/session-hooks.ts` defines real payload/context fields for session hooks: `sessionId`, `sessionKey`, `agentId`, `resumedFrom`, and `messageCount`.
- `src/routing/session-key.ts` and related helpers define canonical session key behavior.
- docs indicate real key families such as `agent:<agentId>:...`, `cron:<job.id>`, `hook:<uuid>`, and `node-<nodeId>`.

What this means:

- `session_id` is real.
- `session_key` is real.
- `agent_id` is real.
- `origin_type` can usually be derived from the session key family, but a dedicated top-level field is still proposed.

### 3. Subagent lifecycle

These are real.

- `src/agents/tools/sessions-spawn-tool.ts` implements `sessions_spawn` with `runtime`, `mode`, `thread`, `cleanup`, `agentId`, `resumeSessionId`, and attachments.
- `src/plugins/types.ts` defines real hook event types for `subagent_spawning`, `subagent_delivery_target`, `subagent_spawned`, and `subagent_ended`.
- `src/plugins/hooks.ts` runs those hooks.
- tests show actual payload members such as `childSessionKey`, `requesterSessionKey`, requester channel/account/to/thread, `runId`, `mode`, and `threadRequested`.

What this means:

- `child_session_key`, `requester_session_key`, `spawn_mode`, and delivery origin are real.
- `channel_pair` as a single normalized object is still proposed, though the underlying pieces already exist.

### 4. Channel pairing and authorization

These are real.

- `src/channels/plugins/pairing.ts` exposes pairing adapter resolution and approval notification.
- `src/pairing/pairing-store.ts` implements allowlist store and pairing request persistence.
- docs state the pairing files live under `~/.openclaw/credentials/`.
- channel integrations such as Mattermost call pairing upsert during authorization failures.

What this means:

- `channel`, `account_id`, sender ID, pairing request creation, approval, and allowlist updates are real.
- a dedicated normalized `pairing_event` schema is still proposed.

### 5. Skills lifecycle

These are real.

- `src/agents/skills-status.ts` builds real skill status reports.
- `src/agents/skills-install.ts` installs skill dependencies.
- `src/gateway/server-methods/skills.ts` exposes `skills.status`, `skills.bins`, `skills.install`, and `skills.update`.
- `src/agents/skills/refresh.ts` tracks skill snapshot version changes and emits refresh events to listeners.
- config types define `skills.entries.<skillKey>` with `enabled`, `apiKey`, `env`, and `config`.

What this means:

- `skill_key`, enable/disable state, install action, env override updates, and refresh versioning are real.
- `skill_change` as a first-class audit event name is still proposed.

### 6. Config mutation and restart workflow

These are real.

- `src/gateway/server-methods/config.ts` implements `config.get`, `config.set`, `config.patch`, and `config.apply`.
- `config.patch` and `config.apply` log actor metadata, diff changed paths, write config, write a restart sentinel payload, and schedule restart.
- `src/infra/restart-sentinel.ts` defines real restart sentinel payloads with `kind`, `status`, `ts`, `sessionKey`, `deliveryContext`, `threadId`, `message`, `doctorHint`, and `stats`.
- `src/config/io.ts` writes `config-audit.jsonl` with forensic metadata under the OpenClaw state dir.

What this means:

- `config_change` is real in substance, but currently split across gateway logs, restart sentinels, and `config-audit.jsonl`.
- `actor.deviceId`, `actor.clientIp`, `changedPaths`, `note`, `restartDelayMs`, and `sessionKey` are real on the control-plane path.

### 7. Exec and process sessions

These are real.

- `src/agents/bash-tools.exec.ts` implements `exec`.
- `src/agents/bash-tools.exec-types.ts` defines real result states including `running`, `completed`, `failed`, `approval-pending`, and `approval-unavailable`.
- `src/agents/bash-tools.process.ts` implements `process list/poll/log/write/kill/clear/remove`.
- `src/agents/bash-process-registry.ts` tracks running and finished sessions.

What this means:

- `exec_session_id`, `cwd`, `command`, `pid`, exit code, duration, output tail, and approval state are real.
- a normalized security event such as `host_exec_started` or `host_exec_denied` is still proposed unless you derive it from tool events or system events.

## Real vs Proposed Mapping

| Proposed concept                              | Status                         | Actual OpenClaw source of truth                      | Notes                                                  |
| --------------------------------------------- | ------------------------------ | ---------------------------------------------------- | ------------------------------------------------------ |
| `run_id`                                      | Real                           | Agent event stream                                   | Native field already exists                            |
| `session_key`                                 | Real                           | Agent events, session hooks, restart sentinel        | Native field already exists                            |
| `session_id`                                  | Real                           | Session hooks, session store                         | Native field already exists                            |
| `agent_id`                                    | Real                           | Session hook context, session key parsing            | Native field already exists                            |
| `event_type`                                  | Proposed normalization         | Stream + phase + hook name                           | Needs one canonical enum                               |
| `tool_name`                                   | Real                           | Tool execution events/hooks                          | Native field already exists                            |
| `tool_call_id`                                | Real                           | Tool execution events/hooks                          | Native field already exists                            |
| `tool_args`                                   | Real with sanitization         | Tool start event payload                             | Already emitted in start events                        |
| `tool_result`                                 | Real with sanitization         | After-tool-call hook payload                         | Already emitted in end events/hooks                    |
| `duration_ms`                                 | Real                           | After-tool-call hook payload                         | Computed in tool handler                               |
| `channel`                                     | Real                           | Pairing, requester origin, delivery origin           | Native across channel and subagent flows               |
| `account_id`                                  | Real                           | Pairing and requester origin                         | Native field in multiple flows                         |
| `sender_id`                                   | Real in channel-specific flows | Pairing request/auth flows                           | Needs channel adapter normalization                    |
| `thread_id`                                   | Real                           | Delivery context, requester origin, restart sentinel | Native field exists                                    |
| `channel_pair`                                | Proposed normalized object     | Requester origin + delivery origin + pairing store   | Underlying fields exist                                |
| `pairing_event`                               | Proposed event name            | Pairing store + plugin pairing adapters              | No single native audit emitter seen                    |
| `skill_key`                                   | Real                           | Skills status/update/install                         | Native field exists                                    |
| `skill_change`                                | Proposed event name            | Skills update/install + refresh watcher              | No single unified emitter seen                         |
| `config_paths_changed`                        | Real                           | `diffConfigPaths()` in config RPCs                   | Native changed-path list exists                        |
| `config_actor`                                | Real on gateway control plane  | Control-plane actor resolution                       | Device/client IP available there                       |
| `config_audit_record`                         | Real                           | `config-audit.jsonl`                                 | Already JSONL and forensics-friendly                   |
| `restart_event`                               | Real                           | Restart sentinel payload                             | Native payload already exists                          |
| `approval_event`                              | Real-ish but fragmented        | Exec approval request/resolution flow                | Native entities exist, unified audit event not obvious |
| `exec_background_session`                     | Real                           | Exec result details + process registry               | Native session tracking exists                         |
| `transcript_path`                             | Real                           | Sessions list tooling                                | Resolved on demand, not always pushed in events        |
| `privacy_policy` keep/hash/redact/drop labels | Proposed                       | Not found as native runtime audit labels             | Still our design layer                                 |

## What was previously only proposed and is still not verified as native

These should still be treated as our design, not OpenClaw’s built-in model:

- one global normalized audit envelope for every subsystem
- top-level `kind/category/severity` taxonomy shared across runs, tools, pairing, skills, and config
- privacy class labels like `KEEP`, `HASH`, `REDACT`, `DROP` embedded in emitted events
- a single SOC-ready JSONL stream containing all important events out of the box
- a native `channel_pair` object with stable schema across all plugins
- a native `skill_change` event family with before/after payloads

## Practical implication for the SOC design

The proposed SOC is still viable, but it should be implemented as a normalization layer over existing OpenClaw internals rather than as an assumption about current native logging.

The cleanest approach is:

1. consume real OpenClaw signals first
2. normalize them into one event schema
3. apply privacy policy at normalization time
4. store the normalized output separately from OpenClaw runtime state

## Minimal grounded schema

If we want the design to stay honest to the real codebase, the normalized core event should start with fields that are already present or directly derivable:

```json
{
  "ts": "2026-03-15T12:34:56.789Z",
  "source": "openclaw",
  "surface": "tool|session|subagent|pairing|skills|config|exec|restart",
  "action": "start|update|end|install|approve|patch|apply|spawn|deny",
  "run_id": "run-123",
  "session_key": "agent:main:discord:group:dev",
  "session_id": "sess-abc",
  "agent_id": "main",
  "channel": "discord",
  "account_id": "work",
  "thread_id": "456",
  "tool_name": "exec",
  "tool_call_id": "call-7",
  "status": "running",
  "details": {}
}
```

Everything else should be additive.

## Recommended implementation order

1. Normalize tool lifecycle from agent events and after-tool-call hooks.
2. Normalize session lifecycle from `session_start` and `session_end` hooks.
3. Normalize subagent lifecycle from subagent hooks.
4. Ingest `config-audit.jsonl` and restart sentinel payloads.
5. Add pairing and skills mutation adapters.
6. Only then add higher-level SOC labels such as severity, ATT&CK mapping, and privacy classes.

## Conclusion

The important correction is this:

- OpenClaw already has the raw internals needed for a serious local SOC pipeline.
- OpenClaw does not currently expose them as one finished SOC audit schema.
- Our earlier JSON examples were directionally correct, but they described the target normalized layer, not the exact native upstream payloads.
