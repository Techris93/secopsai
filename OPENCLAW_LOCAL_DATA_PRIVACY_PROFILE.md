# OpenClaw Local-Data Privacy Profile (Target Collector Contract)

Status note:

- This document describes the target privacy transform applied by the local collector/adapter layer.
- It should not be read as claiming that upstream OpenClaw already emits this exact unified schema natively.
- See `OPENCLAW_ACTUAL_INTERNALS_MAPPING.md` for the verified native surfaces.

## Purpose

This profile keeps user data local while still enabling SOC monitoring and detection.

Design goals:

- Raw user content stays on local infrastructure.
- SIEM receives only minimum required security telemetry.
- Sensitive fields are hashed, tokenized, redacted, or dropped.

## Deployment Baseline

- OpenClaw runtime: local host, private VM, or private VPC.
- Audit log path: `/var/log/openclaw/audit.log` (JSON lines).
- SIEM: Splunk Enterprise in same trust boundary (on-prem or private VPC).
- No outbound enrichment by default (VirusTotal/WHOIS/GeoIP disabled unless explicitly enabled).

## Data Classification

Use four handling classes for every field:

- `KEEP`: store as-is.
- `HASH`: deterministic salted hash (for correlation without plaintext).
- `REDACT`: partially mask value.
- `DROP`: do not emit to SIEM.

## Event Schema (Recommended)

## OpenClaw Audit Schema v1 (Collector Contract)

All collector events should be one JSON object per line and use these top-level keys:

- `ts`
- `event_type`
- `severity`
- `instance_id`
- `host`
- `session_id`
- `request_id`
- `user`
- `action`
- `meta`

### Required by event type

#### `event_type=tool_call`

Required keys:

- `action.kind=tool_call`
- `action.tool_name`
- `action.result.status`
- `action.result.duration_ms`

Optional:

- `action.args.command`
- `action.args.path`
- `action.result.exit_code`

#### `event_type=auth_event`

Required keys:

- `action.kind` in `channel_pair|channel_unpair|login|logout`
- `meta.ip`
- `action.result.status`

#### `event_type=skill_change`

Required keys:

- `action.kind` in `skill_install|skill_update|skill_delete|skill_modified`
- `action.skill`
- `meta.source`

Optional:

- `meta.artifact_hash_before`
- `meta.artifact_hash_after`

#### `event_type=config_change`

Required keys:

- `action.kind=config_update`
- `meta.config_path`

Optional:

- `meta.policy_decision`
- `meta.risk_score`

## Transform Rules (Collector-Side)

Apply this exact pipeline before writing audit log lines:

1. Validate schema for required keys.
2. Normalize missing objects to `{}` for `user`, `action`, `meta`.
3. Apply field classification (`KEEP/HASH/REDACT/DROP`).
4. Add `meta.privacy_profile_version`.
5. Emit sanitized JSON line.

Recommended metadata:

- `meta.privacy_profile_version`: `openclaw-local-v1`
- `meta.transform_mode`: `balanced|strict|forensics`

## Field-Level Policy (Exact Keys)

| Key                         | Policy | Notes                         |
| --------------------------- | ------ | ----------------------------- |
| `ts`                        | KEEP   | UTC ISO-8601                  |
| `event_type`                | KEEP   | bounded enum                  |
| `severity`                  | KEEP   | info/low/medium/high/critical |
| `instance_id`               | KEEP   | non-PII id                    |
| `host`                      | KEEP   | internal hostname             |
| `session_id`                | KEEP   | rotateable id                 |
| `request_id`                | KEEP   | unique request id             |
| `user.channel`              | KEEP   | whatsapp/telegram/slack/etc   |
| `user.channel_id`           | HASH   | HMAC-SHA256                   |
| `user.label`                | DROP   | may contain PII               |
| `action.kind`               | KEEP   | tool_call/auth/etc            |
| `action.tool_name`          | KEEP   | exec/edit/write/etc           |
| `action.skill`              | KEEP   | skill identifier              |
| `action.args.command`       | REDACT | strict mode: HASH             |
| `action.args.prompt`        | DROP   | user content                  |
| `action.args.file_contents` | DROP   | raw content                   |
| `action.args.tokens`        | DROP   | secrets                       |
| `action.args.path`          | KEEP   | optionally home-prefix redact |
| `action.result.status`      | KEEP   | success/failure               |
| `action.result.duration_ms` | KEEP   | numeric                       |
| `action.result.exit_code`   | KEEP   | numeric                       |
| `meta.ip`                   | REDACT | strict mode: HASH             |
| `meta.user_agent`           | REDACT | product family only           |
| `meta.tags`                 | KEEP   | controlled tags               |
| `meta.source`               | KEEP   | clawhub/local/manual          |
| `meta.config_path`          | KEEP   | changed path                  |
| `meta.policy_decision`      | KEEP   | allowed/blocked               |
| `meta.risk_score`           | KEEP   | integer 0-100                 |
| `meta.artifact_hash_before` | KEEP   | integrity hash                |
| `meta.artifact_hash_after`  | KEEP   | integrity hash                |

## Sanitization Examples (Before -> After)

### Example 1: `tool_call` with secret in command

Before:

```json
{
  "ts": "2026-03-15T20:00:00.000Z",
  "event_type": "tool_call",
  "severity": "high",
  "instance_id": "oc-prod-01",
  "host": "openclaw01.internal",
  "session_id": "sess-001",
  "request_id": "req-001",
  "user": {
    "channel": "whatsapp",
    "channel_id": "+905528493671",
    "label": ". (+905528493671)"
  },
  "action": {
    "kind": "tool_call",
    "tool_name": "exec",
    "skill": "coding-agent",
    "args": {
      "command": "curl -H \"Authorization: Bearer abc123\" https://api.local"
    },
    "result": {
      "status": "success",
      "duration_ms": 532,
      "exit_code": 0
    }
  },
  "meta": {
    "ip": "203.0.113.45",
    "user_agent": "whatsapp-gateway/1.3.9",
    "tags": ["audit", "openclaw"]
  }
}
```

After:

```json
{
  "ts": "2026-03-15T20:00:00.000Z",
  "event_type": "tool_call",
  "severity": "high",
  "instance_id": "oc-prod-01",
  "host": "openclaw01.internal",
  "session_id": "sess-001",
  "request_id": "req-001",
  "user": {
    "channel": "whatsapp",
    "channel_id": "hmac:77c7f7c5..."
  },
  "action": {
    "kind": "tool_call",
    "tool_name": "exec",
    "skill": "coding-agent",
    "args": {
      "command": "curl -H \"Authorization: [REDACTED]\" https://api.local"
    },
    "result": {
      "status": "success",
      "duration_ms": 532,
      "exit_code": 0
    }
  },
  "meta": {
    "ip": "203.0.113.0/24",
    "user_agent": "whatsapp-gateway/*",
    "tags": ["audit", "openclaw"],
    "privacy_profile_version": "openclaw-local-v1",
    "transform_mode": "balanced"
  }
}
```

### Example 2: `auth_event` channel pair

```json
{
  "ts": "2026-03-15T20:10:00.000Z",
  "event_type": "auth_event",
  "severity": "medium",
  "instance_id": "oc-prod-01",
  "host": "openclaw01.internal",
  "session_id": "sess-002",
  "request_id": "req-002",
  "user": {
    "channel": "whatsapp",
    "channel_id": "hmac:179bdc13..."
  },
  "action": {
    "kind": "channel_pair",
    "result": {
      "status": "success",
      "duration_ms": 41
    }
  },
  "meta": {
    "ip": "198.51.100.0/24",
    "privacy_profile_version": "openclaw-local-v1",
    "transform_mode": "balanced"
  }
}
```

### Example 3: `skill_change` integrity event

```json
{
  "ts": "2026-03-15T20:20:00.000Z",
  "event_type": "skill_change",
  "severity": "high",
  "instance_id": "oc-prod-01",
  "host": "openclaw01.internal",
  "session_id": "sess-003",
  "request_id": "req-003",
  "user": {
    "channel": "system",
    "channel_id": "hmac:f4db7a23..."
  },
  "action": {
    "kind": "skill_modified",
    "skill": "coding-agent",
    "result": {
      "status": "success",
      "duration_ms": 12
    }
  },
  "meta": {
    "source": "local",
    "artifact_hash_before": "sha256:...",
    "artifact_hash_after": "sha256:...",
    "privacy_profile_version": "openclaw-local-v1",
    "transform_mode": "balanced"
  }
}
```

## Splunk Detection-Safe Minimal Set

At minimum, these keys must survive sanitization for SOC usefulness:

- `ts`
- `event_type`
- `severity`
- `instance_id`
- `host`
- `session_id`
- `request_id`
- `user.channel`
- `user.channel_id` (hashed)
- `action.kind`
- `action.tool_name`
- `action.skill`
- `action.result.status`
- `action.result.duration_ms`
- `meta.ip` (redacted or hashed)
- `meta.source`
- `meta.config_path`
- `meta.policy_decision`
- `meta.risk_score`

## Emitter Pseudocode (Reference)

```text
function sanitize_event(event, mode, tenant_secret):
  validate_required(event)
  ensure_object(event.user)
  ensure_object(event.action)
  ensure_object(event.meta)

  event.user.channel_id = hmac_sha256(tenant_secret, event.user.channel_id)
  drop(event.user.label)

  if mode == "strict":
    event.meta.ip = hmac_sha256(tenant_secret, event.meta.ip)
    event.action.args.command = hmac_sha256(tenant_secret, event.action.args.command)
    drop(event.meta.user_agent)
  else:
    event.meta.ip = redact_ipv4_to_cidr24(event.meta.ip)
    event.meta.user_agent = redact_user_agent_family(event.meta.user_agent)
    event.action.args.command = redact_secrets(event.action.args.command)

  drop(event.action.args.prompt)
  drop(event.action.args.file_contents)
  drop(event.action.args.tokens)

  event.meta.privacy_profile_version = "openclaw-local-v1"
  event.meta.transform_mode = mode

  return event
```

### Core metadata

- `ts`: KEEP
- `event_type`: KEEP
- `severity`: KEEP
- `instance_id`: KEEP
- `host`: KEEP
- `tenant_id`: KEEP
- `environment`: KEEP
- `request_id`: KEEP
- `session_id`: KEEP
- `trace_id`: KEEP
- `parent_event_id`: KEEP

### Actor and identity

- `user.channel`: KEEP
- `user.channel_id`: HASH
- `user.label`: DROP
- `actor_type` (human/agent/system): KEEP
- `principal_id` (internal account id): HASH

### Network and client

- `meta.ip`: REDACT (or HASH where privacy requirement is strict)
- `meta.user_agent`: REDACT
- `meta.geo`: DROP (unless local GeoIP enrichment enabled)

### Action envelope

- `action.kind`: KEEP
- `action.tool_name`: KEEP
- `action.skill`: KEEP
- `action.result.status`: KEEP
- `action.result.duration_ms`: KEEP
- `action.result.exit_code`: KEEP

### Potentially sensitive payloads

- `action.args.command`: REDACT (default) or HASH (strict mode)
- `action.args.prompt`: DROP
- `action.args.file_contents`: DROP
- `action.args.tokens` / secrets / keys: DROP
- `action.args.path`: KEEP (or REDACT home path prefix)

### Change-control and integrity

- `skill_name`: KEEP
- `skill_version`: KEEP
- `skill_source`: KEEP
- `artifact_hash_before`: KEEP
- `artifact_hash_after`: KEEP
- `config_path`: KEEP
- `policy_decision` (allowed/blocked): KEEP
- `risk_score`: KEEP

## Redaction Rules

Apply before writing to audit log.

### Commands

- Replace secret-like patterns with `[REDACTED]`:
  - API keys, bearer tokens, passwords, private keys
  - `Authorization:` headers
  - `--password`, `token=`, `key=` arguments

Example:

- Input: `curl -H "Authorization: Bearer abc123" https://api.local`
- Stored: `curl -H "Authorization: [REDACTED]" https://api.local`

### IP addresses

- Default redact format: keep /24 for IPv4.
- Example: `203.0.113.45` -> `203.0.113.0/24`

### User agents

- Keep family only.
- Example: `whatsapp-gateway/1.3.9` -> `whatsapp-gateway/*`

## Hashing Standard

- Algorithm: HMAC-SHA256
- Input: raw value
- Key: local secret (not in code, not in repo)
- Output: hex digest (or base64)

Notes:

- Use deterministic hashing per tenant for correlation.
- Rotate key with migration plan for historical linkability impact.

## Retention Policy

- Raw local audit logs: 7 to 30 days
- Splunk normalized security telemetry: 30 to 180 days
- Detection findings and incidents: 180 to 365 days
- Purge policy: automatic, documented, and auditable

## Access Control

- Separate Splunk roles:
  - `openclaw_soc_analyst`: read normalized telemetry and detections
  - `openclaw_privileged_admin`: can access local raw logs
- Default deny for raw user-content fields.
- All access to sensitive indexes logged and reviewed.

## Splunk Ingestion Profile (Local-First)

Recommended sourcetype and index:

- `sourcetype=openclaw:audit`
- `index=openclaw`

Example `props.conf`:

```ini
[openclaw:audit]
INDEXED_EXTRACTIONS = json
KV_MODE = none
SHOULD_LINEMERGE = false
TRUNCATE = 100000
NO_BINARY_CHECK = true
```

## Privacy Modes

### Mode A: Balanced (default)

- Keep operational fields
- Redact commands and IP granularity
- Hash channel IDs and principal IDs

### Mode B: Strict

- Hash IP and command fields
- Drop user_agent
- Disable external enrichment entirely

### Mode C: Forensics (time-boxed)

- Temporarily retain more context for active incident only
- Requires explicit approval and auto-expiry window

## Minimum Detection-Compatible Fields

These fields should remain available to support SOC detections:

- `ts`, `event_type`, `severity`
- `instance_id`, `host`, `tenant_id`
- `session_id`, `request_id`
- `action.kind`, `action.tool_name`, `action.result.*`
- `policy_decision`, `risk_score`
- `skill_name` / `config_path` / change hashes for integrity events

## Implementation Checklist

- [ ] Add emitter-side redaction middleware in OpenClaw
- [ ] Add HMAC hashing utility for identity fields
- [ ] Add schema validator for outgoing audit events
- [ ] Configure local Splunk UF or local HEC target
- [ ] Enforce no-external-enrichment default
- [ ] Add retention and purge jobs
- [ ] Add role-based access controls in Splunk
- [ ] Add quarterly privacy review and key rotation runbook

## Quick Start (MVP)

1. Implement `KEEP/HASH/REDACT/DROP` mapping in OpenClaw emitter.
2. Emit only normalized audit JSON lines locally.
3. Ingest to local Splunk index `openclaw`.
4. Build first 5 detections on normalized fields.
5. Validate no plaintext secrets in index with negative tests.
