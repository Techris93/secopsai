# OpenClaw Native Plugin

SecOpsAI is available as a native OpenClaw plugin with a read-first workflow:

- source-backed finding investigation
- source-backed package and release review
- local investigation sessions with plans, artifacts, and approvals
- guarded write helpers for closes, queued actions, and orchestration

The plugin lives in the separate repository at `Techris93/openclaw-secopsai-plugin`, but its tools map directly to the local `secopsai` CLI in your SecOpsAI install.

## Installation

Install from ClawHub:

```bash
openclaw plugins install secopsai
```

If your OpenClaw registry still requires the scoped alias during migration:

```bash
openclaw plugins install clawhub:@techris93/secopsai
```

Or install from local source:

```bash
openclaw plugins install -l /path/to/openclaw-secopsai-plugin
```

## Configuration

Add to your OpenClaw config:

```json
{
  "plugins": {
    "entries": {
      "secopsai": {
        "enabled": true,
        "config": {
          "secopsaiPath": "~/secopsai",
          "socDbPath": "~/secopsai/data/openclaw/findings/openclaw_soc.db",
          "sessionDir": "~/secopsai/data/sessions"
        }
      }
    }
  },
  "tools": {
    "allow": [
      "secopsai_close_finding",
      "secopsai_triage_orchestrate",
      "secopsai_triage_apply_action",
      "secopsai_session_request_close_approval",
      "secopsai_session_request_action_approval",
      "secopsai_session_resolve_approval"
    ]
  }
}
```

### Config keys

| Key | Default | Description |
|---|---|---|
| `secopsaiPath` | `~/secopsai` | Path to the SecOpsAI repo / install |
| `socDbPath` | `~/secopsai/data/openclaw/findings/openclaw_soc.db` | SOC findings SQLite DB |
| `sessionDir` | `~/secopsai/data/sessions` | Investigation session storage |

## Tool families

### Read-only investigation and research

- `secopsai_list_findings`
- `secopsai_investigate_finding`
- `secopsai_investigate_with_sources`
- `secopsai_research_finding`
- `secopsai_research_package`
- `secopsai_edge_assets`
- `secopsai_edge_changes`
- `secopsai_edge_findings`
- `secopsai_review_release_with_sources`
- `secopsai_supply_chain_suggest_fp_action`
- `secopsai_session_list`
- `secopsai_session_show`
- `secopsai_triage_queue`
- `secopsai_triage_summary`

### Guarded write helpers

- `secopsai_close_finding`
- `secopsai_triage_orchestrate`
- `secopsai_triage_apply_action`
- `secopsai_session_request_close_approval`
- `secopsai_session_request_action_approval`
- `secopsai_session_resolve_approval`

Recommended pattern:

1. investigate or research first
2. open or reuse a session
3. request approval for risky action or close
4. resolve the approval and apply it

The plugin write-facing tools are intentionally approval-gated:

- `secopsai_close_finding` requests a `triage_close` approval instead of closing directly.
- `secopsai_triage_apply_action` requests a `triage_action` approval instead of applying directly.
- `secopsai_triage_orchestrate` runs with auto-apply disabled so resulting actions stay reviewable.
- `secopsai_session_resolve_approval` is the only tool that can apply an approved session payload.

## Example flow

```text
secopsai_list_findings status=open limit=20
secopsai_investigate_with_sources findingId=SCM-FA4BAE45589358A2
secopsai_session_list status=open limit=10
secopsai_close_finding findingId=SCM-FA4BAE45589358A2 sessionId=SES-3f6a12bc45de disposition=expected_behavior note="Package not referenced locally."
secopsai_session_resolve_approval sessionId=SES-3f6a12bc45de approvalId=APR-3f6a12bc45de decision=approved apply=true
```

### Source-backed package review

```text
secopsai_review_release_with_sources ecosystem=pypi packageName=litellm version=1.83.10
secopsai_research_package ecosystem=npm packageName=@ant-design/x-skill version=2.6.0
```

### Edge network context

```text
secopsai_edge_assets limit=50
secopsai_edge_changes limit=20
secopsai_edge_findings status=open limit=50
```

These tools read the Core-canonical asset graph and Edge-origin finding store.
They do not run Nmap, queue scans, or change finding state.

### Guarded queued-action flow

```text
secopsai_triage_queue
secopsai_session_request_action_approval sessionId=SES-3f6a12bc45de actionId=ACT-0001 summary="Approve allowlist action for this package."
secopsai_session_resolve_approval sessionId=SES-3f6a12bc45de approvalId=APR-3f6a12bc45de decision=approved apply=true
```

## Operational notes

- Read tools are the safest default for agent use.
- Write tools should stay explicitly allowed and approval-gated.
- Session artifacts let the dashboard, CLI, and plugin point at the same investigation trail.
- `secopsai_investigate_with_sources` is the easiest way to get a single session containing both the investigation report and the source-backed research report.

## Verify the docs against the real tool surface

Run the docs check from the SecOpsAI repo:

```bash
python scripts/verify_docs_examples.py
```

That command validates the documented `secopsai` CLI examples and compares this page’s plugin tool names with the actual tool registry in the plugin repo.

## See also

- [Findings Triage Guide](findings-triage-guide.md)
- [OpenClaw Integration](OpenClaw-Integration.md)
- [API Reference](api-reference.md)
