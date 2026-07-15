# Research And Verification

SecOpsAI now has a local-first research and verification layer that helps keep investigations, docs, and operational examples current.

## Research commands

Use these when you want a source-backed explanation before you change findings, rules, or allowlists:

```bash
secopsai research preflight
secopsai research finding SCM-FA4BAE45589358A2 --search-root ~/secopsai
secopsai research package --ecosystem pypi --package litellm --version 1.83.10 --search-root ~/secopsai
```

The reports are written under `reports/research/` by default and can also be attached to an investigation session.

## Investigation with research attached

This is the fastest end-to-end workflow for an analyst:

```bash
secopsai triage investigate SCM-FA4BAE45589358A2 --search-root ~/secopsai --open-session --with-research --json
```

That flow can attach:

- triage JSON and Markdown reports
- research JSON and Markdown reports
- session events, plan steps, and approval history

## Durable independent research

For the guided package-intake, evidence, disclosure, sandbox-approval, and publication workflow, see [Research Automation](research-automation.md).

Use [Research Cases](research-cases.md) when an investigation must outlive one
finding or report. Cases add structured subjects, evidence provenance, IOCs,
disclosure state, publication readiness, deterministic export, and a
review-only Blog Ops handoff.

## Preflight before triage or correlation

Use preflight when you want to block low-quality automation runs caused by stale telemetry or bad source coverage:

```bash
secopsai research preflight
secopsai correlate --enforce-preflight
secopsai triage orchestrate --search-root ~/secopsai --enforce-preflight
```

This is especially important when replay telemetry has stopped updating or threat-intel freshness has drifted.

## Docs verification

The docs verifier checks that:

- documented `secopsai` examples still parse against the real CLI
- the OpenClaw plugin page still matches the plugin repo’s current tool registry

Run it from the repo root:

```bash
python scripts/verify_docs_examples.py
```

Use this in CI or a daily docs QA check so the site stays aligned with the actual CLI and plugin surface.

## Agent runtime

The local agent runtime adds routing, compaction, repeated-loop checks, and isolated job records:

```bash
secopsai agent route --task "investigate stale replay telemetry before triage"
secopsai agent compact <SESSION_ID> --json
secopsai agent run-job --name docs-qa -- python scripts/docs_source_agent.py --build
secopsai agent jobs --limit 10
```

Use `agent route` before an autonomous workflow to see which tools are read-only, write-gated, or expensive. Use `agent compact` before resuming a long investigation session. Use `agent run-job` for adaptive-intel, replay, docs, or regression work that should leave an auditable job record under `data/agent_jobs/`.

## Docs QA agent

The docs QA agent wraps the verifier and optionally runs a docs build, then writes JSON and Markdown reports under `reports/docs/`:

```bash
python scripts/docs_source_agent.py --build
```

## Recommended automation

To keep things fresh:

1. Keep your regular SecOpsAI refresh scheduler running.
2. Run `secopsai agent run-job --name docs-qa -- python scripts/docs_source_agent.py --build` after CLI or plugin changes.
3. Rebuild docs after successful verification:

```bash
mkdocs build
```

## See also

- [Findings Triage Guide](findings-triage-guide.md)
- [OpenClaw Plugin](OpenClaw-Plugin.md)
- [API Reference](api-reference.md)
