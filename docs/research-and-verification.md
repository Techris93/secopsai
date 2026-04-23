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

## Recommended automation

To keep things fresh:

1. Keep your regular SecOpsAI refresh scheduler running.
2. Run `python scripts/verify_docs_examples.py` after CLI or plugin changes.
3. Rebuild docs after successful verification:

```bash
mkdocs build
```

## See also

- [Findings Triage Guide](findings-triage-guide.md)
- [OpenClaw Plugin](OpenClaw-Plugin.md)
- [API Reference](api-reference.md)
