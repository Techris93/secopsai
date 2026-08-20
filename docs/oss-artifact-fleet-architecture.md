# OSS Artifact Fleet Architecture

## Funnel

SecOpsAI's artifact fleet is organized as four bounded stages:

1. Index metadata and advance a source cursor without downloading artifacts.
2. Scan an authorized artifact with deterministic static rules and safe archive
   inspection.
3. Build minimized model context only when findings exist.
4. Keep suspicious or inconclusive results in the analyst queue.

```text
registry metadata -> artifact_metadata -> scan queue -> artifact_scans
                                                |
                                                v
                                      minimized artifact_triage
                                                |
                                                v
                                      analyst review / research handoff
```

The local implementation uses `secopsai.artifact_fleet` and a bounded SQLite
queue. It bridges existing global registry collectors when available and keeps
unconfigured sources explicit. Hosted deployments can move this state to the
enterprise PostgreSQL data plane behind the same repository contract.

## Safety

Archive traversal, symlinks, devices, archive bombs, size, file-count, and
private-address checks are enforced before source inspection. Package code,
Cargo commands, lifecycle scripts, PowerShell, binaries, and extensions are
never executed. YARA syntax is structurally validated, and optional
`yara-python` compilation can be enabled in CI.

## Triage context

The model receives package metadata, hashes, rule IDs, severities, file paths,
bounded safe context, IOC values, and source references. It does not receive
raw archives, raw secrets, or full source trees by default. Model fallback is
not implicit; the selected provider remains operator-controlled.

## Scale and cost

`artifact-fleet benchmark` is a synthetic worker benchmark only. It reports
capacity and target comparison but never claims that a live registry fleet
scans 114,000 artifacts per day without a production measurement. Real source
freshness, dead letters, queue latency, scan duration, model tokens, and cost
must be recorded by a deployed worker.

## Local and hosted modes

Local mode uses fixture/index files and SQLite. Hosted mode should use the
enterprise PostgreSQL adapter, organization scope, pooled connections, source
cursors, dead letters, and server-side credentials. The dashboard renders
`not_configured` when the helper or hosted endpoint is absent.
