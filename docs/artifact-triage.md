# Artifact Triage

Only artifacts with deterministic findings enter model triage. The context is
limited to package metadata, hashes, rule hits, IOC values, file names, and up to
2,048 bytes around each safe match. Raw archives and credentials are excluded.

Model results are `benign`, `likely_benign`, `suspicious`, or `inconclusive`.
Suspicious and inconclusive results require analyst review. Deep file analysis
is analyst-initiated and approval-gated.

```bash
secopsai artifact-fleet triage --limit 500 --json
secopsai artifact-fleet triage-show ART-0123456789ABCDEF --json
secopsai artifact-fleet analyst-queue --limit 100 --json
```
