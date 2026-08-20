# Artifact Fleet Operations

The artifact fleet is a four-stage funnel: metadata indexing, safe deterministic
artifact scanning, minimized model triage, and analyst escalation.

```bash
secopsai artifact-fleet status --json
secopsai artifact-fleet source-health --json
secopsai artifact-fleet index --fixture tests/fixtures/artifact-fleet/index.json --json
secopsai artifact-fleet scan-artifact --ecosystem crates --package proc-macro1 --version 1.0.107 --artifact tests/fixtures/artifact-fleet/proc-macro1-1.0.107.crate --json
secopsai artifact-fleet analyst-queue --json
secopsai artifact-fleet metrics --json
secopsai artifact-fleet benchmark --artifacts 1000 --workers 4 --fixture-mode --json
```

Indexing never downloads artifacts or calls a model. Scanning never executes
package code, build scripts, binaries, or extensions. Model triage only receives
rule-hit context and metadata. Suspicious and inconclusive results remain in
the analyst queue.

The benchmark is synthetic unless a production worker measurement is explicitly
recorded. Never describe the system as scanning 114,000 artifacts per day based
only on the benchmark.
