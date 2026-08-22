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
secopsai artifact-fleet cycle --since 24h --limit 1000 --workers 4 --json
secopsai artifact-fleet triage --limit 500 --enqueue-model --model xai/grok-4.6 --json
secopsai research rust-package --package proc-macro1 --version 1.0.107 --compare-package proc-macro2 --compare-version 1.0.107 --dry-run --json
```

## Dashboard buttons

In the local dashboard, open **Administration → Automation → Research
pipeline**. Enter the Automation action token in **Automation → Models**, then use the
buttons for **Run automated cycle**, **Index metadata**, **Scan pending**,
**Queue model triage**, **Refresh analyst queue**, **Validate rule pack**, and
**Run fixture benchmark**. The panel shows the output and refreshes queue
metrics after each action. The browser sends an action name and bounded values;
the helper builds an allowlisted argument array and never runs a browser shell.

**Run automated cycle** performs metadata indexing, safe scans for already
authorized local artifact paths, and triage queue preparation. It does not
download or execute packages, run model calls itself, publish research, or
close analyst findings. **Queue model triage** only creates minimized jobs for
the selected model bridge; the bridge and analyst review remain separate.

Exact `scan-artifact` calls are intentionally CLI-only because they require a
reviewed local artifact path and provenance. This prevents a dashboard click
from opening an arbitrary filesystem path. `source-health` and `metrics` are
read through **Refresh fleet** and the panel status response.

The **Exact crates.io package intake** workspace adds the crates.io workflow: preview
official metadata, fetch the exact crate into quarantine, verify its checksum,
run Rust static rules, compare an explicitly supplied reference crate, and
route strong findings into a Research Case. It never runs Cargo or creates a
public draft without the case publication gates.

## Optional scheduled cycle

For a local helper, run the cycle from a scheduler using the same bounded
command (for example, a launchd timer or CI schedule):

```bash
secopsai artifact-fleet cycle --since 24h --limit 1000 --workers 4 --json
```

Keep the scheduler pointed at a dedicated `SECOPSAI_ARTIFACT_FLEET_DB_PATH`.
Leave model execution and publication approval outside the scheduler unless a
separate, explicitly approved bridge policy is configured.

Indexing never downloads artifacts or calls a model. Scanning never executes
package code, build scripts, binaries, or extensions. Model triage only receives
rule-hit context and metadata. Suspicious and inconclusive results remain in
the analyst queue.

The benchmark is synthetic unless a production worker measurement is explicitly
recorded. Never describe the system as scanning 114,000 artifacts per day based
only on the benchmark.
