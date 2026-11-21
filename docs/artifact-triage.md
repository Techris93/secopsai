# Artifact Triage

Artifact triage is the stage of the OSS artifact fleet where a model reviews
what the deterministic scanners found in a package. Only artifacts with
deterministic findings reach it, and a model never sees the raw package.

## What the model sees

The triage context is minimized:

- package metadata and file hashes
- rule hits and IOC values
- file names
- up to 2,048 bytes of text around each safe match

Raw archives, credentials and anything outside those excerpts are excluded.
Packages are never installed or executed at any stage.

## Run triage

```bash
secopsai artifact-fleet triage --enqueue-model --limit 500 --json   # queue pending contexts for the model bridge
secopsai artifact-fleet triage --artifact-id ART-0123456789ABCDEF --json   # queue one artifact
secopsai artifact-fleet triage-show ART-0123456789ABCDEF --json     # the stored context and result
secopsai artifact-fleet analyst-queue --limit 100 --json            # artifacts waiting for an analyst
```

Queuing creates jobs for the configured model bridge; the CLI itself makes no
model call. `--model` selects the model the bridge should use.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `benign` | The findings are expected behaviour for this package |
| `likely_benign` | The findings look like false positives |
| `suspicious` | Likely malicious; the model's malicious probability of 70 or more always gives this verdict |
| `inconclusive` | Not enough evidence either way |

## When an artifact closes without an analyst

A result closes the artifact (`resolved`) only when all of these hold:

- automated closure is enabled
- the result is a calibrated benign verdict from a model whose calibration has
  been approved, and that calibration covered the package's ecosystem
- the evidence coverage is complete
- the result cites evidence references, and every one of them exists in the
  context the model was given

Otherwise the artifact goes to `analyst_review`, which is where every result
goes while automated closure is off. Suspicious and inconclusive results always
need an analyst. Deeper file analysis is analyst-initiated and approval-gated.

See [OSS Artifact Fleet Operations](artifact-fleet-operations.md) for the
index and scan stages before triage, and
[Artifact Rule Packs](artifact-rule-packs.md) for the rules that produce the
findings.
