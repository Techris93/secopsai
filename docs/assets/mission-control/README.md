# Mission Control screenshots

This directory contains the canonical SecOpsAI Mission Control product tour
used by the core and dashboard READMEs.

Every image uses representative sample data. Screenshots must never contain
real tokens, credentials, customer records, private telemetry, personal email
addresses, or local-only filesystem paths.

## Canonical set

| File | Operator story |
| --- | --- |
| `overview.png` | Priorities, review queues, recent changes, and service health |
| `model-routing.png` | Persisted primary-model selection, health, and explicit fallback policy |
| `artifact-fleet.png` | Metadata indexing, deterministic/YARA analysis, minimized model triage, and analyst escalation |
| `research-case.png` | Evidence readiness, case progression, guarded decisions, and publication handoff |
| `findings.png` | Latest-first evidence-backed findings with impact and next safe action |
| `publications.png` | Editorial review, approved media, staging, archive preservation, and separate deployment |
| `enterprise.png` | Connector readiness, vulnerability context, authorized DAST, and governance workflows |

## Reproducible capture

Use the documentation fixture in the dashboard repository:

```text
tests/fixtures/readme-product-tour.html?view=overview
tests/fixtures/readme-product-tour.html?view=model-routing
tests/fixtures/readme-product-tour.html?view=artifact-fleet
tests/fixtures/readme-product-tour.html?view=research
tests/fixtures/readme-product-tour.html?view=findings
tests/fixtures/readme-product-tour.html?view=publications
tests/fixtures/readme-product-tour.html?view=enterprise
```

1. Start the canonical dashboard checkout with `./start-local-dashboard-stack.sh`.
2. Open each fixture URL under `http://127.0.0.1:45680/`.
3. Set the browser viewport to exactly 1600 by 900 CSS pixels.
4. Capture the viewport only, without browser chrome.
5. Save all seven files as true PNG images at 1600 by 900.
6. Recapture the complete set whenever the product shell or information architecture changes materially.

## Review checklist

- The dark green navigation, bright workspace, restrained green accents, and high-contrast text match the current product.
- The current section and operator purpose are immediately understandable.
- Labels and action states match real product behavior.
- Tables remain legible at GitHub's standard README width.
- No panel is clipped, empty, hidden behind a drawer, or surrounded by excessive blank space.
- The sample-data notice is visible in every capture.
- `file *.png` reports PNG data and every image has the same 1600 by 900 dimensions.
- Both READMEs render cleanly on desktop and mobile before the images are committed.
