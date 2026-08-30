# Execution-Grounded Research Validation Report

**Validation date:** 2026-08-30
**Scope:** SecOpsAI Core and Mission Control dashboard
**Methodological inspiration:** [Accelerating Scientific Research with Gemini in the Real-World](https://arxiv.org/html/2608.26701v1). SecOpsAI is an independent defensive implementation; it does not copy the paper's text, prompts, figures, code, weights, or branding.

## Executive Result

The execution-grounded research path is implemented as one guarded pipeline:

`Discovery -> hypotheses -> safety/scope -> evidence plan -> scaffold -> transition -> full safe research -> immutable run bundle -> claim ledger -> specialist review -> blind review -> audits -> publication gate`

All core and dashboard regression checks completed successfully during this validation. The full Core suite completed with **683 passed, 4 subtests passed, and 16 warnings**. No package, build script, extension, binary, container, or payload was executed. The deterministic benchmark passed with zero unsupported claims, zero false positives, zero false negatives, complete claim coverage, and complete publication-block accuracy under the full-control fixture mode.

## Traceability Matrix

| Method or safety property | Implementation evidence | Verification evidence | Operator surface |
| --- | --- | --- | --- |
| Competing falsifiable hypotheses | `secopsai/research_reliability.py` hypothesis generation and ranking | `tests/test_research_reliability.py` hypothesis/ranking tests | Research Case reliability workspace |
| Pairwise and uncertainty-aware selection | Pairwise comparison, UCB-style ranking, cost/safety budgets | Reliability unit tests and fixture benchmark | Hypothesis ranking action |
| Versioned evidence plans and reflection | Plan revisions record intended, executed, missing, and contradicted evidence | Plan/scaffold/transition tests | Evidence Plan card |
| Scaffold, transition, and full safe research | Three explicit no-execution stages with transition gate | Stage transition tests and full suite | Research actions |
| Immutable execution bundles | Chained hashes, inputs, tool/model/resource snapshots, errors, and output hashes | Bundle verification tests | Run bundle view |
| Claim-level ledger | Extraction, support/contradiction state, evidence IDs, inference state, and clipping | Claim verification/clipping tests | Claim Ledger card |
| Unsupported/contradicted claim blocking | Hard publication blockers plus qualified rewrite/removal | Publication safety and adversarial fixture tests | Publication Safety card |
| Quality and originality checks | Completeness, attribution/originality, visual-QA, and multi-objective quality scoring | Audit tests and benchmark | Audit cards |
| Compositional safety | Directive screening and secret-read plus network-send composition detection | Unsafe-plan adversarial fixture | Safety status and blockers |
| Specialist plus blinded review | Independent reviewer receives bundle/claims without primary verdict; disagreement persisted | Specialist/blind-review/adjudication tests | Review and adjudication cards |
| Resource-aware orchestration | CPU/RSS/disk/queue/model/latency/cost snapshots and durable busy/heartbeat state | Bridge/job tests and bundle assertions | Models, Jobs, and run cards |
| Explicit model routing | Selected OpenCodex model and fallback policy are persisted and snapshotted; no silent switch | Model persistence and probe-scope tests | Automation -> Models |
| Typed APIs and allowlisted actions | Typed CLI and helper routes call direct functions or fixed argument arrays | CLI/API tests and dashboard tests | Button prerequisites and CLI fallback |
| Adversarial evaluation | 15 isolated fixtures plus ablations for disabled controls and unconstrained baseline | `tests/test_research_reliability.py` benchmark assertions | Reliability Benchmark docs |
| Visual publication verification | Desktop/mobile metadata, contrast, overflow, alt text, attribution, and licensing checks | Visual-QA tests | Visual QA card |
| Human approval boundaries | Sandbox, disclosure, publication, deploy, destructive actions, and external communication remain gated | Dashboard action-state tests | Publication and deployment controls |

## Verification Evidence

### Core

- `python3 -m py_compile secopsai/cli.py secopsai/supply_chain.py secopsai/rust_package_research.py secopsai/artifact_fleet.py secopsai/blog.py secopsai/research_reliability.py secopsai/specialist_orchestrator.py scripts/verify_docs_examples.py` — passed.
- `.venv/bin/python -m pytest tests/test_research_reliability.py -q` — **15 passed**.
- `.venv/bin/python -m pytest tests/test_research_reliability.py tests/test_verify_docs_examples.py tests/test_sqlite_writer_lock.py -q` — **25 passed**.
- `.venv/bin/python -m pytest -q` — **683 passed, 4 subtests passed, 16 warnings** in 384.81 seconds.
- `python3 scripts/verify_docs_examples.py` — `ok: true`, **14 documents**, **115 commands**.
- `mkdocs build --strict` — passed. Existing informational notices identify legacy documents outside the pre-existing navigation; all new reliability documents are in navigation.
- `git diff --check` — passed before release.

The full suite initially exposed two concrete regressions. The website copy test failed because `website/index.html` had not mirrored the public `www/index.html` reliability copy; the copies were synchronized. The SQLite writer-lock test inherited this shell's intentional `SECOPS_BUSY_TIMEOUT_MS=30000` setting instead of testing the default; the test now removes that environment override, leaving production configurability unchanged. The focused regressions and the complete suite pass after both fixes.

### Dashboard

- `npm test` — passed: Blog Ops worker, professional console, and research-case/detection-learning runtime checks.
- `npm run check` — passed.
- `python3 -m py_compile dashboard_server.py` — passed.
- `python3 -m unittest tests/test_triage_ops_evidence.py -q` — **47 tests passed**.
- `/Users/chrixchange/secopsai/.venv/bin/python -m pytest tests/test_intelligence_ui.py -q` — **12 passed**.
- `git diff --check` — passed.

The signed-in local console was inspected at `http://127.0.0.1:45680`. Research Cases rendered without the former `artifacts is not defined` `ReferenceError`; the generic Automation -> Research pipeline rendered the adapter-driven workflow, safe-action explanations, selected-model controls, and publication separation. Static and runtime dashboard tests cover the reliability workspace, resolved-review gate, blocked actions, and Guide content.

An eight-request concurrent read probe across collector status, coverage windows, feed events, and triage state returned `ok: true` for every request. A previously cached long-lived tab had shown a transient SQLite lock message while the 5.5 GB local store was under concurrent polling; the direct CLI and subsequent serialized/concurrent probes completed successfully without changing production data.

## Benchmark Evidence

The isolated fixture file `secopsai/reliability_benchmark_fixtures.json` contains 15 adversarial scenarios: fabricated hashes/versions/IOCs, empty logs, hard-coded success, mocked analysis, selective reporting, asymmetric comparisons, source-domain IOC confusion, unsupported attribution, conflicting evidence, legitimate false positives, real source-backed compromise, reviewer disagreement, and unsafe compositional action plans.

The full-control benchmark run recorded:

- Unsupported claim rate: **0**
- Claim evidence coverage: **1.0**
- Publication-block accuracy: **1.0**
- False positives: **0**
- False negatives: **0**
- Production controls modified: **false**
- Model calls required: **0**

Ablation results are retained for comparison only. They never disable controls in production and are not used as a release gate.

## Safety and Known Limitations

- Artifact and package research is static and metadata-first. Dynamic sandbox submission is external, approval-gated, and must be represented by a linked evidence record before it can support a final claim.
- Model output is bounded review, not evidence. If the selected model is unavailable and fallback is disabled, the job remains queued; no silent provider substitution occurs.
- Visual-QA checks store sanitized metadata and require human review of screenshots, licensing, and editorial presentation.
- The benchmark is deterministic and offline; it demonstrates control behavior, not production threat prevalence or the performance of any external model.
- Local SQLite remains appropriate for local-first operation. A shared high-volume deployment should use the documented transactional/hosted data-plane migration and monitor storage/reader contention.
- The methodology is adapted independently from the cited paper and does not imply affiliation, endorsement, or reproduction of protected material.

## Operator Acceptance Checklist

1. Open Mission Control and verify helper, data plane, collectors, and model bridge health.
2. Confirm the selected OpenCodex model and explicit fallback policy.
3. Run or inspect the safe cycle, then select a lead with registry/source evidence.
4. Use the Research Case reliability workspace in order: hypotheses, plan, scaffold, transition, full safe research, bundle, ledger, reviews, audits, and publication safety.
5. Resolve unsupported claims and material reviewer disagreement before approval.
6. Create a review-only draft only after the hard gates pass.
7. Keep **Approve**, **Publish approved**, and **Deploy blog** as separate, auditable actions.

Detailed operator procedures are in [Research Reliability Operations](research-reliability.md), [Research Claim Ledger](research-claim-ledger.md), [Research Review and Adjudication](research-review-and-adjudication.md), [Research Visual QA](research-visual-qa.md), and [Execution-Grounded Research Architecture](execution-grounded-research-architecture.md).
