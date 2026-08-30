# Research Reliability Benchmark

SecOpsAI includes an offline, deterministic benchmark for the controls that
protect source-backed research. It uses synthetic fixtures only and never
installs, executes, uploads, or mutates production data.

## Conditions

The benchmark compares:

1. **Full controls**: hypothesis pool, safety screen, scaffold/transition
   gates, immutable bundles, claim verification/clipping, completeness,
   originality, visual QA, and publication blockers.
2. **Claim clipping disabled**: tests whether unsupported sentences reach the
   manuscript without the correction pass.
3. **Completeness audit disabled**: tests whether omitted failures or
   selective reporting pass without the audit.
4. **Unconstrained mock baseline**: demonstrates why mocked success and
   unverified model prose cannot be accepted as evidence.

Production controls are never disabled; the latter conditions run in isolated
fixture logic solely to measure the safety benefit.

## Measures

Results include unsupported-claim rate, evidence coverage, hallucination
severity, methodology divergence, selective-reporting rate,
plagiarism/attribution failures, reviewer disagreement, false positives,
false negatives, publication-block accuracy, latency, token estimate, and
cost estimate. A passing run requires the full-control condition to prevent
unsupported or unsafe publication while keeping the legitimate fixture
available.

## Run it

```bash
secopsai research reliability benchmark --json
```

The fixture file is `secopsai/reliability_benchmark_fixtures.json`. Its digest
is validated before execution and the benchmark reports whether production
controls were modified (`false` is required). Do not add real malware, private
telemetry, credentials, or downloaded archives to the fixture set.
