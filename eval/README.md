# SecOpsAI Evaluation Harness

SecOpsAI currently has two evaluation entrypoints:

- `python evaluate.py` is the canonical detector benchmark used for rule tuning, regression checks, and score tracking under `data/`.
- `python -m eval.harness.runner` is the v2 scenario/performance harness that writes report artifacts under `eval/reports/`.
- `python -m pytest tests/test_biological_intelligence.py` verifies the Biological Intelligence Layer coverage for immune response, ant trails, mycelium routing, flocking heuristics, predator-prey simulation, skin barriers, circadian timing, tree-root prioritization, echolocation probes, and camouflage recommendations.

Use `evaluate.py` when changing detection logic in `detect.py` or tracking benchmark changes. Treat the v2 harness as supplementary: use it when you need scenario-level gates or a report-oriented run across fallback datasets or future scenario suites.

For consistent interpreter selection, prefer `./scripts/run_eval_harness.sh`, which uses the repo `.venv` when present.

## v2 Architecture

```
eval/
├── harness/                 # Core evaluation engine
│   ├── __init__.py
│   ├── runner.py           # Main evaluation orchestrator
│   ├── metrics.py          # Metric calculations
│   └── reporters.py        # Report generators
├── reports/                # Generated reports
└── config.yaml             # Evaluation configuration
```

When `data/test_scenarios/` is absent, the v2 runner automatically falls back to labeled datasets already present in `data/`.

## Evaluation Dimensions

### 1. Detection Accuracy

- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1 Score**: Harmonic mean of precision and recall
- **FPR**: False Positive Rate
- **Per-rule metrics**: Individual rule performance
- **Per-scenario metrics**: Performance by attack category

### 2. Coverage Analysis

- **MITRE ATT&CK Coverage**: Map detections to ATT&CK techniques
- **Scenario Coverage**: % of scenarios detected
- **Platform Coverage**: macOS, Linux, Windows, OpenClaw

### 3. Performance

- **Throughput**: Events processed per second
- **Latency**: Time from event to detection
- **Memory**: Peak memory usage
- **Scaling**: Performance under load

### 4. Robustness

- **Adversarial Resilience**: Detection under evasion
- **Noise Tolerance**: Performance with benign noise
- **Temporal Stability**: Consistency over time

### 5. Operational Readiness

- **Alert Quality**: Signal-to-noise ratio
- **Context Richness**: Evidence quality
- **Actionability**: Mitigation recommendations

### 6. Biological Intelligence

- **Threat memory**: repeated traits increase adaptive confidence and decay over time
- **Containment guidance**: immune response mode recommends access tightening, quarantine, and logging changes
- **Weak-signal routing**: related users, hosts, packages, sessions, and rules are grouped for analyst attention
- **Safe probing**: echolocation-style checks verify suspicious entities without destructive actions

## Usage

```bash
# Canonical detector benchmark
cd secopsai
python evaluate.py
python evaluate.py --verbose

# Preferred v2 wrapper
./scripts/run_eval_harness.sh --full

# Run full v2 evaluation suite
cd secopsai
python -m eval.harness.runner --full

# Run specific evaluation
python -m eval.harness.runner --category supply_chain
python -m eval.harness.runner --scenario malware_detected
python -m eval.harness.runner --performance

# Run with baselines
python -m eval.harness.runner --compare-baseline

# Generate report into a custom directory
./scripts/run_eval_harness.sh --output ./eval-reports/

# CI mode (non-interactive, strict gates)
python -m eval.harness.runner --ci

# Biological Intelligence Layer regression coverage
python -m pytest tests/test_biological_intelligence.py
```

## Dependencies

The v2 harness uses `psutil` for process profiling and `PyYAML` for config parsing. Those packages are declared in the project dependencies. If they are temporarily unavailable, the CLI now falls back to built-in defaults so help text and default runs still remain usable.

## CI Integration

The harness integrates with GitHub Actions for:

- Automated regression testing on PRs
- Daily benchmark runs
- Performance tracking over time
- Slack notifications on failures

## Configuration

Edit `eval/config.yaml` to customize:

- Evaluation thresholds
- Scenario selection
- Metric weights
- Report formats
