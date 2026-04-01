# SecOpsAI Evaluation Harness v2

A comprehensive evaluation framework for SecOpsAI that tests detection accuracy, performance, robustness, and real-world scenario coverage.

## Architecture

```
eval/
├── harness/                 # Core evaluation engine
│   ├── __init__.py
│   ├── runner.py           # Main evaluation orchestrator
│   ├── metrics.py          # Metric calculations
│   ├── reporters.py        # Report generators
│   └── assertions.py       # Test assertions
├── scenarios/              # Test scenarios by category
│   ├── supply_chain/       # npm/PyPI poisoning, typosquatting
│   ├── malware/            # RATs, droppers, cryptominers
│   ├── exfiltration/       # Data exfiltration techniques
│   ├── persistence/        # Launch agents, cron, registry
│   ├── privilege_escalation/  # Sudo exploits, SUID abuse
│   ├── defense_evasion/    # Process injection, obfuscation
│   └── benign/             # False positive test cases
├── fixtures/               # Test data generators
│   ├── event_factory.py    # Generate synthetic events
│   ├── network_factory.py  # Generate network traffic
│   └── file_factory.py     # Generate file artifacts
├── adversarial/            # Adversarial testing
│   ├── obfuscators.py      # Payload obfuscation
│   ├── evasion.py          # Evasion techniques
│   └── mutations.py        # Attack mutations
├── benchmarks/             # Performance benchmarks
│   ├── throughput.py       # Events/second
│   ├── latency.py          # Detection latency
│   └── memory.py           # Memory usage
├── baselines/              # Baseline comparisons
│   └── known_good/         # Validated detection outputs
├── reports/                # Generated reports (gitignored)
└── config.yaml             # Evaluation configuration
```

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

## Usage

```bash
# Run full evaluation suite
cd secopsai
python -m eval.harness.runner --full

# Run specific evaluation
python -m eval.harness.runner --category supply_chain
python -m eval.harness.runner --scenario malware_detected
python -m eval.harness.runner --performance

# Run with baselines
python -m eval.harness.runner --compare-baseline

# Generate report
python -m eval.harness.runner --report html --output ./eval-reports/

# CI mode (non-interactive, strict gates)
python -m eval.harness.runner --ci
```

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
