# API Reference

Python API documentation for integrating secopsai into your security tools.

## Design Philosophy

All functions are designed for:

- **Composability**: Use individually or chain together
- **Type Safety**: Full Python type hints
- **Reproducibility**: Deterministic outputs with optional seeding
- **Error Handling**: Clear exceptions with actionable messages

---

## Core Functions

### Detection Pipeline

```python
from detect import run_detection, DETECTION_RULES

# Run all rules on events
findings: List[str] = run_detection(events)

# Run specific rule
if "RULE-101" in DETECTION_RULES:
    dangerous_findings = DETECTION_RULES["RULE-101"](events)

# List available rules
print(list(DETECTION_RULES.keys()))
# Output: ['RULE-001', ..., 'RULE-110']
```

#### `run_detection(events: List[Dict]) -> List[str]`

Runs all registered detection rules against event list.

**Parameters:**

- `events` (List[Dict]): Event batch, each with at minimum:
  - `event_id` (str): unique identifier
  - `timestamp` (str): ISO 8601 format

**Returns:**

- List of detected `event_id` strings that triggered rules

**Raises:**

- `ValueError`: If events schema invalid
- `KeyError`: If required field missing

**Example:**

```python
events = [
    {
        "event_id": "evt-001",
        "timestamp": "2026-03-15T14:23:45Z",
        "surface": "exec",
        "command": "curl | bash",
        "label": "malicious"
    }
]

findings = run_detection(events)
# Output: ['evt-001']
```

---

### Benchmark Evaluation

```python
from evaluate import evaluate_benchmark

report = evaluate_benchmark(
    labeled_events=labeled,
    unlabeled_events=unlabeled,
    verbose=True
)

print(f"F1: {report['f1_score']}")
print(f"Precision: {report['precision']}")
print(f"Recall: {report['recall']}")
```

#### `evaluate_benchmark(labeled_events, unlabeled_events, verbose=False) -> Dict`

Evaluates detection rules against labeled corpus.

**Parameters:**

- `labeled_events` (List[Dict]): Attack events with `label="malicious"`
- `unlabeled_events` (List[Dict]): Benign events with `label="benign"`
- `verbose` (bool): Print detailed per-rule breakdown

**Returns:**
Dict with keys:

```python
{
    "f1_score": float,           # Harmonic mean of precision & recall
    "precision": float,          # TP / (TP + FP)
    "recall": float,             # TP / (TP + FN)
    "false_positive_rate": float,# FP / (FP + TN)
    "accuracy": float,           # (TP + TN) / (TN + FP + FN + TP)

    "true_positives": int,       # Correctly detected attacks
    "false_positives": int,      # Benign flagged as attacks
    "false_negatives": int,      # Attacks not detected
    "true_negatives": int,       # Correctly cleared benign

    "per_rule_breakdown": {      # Per-rule metrics
        "RULE-101": {
            "fires": int,
            "true_positives": int,
            "false_positives": int
        },
        ...
    }
}
```

**Example:**

```python
import json

with open('labeled.json') as f:
    labeled = json.load(f)

with open('unlabeled.json') as f:
    unlabeled = json.load(f)

report = evaluate_benchmark(labeled, unlabeled, verbose=True)

if report['f1_score'] >= 0.9:
    print("✓ Detection quality acceptable")
else:
    print("✗ Detection needs tuning")
```

---

### Data Generation

```python
from generate_openclaw_attack_mix import build_attack_records, build_outputs

# Generate attack events
attack_records = build_attack_records(
    base_events=benign_events,
    benign_count=58,
    attack_count=22,
    seed=42
)

# Write to disk
build_outputs(
    attack_records=attack_records,
    output_labeled="labeled.json",
    output_unlabeled="unlabeled.json",
    output_audit="audit.jsonl"
)
```

#### `build_attack_records(base_events, benign_count, attack_count, seed=None) -> List[Dict]`

Generates deterministic attack scenarios on top of benign base events.

**Parameters:**

- `base_events` (List[Dict]): Benign baseline events to augment
- `benign_count` (int): How many benign events to keep
- `attack_count` (int): How many attack scenarios to generate
- `seed` (int, optional): Random seed for reproducibility

**Returns:**

- List of labeled events:
  ```python
  {
      "event_id": "evt-atk-001",
      "label": "malicious",      # or "benign"
      "attack_type": "T1059",    # MITRE ATT&CK code
      ...
  }
  ```

**Attack Types Generated:**

- T1059: Dangerous execution
- T1528: Sensitive config change
- T1195: Skill source drift
- T1078: Policy denial churn
- T1087: Tool burst
- T1104: Subagent fanout
- T1529: Restart loop
- T1048: Data exfiltration
- T1204: Malware presence

**Example:**

```python
import json

# Load benign baseline
with open('benign.json') as f:
    benign = json.load(f)

# Generate reproducible 80-event corpus
attacks = build_attack_records(benign, benign_count=58, attack_count=22, seed=42)

# Save for later
with open('attack_mix.json', 'w') as f:
    json.dump(attacks, f)
```

---

### Findings Report

```python
from findings import build_findings_report, dedup_findings

report = build_findings_report(
    detected_event_ids=['evt-001', 'evt-042'],
    all_events=events,
    rules=DETECTION_RULES
)

# Deduplicate overlapping findings
deduped = dedup_findings(report['findings'])

print(f"Found {len(deduped)} incidents")
```

#### `build_findings_report(detected_event_ids, all_events, rules) -> Dict`

Generates structured findings report with deduplication and severity ranking.

**Parameters:**

- `detected_event_ids` (List[str]): IDs returned by `run_detection()`
- `all_events` (List[Dict]): Full event list with metadata
- `rules` (Dict): DETECTION_RULES registry

**Returns:**

```python
{
    "total_findings": int,
    "findings": [
        {
            "finding_id": "OCF-001",
            "title": str,
            "rule_id": str,
            "attack_type": str,
            "severity": str,        # CRITICAL, HIGH, MEDIUM, LOW
            "confidence": float,    # 0.0-1.0
            "event_ids": [str],
            "description": str,
            "pattern": str,
            "remediation": str,
            "timestamp": str
        },
        ...
    ],
    "severity_breakdown": {
        "CRITICAL": int,
        "HIGH": int,
        "MEDIUM": int,
        "LOW": int
    }
}
```

**Example:**

```python
from detect import run_detection, DETECTION_RULES
from findings import build_findings_report
import json

# Run detection
findings_ids = run_detection(events)

# Build report
report = build_findings_report(findings_ids, events, DETECTION_RULES)

# Save findings
with open('findings.json', 'w') as f:
    json.dump(report, f, indent=2)

# Print summary
print(f"Critical: {report['severity_breakdown']['CRITICAL']}")
print(f"High: {report['severity_breakdown']['HIGH']}")
```

---

### Data Normalization

```python
from prepare import normalize_events

normalized = normalize_events(raw_events)
```

#### `normalize_events(events: List[Dict]) -> List[Dict]`

Normalizes raw event logs into detector-ready schema.

**Schema (output):**

```python
{
    "event_id": str,
    "timestamp": str,           # ISO 8601
    "sourcetype": str,          # openclaw_*, botsv3_*, etc
    "surface": str,             # tool, exec, session, config, etc
    "action": str,              # write, read, start, stop
    "label": str,               # "benign" or "malicious"
    "attack_type": str,         # MITRE code: T1059, T1048, etc
    "severity_hint": str,       # LOW, MEDIUM, HIGH, CRITICAL

    # Surface-specific fields
    "tool_name": str,           # if surface=tool
    "command": str,             # if surface=exec
    "username": str,            # if available
    "status": str,              # success, denied, failed, etc
    ...
}
```

**Example:**

```python
raw = [
    {
        "raw_timestamp": 1710518625000,
        "event": "tool_started",
        "args": ["curl", "|", "bash"]
    }
]

clean = normalize_events(raw)
# Output: [{ "timestamp": "2026-03-15T14:23:45Z", "command": "curl | bash", ... }]
```

---

## Custom Rule Development

### Template

```python
from typing import List, Dict

def detect_custom_pattern(events: List[Dict]) -> List[str]:
    """
    Detects custom attack pattern.

    Returns:
        List of event_ids that match the pattern
    """
    findings = []

    for event in events:
        # Check event properties
        if event.get("sourcetype", "").startswith("openclaw_"):
            if "dangerous" in event.get("command", "").lower():
                findings.append(event["event_id"])

    return findings

# Register in DETECTION_RULES
DETECTION_RULES["RULE-201"] = detect_custom_pattern
```

### Testing Custom Rule

```python
from detect import DETECTION_RULES

# Define test events
test_events = [
    {
        "event_id": "evt-test-1",
        "timestamp": "2026-03-15T14:00:00Z",
        "sourcetype": "openclaw_tool",
        "command": "dangerous command here"
    }
]

# Run custom rule
matches = DETECTION_RULES["RULE-201"](test_events)
assert "evt-test-1" in matches, "Custom rule should detect test event"
```

---

## OpenClaw Integration

### Export Native Telemetry

```python
from export_real_openclaw_native import export_openclaw_surfaces

export_openclaw_surfaces(
    openclaw_root="~/.openclaw",
    output_dir="data/openclaw/native"
)
```

### Ingest Native Surfaces

```python
from ingest_openclaw import ingest_surfaces

ingest_surfaces(
    input_root="data/openclaw/native",
    output="data/openclaw/raw/audit.jsonl",
    surfaces=["agent-events.jsonl", "exec-events.jsonl"]
)
```

---

## Error Handling

All functions raise typed exceptions:

```python
from detect import InvalidEventSchema

try:
    findings = run_detection(events)
except InvalidEventSchema as e:
    print(f"Event schema error: {e}")
    # Handle gracefully
```

Common exceptions:

- `ValueError`: Invalid parameter
- `KeyError`: Missing required field
- `FileNotFoundError`: Data file not found
- `json.JSONDecodeError`: Malformed JSON input

---

## Type Hints Reference

All functions use Python 3.10+ type hints:

```python
def example(
    events: list[dict],
    threshold: int = 5,
    verbose: bool | None = None,
) -> tuple[list[str], dict]:
    """Type-hinted example function"""
    pass
```

---

## Performance Characteristics

| Operation                 | Time (80 events) | Memory   |
| ------------------------- | ---------------- | -------- |
| `run_detection()`         | &lt;1ms          | &lt;10MB |
| `evaluate_benchmark()`    | ~100ms           | ~50MB    |
| `build_attack_records()`  | ~50ms            | ~30MB    |
| `build_findings_report()` | ~20ms            | ~15MB    |

---

**Next:** [Deployment Guide](deployment-guide.md) for production setup.
