<p align="center">
  <h1 align="center">🛡️ SecOps Autoresearch</h1>
  <p align="center">
    <strong>Autonomous Security Detection Optimization</strong>
  </p>
  <p align="center">
    Inspired by <a href="https://github.com/karpathy/autoresearch">karpathy/autoresearch</a> · Built on <a href="https://github.com/Techris93/OpenSentinel">OpenSentinel</a>
  </p>
</p>

---

## Overview

SecOps Autoresearch applies Karpathy's [autoresearch](https://github.com/karpathy/autoresearch) pattern to **cybersecurity detection rules** instead of LLM training. An AI agent autonomously optimizes detection rules, thresholds, and anomaly parameters to maximize detection accuracy — measured by F1 score against labeled security events.

| Autoresearch (LLM Training)          | SecOps Autoresearch (Detection)         |
| ------------------------------------ | --------------------------------------- |
| `prepare.py` — tokenizer + data prep | `prepare.py` — synthetic labeled events |
| `train.py` — model + optimizer       | `detect.py` — rules + thresholds        |
| `program.md` — agent instructions    | `program.md` — agent instructions       |
| Metric: `val_bpb`                    | Metric: `f1_score`                      |
| 5-minute training runs               | ~1-minute evaluation runs               |

## Quick Start

```bash
# 1. Generate test data (one-time, ~2 seconds)
python prepare.py

# 2. Run baseline evaluation
python evaluate.py --verbose

# 3. Start the agent
# Point your AI agent (Claude, Codex, Gemini, etc.) at this repo and say:
# "Read program.md and start an experiment"
```

**Requirements:** Python 3.10+. No GPU, no external APIs, no network access needed.

## Validation

Run the regression suite and benchmark together:

```bash
python -m unittest discover -s tests -v && python evaluate.py
```

Current validated benchmark on the generated dataset:

```text
F1 Score: 1.000000
Precision: 1.000000
Recall: 1.000000
False Positive Rate: 0.000000
```

## BOTSv3 Integration

If you added the BOTSv3 content CSVs (`ctf_questions.csv`, `ctf_answers.csv`, `ctf_hints.csv`), run:

```bash
python botsv3_ingest.py
```

This generates `data/botsv3_qa.json`, a normalized metadata bundle (questions, answers, hints).

Important: this metadata is not the raw telemetry. To evaluate `detect.py` with BOTSv3, you still need to:

1. Export BOTSv3 event logs from Splunk (for example as JSON/CSV per sourcetype)
2. Map exported events into this project's `data/events.json` schema (`timestamp`, `event_id`, `label`, `attack_type`, and event fields)
3. Run `python evaluate.py` against the converted labeled data

Safe local workflow with exported BOTSv3 CSVs:

```bash
# 1) Convert Splunk CSV exports into normalized BOTSv3 events
python botsv3_convert.py

# 2) Evaluate detection rules against BOTSv3 without modifying baseline events.json
python evaluate_botsv3.py

# 3) Run default benchmark as usual (synthetic baseline)
python evaluate.py
```

The `evaluate_botsv3.py` helper temporarily swaps in BOTSv3 data for both
`data/events.json` and `data/events_unlabeled.json`, then always restores both
baseline files afterward.

## OpenClaw Sample Workflow

This repository now includes a small OpenClaw adapter-event sample corpus and a
normalizer that converts it into the flat event shape consumed by `detect.py`.

Sample raw corpus:

- `data/openclaw/raw/sample_audit.jsonl`

Schemas:

- `schemas/openclaw_audit.schema.json`
- `schemas/normalized_event.schema.json`

Convert the sample corpus into labeled and unlabeled replay files:

```bash
python openclaw_prepare.py --stats
```

This writes:

- `data/openclaw/replay/labeled/sample_events.json`
- `data/openclaw/replay/unlabeled/sample_events.json`

Score the generated OpenClaw replay bundle directly:

```bash
python evaluate_openclaw.py --verbose
```

Generate grouped local findings from the replay bundle:

```bash
python openclaw_findings.py
```

This writes a timestamped findings bundle and updates a local SQLite store under:

- `data/openclaw/findings/`

Default local database:

- `data/openclaw/findings/openclaw_soc.db`

The findings generator now deduplicates overlapping rule hits into ranked incidents
and preserves analyst `status`, `disposition`, and `notes` in the local store
across regeneration runs.

Operator helpers for the local store:

```bash
# List findings
python soc_store.py list

# Show one finding with notes and dedup metadata
python soc_store.py show OCF-EXAMPLE

# Update analyst state
python soc_store.py set-disposition OCF-EXAMPLE true_positive
python soc_store.py set-status OCF-EXAMPLE triaged
python soc_store.py add-note OCF-EXAMPLE analyst "validated in replay"
```

Incident bundles now expose dedup metadata directly in the JSON payload:

- `merged_from_rule_ids`
- `dedup_reason`

The OpenClaw path is additive: it does not replace the synthetic benchmark or
the BOTSv3 benchmark. The new OpenClaw-specific rules in `detect.py` only act on
events whose `sourcetype` starts with `openclaw_`.

## Real OpenClaw Ingestion

To start using this against real OpenClaw surface exports, write native JSONL
files for these surfaces under a directory such as `data/openclaw/native/`:

- `agent-events.jsonl`
- `session-hooks.jsonl`
- `subagent-hooks.jsonl`
- `config-audit.jsonl`
- `restart-sentinels.jsonl`

Then ingest them into a detector-ready audit bundle:

```bash
python ingest_openclaw.py --input-root data/openclaw/native --output data/openclaw/raw/audit.jsonl --stats
```

The ingester maps those native surface exports into the adapter contract in:

- `schemas/openclaw_audit.schema.json`

From there, run the existing normalization and findings flow:

```bash
python openclaw_prepare.py --input data/openclaw/raw/audit.jsonl \
  --output data/openclaw/replay/labeled/current.json \
  --unlabeled-output data/openclaw/replay/unlabeled/current.json

python openclaw_findings.py --input data/openclaw/replay/labeled/current.json
python soc_store.py list
```

## Project Structure

```
prepare.py      — Data prep: generates ~2000 labeled security events (DO NOT MODIFY)
detect.py       — Detection rules + thresholds (AGENT MODIFIES THIS)
evaluate.py     — Scoring engine: F1, precision, recall, FPR (DO NOT MODIFY)
program.md      — Agent instructions for the autonomous loop
data/           — Generated event data and experiment logs
```

## How It Works

1. `prepare.py` generates a deterministic dataset of ~2000 security events:
   - **6 attack types** mapped to MITRE ATT&CK: brute force (T1110), DNS exfiltration (T1048.003), C2 beaconing (T1071), lateral movement (T1021.002), PowerShell abuse (T1059.001), privilege escalation (T1068)
   - **Benign traffic**: normal auth, DNS, firewall, and process events

2. The agent modifies `detect.py` to improve detection accuracy

3. `evaluate.py` runs the detection pipeline and computes:
   - **F1 Score** (primary metric — harmonic mean of precision and recall)
   - Precision, recall, false positive rate
   - Per-rule breakdown and missed attack analysis

4. If the score improves, the agent commits `detect.py` to a git feature branch

5. Repeat indefinitely — the agent accumulates improvements over time

## Detection Rules (Baseline)

| Rule     | MITRE     | Attack Type            |
| -------- | --------- | ---------------------- |
| RULE-001 | T1110     | Brute Force Detection  |
| RULE-002 | T1048.003 | DNS Exfiltration       |
| RULE-003 | T1071     | C2 Beaconing           |
| RULE-004 | T1021.002 | Lateral Movement (SMB) |
| RULE-005 | T1059.001 | PowerShell Abuse       |
| RULE-006 | T1068     | Privilege Escalation   |

## Connection to OpenSentinel

This project uses detection rules ported from [OpenSentinel](https://github.com/Techris93/OpenSentinel), an AI-powered SOC Command Center. Improvements discovered by autoresearch can be ported back to OpenSentinel's production detection engine.

## License

MIT
