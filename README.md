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

| Autoresearch (LLM Training) | SecOps Autoresearch (Detection) |
|---|---|
| `prepare.py` — tokenizer + data prep | `prepare.py` — synthetic labeled events |
| `train.py` — model + optimizer | `detect.py` — rules + thresholds |
| `program.md` — agent instructions | `program.md` — agent instructions |
| Metric: `val_bpb` | Metric: `f1_score` |
| 5-minute training runs | ~1-minute evaluation runs |

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

| Rule | MITRE | Attack Type |
|------|-------|-------------|
| RULE-001 | T1110 | Brute Force Detection |
| RULE-002 | T1048.003 | DNS Exfiltration |
| RULE-003 | T1071 | C2 Beaconing |
| RULE-004 | T1021.002 | Lateral Movement (SMB) |
| RULE-005 | T1059.001 | PowerShell Abuse |
| RULE-006 | T1068 | Privilege Escalation |

## Connection to OpenSentinel

This project uses detection rules ported from [OpenSentinel](https://github.com/Techris93/OpenSentinel), an AI-powered SOC Command Center. Improvements discovered by autoresearch can be ported back to OpenSentinel's production detection engine.

## License

MIT
