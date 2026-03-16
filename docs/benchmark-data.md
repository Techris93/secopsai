# Benchmark Data

secopsai is validated against a reproducible labeled OpenClaw attack corpus.

## Current Baseline

- F1 score: 1.000000
- Precision: 1.000000
- Recall: 1.000000
- False positives: 0

## How to Reproduce

```bash
python generate_openclaw_attack_mix.py --stats
python evaluate_openclaw.py \
  --labeled data/openclaw/replay/labeled/attack_mix.json \
  --unlabeled data/openclaw/replay/unlabeled/attack_mix.json \
  --mode benchmark \
  --verbose
```

## What It Covers

- dangerous execution
- sensitive config changes
- skill source drift
- policy denial churn
- tool burst abuse
- pairing churn abuse
- subagent fanout
- restart loops
- data exfiltration
- malware presence

For detailed rule behavior, see [Rules Registry](rules-registry.md).
