## BOTSv3 Integration

This directory contains optional BOTSv3 conversion and evaluation helpers.

It is intentionally outside the core autoresearch loop.

Use the root benchmark for rule optimization:

```bash
python prepare.py
python evaluate.py --verbose
```

Use BOTSv3 only when you want an additional realism check against exported Splunk data:

```bash
python integrations/botsv3/botsv3_convert.py
python integrations/botsv3/evaluate_botsv3.py --verbose
```

Files here:

- `botsv3_convert.py` converts exported BOTSv3 CSV telemetry into `data/botsv3_events.json`
- `botsv3_ingest.py` normalizes BOTSv3 challenge metadata into `data/botsv3_qa.json`
- `evaluate_botsv3.py` temporarily evaluates `detect.py` against BOTSv3 without replacing the baseline synthetic dataset permanently
