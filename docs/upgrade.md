# Upgrade Notes

This project does not currently publish a formal upgrade guide.

## Safe Upgrade Process

1. Pull the latest `main` branch.
2. Recreate or refresh the virtual environment.
3. Reinstall dependencies.
4. Re-run the benchmark corpus and regression tests.
5. Rebuild the container image if you deploy with Docker or Render.

## Commands

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
python evaluate.py
```

For deployment-specific rollout notes, see [Deployment Guide](deployment-guide.md).
