# Quick Reference

This page condenses the most useful launch and implementation details for secopsai.

## What Is Included

- One-command setup via `setup.sh`
- Core product documentation for install, rules, API, and deployment
- Container deployment with `Dockerfile` and `docker-compose.yml`
- CI/CD workflows for test, benchmark, and security scans

## Recommended First Steps

```bash
bash setup.sh --help
python generate_openclaw_attack_mix.py --stats
python evaluate_openclaw.py --mode benchmark --verbose
```

## Launch Path

1. Review [Getting Started](getting-started.md)
2. Validate the benchmark corpus and evaluation flow
3. Deploy the worker container on Render
4. Publish docs from this MkDocs site

## Repository Guide

The longer planning version is kept in the repository root:

- [QUICK-REFERENCE.md](https://github.com/Techris93/secops-autoresearch/blob/main/QUICK-REFERENCE.md)
